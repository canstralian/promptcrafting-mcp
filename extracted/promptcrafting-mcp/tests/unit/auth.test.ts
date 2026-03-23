// tests/unit/auth.test.ts — Unit tests for JWT verification + RBAC middleware
import { describe, it, expect } from "vitest";
import { authMiddleware, requirePermission } from "../../src/middleware/auth.js";
import { ROLE_PERMISSIONS } from "../../src/types.js";

const JWT_SECRET = "test-jwt-secret-32-characters-long";

// ─── Real JWT helpers (Web Crypto, same path as production) ──────────────────

async function makeJWT(
  payload: Record<string, unknown>,
  secret: string,
  headerOverrides: Record<string, unknown> = {}
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT", ...headerOverrides };
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const headerB64 = enc(header);
  const payloadB64 = enc(payload);
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

function validClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: "user-123",
    role: "admin",
    iss: "promptcrafting.net",
    aud: "promptcrafting-mcp",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

// Minimal Hono-like context factory
function makeCtx(token: string | null, envOverrides: Record<string, unknown> = {}) {
  const headers: Record<string, string> = {};
  if (token !== null) headers["Authorization"] = `Bearer ${token}`;

  const ctx: any = {
    req: { header: (name: string) => headers[name] ?? null },
    env: { JWT_SECRET, ...envOverrides },
    _store: {} as Record<string, unknown>,
    set(key: string, value: unknown) { this._store[key] = value; },
    get(key: string) { return this._store[key]; },
    json(body: unknown, status = 200) { return { body, status }; },
  };
  return ctx;
}

// ─── authMiddleware ───────────────────────────────────────────────────────────

describe("authMiddleware", () => {
  it("should pass and set context for a valid HS256 token", async () => {
    const token = await makeJWT(validClaims(), JWT_SECRET);
    const ctx = makeCtx(token);
    let nextCalled = false;

    const mw = authMiddleware();
    await mw(ctx, async () => { nextCalled = true; });

    expect(nextCalled).toBe(true);
    expect(ctx.get("userId")).toBe("user-123");
    expect(ctx.get("userRole")).toBe("admin");
  });

  it("should reject request with missing Authorization header", async () => {
    const ctx = makeCtx(null);
    const mw = authMiddleware();
    const result = await mw(ctx, async () => {});
    expect(result.status).toBe(401);
  });

  it("should reject token with wrong algorithm (RS256 confusion attack)", async () => {
    const token = await makeJWT(validClaims(), JWT_SECRET, { alg: "RS256" });
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with alg: none", async () => {
    const claims = validClaims();
    const enc = (obj: unknown) =>
      btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const token = `${enc({ alg: "none", typ: "JWT" })}.${enc(claims)}.`;
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject expired token", async () => {
    const token = await makeJWT(validClaims({ exp: Math.floor(Date.now() / 1000) - 10 }), JWT_SECRET);
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with wrong issuer", async () => {
    const token = await makeJWT(validClaims({ iss: "evil.example.com" }), JWT_SECRET);
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with wrong audience", async () => {
    const token = await makeJWT(validClaims({ aud: "other-service" }), JWT_SECRET);
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with missing sub claim", async () => {
    const { sub: _sub, ...noPrincipal } = validClaims() as any;
    const token = await makeJWT(noPrincipal, JWT_SECRET);
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with unknown role", async () => {
    const token = await makeJWT(validClaims({ role: "superuser" }), JWT_SECRET);
    const ctx = makeCtx(token);
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject token with tampered signature", async () => {
    const valid = await makeJWT(validClaims(), JWT_SECRET);
    const parts = valid.split(".");
    parts[2] = parts[2].slice(0, -4) + "xxxx"; // corrupt last 4 chars
    const ctx = makeCtx(parts.join("."));
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });

  it("should reject malformed token (only 2 parts)", async () => {
    const ctx = makeCtx("header.payload");
    const result = await mw_call(ctx);
    expect(result.status).toBe(401);
  });
});

// Helper to run authMiddleware and capture the return value
async function mw_call(ctx: any): Promise<{ status: number; body: unknown }> {
  const mw = authMiddleware();
  const result = await mw(ctx, async () => {});
  return result as any;
}

// ─── requirePermission ────────────────────────────────────────────────────────

describe("requirePermission", () => {
  function ctxWithRole(role: "admin" | "operator" | "viewer") {
    const ctx: any = {
      _store: { userRole: role },
      get(k: string) { return this._store[k]; },
      set(k: string, v: unknown) { this._store[k] = v; },
      json(body: unknown, status = 200) { return { body, status }; },
    };
    return ctx;
  }

  it("admin should be granted template:create", async () => {
    const ctx = ctxWithRole("admin");
    let nextCalled = false;
    await requirePermission("template:create")(ctx, async () => { nextCalled = true; });
    expect(nextCalled).toBe(true);
  });

  it("viewer should be denied template:create", async () => {
    const ctx = ctxWithRole("viewer");
    const result: any = await requirePermission("template:create")(ctx, async () => {});
    expect(result.status).toBe(403);
    expect(result.body.missing).toContain("template:create");
  });

  it("viewer should be denied hitl:resolve", async () => {
    const ctx = ctxWithRole("viewer");
    const result: any = await requirePermission("hitl:resolve")(ctx, async () => {});
    expect(result.status).toBe(403);
  });

  it("operator should be granted hitl:resolve", async () => {
    const ctx = ctxWithRole("operator");
    let nextCalled = false;
    await requirePermission("hitl:resolve")(ctx, async () => { nextCalled = true; });
    expect(nextCalled).toBe(true);
  });

  it("operator should be denied template:create", async () => {
    const ctx = ctxWithRole("operator");
    const result: any = await requirePermission("template:create")(ctx, async () => {});
    expect(result.status).toBe(403);
  });

  it("admin should be denied when role is absent from context", async () => {
    const ctx: any = {
      _store: {},
      get(k: string) { return this._store[k]; },
      json(body: unknown, status = 200) { return { body, status }; },
    };
    const result: any = await requirePermission("template:read")(ctx, async () => {});
    expect(result.status).toBe(500);
  });

  it("should deny when multiple permissions are required and role has only some", async () => {
    // operator has prompt:execute but NOT template:create
    const ctx = ctxWithRole("operator");
    const result: any = await requirePermission("prompt:execute", "template:create")(ctx, async () => {});
    expect(result.status).toBe(403);
    expect(result.body.missing).toContain("template:create");
  });
});

// ─── ROLE_PERMISSIONS shape invariants ───────────────────────────────────────

describe("ROLE_PERMISSIONS invariants", () => {
  it("admin should have all permissions that operator has", () => {
    const adminPerms = new Set(ROLE_PERMISSIONS.admin);
    for (const p of ROLE_PERMISSIONS.operator) {
      expect(adminPerms.has(p as any)).toBe(true);
    }
  });

  it("viewer should not have hitl:resolve", () => {
    expect(ROLE_PERMISSIONS.viewer).not.toContain("hitl:resolve");
  });

  it("viewer should not have template:create, update, or delete", () => {
    const viewerPerms = ROLE_PERMISSIONS.viewer as readonly string[];
    expect(viewerPerms).not.toContain("template:create");
    expect(viewerPerms).not.toContain("template:update");
    expect(viewerPerms).not.toContain("template:delete");
  });
});
