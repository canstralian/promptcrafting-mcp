import { describe, it, expect } from "vitest";
import app from "../src/index.js";
import type { Env, PromptTemplate } from "../src/types.js";

const TEST_USER_ID = "user-delete-test";
const JWT_SECRET = "test-secret";

function b64url(input: string): string {
  return Buffer.from(input).toString("base64url");
}

async function signJwt(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = b64url(JSON.stringify(header));
  const encodedPayload = b64url(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const encodedSignature = Buffer.from(new Uint8Array(signature)).toString("base64url");
  return `${data}.${encodedSignature}`;
}

function makeTemplate(partial: Partial<PromptTemplate> = {}): PromptTemplate {
  return {
    id: "test123",
    name: "Test Template",
    description: "A template for delete tests",
    version: 7,
    layers: {
      role: "Security reviewer",
      objective: "Validate correctness",
      constraints: "Never leak secrets",
      outputShape: "JSON",
    },
    contentHash: "deadbeefhash",
    hmacSignature: "signature",
    requiresHITL: false,
    tags: [],
    createdBy: "tester",
    createdAt: "2026-03-26T00:00:00.000Z",
    updatedAt: "2026-03-26T00:00:00.000Z",
    ...partial,
  };
}

class KVStub {
  store = new Map<string, unknown>();

  async get(key: string, _type?: "json"): Promise<any> {
    if (!this.store.has(key)) return null;
    return this.store.get(key);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(): Promise<{ keys: Array<{ name: string; metadata?: unknown }> }> {
    return { keys: [] };
  }
}

class D1Stub {
  inserts: Array<{
    template_id: string;
    action: string;
    user_id: string;
    version: number;
    content_hash: string;
    hmac_valid: number;
  }> = [];

  prepare(query: string): {
    bind: (...args: unknown[]) => { run: () => Promise<void> };
  } {
    return {
      bind: (...args: unknown[]) => ({
        run: async () => {
          if (query.includes("INSERT INTO template_changes")) {
            this.inserts.push({
              template_id: String(args[0]),
              action: String(args[1]),
              user_id: String(args[2]),
              version: Number(args[3]),
              content_hash: String(args[4]),
              hmac_valid: Number(args[5]),
            });
          }
        },
      }),
    };
  }
}

function makeEnv(kv: KVStub, d1: D1Stub): Env {
  return {
    MCP_SERVER: {} as DurableObjectNamespace,
    PROMPT_TEMPLATES: kv as unknown as KVNamespace,
    AUDIT_DB: d1 as unknown as D1Database,
    AI: {} as Ai,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    BURST_LIMITER: { limit: async () => ({ success: true }) },
    JWT_SECRET,
    TEMPLATE_HMAC_KEY: "hmac",
    ENVIRONMENT: "test",
    LOG_LEVEL: "debug",
    HITL_TIMEOUT_MS: "10000",
    MAX_PROMPT_LENGTH: "10000",
  };
}

describe("DELETE /api/v1/templates/:id", () => {
  it("deletes an existing template and writes an audit record", async () => {
    const kv = new KVStub();
    const d1 = new D1Stub();
    const env = makeEnv(kv, d1);
    kv.store.set("template:test123", makeTemplate());

    const token = await signJwt({
      sub: TEST_USER_ID,
      role: "admin",
      iss: "promptcrafting.net",
      aud: "promptcrafting-mcp",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }, JWT_SECRET);

    const res = await app.fetch(
      new Request("http://local.test/api/v1/templates/test123", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      deleted: true,
      id: "test123",
      note: "Versioned copies retained for 90 days",
    });
    expect(kv.store.has("template:test123")).toBe(false);

    expect(d1.inserts).toHaveLength(1);
    expect(d1.inserts[0]).toMatchObject({
      template_id: "test123",
      action: "delete",
      user_id: TEST_USER_ID,
      version: 7,
      content_hash: "deadbeefhash",
    });
  });

  it("returns 404 when template is missing", async () => {
    const kv = new KVStub();
    const d1 = new D1Stub();
    const env = makeEnv(kv, d1);

    const token = await signJwt({
      sub: TEST_USER_ID,
      role: "admin",
      iss: "promptcrafting.net",
      aud: "promptcrafting-mcp",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }, JWT_SECRET);

    const res = await app.fetch(
      new Request("http://local.test/api/v1/templates/missing123", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Template not found" });
    expect(d1.inserts).toHaveLength(0);
  });
});
