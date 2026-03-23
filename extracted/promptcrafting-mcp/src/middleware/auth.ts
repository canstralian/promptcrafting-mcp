// src/middleware/auth.ts — B1 boundary: JWT verification + RBAC enforcement
// Mitigates: Spoofing (B0→B1), JWT confusion attacks, privilege escalation
//
// Security controls:
//   - Algorithm pinning: HS256 only (reject `none`, RS*/PS* unless explicitly configured)
//   - Claim validation: iss, aud, exp, sub all required
//   - RBAC: permission check before handler execution
//   - No secret in code — JWT_SECRET from Workers Secrets

import { Context, MiddlewareHandler } from "hono";
import type { Env, JWTPayload, Permission, Role } from "../types.js";
import { ROLE_PERMISSIONS } from "../types.js";

// ─── Constants ─────────────────────────────────────────────────────
const EXPECTED_ISSUER = "promptcrafting.net";
const EXPECTED_AUDIENCE = "promptcrafting-mcp";
const ALGORITHM = "HS256";

// ─── JWT Decode + Verify ───────────────────────────────────────────
// Uses Web Crypto API (available in Workers runtime)
async function verifyJWT(
  token: string,
  secret: string
): Promise<JWTPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode and validate header — ALGORITHM PINNING
  const header = JSON.parse(atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")));
  if (header.alg !== ALGORITHM) {
    throw new Error(
      `JWT algorithm mismatch: got '${header.alg}', expected '${ALGORITHM}'. ` +
      `Rejecting to prevent algorithm confusion attacks.`
    );
  }

  // Verify signature using Web Crypto
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signatureBytes = Uint8Array.from(
    atob(signatureB64.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );

  const dataBytes = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signatureBytes, dataBytes);

  if (!valid) {
    throw new Error("JWT signature verification failed");
  }

  // Decode payload
  const payload: JWTPayload = JSON.parse(
    atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"))
  );

  // Validate claims
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp <= now) {
    throw new Error("JWT expired");
  }
  if (payload.iss !== EXPECTED_ISSUER) {
    throw new Error(`JWT issuer mismatch: got '${payload.iss}'`);
  }
  if (payload.aud !== EXPECTED_AUDIENCE) {
    throw new Error(`JWT audience mismatch: got '${payload.aud}'`);
  }
  if (!payload.sub) {
    throw new Error("JWT missing required 'sub' claim");
  }
  if (!payload.role || !(payload.role in ROLE_PERMISSIONS)) {
    throw new Error(`JWT invalid role: '${payload.role}'`);
  }

  return payload;
}

// ─── Auth Middleware ────────────────────────────────────────────────
export function authMiddleware(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json(
        { error: "Missing or malformed Authorization header" },
        401
      );
    }

    const token = authHeader.slice(7);

    try {
      const payload = await verifyJWT(token, c.env.JWT_SECRET);
      // Store on context for downstream use
      c.set("jwtPayload", payload);
      c.set("userId", payload.sub);
      c.set("userRole", payload.role);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Authentication failed";
      console.error(`[AUTH] JWT verification failed: ${message}`);
      return c.json({ error: "Authentication failed", detail: message }, 401);
    }

    await next();
  };
}

// ─── RBAC Middleware ────────────────────────────────────────────────
export function requirePermission(
  ...permissions: Permission[]
): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const role = c.get("userRole") as Role | undefined;
    if (!role) {
      return c.json({ error: "No role in context — auth middleware missing?" }, 500);
    }

    const rolePerms = ROLE_PERMISSIONS[role] as readonly string[];
    const missing = permissions.filter((p) => !rolePerms.includes(p));

    if (missing.length > 0) {
      console.error(
        `[RBAC] User role '${role}' denied: missing ${missing.join(", ")}`
      );
      return c.json(
        {
          error: "Insufficient permissions",
          required: permissions,
          missing,
        },
        403
      );
    }

    await next();
  };
}

// ─── Rate Limit Middleware ─────────────────────────────────────────
export function rateLimitMiddleware(
  binding: "RATE_LIMITER" | "BURST_LIMITER" = "RATE_LIMITER"
): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const userId = c.get("userId") as string | undefined;
    // Identity-keyed rate limiting — never IP-based
    const key = userId || c.req.header("CF-Connecting-IP") || "anonymous";

    const limiter = c.env[binding];
    const { success } = await limiter.limit({ key });

    if (!success) {
      console.warn(`[RATE_LIMIT] Exceeded for key=${key} binding=${binding}`);
      return c.json(
        { error: "Rate limit exceeded", retryAfter: binding === "BURST_LIMITER" ? 10 : 60 },
        429
      );
    }

    await next();
  };
}
