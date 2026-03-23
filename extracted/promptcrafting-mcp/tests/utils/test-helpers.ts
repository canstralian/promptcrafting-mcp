// tests/utils/test-helpers.ts — Shared test utilities
import type { Env } from "../../src/types.js";

export const TEST_USER_ID = "test-user-123";
export const TEST_TEMPLATE_HMAC_KEY = "test-hmac-key-32-characters-long";
export const TEST_JWT_SECRET = "test-jwt-secret-32-characters-long";

/**
 * Generate a simple test JWT token (no actual crypto, just for testing)
 */
export function generateTestJWT(userId: string = TEST_USER_ID, role: string = "admin"): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({
    sub: userId,
    iss: "promptcrafting-test",
    aud: "promptcrafting-api",
    exp: Math.floor(Date.now() / 1000) + 3600,
    role,
    permissions: ["template:read", "template:create", "template:update", "template:delete", "hitl:resolve", "audit:read"],
  }));
  // In real tests, this would need proper HMAC signature
  const signature = "test-signature";
  return `${header}.${payload}.${signature}`;
}

/**
 * Helper to compute HMAC-SHA256 (mimics src/services/prompt-builder.ts)
 */
export async function computeHMAC(content: string, key: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(content));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Helper to compute SHA-256 hash
 */
export async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(content));
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Wait for a condition with timeout
 */
export async function waitFor(
  condition: () => Promise<boolean> | boolean,
  timeoutMs: number = 5000,
  intervalMs: number = 100
): Promise<boolean> {
  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    if (await condition()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}

/**
 * Initialize test database with required schema
 */
export async function initTestDatabase(db: D1Database): Promise<void> {
  // Read and execute migration files
  const migration1 = `
    CREATE TABLE IF NOT EXISTS prompt_audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL UNIQUE,
      session_id TEXT,
      template_id TEXT NOT NULL,
      template_version INTEGER NOT NULL DEFAULT 1,
      user_id TEXT NOT NULL,
      model TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('success','error','rate_limited','filtered','hitl_rejected','hitl_timeout')),
      latency_ms INTEGER NOT NULL DEFAULT 0,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      guardrail_flags TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_audit_template ON prompt_audit_logs(template_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON prompt_audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_status ON prompt_audit_logs(status);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON prompt_audit_logs(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_request ON prompt_audit_logs(request_id);

    CREATE TABLE IF NOT EXISTS guardrail_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      pass INTEGER NOT NULL CHECK(pass IN (0, 1)),
      reason TEXT,
      score REAL,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (request_id) REFERENCES prompt_audit_logs(request_id)
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_guardrail_request ON guardrail_events(request_id);
    CREATE INDEX IF NOT EXISTS idx_guardrail_stage ON guardrail_events(stage);
    CREATE INDEX IF NOT EXISTS idx_guardrail_pass ON guardrail_events(pass);

    CREATE TABLE IF NOT EXISTS template_changes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      template_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('create','update','delete')),
      user_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      content_hash TEXT NOT NULL,
      hmac_valid INTEGER NOT NULL CHECK(hmac_valid IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_template_changes_tid ON template_changes(template_id);
    CREATE INDEX IF NOT EXISTS idx_template_changes_uid ON template_changes(user_id);
  `;

  const migration2 = `
    CREATE TABLE IF NOT EXISTS hitl_approvals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL UNIQUE,
      template_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','timed_out')),
      expires_at TEXT NOT NULL,
      resolved_by TEXT,
      resolved_at TEXT,
      context TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_hitl_request ON hitl_approvals(request_id);
    CREATE INDEX IF NOT EXISTS idx_hitl_status ON hitl_approvals(status);
    CREATE INDEX IF NOT EXISTS idx_hitl_template ON hitl_approvals(template_id);
    CREATE INDEX IF NOT EXISTS idx_hitl_user ON hitl_approvals(user_id);
    CREATE INDEX IF NOT EXISTS idx_hitl_expires ON hitl_approvals(expires_at);

    CREATE TABLE IF NOT EXISTS hitl_dead_letter (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL,
      template_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      expired_at TEXT NOT NULL,
      context TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_hitl_dl_request ON hitl_dead_letter(request_id);
    CREATE INDEX IF NOT EXISTS idx_hitl_dl_template ON hitl_dead_letter(template_id);
    CREATE INDEX IF NOT EXISTS idx_hitl_dl_user ON hitl_dead_letter(user_id);
  `;

  // Execute migrations
  await db.exec(migration1);
  await db.exec(migration2);
}
