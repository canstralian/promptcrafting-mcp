// src/services/audit.ts — B3 boundary: immutable audit trail via D1
// Mitigates: Repudiation (STRIDE-R), compliance gaps, forensic blind spots
//
// All writes use ctx.waitUntil() for non-blocking execution.
// Logs prompt hashes, not raw prompts (GDPR-safe).

import type { AuditLogEntry, Env, GuardrailVerdict } from "../types.js";

// ─── Write Audit Log ───────────────────────────────────────────────
export async function writeAuditLog(
  db: D1Database,
  entry: AuditLogEntry
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO prompt_audit_logs (
          request_id, session_id, template_id, template_version,
          user_id, model, status, latency_ms,
          input_tokens, output_tokens, guardrail_flags, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        entry.requestId,
        entry.sessionId,
        entry.templateId,
        entry.templateVersion,
        entry.userId,
        entry.model,
        entry.status,
        entry.latencyMs,
        entry.inputTokens,
        entry.outputTokens,
        entry.guardrailFlags,
        entry.createdAt
      )
      .run();
  } catch (err) {
    // Audit failure must not crash the request pipeline.
    // Log to console (captured by Workers observability).
    console.error("[AUDIT] Failed to write audit log:", err);
  }
}

// ─── Write Guardrail Event ─────────────────────────────────────────
export async function writeGuardrailEvent(
  db: D1Database,
  requestId: string,
  stage: string,
  verdict: GuardrailVerdict
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO guardrail_events (
          request_id, stage, pass, reason, score, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(
        requestId,
        stage,
        verdict.pass ? 1 : 0,
        verdict.reason ?? null,
        verdict.score ?? null,
        verdict.details ? JSON.stringify(verdict.details) : null
      )
      .run();
  } catch (err) {
    console.error("[AUDIT] Failed to write guardrail event:", err);
  }
}

// ─── Write Template Change ─────────────────────────────────────────
// Records every create/update/delete operation on templates.
// The template_changes table exists in D1 but was never written to — this closes
// the repudiation gap for destructive operations (STRIDE-R at B3).
export async function writeTemplateChange(
  db: D1Database,
  entry: {
    templateId: string;
    action: "create" | "update" | "delete";
    userId: string;
    version: number;
    contentHash: string;
    hmacValid: boolean;
  }
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO template_changes (
          template_id, action, user_id, version, content_hash, hmac_valid, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(
        entry.templateId,
        entry.action,
        entry.userId,
        entry.version,
        entry.contentHash,
        entry.hmacValid ? 1 : 0
      )
      .run();
  } catch (err) {
    // Non-fatal — log and continue, but surface loudly so ops can investigate.
    console.error("[AUDIT] Failed to write template change log:", err);
  }
}

// ─── Query Audit Logs ──────────────────────────────────────────────
export async function queryAuditLogs(
  db: D1Database,
  filters: {
    userId?: string;
    templateId?: string;
    status?: string;
    since?: string;
    limit?: number;
    offset?: number;
  }
): Promise<{ logs: AuditLogEntry[]; total: number }> {
  const conditions: string[] = ["1=1"];
  const params: (string | number)[] = [];

  if (filters.userId) {
    conditions.push("user_id = ?");
    params.push(filters.userId);
  }
  if (filters.templateId) {
    conditions.push("template_id = ?");
    params.push(filters.templateId);
  }
  if (filters.status) {
    conditions.push("status = ?");
    params.push(filters.status);
  }
  if (filters.since) {
    conditions.push("created_at >= ?");
    params.push(filters.since);
  }

  const where = conditions.join(" AND ");
  const limit = Math.min(filters.limit ?? 50, 200);
  const offset = filters.offset ?? 0;

  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM prompt_audit_logs WHERE ${where}`)
    .bind(...params)
    .first<{ total: number }>();

  const logsResult = await db
    .prepare(
      `SELECT * FROM prompt_audit_logs WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    )
    .bind(...params, limit, offset)
    .all();

  return {
    logs: (logsResult.results ?? []) as unknown as AuditLogEntry[],
    total: countResult?.total ?? 0,
  };
}
