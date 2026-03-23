// src/services/hitl.ts — Human-In-The-Loop (HITL) gate
// Boundary: B3 (Data + Policy Layer)
//
// SPEC KIT alignment: A3 Approval Bypass / REQUIRE_HITL (agent-core-v1.0)
// Failure mode: REQUIRE_HITL — execution is blocked until a human approves,
// rejects, or the window expires. Timeout routes to dead-letter, never to
// silent pass. There is no code path that bypasses the gate on timeout.
//
// Architecture:
//   1. requestHITLApproval() writes a 'pending' record to D1 and returns.
//   2. waitForHITLDecision() polls D1 on a 2s interval until:
//      a. status = 'approved'  → returns { approved: true }
//      b. status = 'rejected'  → returns { approved: false, reason: 'rejected' }
//      c. expires_at < now     → writes timed_out + dead-letter, returns { approved: false, reason: 'timed_out' }
//   3. resolveHITLApproval() is called by the approval endpoint (admin/operator only).
//
// Polling is intentionally simple — no WebSockets, no queues.
// Cloudflare Durable Objects have a 30s CPU time limit per request; the caller
// (promptcraft_execute_prompt) must enforce the timeout externally and use
// ctx.waitUntil() for long-poll continuations if needed.

import type { Env } from "../types.js";

// ─── Types ─────────────────────────────────────────────────────────

export type HITLStatus = "pending" | "approved" | "rejected" | "timed_out";

export interface HITLApprovalRequest {
  requestId: string;
  templateId: string;
  templateName: string;
  userId: string;
  /** JSON-safe summary of variables (no raw values — hashed) */
  variablesHash: string;
  /** Timeout window in milliseconds (from HITL_TIMEOUT_MS env var) */
  timeoutMs: number;
}

export interface HITLDecision {
  approved: boolean;
  reason: "approved" | "rejected" | "timed_out";
  resolvedBy?: string;
  resolvedAt?: string;
}

// ─── Request HITL Approval ─────────────────────────────────────────
// Writes a pending approval record. Non-blocking — returns immediately
// after the DB write. The caller then calls waitForHITLDecision().
export async function requestHITLApproval(
  db: D1Database,
  req: HITLApprovalRequest
): Promise<void> {
  const expiresAt = new Date(Date.now() + req.timeoutMs).toISOString();

  const context = JSON.stringify({
    templateId: req.templateId,
    templateName: req.templateName,
    variablesHash: req.variablesHash,
    requestedAt: new Date().toISOString(),
  });

  await db
    .prepare(
      `INSERT INTO hitl_approvals
        (request_id, template_id, user_id, status, expires_at, context, created_at)
       VALUES (?, ?, ?, 'pending', ?, ?, datetime('now'))`
    )
    .bind(req.requestId, req.templateId, req.userId, expiresAt, context)
    .run();
}

// ─── Wait For HITL Decision ────────────────────────────────────────
// Polls D1 every POLL_INTERVAL_MS until decision or timeout.
// On timeout: writes terminal 'timed_out' record + dead-letter entry.
// INVARIANT: never returns { approved: true } on timeout.
export async function waitForHITLDecision(
  db: D1Database,
  requestId: string,
  timeoutMs: number
): Promise<HITLDecision> {
  const POLL_INTERVAL_MS = 2_000;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const row = await db
      .prepare(`SELECT status, resolved_by, resolved_at, expires_at FROM hitl_approvals WHERE request_id = ?`)
      .bind(requestId)
      .first<{ status: HITLStatus; resolved_by: string | null; resolved_at: string | null; expires_at: string }>();

    if (!row) {
      // Record missing — should never happen, but fail closed
      return { approved: false, reason: "rejected" };
    }

    if (row.status === "approved") {
      return {
        approved: true,
        reason: "approved",
        resolvedBy: row.resolved_by ?? undefined,
        resolvedAt: row.resolved_at ?? undefined,
      };
    }

    if (row.status === "rejected") {
      return {
        approved: false,
        reason: "rejected",
        resolvedBy: row.resolved_by ?? undefined,
        resolvedAt: row.resolved_at ?? undefined,
      };
    }

    if (row.status === "timed_out") {
      // Already marked timed out (race condition — another request beat us here)
      return { approved: false, reason: "timed_out" };
    }

    // Check wall-clock expiry even if status is still 'pending'
    const expiresAt = new Date(row.expires_at).getTime();
    if (Date.now() >= expiresAt) {
      break; // Fall through to timeout handler below
    }

    // Still pending — wait before next poll
    await sleep(POLL_INTERVAL_MS);
  }

  // ─── Timeout handler ───────────────────────────────────────────
  // INVARIANT: This is the ONLY place timed_out is written.
  // Never fails silently — always routes to dead-letter.
  await markTimedOut(db, requestId);
  return { approved: false, reason: "timed_out" };
}

// ─── Resolve HITL Approval ─────────────────────────────────────────
// Called by the approval endpoint. Only admins/operators may call this.
// Rejects if the request has already reached a terminal state.
export async function resolveHITLApproval(
  db: D1Database,
  requestId: string,
  resolution: "approved" | "rejected",
  resolvedBy: string
): Promise<{ ok: boolean; error?: string }> {
  const row = await db
    .prepare(`SELECT status FROM hitl_approvals WHERE request_id = ?`)
    .bind(requestId)
    .first<{ status: HITLStatus }>();

  if (!row) {
    return { ok: false, error: `HITL request not found: ${requestId}` };
  }

  if (row.status !== "pending") {
    return {
      ok: false,
      error: `Cannot resolve — request is already in terminal state: ${row.status}`,
    };
  }

  const resolvedAt = new Date().toISOString();

  await db
    .prepare(
      `UPDATE hitl_approvals
       SET status = ?, resolved_by = ?, resolved_at = ?
       WHERE request_id = ? AND status = 'pending'`
    )
    .bind(resolution, resolvedBy, resolvedAt, requestId)
    .run();

  return { ok: true };
}

// ─── Get HITL Approval Status ──────────────────────────────────────
// Read-only — used by the MCP query_audit tool and admin endpoints.
export async function getHITLApprovalStatus(
  db: D1Database,
  requestId: string
): Promise<{
  requestId: string;
  status: HITLStatus;
  expiresAt: string;
  resolvedBy: string | null;
  resolvedAt: string | null;
  context: Record<string, unknown> | null;
} | null> {
  const row = await db
    .prepare(`SELECT * FROM hitl_approvals WHERE request_id = ?`)
    .bind(requestId)
    .first<{
      request_id: string;
      status: HITLStatus;
      expires_at: string;
      resolved_by: string | null;
      resolved_at: string | null;
      context: string | null;
    }>();

  if (!row) return null;

  return {
    requestId: row.request_id,
    status: row.status,
    expiresAt: row.expires_at,
    resolvedBy: row.resolved_by,
    resolvedAt: row.resolved_at,
    context: row.context ? JSON.parse(row.context) : null,
  };
}

// ─── List Pending HITL Approvals ───────────────────────────────────
// Used by admin/operator dashboards to surface outstanding approval requests.
export async function listPendingHITLApprovals(
  db: D1Database,
  limit = 50
): Promise<Array<{
  requestId: string;
  templateId: string;
  userId: string;
  expiresAt: string;
  context: Record<string, unknown> | null;
  createdAt: string;
}>> {
  const result = await db
    .prepare(
      `SELECT request_id, template_id, user_id, expires_at, context, created_at
       FROM hitl_approvals
       WHERE status = 'pending' AND expires_at > datetime('now')
       ORDER BY created_at ASC
       LIMIT ?`
    )
    .bind(limit)
    .all<{
      request_id: string;
      template_id: string;
      user_id: string;
      expires_at: string;
      context: string | null;
      created_at: string;
    }>();

  return (result.results ?? []).map((r) => ({
    requestId: r.request_id,
    templateId: r.template_id,
    userId: r.user_id,
    expiresAt: r.expires_at,
    context: r.context ? JSON.parse(r.context) : null,
    createdAt: r.created_at,
  }));
}

// ─── Internal: Mark Timed Out + Dead-Letter ────────────────────────
async function markTimedOut(db: D1Database, requestId: string): Promise<void> {
  const timedOutAt = new Date().toISOString();

  // Fetch context for dead-letter record before updating
  const row = await db
    .prepare(`SELECT template_id, user_id, context FROM hitl_approvals WHERE request_id = ?`)
    .bind(requestId)
    .first<{ template_id: string; user_id: string; context: string | null }>();

  // Update status to timed_out (use conditional update to avoid races)
  await db
    .prepare(
      `UPDATE hitl_approvals
       SET status = 'timed_out', resolved_at = ?
       WHERE request_id = ? AND status = 'pending'`
    )
    .bind(timedOutAt, requestId)
    .run();

  // Write dead-letter record — append-only, never deleted
  if (row) {
    await db
      .prepare(
        `INSERT INTO hitl_dead_letter
          (request_id, template_id, user_id, expired_at, context, created_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(requestId, row.template_id, row.user_id, timedOutAt, row.context)
      .run();
  }
}

// ─── Utility ───────────────────────────────────────────────────────
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
