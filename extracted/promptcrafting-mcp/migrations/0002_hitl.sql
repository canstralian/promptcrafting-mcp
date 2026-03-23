-- migrations/0002_hitl.sql
-- HITL (Human-In-The-Loop) gate tables
-- Run with: wrangler d1 execute promptcrafting-audit --file=migrations/0002_hitl.sql
--
-- SPEC KIT alignment: A3 Approval Bypass / REQUIRE_HITL (agent-core-v1.0)
-- Failure mode: REQUIRE_HITL — blocks execution until approval, timeout, or reject

-- ─── HITL Approvals ────────────────────────────────────────────────
-- One record per approval request. Status transitions:
--   pending → approved | rejected | timed_out
-- Only one terminal state is ever written (no updates after terminal).
CREATE TABLE IF NOT EXISTS hitl_approvals (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id      TEXT    NOT NULL UNIQUE,  -- matches prompt_audit_logs.request_id
  template_id     TEXT    NOT NULL,
  user_id         TEXT    NOT NULL,         -- requesting user
  status          TEXT    NOT NULL DEFAULT 'pending'
                          CHECK(status IN ('pending','approved','rejected','timed_out')),
  expires_at      TEXT    NOT NULL,         -- ISO-8601 UTC deadline
  resolved_by     TEXT,                     -- approver user_id (NULL if timed_out/still pending)
  resolved_at     TEXT,                     -- ISO-8601 UTC resolution timestamp
  context         TEXT,                     -- JSON: template name, layers summary, variables hash
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_hitl_request    ON hitl_approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_hitl_status     ON hitl_approvals(status);
CREATE INDEX IF NOT EXISTS idx_hitl_template   ON hitl_approvals(template_id);
CREATE INDEX IF NOT EXISTS idx_hitl_user       ON hitl_approvals(user_id);
CREATE INDEX IF NOT EXISTS idx_hitl_expires    ON hitl_approvals(expires_at);

-- ─── HITL Dead-Letter Queue ────────────────────────────────────────
-- Captures approval requests that timed out without resolution.
-- Required for forensic audit of unanswered approvals.
-- Never deleted — append-only for compliance.
CREATE TABLE IF NOT EXISTS hitl_dead_letter (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id      TEXT    NOT NULL,
  template_id     TEXT    NOT NULL,
  user_id         TEXT    NOT NULL,
  expired_at      TEXT    NOT NULL,         -- when the approval window closed
  context         TEXT,                     -- JSON snapshot of original request context
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_hitl_dl_request  ON hitl_dead_letter(request_id);
CREATE INDEX IF NOT EXISTS idx_hitl_dl_template ON hitl_dead_letter(template_id);
CREATE INDEX IF NOT EXISTS idx_hitl_dl_user     ON hitl_dead_letter(user_id);
