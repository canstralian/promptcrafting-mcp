-- migrations/0001_init.sql
-- D1 schema for promptcrafting-mcp audit trail
-- Run with: wrangler d1 execute promptcrafting-audit --file=migrations/0001_init.sql

-- ─── Prompt Audit Logs ─────────────────────────────────────────────
-- Records every prompt execution with guardrail results.
-- Stores hashes, not raw prompts (GDPR-safe).
CREATE TABLE IF NOT EXISTS prompt_audit_logs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id      TEXT    NOT NULL UNIQUE,
  session_id      TEXT,
  template_id     TEXT    NOT NULL,
  template_version INTEGER NOT NULL DEFAULT 1,
  user_id         TEXT    NOT NULL,
  model           TEXT    NOT NULL,
  status          TEXT    NOT NULL CHECK(status IN ('success','error','rate_limited','filtered')),
  latency_ms      INTEGER NOT NULL DEFAULT 0,
  input_tokens    INTEGER NOT NULL DEFAULT 0,
  output_tokens   INTEGER NOT NULL DEFAULT 0,
  guardrail_flags TEXT,  -- JSON-encoded guardrail verdicts
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Query patterns: by template, by user, by time range, by status
CREATE INDEX IF NOT EXISTS idx_audit_template   ON prompt_audit_logs(template_id);
CREATE INDEX IF NOT EXISTS idx_audit_user       ON prompt_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_status     ON prompt_audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_created    ON prompt_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_request    ON prompt_audit_logs(request_id);

-- ─── Guardrail Events ──────────────────────────────────────────────
-- Fine-grained tracking of each guardrail stage per request.
CREATE TABLE IF NOT EXISTS guardrail_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id  TEXT    NOT NULL,
  stage       TEXT    NOT NULL,  -- 'input_sanitize', 'hmac_verify', 'output_schema', 'pii_detect', 'canary_check'
  pass        INTEGER NOT NULL CHECK(pass IN (0, 1)),
  reason      TEXT,
  score       REAL,
  details     TEXT,   -- JSON-encoded details
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (request_id) REFERENCES prompt_audit_logs(request_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_guardrail_request ON guardrail_events(request_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_stage   ON guardrail_events(stage);
CREATE INDEX IF NOT EXISTS idx_guardrail_pass    ON guardrail_events(pass);

-- ─── Template Change Log ───────────────────────────────────────────
-- Tracks template create/update/delete operations for admin audit.
CREATE TABLE IF NOT EXISTS template_changes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id   TEXT    NOT NULL,
  action        TEXT    NOT NULL CHECK(action IN ('create','update','delete')),
  user_id       TEXT    NOT NULL,
  version       INTEGER NOT NULL,
  content_hash  TEXT    NOT NULL,
  hmac_valid    INTEGER NOT NULL CHECK(hmac_valid IN (0, 1)),
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_template_changes_tid ON template_changes(template_id);
CREATE INDEX IF NOT EXISTS idx_template_changes_uid ON template_changes(user_id);
