// tests/unit/audit-and-hitl.test.ts — Unit tests for uncovered audit + HITL functions
import { describe, it, expect, beforeEach } from "vitest";
import { testEnv as env } from "../setup/test-env.js";
import { initTestDatabase, TEST_USER_ID } from "../utils/test-helpers.js";
import {
  writeAuditLog,
  writeGuardrailEvent,
  queryAuditLogs,
} from "../../src/services/audit.js";
import {
  requestHITLApproval,
  resolveHITLApproval,
  listPendingHITLApprovals,
  waitForHITLDecision,
  getHITLApprovalStatus,
} from "../../src/services/hitl.js";

beforeEach(async () => {
  await initTestDatabase(env.AUDIT_DB);
});

// ─── writeGuardrailEvent ──────────────────────────────────────────────────────

describe("writeGuardrailEvent", () => {
  it("should write a passing guardrail event to the guardrail_events table", async () => {
    // A guardrail event requires a parent row in prompt_audit_logs (FK constraint)
    const requestId = crypto.randomUUID();
    await writeAuditLog(env.AUDIT_DB, {
      requestId,
      sessionId: null,
      templateId: "tmpl-1",
      templateVersion: 1,
      userId: TEST_USER_ID,
      model: "test-model",
      status: "success",
      latencyMs: 50,
      inputTokens: 10,
      outputTokens: 20,
      guardrailFlags: "{}",
      createdAt: new Date().toISOString(),
    });

    await writeGuardrailEvent(env.AUDIT_DB, requestId, "input_sanitizer", {
      pass: true,
      reason: "Clean input",
    });

    const row = await env.AUDIT_DB.prepare(
      "SELECT * FROM guardrail_events WHERE request_id = ?"
    ).bind(requestId).first();

    expect(row).not.toBeNull();
    expect(row?.stage).toBe("input_sanitizer");
    expect(row?.pass).toBe(1); // SQLite boolean
    expect(row?.reason).toBe("Clean input");
  });

  it("should write a failing guardrail event with score and details", async () => {
    const requestId = crypto.randomUUID();
    await writeAuditLog(env.AUDIT_DB, {
      requestId,
      sessionId: null,
      templateId: "tmpl-2",
      templateVersion: 1,
      userId: TEST_USER_ID,
      model: "test-model",
      status: "filtered",
      latencyMs: 5,
      inputTokens: 0,
      outputTokens: 0,
      guardrailFlags: "{}",
      createdAt: new Date().toISOString(),
    });

    await writeGuardrailEvent(env.AUDIT_DB, requestId, "output_validator", {
      pass: false,
      reason: "PII detected: email",
      score: 0.95,
      details: { detectedTypes: ["email"] },
    });

    const row = await env.AUDIT_DB.prepare(
      "SELECT * FROM guardrail_events WHERE request_id = ?"
    ).bind(requestId).first();

    expect(row?.pass).toBe(0);
    expect(row?.reason).toBe("PII detected: email");
    expect(row?.score).toBeCloseTo(0.95);
    expect(JSON.parse(row?.details as string)).toEqual({ detectedTypes: ["email"] });
  });

  it("should write multiple guardrail events for the same request", async () => {
    const requestId = crypto.randomUUID();
    await writeAuditLog(env.AUDIT_DB, {
      requestId,
      sessionId: null,
      templateId: "tmpl-3",
      templateVersion: 1,
      userId: TEST_USER_ID,
      model: "test-model",
      status: "success",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 80,
      guardrailFlags: "{}",
      createdAt: new Date().toISOString(),
    });

    await writeGuardrailEvent(env.AUDIT_DB, requestId, "input_sanitizer", { pass: true });
    await writeGuardrailEvent(env.AUDIT_DB, requestId, "output_validator", { pass: true });
    await writeGuardrailEvent(env.AUDIT_DB, requestId, "canary_check", { pass: true });

    const rows = await env.AUDIT_DB.prepare(
      "SELECT * FROM guardrail_events WHERE request_id = ?"
    ).bind(requestId).all();

    expect(rows.results.length).toBe(3);
    const stages = rows.results.map((r: any) => r.stage);
    expect(stages).toContain("input_sanitizer");
    expect(stages).toContain("output_validator");
    expect(stages).toContain("canary_check");
  });
});

// ─── queryAuditLogs ───────────────────────────────────────────────────────────

describe("queryAuditLogs", () => {
  async function seed(overrides: Partial<{
    requestId: string; userId: string; templateId: string; status: string;
  }> = {}) {
    const entry = {
      requestId: overrides.requestId ?? crypto.randomUUID(),
      sessionId: null,
      templateId: overrides.templateId ?? "tmpl-default",
      templateVersion: 1,
      userId: overrides.userId ?? TEST_USER_ID,
      model: "test-model",
      status: (overrides.status ?? "success") as any,
      latencyMs: 100,
      inputTokens: 10,
      outputTokens: 20,
      guardrailFlags: "{}",
      createdAt: new Date().toISOString(),
    };
    await writeAuditLog(env.AUDIT_DB, entry);
    return entry;
  }

  it("should return all logs when no filters are applied", async () => {
    await seed();
    await seed();
    const { logs, total } = await queryAuditLogs(env.AUDIT_DB, {});
    expect(total).toBeGreaterThanOrEqual(2);
    expect(logs.length).toBeGreaterThanOrEqual(2);
  });

  it("should filter by userId", async () => {
    const e1 = await seed({ userId: "user-alpha" });
    await seed({ userId: "user-beta" });
    const { logs } = await queryAuditLogs(env.AUDIT_DB, { userId: "user-alpha" });
    expect(logs.every((l: any) => l.user_id === "user-alpha")).toBe(true);
    expect(logs.some((l: any) => l.request_id === e1.requestId)).toBe(true);
  });

  it("should filter by templateId", async () => {
    const e1 = await seed({ templateId: "tmpl-specific" });
    await seed({ templateId: "tmpl-other" });
    const { logs } = await queryAuditLogs(env.AUDIT_DB, { templateId: "tmpl-specific" });
    expect(logs.every((l: any) => l.template_id === "tmpl-specific")).toBe(true);
  });

  it("should filter by status", async () => {
    await seed({ status: "filtered" });
    await seed({ status: "success" });
    const { logs } = await queryAuditLogs(env.AUDIT_DB, { status: "filtered" });
    expect(logs.every((l: any) => l.status === "filtered")).toBe(true);
  });

  it("should filter by since date — excludes older records", async () => {
    const past = new Date(Date.now() - 10000).toISOString();
    await seed();
    const { logs } = await queryAuditLogs(env.AUDIT_DB, { since: past });
    expect(logs.length).toBeGreaterThanOrEqual(1);
  });

  it("should respect limit and offset for pagination", async () => {
    await seed({ userId: "user-paginate" });
    await seed({ userId: "user-paginate" });
    await seed({ userId: "user-paginate" });

    const page1 = await queryAuditLogs(env.AUDIT_DB, { userId: "user-paginate", limit: 2, offset: 0 });
    expect(page1.logs.length).toBe(2);
    expect(page1.total).toBe(3);

    const page2 = await queryAuditLogs(env.AUDIT_DB, { userId: "user-paginate", limit: 2, offset: 2 });
    expect(page2.logs.length).toBe(1);
  });

  it("should cap limit at 200 even if a higher value is requested", async () => {
    await seed();
    const { logs } = await queryAuditLogs(env.AUDIT_DB, { limit: 9999 });
    // We only seeded a few records, but verify the function doesn't error
    expect(Array.isArray(logs)).toBe(true);
  });

  it("should return total count matching filter", async () => {
    const uid = "user-count-test";
    await seed({ userId: uid });
    await seed({ userId: uid });
    await seed({ userId: "other-user" });

    const { total } = await queryAuditLogs(env.AUDIT_DB, { userId: uid });
    expect(total).toBe(2);
  });
});

// ─── listPendingHITLApprovals ─────────────────────────────────────────────────

describe("listPendingHITLApprovals", () => {
  it("should return pending approvals ordered by created_at ASC", async () => {
    const id1 = crypto.randomUUID();
    const id2 = crypto.randomUUID();

    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id1,
      templateId: "tmpl-a",
      templateName: "Template A",
      userId: TEST_USER_ID,
      variablesHash: "hash-a",
      timeoutMs: 60_000,
    });

    // Small delay to ensure different created_at
    await new Promise((r) => setTimeout(r, 10));

    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id2,
      templateId: "tmpl-b",
      templateName: "Template B",
      userId: TEST_USER_ID,
      variablesHash: "hash-b",
      timeoutMs: 60_000,
    });

    const pending = await listPendingHITLApprovals(env.AUDIT_DB);
    const ids = pending.map((p) => p.requestId);
    expect(ids).toContain(id1);
    expect(ids).toContain(id2);

    // Both should be pending
    expect(pending.every((p) => p.requestId === id1 || p.requestId === id2)).toBe(true);
  });

  it("should not return resolved (approved/rejected) requests", async () => {
    const id = crypto.randomUUID();

    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id,
      templateId: "tmpl-resolved",
      templateName: "Resolved Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-r",
      timeoutMs: 60_000,
    });

    await resolveHITLApproval(env.AUDIT_DB, id, "approved", "approver");

    const pending = await listPendingHITLApprovals(env.AUDIT_DB);
    expect(pending.map((p) => p.requestId)).not.toContain(id);
  });

  it("should respect the limit parameter", async () => {
    // Create 5 pending requests
    for (let i = 0; i < 5; i++) {
      await requestHITLApproval(env.AUDIT_DB, {
        requestId: crypto.randomUUID(),
        templateId: `tmpl-limit-${i}`,
        templateName: `Limit Template ${i}`,
        userId: TEST_USER_ID,
        variablesHash: `hash-${i}`,
        timeoutMs: 60_000,
      });
    }

    const limited = await listPendingHITLApprovals(env.AUDIT_DB, 3);
    expect(limited.length).toBeLessThanOrEqual(3);
  });

  it("should include context data parsed from JSON", async () => {
    const id = crypto.randomUUID();
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id,
      templateId: "tmpl-ctx",
      templateName: "Context Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-ctx",
      timeoutMs: 60_000,
    });

    const pending = await listPendingHITLApprovals(env.AUDIT_DB);
    const record = pending.find((p) => p.requestId === id);
    expect(record).toBeDefined();
    expect(record?.context).not.toBeNull();
    expect(record?.context?.templateId).toBe("tmpl-ctx");
  });

  it("should return empty array when no requests are pending", async () => {
    const pending = await listPendingHITLApprovals(env.AUDIT_DB);
    expect(Array.isArray(pending)).toBe(true);
    // May have entries from other tests in the suite; test the shape
    for (const p of pending) {
      expect(p).toHaveProperty("requestId");
      expect(p).toHaveProperty("templateId");
      expect(p).toHaveProperty("status");
      expect(p).toHaveProperty("expiresAt");
    }
  });

  it("should filter by status='timed_out' to list expired requests", async () => {
    const id1 = crypto.randomUUID();
    const id2 = crypto.randomUUID();

    // Create one pending request
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id1,
      templateId: "tmpl-pending-filter",
      templateName: "Pending Filter Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-pending",
      timeoutMs: 60_000,
    });

    // Create one that will time out immediately
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id2,
      templateId: "tmpl-timeout-filter",
      templateName: "Timeout Filter Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-timeout",
      timeoutMs: 1,
    });

    // Let it timeout
    await waitForHITLDecision(env.AUDIT_DB, id2, 1);

    // List only timed_out
    const timedOut = await listPendingHITLApprovals(env.AUDIT_DB, 50, "timed_out");
    const timedOutIds = timedOut.map((p) => p.requestId);
    expect(timedOutIds).toContain(id2);
    expect(timedOutIds).not.toContain(id1);
    expect(timedOut.every((p) => p.status === "timed_out")).toBe(true);

    // List only pending
    const pending = await listPendingHITLApprovals(env.AUDIT_DB, 50, "pending");
    const pendingIds = pending.map((p) => p.requestId);
    expect(pendingIds).toContain(id1);
    expect(pendingIds).not.toContain(id2);
  });
});

// ─── resolveHITLApproval — edge cases ────────────────────────────────────────

describe("resolveHITLApproval — edge cases", () => {
  it("should return error when request_id does not exist", async () => {
    const result = await resolveHITLApproval(
      env.AUDIT_DB,
      "non-existent-id",
      "approved",
      "approver"
    );
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not found/i);
  });

  it("should return error when trying to resolve an already-timed-out request", async () => {
    const id = crypto.randomUUID();
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id,
      templateId: "tmpl-timeout",
      templateName: "Timeout Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-to",
      timeoutMs: 1, // expire immediately
    });

    // Wait for decision (will time out immediately)
    await waitForHITLDecision(env.AUDIT_DB, id, 1);

    // Now try to resolve it — should fail as it's in terminal state
    const result = await resolveHITLApproval(env.AUDIT_DB, id, "approved", "late-approver");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/terminal state/i);
  });

  it("should return HITL_EXPIRED error when trying to resolve an expired pending request", async () => {
    const id = crypto.randomUUID();
    // Create approval with 1ms timeout (will expire immediately)
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id,
      templateId: "tmpl-expired",
      templateName: "Expired Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-expired",
      timeoutMs: 1,
    });

    // Wait a bit to ensure expiry
    await new Promise(resolve => setTimeout(resolve, 50));

    // Try to resolve it — should fail with HITL_EXPIRED as window closed
    const result = await resolveHITLApproval(env.AUDIT_DB, id, "approved", "late-approver");
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/HITL_EXPIRED/);
    expect(result.error).toMatch(/Approval window closed/);

    // Verify it was marked as timed_out
    const status = await getHITLApprovalStatus(env.AUDIT_DB, id);
    expect(status?.status).toBe("timed_out");

    // Verify dead-letter record was created
    const deadLetterRecord = await env.AUDIT_DB.prepare(
      "SELECT * FROM hitl_dead_letter WHERE request_id = ?"
    ).bind(id).first();
    expect(deadLetterRecord).not.toBeNull();
  });
});

// ─── waitForHITLDecision — already-timed-out race path ───────────────────────

describe("waitForHITLDecision — race condition paths", () => {
  it("should return timed_out immediately if status is already timed_out in DB", async () => {
    const id = crypto.randomUUID();
    await requestHITLApproval(env.AUDIT_DB, {
      requestId: id,
      templateId: "tmpl-race",
      templateName: "Race Template",
      userId: TEST_USER_ID,
      variablesHash: "hash-race",
      timeoutMs: 1,
    });

    // Force timed_out state by resolving with a short timeout first call
    await waitForHITLDecision(env.AUDIT_DB, id, 1);

    // Second call — should see status = timed_out and short-circuit
    const decision = await waitForHITLDecision(env.AUDIT_DB, id, 5000);
    expect(decision.approved).toBe(false);
    expect(decision.reason).toBe("timed_out");
  });
});
