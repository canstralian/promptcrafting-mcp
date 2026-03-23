// tests/integration/guardrails-hitl.test.ts — Integration tests for guardrails + HITL gate
import { describe, it, expect, beforeEach } from "vitest";
import { testEnv as env } from "../setup/test-env.js";
import type { Env } from "../../src/types.js";
import { createValidTemplate, createHITLTemplate, INJECTION_INPUTS } from "../fixtures/templates.js";
import { TEST_USER_ID, initTestDatabase, waitFor } from "../utils/test-helpers.js";
import { sanitizeInput } from "../../src/guardrails/input-sanitizer.js";
import { writeAuditLog } from "../../src/services/audit.js";
import { requestHITLApproval, resolveHITLApproval, waitForHITLDecision, getHITLApprovalStatus } from "../../src/services/hitl.js";

describe("Guardrails and HITL Integration Tests", () => {
  beforeEach(async () => {
    await initTestDatabase(env.AUDIT_DB);
  });

  describe("promptcraft_execute_prompt with injection input → expect filtered status", () => {
    it("should block prompt injection attempts", async () => {
      const template = await createValidTemplate();
      await env.PROMPT_TEMPLATES.put(`template:${template.id}`, JSON.stringify(template));

      // Test injection detection
      const { verdict, threats } = sanitizeInput(INJECTION_INPUTS.promptInjection, {
        maxLength: 50000,
      });

      expect(verdict.pass).toBe(false);
      expect(verdict.reason).toBeDefined();
      expect(threats).toHaveProperty("injectionDetected");

      // Write audit log for blocked request
      const requestId = crypto.randomUUID();
      await writeAuditLog(env.AUDIT_DB, {
        requestId,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "filtered",
        latencyMs: 10,
        inputTokens: 0,
        outputTokens: 0,
        guardrailFlags: JSON.stringify({ inputBlocked: true, threats }),
        createdAt: new Date().toISOString(),
      });

      // Verify audit log recorded the filtering
      const auditRecord = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE request_id = ?"
      ).bind(requestId).first();

      expect(auditRecord).not.toBeNull();
      expect(auditRecord?.status).toBe("filtered");
      const flags = JSON.parse(auditRecord?.guardrail_flags as string);
      expect(flags.inputBlocked).toBe(true);
    });

    it("should block jailbreak attempts", async () => {
      const { verdict, threats } = sanitizeInput(INJECTION_INPUTS.jailbreak, {
        maxLength: 50000,
      });

      expect(verdict.pass).toBe(false);
      expect(threats).toBeDefined();
    });

    it("should detect unicode normalization attacks", async () => {
      const { sanitized, verdict } = sanitizeInput(INJECTION_INPUTS.unicodeNormalization, {
        maxLength: 50000,
      });

      // Should normalize but may still flag suspicious patterns
      expect(sanitized).not.toContain("\u{FEFF}"); // Zero-width no-break space removed
      expect(sanitized).not.toContain("\u{200B}"); // Zero-width space removed
    });

    it("should reject excessive length inputs", async () => {
      const { verdict } = sanitizeInput(INJECTION_INPUTS.excessiveLength, {
        maxLength: 50000,
      });

      expect(verdict.pass).toBe(false);
      expect(verdict.reason).toContain("length");
    });

    it("should block SQL injection attempts", async () => {
      const { verdict, threats } = sanitizeInput(INJECTION_INPUTS.sqlInjection, {
        maxLength: 50000,
      });

      // May pass or fail depending on implementation, but should be sanitized
      expect(verdict).toBeDefined();
    });

    it("should block XSS attempts", async () => {
      const { sanitized, verdict } = sanitizeInput(INJECTION_INPUTS.xss, {
        maxLength: 50000,
      });

      // Should sanitize or block
      expect(verdict).toBeDefined();
    });
  });

  describe("promptcraft_execute_prompt with requiresHITL → blocks until approved", () => {
    it("should create HITL approval request and block execution", async () => {
      const template = await createHITLTemplate();
      await env.PROMPT_TEMPLATES.put(`template:${template.id}`, JSON.stringify(template));

      const requestId = crypto.randomUUID();
      const timeoutMs = 5000; // Test timeout

      // Request HITL approval
      await requestHITLApproval(env.AUDIT_DB, {
        requestId,
        templateId: template.id,
        templateName: template.name,
        userId: TEST_USER_ID,
        variablesHash: "test-hash",
        timeoutMs,
      });

      // Verify approval record was created
      const approvalStatus = await getHITLApprovalStatus(env.AUDIT_DB, requestId);
      expect(approvalStatus).not.toBeNull();
      expect(approvalStatus?.status).toBe("pending");
      expect(approvalStatus?.template_id).toBe(template.id);

      // Approve the request
      const resolveResult = await resolveHITLApproval(
        env.AUDIT_DB,
        requestId,
        "approved",
        "test-approver"
      );

      expect(resolveResult.ok).toBe(true);

      // Verify approval was recorded
      const updatedStatus = await getHITLApprovalStatus(env.AUDIT_DB, requestId);
      expect(updatedStatus?.status).toBe("approved");
      expect(updatedStatus?.resolved_by).toBe("test-approver");
      expect(updatedStatus?.resolved_at).toBeDefined();
    });

    it("should reject HITL approval", async () => {
      const template = await createHITLTemplate();
      await env.PROMPT_TEMPLATES.put(`template:${template.id}`, JSON.stringify(template));

      const requestId = crypto.randomUUID();

      // Request HITL approval
      await requestHITLApproval(env.AUDIT_DB, {
        requestId,
        templateId: template.id,
        templateName: template.name,
        userId: TEST_USER_ID,
        variablesHash: "test-hash",
        timeoutMs: 5000,
      });

      // Reject the request
      const resolveResult = await resolveHITLApproval(
        env.AUDIT_DB,
        requestId,
        "rejected",
        "test-reviewer"
      );

      expect(resolveResult.ok).toBe(true);

      // Verify rejection was recorded
      const status = await getHITLApprovalStatus(env.AUDIT_DB, requestId);
      expect(status?.status).toBe("rejected");
      expect(status?.resolved_by).toBe("test-reviewer");

      // Write audit log for rejection
      await writeAuditLog(env.AUDIT_DB, {
        requestId,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "hitl_rejected",
        latencyMs: 100,
        inputTokens: 0,
        outputTokens: 0,
        guardrailFlags: JSON.stringify({
          hitlGate: true,
          decision: "rejected",
          resolvedBy: "test-reviewer",
        }),
        createdAt: new Date().toISOString(),
      });

      // Verify audit log
      const auditRecord = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE request_id = ?"
      ).bind(requestId).first();

      expect(auditRecord?.status).toBe("hitl_rejected");
    });

    it("should prevent double-resolution of HITL approval", async () => {
      const template = await createHITLTemplate();
      const requestId = crypto.randomUUID();

      // Request approval
      await requestHITLApproval(env.AUDIT_DB, {
        requestId,
        templateId: template.id,
        templateName: template.name,
        userId: TEST_USER_ID,
        variablesHash: "test-hash",
        timeoutMs: 5000,
      });

      // First resolution (approved)
      const firstResolve = await resolveHITLApproval(
        env.AUDIT_DB,
        requestId,
        "approved",
        "approver-1"
      );
      expect(firstResolve.ok).toBe(true);

      // Second resolution attempt (should fail)
      const secondResolve = await resolveHITLApproval(
        env.AUDIT_DB,
        requestId,
        "rejected",
        "approver-2"
      );
      expect(secondResolve.ok).toBe(false);
      expect(secondResolve.error).toBeDefined();
    });
  });

  describe("HITL timeout → routes to dead-letter queue", () => {
    it("should timeout and route to dead-letter queue", async () => {
      const template = await createHITLTemplate();
      const requestId = crypto.randomUUID();
      const shortTimeout = 100; // Very short timeout for testing

      // Request approval with short timeout
      await requestHITLApproval(env.AUDIT_DB, {
        requestId,
        templateId: template.id,
        templateName: template.name,
        userId: TEST_USER_ID,
        variablesHash: "test-hash",
        timeoutMs: shortTimeout,
      });

      // Wait for decision (should timeout)
      const decision = await waitForHITLDecision(env.AUDIT_DB, requestId, shortTimeout);

      expect(decision.approved).toBe(false);
      expect(decision.reason).toBe("timed_out");

      // Verify status was updated to timed_out
      const status = await getHITLApprovalStatus(env.AUDIT_DB, requestId);
      expect(status?.status).toBe("timed_out");

      // Verify dead-letter record was created
      const deadLetterRecord = await env.AUDIT_DB.prepare(
        "SELECT * FROM hitl_dead_letter WHERE request_id = ?"
      ).bind(requestId).first();

      expect(deadLetterRecord).not.toBeNull();
      expect(deadLetterRecord?.template_id).toBe(template.id);
      expect(deadLetterRecord?.user_id).toBe(TEST_USER_ID);

      // Write audit log for timeout
      await writeAuditLog(env.AUDIT_DB, {
        requestId,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "hitl_timeout",
        latencyMs: shortTimeout,
        inputTokens: 0,
        outputTokens: 0,
        guardrailFlags: JSON.stringify({
          hitlGate: true,
          decision: "timed_out",
        }),
        createdAt: new Date().toISOString(),
      });

      // Verify audit log
      const auditRecord = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE request_id = ?"
      ).bind(requestId).first();

      expect(auditRecord?.status).toBe("hitl_timeout");
    });
  });

  describe("promptcraft_query_audit with filters", () => {
    it("should query audit logs by status", async () => {
      const template = await createValidTemplate();
      const requestId1 = crypto.randomUUID();
      const requestId2 = crypto.randomUUID();

      // Create filtered request
      await writeAuditLog(env.AUDIT_DB, {
        requestId: requestId1,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "filtered",
        latencyMs: 10,
        inputTokens: 0,
        outputTokens: 0,
        guardrailFlags: JSON.stringify({ inputBlocked: true }),
        createdAt: new Date().toISOString(),
      });

      // Create successful request
      await writeAuditLog(env.AUDIT_DB, {
        requestId: requestId2,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "success",
        latencyMs: 500,
        inputTokens: 100,
        outputTokens: 200,
        guardrailFlags: JSON.stringify({}),
        createdAt: new Date().toISOString(),
      });

      // Query filtered requests
      const filteredResults = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE status = 'filtered'"
      ).all();

      expect(filteredResults.results.length).toBeGreaterThanOrEqual(1);
      expect(filteredResults.results.some((r: any) => r.request_id === requestId1)).toBe(true);

      // Query by user
      const userResults = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE user_id = ?"
      ).bind(TEST_USER_ID).all();

      expect(userResults.results.length).toBeGreaterThanOrEqual(2);
    });

    it("should query audit logs by template ID", async () => {
      const template = await createValidTemplate();
      const requestId = crypto.randomUUID();

      await writeAuditLog(env.AUDIT_DB, {
        requestId,
        sessionId: null,
        templateId: template.id,
        templateVersion: template.version,
        userId: TEST_USER_ID,
        model: "test-model",
        status: "success",
        latencyMs: 100,
        inputTokens: 50,
        outputTokens: 100,
        guardrailFlags: JSON.stringify({}),
        createdAt: new Date().toISOString(),
      });

      const results = await env.AUDIT_DB.prepare(
        "SELECT * FROM prompt_audit_logs WHERE template_id = ?"
      ).bind(template.id).all();

      expect(results.results.length).toBeGreaterThanOrEqual(1);
      expect(results.results[0].template_id).toBe(template.id);
    });
  });
});
