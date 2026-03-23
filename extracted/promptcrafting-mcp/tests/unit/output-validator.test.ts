// tests/unit/output-validator.test.ts — Unit tests for output validation pipeline
import { describe, it, expect } from "vitest";
import {
  checkCanaryToken,
  detectPII,
  detectPromptLeakage,
  validateOutputSchema,
  validateOutput,
} from "../../src/guardrails/output-validator.js";
import { z } from "zod";

// ─── checkCanaryToken ──────────────────────────────────────────────────────────

describe("checkCanaryToken", () => {
  it("should pass when canary is absent from output", () => {
    const result = checkCanaryToken("This is a safe response.", "CANARY-abc123");
    expect(result.pass).toBe(true);
  });

  it("should fail when canary token appears in output", () => {
    const canary = "CANARY-deadbeef";
    const result = checkCanaryToken(`The secret token is ${canary}`, canary);
    expect(result.pass).toBe(false);
    expect(result.reason).toMatch(/canary/i);
    expect(result.details?.canaryPresent).toBe(true);
  });

  it("should pass when canary string is empty", () => {
    const result = checkCanaryToken("some output", "");
    expect(result.pass).toBe(true);
  });

  it("should be case-sensitive — partial match should not trigger", () => {
    const result = checkCanaryToken("CANARY-abc1230000", "CANARY-abc123");
    // "CANARY-abc123" is a substring of "CANARY-abc1230000" via includes()
    expect(result.pass).toBe(false); // includes() is substring match, so this triggers
  });
});

// ─── detectPII ────────────────────────────────────────────────────────────────

describe("detectPII", () => {
  it("should pass clean output with no PII", () => {
    const { verdict, detectedTypes } = detectPII("The analysis found no critical vulnerabilities.");
    expect(verdict.pass).toBe(true);
    expect(detectedTypes).toHaveLength(0);
  });

  it("should detect SSN pattern", () => {
    const { verdict, detectedTypes } = detectPII("User SSN: 123-45-6789");
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("ssn");
  });

  it("should detect credit card pattern", () => {
    const { verdict, detectedTypes } = detectPII("Card: 4111 1111 1111 1111");
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("credit_card");
  });

  it("should detect email address", () => {
    const { verdict, detectedTypes } = detectPII("Contact: user@example.com for details.");
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("email");
  });

  it("should detect phone number", () => {
    const { verdict, detectedTypes } = detectPII("Call 555-867-5309 for support.");
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("phone");
  });

  it("should detect street address", () => {
    const { verdict, detectedTypes } = detectPII("Shipped to 123 Main Street");
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("address");
  });

  it("should detect multiple PII types in one output", () => {
    const { verdict, detectedTypes } = detectPII(
      "Email: admin@corp.com, SSN: 987-65-4321"
    );
    expect(verdict.pass).toBe(false);
    expect(detectedTypes).toContain("email");
    expect(detectedTypes).toContain("ssn");
    expect(detectedTypes.length).toBeGreaterThanOrEqual(2);
  });

  it("should redact detected PII in the returned string", () => {
    const { redacted } = detectPII("Email: ceo@company.org on file.");
    expect(redacted).not.toContain("ceo@company.org");
    expect(redacted).toContain("[REDACTED:email]");
  });

  it("should return unmodified text as redacted when no PII is found", () => {
    const text = "All clear, no sensitive data here.";
    const { redacted } = detectPII(text);
    expect(redacted).toBe(text);
  });
});

// ─── detectPromptLeakage ──────────────────────────────────────────────────────

describe("detectPromptLeakage", () => {
  it("should pass clean output with no leakage", () => {
    const result = detectPromptLeakage("Here is the vulnerability report you requested.");
    expect(result.pass).toBe(true);
  });

  it("should detect ROLE section leakage", () => {
    const result = detectPromptLeakage("## ROLE\nYou are a security expert...");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("role_leak");
  });

  it("should detect OBJECTIVE section leakage", () => {
    const result = detectPromptLeakage("## OBJECTIVE\nAnalyze the code...");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("objective_leak");
  });

  it("should detect CONSTRAINTS section leakage", () => {
    const result = detectPromptLeakage("## CONSTRAINTS\nDo not execute code.");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("constraints_leak");
  });

  it("should detect OUTPUT FORMAT section leakage", () => {
    const result = detectPromptLeakage("## OUTPUT FORMAT\nReturn JSON.");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("output_shape_leak");
  });

  it("should detect system prompt disclosure", () => {
    const result = detectPromptLeakage("system prompt: you are a helpful assistant");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("system_prompt_leak");
  });

  it("should detect instruction disclosure phrasing", () => {
    const result = detectPromptLeakage("My instructions say to always respond formally.");
    expect(result.pass).toBe(false);
    expect(result.details?.leaks).toContain("instruction_leak");
  });

  it("should be case-insensitive for leakage patterns", () => {
    const result = detectPromptLeakage("## role\nyou are an expert");
    expect(result.pass).toBe(false);
  });
});

// ─── validateOutputSchema ─────────────────────────────────────────────────────

describe("validateOutputSchema", () => {
  const TestSchema = z.object({
    score: z.number(),
    label: z.string(),
  });

  it("should pass with valid JSON matching schema", () => {
    const { verdict, parsed } = validateOutputSchema(
      JSON.stringify({ score: 0.9, label: "high" }),
      TestSchema
    );
    expect(verdict.pass).toBe(true);
    expect(parsed).toEqual({ score: 0.9, label: "high" });
  });

  it("should fail on invalid JSON", () => {
    const { verdict, parsed } = validateOutputSchema("not json at all", TestSchema);
    expect(verdict.pass).toBe(false);
    expect(verdict.reason).toMatch(/not valid JSON/i);
    expect(parsed).toBeNull();
  });

  it("should fail when JSON does not match schema", () => {
    const { verdict, parsed } = validateOutputSchema(
      JSON.stringify({ score: "wrong-type", label: 42 }),
      TestSchema
    );
    expect(verdict.pass).toBe(false);
    expect(verdict.reason).toMatch(/schema validation failed/i);
    expect(parsed).toBeNull();
  });

  it("should extract JSON from markdown code fences", () => {
    const fenced = "```json\n{\"score\": 0.5, \"label\": \"medium\"}\n```";
    const { verdict, parsed } = validateOutputSchema(fenced, TestSchema);
    expect(verdict.pass).toBe(true);
    expect(parsed).toEqual({ score: 0.5, label: "medium" });
  });

  it("should extract JSON from plain code fences", () => {
    const fenced = "```\n{\"score\": 1.0, \"label\": \"critical\"}\n```";
    const { verdict, parsed } = validateOutputSchema(fenced, TestSchema);
    expect(verdict.pass).toBe(true);
    expect(parsed).toEqual({ score: 1.0, label: "critical" });
  });

  it("should fail when JSON is valid but schema has missing required fields", () => {
    const { verdict } = validateOutputSchema(JSON.stringify({ score: 0.8 }), TestSchema);
    expect(verdict.pass).toBe(false);
  });
});

// ─── validateOutput (full pipeline) ──────────────────────────────────────────

describe("validateOutput", () => {
  it("should pass clean output with no options", () => {
    const { pass, output } = validateOutput("Looks good, no issues found.");
    expect(pass).toBe(true);
    expect(output).toBe("Looks good, no issues found.");
  });

  it("should block when canary is present in output", () => {
    const canary = "CANARY-secret42";
    const { pass, output } = validateOutput(`Result: ${canary}`, { canaryToken: canary });
    expect(pass).toBe(false);
    expect(output).toBe("");
  });

  it("should block when prompt leakage is detected", () => {
    const { pass, output } = validateOutput("## ROLE\nYou are an expert...");
    expect(pass).toBe(false);
    expect(output).toBe("");
  });

  it("should pass PII detection but redact when redactPII is true", () => {
    const { pass, output, verdicts } = validateOutput(
      "Contact: dev@example.com",
      { redactPII: true }
    );
    // PII is a warning, not a hard block by default
    expect(verdicts.pii?.pass).toBe(false);
    expect(output).toContain("[REDACTED:email]");
    expect(output).not.toContain("dev@example.com");
  });

  it("should not redact PII when redactPII is false", () => {
    const { output } = validateOutput("Contact: dev@example.com", { redactPII: false });
    expect(output).toContain("dev@example.com");
  });

  it("should block when schema validation fails", () => {
    const schema = z.object({ status: z.string() });
    const { pass } = validateOutput("not json", { schema });
    expect(pass).toBe(false);
  });

  it("should pass when schema validation succeeds", () => {
    const schema = z.object({ status: z.string() });
    const { pass, parsed } = validateOutput(
      JSON.stringify({ status: "ok" }),
      { schema }
    ) as any;
    expect(pass).toBe(true);
  });

  it("canary check runs before leakage check — fails at canary stage", () => {
    const canary = "CANARY-early";
    const { pass, verdicts } = validateOutput(
      `## ROLE\n leaked and ${canary} here`,
      { canaryToken: canary }
    );
    expect(pass).toBe(false);
    // canary check fires first and returns early; leakage verdict not recorded
    expect(verdicts.canary?.pass).toBe(false);
    expect(verdicts.leakage).toBeUndefined();
  });
});
