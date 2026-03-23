// src/guardrails/output-validator.ts — B2 boundary: output validation pipeline
// Mitigates: Schema drift, PII leakage, prompt leakage, toxic output
//
// Pipeline position: after model inference, before response delivery
//
// Fail-closed: if validation fails, the output is NOT returned to the user.

import { z, type ZodSchema } from "zod";
import type { GuardrailVerdict } from "../types.js";

// ─── PII Patterns ──────────────────────────────────────────────────
// Regex-based first pass; production should add NER (Presidio, LLM Guard).
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, label: "ssn" },
  { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, label: "credit_card" },
  { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, label: "email" },
  { pattern: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, label: "phone" },
  { pattern: /\b\d{1,5}\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct)\b/i, label: "address" },
];

// ─── Prompt Leakage Patterns ───────────────────────────────────────
// Detects if the model is echoing system instructions in its output.
const LEAKAGE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /##\s*ROLE\n/i, label: "role_leak" },
  { pattern: /##\s*OBJECTIVE\n/i, label: "objective_leak" },
  { pattern: /##\s*CONSTRAINTS\n/i, label: "constraints_leak" },
  { pattern: /##\s*OUTPUT\s*(FORMAT|SHAPE)\n/i, label: "output_shape_leak" },
  { pattern: /system\s*prompt\s*:/i, label: "system_prompt_leak" },
  { pattern: /my\s+instructions\s+(are|say|tell)/i, label: "instruction_leak" },
];

// ─── Canary Token Check ────────────────────────────────────────────
// If a canary string embedded in the system prompt appears in the output,
// a prompt extraction attack succeeded.
export function checkCanaryToken(output: string, canary: string): GuardrailVerdict {
  if (canary && output.includes(canary)) {
    return {
      pass: false,
      reason: "Canary token detected in output — prompt extraction attack",
      details: { canaryPresent: true },
    };
  }
  return { pass: true };
}

// ─── PII Detection ─────────────────────────────────────────────────
export function detectPII(output: string): {
  verdict: GuardrailVerdict;
  detectedTypes: string[];
  redacted: string;
} {
  const detectedTypes: string[] = [];
  let redacted = output;

  for (const { pattern, label } of PII_PATTERNS) {
    if (pattern.test(output)) {
      detectedTypes.push(label);
      redacted = redacted.replace(new RegExp(pattern, "g"), `[REDACTED:${label}]`);
    }
  }

  return {
    verdict: {
      pass: detectedTypes.length === 0,
      reason: detectedTypes.length > 0
        ? `PII detected: ${detectedTypes.join(", ")}`
        : "No PII detected",
      details: { detectedTypes },
    },
    detectedTypes,
    redacted,
  };
}

// ─── Prompt Leakage Detection ──────────────────────────────────────
export function detectPromptLeakage(output: string): GuardrailVerdict {
  const leaks: string[] = [];
  for (const { pattern, label } of LEAKAGE_PATTERNS) {
    if (pattern.test(output)) {
      leaks.push(label);
    }
  }

  return {
    pass: leaks.length === 0,
    reason: leaks.length > 0
      ? `Prompt leakage detected: ${leaks.join(", ")}`
      : "No leakage detected",
    details: { leaks },
  };
}

// ─── Schema Validation (Zod) ───────────────────────────────────────
// Attempts to parse model output as JSON and validate against a Zod schema.
// Fail-closed: invalid schema = blocked response.
export function validateOutputSchema<T>(
  output: string,
  schema: ZodSchema<T>
): { verdict: GuardrailVerdict; parsed: T | null } {
  // Attempt JSON extraction — handle markdown code fences
  let jsonStr = output.trim();
  const fenceMatch = jsonStr.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) {
    jsonStr = fenceMatch[1].trim();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return {
      verdict: {
        pass: false,
        reason: "Output is not valid JSON",
        details: { rawLength: output.length },
      },
      parsed: null,
    };
  }

  const result = schema.safeParse(parsed);
  if (!result.success) {
    return {
      verdict: {
        pass: false,
        reason: `Schema validation failed: ${result.error.issues.map((i) => i.message).join("; ")}`,
        details: { issues: result.error.issues },
      },
      parsed: null,
    };
  }

  return {
    verdict: { pass: true, reason: "Schema validation passed" },
    parsed: result.data,
  };
}

// ─── Full Output Validation Pipeline ───────────────────────────────
// Runs all checks in sequence. Fail-closed: first failure stops the pipeline.
export function validateOutput(
  output: string,
  options: {
    canaryToken?: string;
    schema?: ZodSchema;
    redactPII?: boolean;
  } = {}
): {
  pass: boolean;
  output: string;        // Potentially redacted
  verdicts: Record<string, GuardrailVerdict>;
} {
  const verdicts: Record<string, GuardrailVerdict> = {};

  // 1. Canary check
  if (options.canaryToken) {
    verdicts.canary = checkCanaryToken(output, options.canaryToken);
    if (!verdicts.canary.pass) {
      return { pass: false, output: "", verdicts };
    }
  }

  // 2. Prompt leakage
  verdicts.leakage = detectPromptLeakage(output);
  if (!verdicts.leakage.pass) {
    return { pass: false, output: "", verdicts };
  }

  // 3. PII detection + optional redaction
  const piiResult = detectPII(output);
  verdicts.pii = piiResult.verdict;
  const currentOutput = options.redactPII ? piiResult.redacted : output;
  // PII detection is a warning, not a hard block (unless policy requires it)

  // 4. Schema validation (if schema provided)
  if (options.schema) {
    const schemaResult = validateOutputSchema(currentOutput, options.schema);
    verdicts.schema = schemaResult.verdict;
    if (!verdicts.schema.pass) {
      return { pass: false, output: "", verdicts };
    }
  }

  const allPass = Object.values(verdicts).every((v) => v.pass);
  return { pass: allPass, output: currentOutput, verdicts };
}
