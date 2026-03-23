// tests/unit/prompt-builder.test.ts — Unit tests for the four-layer prompt compiler
import { describe, it, expect } from "vitest";
import {
  hashContent,
  signContent,
  verifyContent,
  generateCanaryToken,
  compilePrompt,
  PromptTemplateBuilder,
} from "../../src/services/prompt-builder.js";
import type { PromptTemplate } from "../../src/types.js";

const HMAC_KEY = "test-hmac-key-32-characters-long";

// ─── hashContent ──────────────────────────────────────────────────────────────

describe("hashContent", () => {
  it("should return a 64-char hex SHA-256 digest", async () => {
    const hash = await hashContent("hello world");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should produce the same hash for identical input", async () => {
    const a = await hashContent("consistent");
    const b = await hashContent("consistent");
    expect(a).toBe(b);
  });

  it("should produce different hashes for different inputs", async () => {
    const a = await hashContent("foo");
    const b = await hashContent("bar");
    expect(a).not.toBe(b);
  });

  it("should handle empty string", async () => {
    const hash = await hashContent("");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ─── signContent / verifyContent ─────────────────────────────────────────────

describe("signContent and verifyContent", () => {
  it("should sign and verify matching content", async () => {
    const sig = await signContent("my template", HMAC_KEY);
    const valid = await verifyContent("my template", sig, HMAC_KEY);
    expect(valid).toBe(true);
  });

  it("should fail verification when content is tampered", async () => {
    const sig = await signContent("original content", HMAC_KEY);
    const valid = await verifyContent("TAMPERED content", sig, HMAC_KEY);
    expect(valid).toBe(false);
  });

  it("should fail verification when key differs", async () => {
    const sig = await signContent("content", HMAC_KEY);
    const valid = await verifyContent("content", sig, "different-hmac-key-32-chars-here");
    expect(valid).toBe(false);
  });

  it("should fail verification when signature is truncated (length mismatch)", async () => {
    const sig = await signContent("content", HMAC_KEY);
    const valid = await verifyContent("content", sig.slice(0, -4), HMAC_KEY);
    expect(valid).toBe(false);
  });

  it("should return a 64-char hex HMAC signature", async () => {
    const sig = await signContent("content", HMAC_KEY);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ─── generateCanaryToken ─────────────────────────────────────────────────────

describe("generateCanaryToken", () => {
  it("should return a string starting with CANARY-", () => {
    const token = generateCanaryToken();
    expect(token).toMatch(/^CANARY-[0-9a-f]{32}$/);
  });

  it("should generate unique tokens each call", () => {
    const tokens = new Set(Array.from({ length: 20 }, () => generateCanaryToken()));
    expect(tokens.size).toBe(20);
  });
});

// ─── compilePrompt ────────────────────────────────────────────────────────────

function makeTemplate(overrides: Partial<PromptTemplate["layers"]> = {}): PromptTemplate {
  return {
    id: "test-id",
    name: "Test Template",
    description: "Unit test template",
    version: 1,
    layers: {
      role: "You are a security expert.",
      objective: "Analyze the provided code.",
      constraints: "Do not execute anything.",
      outputShape: "Return JSON.",
      ...overrides,
    },
    contentHash: "abc",
    hmacSignature: "def",
    requiresHITL: false,
    tags: [],
    createdBy: "test",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

describe("compilePrompt", () => {
  it("should include all four layers in the system prompt", () => {
    const { systemPrompt } = compilePrompt(makeTemplate());
    expect(systemPrompt).toContain("## ROLE");
    expect(systemPrompt).toContain("## OBJECTIVE");
    expect(systemPrompt).toContain("## CONSTRAINTS");
    expect(systemPrompt).toContain("## OUTPUT FORMAT");
  });

  it("should embed the canary token in the constraints block", () => {
    const { systemPrompt, canaryToken } = compilePrompt(makeTemplate());
    expect(systemPrompt).toContain(`CANARY: ${canaryToken}`);
  });

  it("should use the provided canary token when supplied", () => {
    const myCanary = "CANARY-preset";
    const { canaryToken, systemPrompt } = compilePrompt(makeTemplate(), { canaryToken: myCanary });
    expect(canaryToken).toBe(myCanary);
    expect(systemPrompt).toContain(myCanary);
  });

  it("should generate a fresh canary when not supplied", () => {
    const { canaryToken } = compilePrompt(makeTemplate());
    expect(canaryToken).toMatch(/^CANARY-[0-9a-f]{32}$/);
  });

  it("should produce an empty userPrompt when no userInput is given", () => {
    const { userPrompt } = compilePrompt(makeTemplate());
    expect(userPrompt).toBe("");
  });

  it("should wrap userInput in structured separation tags", () => {
    const { userPrompt } = compilePrompt(makeTemplate(), { userInput: "analyze this" });
    expect(userPrompt).toContain("<user_input>");
    expect(userPrompt).toContain("analyze this");
    expect(userPrompt).toContain("</user_input>");
  });

  it("should apply sandwich defense by default", () => {
    const { userPrompt } = compilePrompt(makeTemplate(), { userInput: "analyze this" });
    expect(userPrompt).toContain("Remember:");
    expect(userPrompt).toContain("---");
  });

  it("should skip sandwich defense when sandwichDefense is false", () => {
    const { userPrompt } = compilePrompt(makeTemplate(), {
      userInput: "analyze this",
      sandwichDefense: false,
    });
    expect(userPrompt).not.toContain("Remember:");
  });

  it("should interpolate variables into userInput", () => {
    const { userPrompt } = compilePrompt(makeTemplate(), {
      userInput: "Review {{language}} code for {{issue}}.",
      variables: { language: "TypeScript", issue: "injection vulnerabilities" },
    });
    expect(userPrompt).toContain("TypeScript");
    expect(userPrompt).toContain("injection vulnerabilities");
    expect(userPrompt).not.toContain("{{language}}");
    expect(userPrompt).not.toContain("{{issue}}");
  });

  it("should leave unmatched variable placeholders untouched", () => {
    const { userPrompt } = compilePrompt(makeTemplate(), {
      userInput: "Review {{language}} code.",
      variables: { other: "value" },
    });
    // {{language}} has no corresponding variable — stays as-is
    expect(userPrompt).toContain("{{language}}");
  });

  it("should include security directives in the constraints block", () => {
    const { systemPrompt } = compilePrompt(makeTemplate());
    expect(systemPrompt).toContain("SECURITY DIRECTIVES:");
    expect(systemPrompt).toContain("<user_input>");
    expect(systemPrompt).toContain("Never reveal");
  });
});

// ─── PromptTemplateBuilder ────────────────────────────────────────────────────

describe("PromptTemplateBuilder", () => {
  it("should build a template with all required fields set", async () => {
    const t = await new PromptTemplateBuilder()
      .name("My Template")
      .role("You are an expert.")
      .objective("Do the thing.")
      .constraints("Be safe.")
      .outputShape("Return JSON.")
      .tags(["test"])
      .createdBy("user-1")
      .build(HMAC_KEY);

    expect(t.name).toBe("My Template");
    expect(t.version).toBe(1);
    expect(t.layers.role).toBe("You are an expert.");
    expect(t.layers.objective).toBe("Do the thing.");
    expect(t.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.hmacSignature).toMatch(/^[0-9a-f]{64}$/);
    expect(t.requiresHITL).toBe(false);
  });

  it("should throw when name is missing", async () => {
    await expect(
      new PromptTemplateBuilder()
        .role("Expert.")
        .objective("Do it.")
        .build(HMAC_KEY)
    ).rejects.toThrow(/name/i);
  });

  it("should throw when objective is missing", async () => {
    await expect(
      new PromptTemplateBuilder()
        .name("T")
        .role("Expert.")
        .build(HMAC_KEY)
    ).rejects.toThrow(/objective/i);
  });

  it("should throw when role is missing", async () => {
    await expect(
      new PromptTemplateBuilder()
        .name("T")
        .objective("Do it.")
        .build(HMAC_KEY)
    ).rejects.toThrow(/role/i);
  });

  it("should use default constraints when not set", async () => {
    const t = await new PromptTemplateBuilder()
      .name("T")
      .role("Expert.")
      .objective("Do it.")
      .build(HMAC_KEY);
    expect(t.layers.constraints).toBe("Follow standard safety guidelines.");
  });

  it("should use default outputShape when not set", async () => {
    const t = await new PromptTemplateBuilder()
      .name("T")
      .role("Expert.")
      .objective("Do it.")
      .build(HMAC_KEY);
    expect(t.layers.outputShape).toBe("Respond in plain text.");
  });

  it("should set requiresHITL when explicitly enabled", async () => {
    const t = await new PromptTemplateBuilder()
      .name("HITL Template")
      .role("Auditor.")
      .objective("Review.")
      .requiresHITL(true)
      .build(HMAC_KEY);
    expect(t.requiresHITL).toBe(true);
  });

  it("should produce a valid HMAC that passes verifyContent", async () => {
    const t = await new PromptTemplateBuilder()
      .name("Verify Me")
      .role("Expert.")
      .objective("Analyze.")
      .build(HMAC_KEY);

    const compiled = [t.layers.role, t.layers.objective, t.layers.constraints, t.layers.outputShape].join("\n");
    const valid = await verifyContent(compiled, t.hmacSignature, HMAC_KEY);
    expect(valid).toBe(true);
  });

  it("should use a provided id", async () => {
    const t = await new PromptTemplateBuilder("fixed-id-123")
      .name("T")
      .role("R.")
      .objective("O.")
      .build(HMAC_KEY);
    expect(t.id).toBe("fixed-id-123");
  });
});
