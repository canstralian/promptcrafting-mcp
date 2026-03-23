// src/schemas/index.ts — Zod schemas for all MCP tool inputs
// These enforce structural validation at B2 boundary entry.

import { z } from "zod";

// ─── Template Schemas ──────────────────────────────────────────────

export const CreateTemplateSchema = z.object({
  name: z.string()
    .min(3, "Template name must be at least 3 characters")
    .max(100, "Template name must not exceed 100 characters")
    .describe("Human-readable template name"),
  description: z.string()
    .max(500, "Description must not exceed 500 characters")
    .default("")
    .describe("Brief description of what the template does"),
  objective: z.string()
    .min(10, "Objective must be at least 10 characters")
    .max(5000)
    .describe("Layer 1: Clear task definition and success criteria"),
  role: z.string()
    .min(10, "Role must be at least 10 characters")
    .max(5000)
    .describe("Layer 2: Persona, domain expertise, and situational context"),
  constraints: z.string()
    .max(5000)
    .default("Follow standard safety guidelines.")
    .describe("Layer 3: Boundaries, forbidden actions, rules"),
  outputShape: z.string()
    .max(5000)
    .default("Respond in well-structured plain text.")
    .describe("Layer 4: Expected format, schema, length, examples"),
  tags: z.array(z.string().max(50)).max(20).default([])
    .describe("Categorization tags"),
  model: z.string().max(100).optional()
    .describe("Target model hint (e.g., @cf/meta/llama-4-scout-17b-16e-instruct)"),
}).strict();

export const UpdateTemplateSchema = z.object({
  templateId: z.string().uuid("Invalid template ID format"),
  objective: z.string().min(10).max(5000).optional(),
  role: z.string().min(10).max(5000).optional(),
  constraints: z.string().max(5000).optional(),
  outputShape: z.string().max(5000).optional(),
  description: z.string().max(500).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  model: z.string().max(100).optional(),
}).strict();

export const GetTemplateSchema = z.object({
  templateId: z.string().uuid("Invalid template ID format"),
  version: z.number().int().positive().optional()
    .describe("Specific version to fetch; omit for latest"),
}).strict();

export const ListTemplatesSchema = z.object({
  tags: z.array(z.string()).optional()
    .describe("Filter by tags"),
  limit: z.number().int().min(1).max(100).default(20),
  cursor: z.string().optional()
    .describe("KV list cursor for pagination"),
}).strict();

export const DeleteTemplateSchema = z.object({
  templateId: z.string().uuid("Invalid template ID format"),
}).strict();

// ─── Prompt Execution Schemas ──────────────────────────────────────

export const ExecutePromptSchema = z.object({
  templateId: z.string().uuid("Invalid template ID format"),
  templateVersion: z.number().int().positive().optional(),
  userInput: z.string()
    .max(50000, "User input exceeds maximum length")
    .optional()
    .describe("User-provided input to process (treated as DATA, not instructions)"),
  variables: z.record(z.string(), z.string().max(10000))
    .default({})
    .describe("Template variable substitutions"),
  model: z.string().max(100).optional()
    .describe("Override target model"),
  sandwichDefense: z.boolean().default(true)
    .describe("Apply post-input reinforcement defense"),
  maxTokens: z.number().int().min(1).max(16384).default(4096),
  outputSchema: z.string().optional()
    .describe("JSON Schema string for output validation (fail-closed)"),
}).strict();

export const ValidatePromptSchema = z.object({
  templateId: z.string().uuid("Invalid template ID format"),
  userInput: z.string().max(50000),
  variables: z.record(z.string(), z.string().max(10000)).default({}),
}).strict();

// ─── Audit Query Schemas ───────────────────────────────────────────

export const QueryAuditSchema = z.object({
  userId: z.string().optional(),
  templateId: z.string().uuid().optional(),
  status: z.enum(["success", "error", "rate_limited", "filtered"]).optional(),
  since: z.string().datetime().optional()
    .describe("ISO 8601 datetime — return logs after this time"),
  limit: z.number().int().min(1).max(200).default(50),
  offset: z.number().int().min(0).default(0),
}).strict();

// ─── Security Assessment Output Schema ─────────────────────────────
// Example output schema for vulnerability assessment prompts.
export const VulnAssessmentOutputSchema = z.object({
  findings: z.array(
    z.object({
      port: z.number().int().min(1).max(65535),
      service: z.string().max(200),
      severity: z.enum(["critical", "high", "medium", "low", "info"]),
      cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/).optional(),
      cvssScore: z.number().min(0).max(10).optional(),
      confidence: z.number().min(0).max(1),
      remediation: z.string().max(1000),
    })
  ),
  riskRating: z.enum(["critical", "high", "medium", "low"]),
  nextSteps: z.array(z.string().max(500)),
});

// ─── Type Exports ──────────────────────────────────────────────────
export type CreateTemplateInput = z.infer<typeof CreateTemplateSchema>;
export type UpdateTemplateInput = z.infer<typeof UpdateTemplateSchema>;
export type GetTemplateInput = z.infer<typeof GetTemplateSchema>;
export type ListTemplatesInput = z.infer<typeof ListTemplatesSchema>;
export type DeleteTemplateInput = z.infer<typeof DeleteTemplateSchema>;
export type ExecutePromptInput = z.infer<typeof ExecutePromptSchema>;
export type ValidatePromptInput = z.infer<typeof ValidatePromptSchema>;
export type QueryAuditInput = z.infer<typeof QueryAuditSchema>;
