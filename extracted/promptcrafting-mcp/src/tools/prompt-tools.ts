// src/tools/prompt-tools.ts — MCP tool implementations
// These are registered on the McpServer inside the McpAgent Durable Object.
//
// Tool naming: promptcraft_{action}_{resource} (following MCP best practices)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env, PromptTemplate } from "../types.js";
import {
  CreateTemplateSchema, UpdateTemplateSchema, GetTemplateSchema,
  ListTemplatesSchema, DeleteTemplateSchema, ExecutePromptSchema,
  ValidatePromptSchema, QueryAuditSchema,
} from "../schemas/index.js";
import {
  PromptTemplateBuilder, compilePrompt, verifyContent,
  hashContent, signContent,
} from "../services/prompt-builder.js";
import { sanitizeInput } from "../guardrails/input-sanitizer.js";
import { validateOutput, checkCanaryToken } from "../guardrails/output-validator.js";
import { writeAuditLog, writeGuardrailEvent, queryAuditLogs } from "../services/audit.js";

// ─── Register All Tools ────────────────────────────────────────────
export function registerPromptTools(server: McpServer, env: Env, userId: string): void {

  // ═══════════════════════════════════════════════════════════════════
  // TEMPLATE MANAGEMENT TOOLS
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_create_template",
    {
      title: "Create Prompt Template",
      description: `Create a new four-layer prompt template with HMAC-signed content integrity.

Layers:
  - objective: Clear task definition and success criteria
  - role: Persona, domain expertise, situational context
  - constraints: Boundaries, forbidden actions, rules
  - outputShape: Expected format, schema, examples

The template is signed with HMAC-SHA256 to prevent tampering in storage.
Returns the template ID, version, and content hash.`,
      inputSchema: CreateTemplateSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (params) => {
      const builder = new PromptTemplateBuilder();
      const template = await builder
        .name(params.name)
        .description(params.description ?? "")
        .objective(params.objective)
        .role(params.role)
        .constraints(params.constraints ?? "Follow standard safety guidelines.")
        .outputShape(params.outputShape ?? "Respond in well-structured plain text.")
        .tags(params.tags ?? [])
        .model(params.model)
        .createdBy(userId)
        .build(env.TEMPLATE_HMAC_KEY);

      // Store in KV (latest)
      await env.PROMPT_TEMPLATES.put(
        `template:${template.id}`,
        JSON.stringify(template),
        { metadata: { name: template.name, version: template.version } }
      );
      // Store versioned copy (90-day retention)
      await env.PROMPT_TEMPLATES.put(
        `template:${template.id}:v${template.version}`,
        JSON.stringify(template),
        { expirationTtl: 60 * 60 * 24 * 90 }
      );

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            id: template.id,
            name: template.name,
            version: template.version,
            contentHash: template.contentHash,
            created: true,
          }),
        }],
      };
    }
  );

  server.registerTool(
    "promptcraft_get_template",
    {
      title: "Get Prompt Template",
      description: `Retrieve a prompt template by ID with HMAC integrity verification.
Optionally specify a version number to fetch a historical version.
Returns the full template including all four layers and metadata.`,
      inputSchema: GetTemplateSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const key = params.version
        ? `template:${params.templateId}:v${params.version}`
        : `template:${params.templateId}`;

      const raw = await env.PROMPT_TEMPLATES.get(key, "json") as PromptTemplate | null;
      if (!raw) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      // Verify HMAC integrity
      const compiled = [raw.layers.role, raw.layers.objective, raw.layers.constraints, raw.layers.outputShape].join("\n");
      const valid = await verifyContent(compiled, raw.hmacSignature, env.TEMPLATE_HMAC_KEY);
      if (!valid) {
        console.error(`[SECURITY] HMAC verification failed for template ${params.templateId} — possible tampering`);
        return {
          isError: true,
          content: [{ type: "text", text: "Template integrity check failed — content may have been tampered with" }],
        };
      }

      return { content: [{ type: "text", text: JSON.stringify(raw, null, 2) }] };
    }
  );

  server.registerTool(
    "promptcraft_list_templates",
    {
      title: "List Prompt Templates",
      description: "List available prompt templates with optional tag filtering and pagination.",
      inputSchema: ListTemplatesSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const listResult = await env.PROMPT_TEMPLATES.list({
        prefix: "template:",
        limit: params.limit ?? 20,
        cursor: params.cursor,
      });

      // Filter out versioned keys (they contain :v)
      const templates = listResult.keys
        .filter((k) => !k.name.includes(":v"))
        .map((k) => ({
          id: k.name.replace("template:", ""),
          name: (k.metadata as Record<string, unknown>)?.name ?? "unknown",
          version: (k.metadata as Record<string, unknown>)?.version ?? 1,
        }));

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            templates,
            count: templates.length,
            cursor: listResult.list_complete ? null : listResult.cursor,
            hasMore: !listResult.list_complete,
          }),
        }],
      };
    }
  );

  server.registerTool(
    "promptcraft_delete_template",
    {
      title: "Delete Prompt Template",
      description: "Delete a prompt template by ID. Versioned copies are retained for audit compliance.",
      inputSchema: DeleteTemplateSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      await env.PROMPT_TEMPLATES.delete(`template:${params.templateId}`);
      return {
        content: [{ type: "text", text: JSON.stringify({ deleted: true, id: params.templateId, note: "Versioned copies retained for audit" }) }],
      };
    }
  );

  // ═══════════════════════════════════════════════════════════════════
  // PROMPT EXECUTION TOOLS
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_execute_prompt",
    {
      title: "Execute Prompt",
      description: `Execute a prompt template with the full security pipeline:
1. Load template from KV with HMAC verification
2. Sanitize user input (NFKC, injection detection, length)
3. Compile four-layer prompt with structured separation + sandwich defense
4. Run inference via Workers AI
5. Validate output (schema, PII, leakage, canary token)
6. Log audit trail to D1

Returns the model output, guardrail results, and usage metrics.
Fail-closed: if any guardrail fails, the output is NOT returned.`,
      inputSchema: ExecutePromptSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async (params) => {
      const requestId = crypto.randomUUID();
      const startTime = Date.now();

      // 1. Load and verify template
      const key = params.templateVersion
        ? `template:${params.templateId}:v${params.templateVersion}`
        : `template:${params.templateId}`;
      const template = await env.PROMPT_TEMPLATES.get(key, "json") as PromptTemplate | null;

      if (!template) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      const compiled = [template.layers.role, template.layers.objective, template.layers.constraints, template.layers.outputShape].join("\n");
      const hmacValid = await verifyContent(compiled, template.hmacSignature, env.TEMPLATE_HMAC_KEY);
      if (!hmacValid) {
        await writeAuditLog(env.AUDIT_DB, {
          requestId, sessionId: null, templateId: params.templateId,
          templateVersion: template.version, userId, model: params.model ?? "none",
          status: "filtered", latencyMs: Date.now() - startTime,
          inputTokens: 0, outputTokens: 0,
          guardrailFlags: JSON.stringify({ hmacFailed: true }),
          createdAt: new Date().toISOString(),
        });
        return { isError: true, content: [{ type: "text", text: "Template integrity check failed" }] };
      }

      // 2. Sanitize user input
      if (params.userInput) {
        const { verdict, threats } = sanitizeInput(params.userInput, {
          maxLength: parseInt(env.MAX_PROMPT_LENGTH || "50000"),
        });
        if (!verdict.pass) {
          await writeAuditLog(env.AUDIT_DB, {
            requestId, sessionId: null, templateId: params.templateId,
            templateVersion: template.version, userId, model: params.model ?? "none",
            status: "filtered", latencyMs: Date.now() - startTime,
            inputTokens: 0, outputTokens: 0,
            guardrailFlags: JSON.stringify({ inputBlocked: true, threats }),
            createdAt: new Date().toISOString(),
          });
          return { isError: true, content: [{ type: "text", text: `Input rejected: ${verdict.reason}` }] };
        }
      }

      // 3. Compile prompt
      const { systemPrompt, userPrompt, canaryToken } = compilePrompt(template, {
        userInput: params.userInput,
        variables: params.variables,
        sandwichDefense: params.sandwichDefense,
      });

      // 4. Run inference
      const model = params.model || template.model || "@cf/meta/llama-4-scout-17b-16e-instruct";
      let rawOutput: string;
      try {
        const aiResult = await env.AI.run(model as BaseAiTextGenerationModels, {
          messages: [
            { role: "system", content: systemPrompt },
            ...(userPrompt ? [{ role: "user" as const, content: userPrompt }] : []),
          ],
          max_tokens: params.maxTokens,
        });
        rawOutput = typeof aiResult === "string"
          ? aiResult
          : (aiResult as Record<string, unknown>).response as string ?? "";
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        await writeAuditLog(env.AUDIT_DB, {
          requestId, sessionId: null, templateId: params.templateId,
          templateVersion: template.version, userId, model,
          status: "error", latencyMs: Date.now() - startTime,
          inputTokens: 0, outputTokens: 0,
          guardrailFlags: JSON.stringify({ inferenceError: errMsg }),
          createdAt: new Date().toISOString(),
        });
        return { isError: true, content: [{ type: "text", text: `Inference failed: ${errMsg}` }] };
      }

      // 5. Validate output
      const outputValidation = validateOutput(rawOutput, {
        canaryToken,
        redactPII: true,
      });

      if (!outputValidation.pass) {
        await writeAuditLog(env.AUDIT_DB, {
          requestId, sessionId: null, templateId: params.templateId,
          templateVersion: template.version, userId, model,
          status: "filtered", latencyMs: Date.now() - startTime,
          inputTokens: 0, outputTokens: 0,
          guardrailFlags: JSON.stringify(outputValidation.verdicts),
          createdAt: new Date().toISOString(),
        });
        return { isError: true, content: [{ type: "text", text: "Output blocked by security guardrails" }] };
      }

      // 6. Audit log (non-blocking in production via ctx.waitUntil)
      const latencyMs = Date.now() - startTime;
      await writeAuditLog(env.AUDIT_DB, {
        requestId, sessionId: null, templateId: params.templateId,
        templateVersion: template.version, userId, model,
        status: "success", latencyMs,
        inputTokens: 0, outputTokens: 0,
        guardrailFlags: JSON.stringify(outputValidation.verdicts),
        createdAt: new Date().toISOString(),
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            requestId,
            output: outputValidation.output,
            model,
            latencyMs,
            guardrails: outputValidation.verdicts,
          }),
        }],
      };
    }
  );

  // ═══════════════════════════════════════════════════════════════════
  // VALIDATION TOOL (dry-run, no inference)
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_validate_input",
    {
      title: "Validate Prompt Input",
      description: `Dry-run validation of user input against a template without executing inference.
Returns sanitization results, detected threats, compiled prompt preview, and template integrity status.`,
      inputSchema: ValidatePromptSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      // Load template
      const template = await env.PROMPT_TEMPLATES.get(`template:${params.templateId}`, "json") as PromptTemplate | null;
      if (!template) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      // Verify HMAC
      const compiled = [template.layers.role, template.layers.objective, template.layers.constraints, template.layers.outputShape].join("\n");
      const hmacValid = await verifyContent(compiled, template.hmacSignature, env.TEMPLATE_HMAC_KEY);

      // Sanitize input
      const { sanitized, verdict, threats } = sanitizeInput(params.userInput);

      // Compile prompt (for preview)
      const { systemPrompt, userPrompt } = compilePrompt(template, {
        userInput: verdict.pass ? sanitized : undefined,
        variables: params.variables,
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            templateIntegrity: hmacValid ? "verified" : "FAILED — possible tampering",
            inputValidation: verdict,
            threats,
            promptPreview: {
              systemPromptLength: systemPrompt.length,
              userPromptLength: userPrompt.length,
              // Do NOT expose full system prompt — leakage risk
              systemPromptHash: await hashContent(systemPrompt),
            },
          }, null, 2),
        }],
      };
    }
  );

  // ═══════════════════════════════════════════════════════════════════
  // AUDIT QUERY TOOL
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_query_audit",
    {
      title: "Query Audit Logs",
      description: "Query the prompt execution audit trail with filters for user, template, status, and time range.",
      inputSchema: QueryAuditSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const result = await queryAuditLogs(env.AUDIT_DB, params);
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
