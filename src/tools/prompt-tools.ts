// src/tools/prompt-tools.ts — MCP tool implementations
// These are registered on the McpServer inside the McpAgent Durable Object.
//
// Tool naming: promptcraft_{action}_{resource} (following MCP best practices)
//
// Changelog:
//   - [FIX] promptcraft_create_template: now writes to template_changes audit table
//   - [FIX] promptcraft_delete_template: now reads template before deleting (for hash),
//           writes to template_changes audit table, fails gracefully if template not found
//   - [FIX] All tools now import writeTemplateChange from audit service
//   - [NOTE] onToolCall (McpAgent) must be invoked explicitly — see mcp-agent.ts
//   - [HITL] promptcraft_execute_prompt: blocks on requiresHITL templates until
//           approved, rejected, or timed out. Timeout → dead-letter. Never silent pass.
//           SPEC KIT: A3 Approval Bypass / REQUIRE_HITL (agent-core-v1.0)
//   - [HITL] Added promptcraft_resolve_hitl, promptcraft_get_hitl_status,
//           promptcraft_list_pending_hitl tools

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Env, PromptTemplate } from "../types.js";
import {
  CreateTemplateSchema, UpdateTemplateSchema, GetTemplateSchema,
  ListTemplatesSchema, DeleteTemplateSchema, SetABWeightSchema, ExecutePromptSchema,
  ValidatePromptSchema, QueryAuditSchema,
  ResolveHITLSchema, GetHITLStatusSchema, ListPendingHITLSchema,
} from "../schemas/index.js";
import {
  PromptTemplateBuilder, compilePrompt, verifyContent,
  hashContent, signContent,
} from "../services/prompt-builder.js";
import { sanitizeInput } from "../guardrails/input-sanitizer.js";
import { validateOutput } from "../guardrails/output-validator.js";
import {
  writeAuditLog, writeGuardrailEvent, writeTemplateChange, queryAuditLogs,
} from "../services/audit.js";
import {
  requestHITLApproval, waitForHITLDecision, resolveHITLApproval,
  getHITLApprovalStatus, listPendingHITLApprovals,
} from "../services/hitl.js";

// ─── Register All Tools ────────────────────────────────────────────
export function registerPromptTools(server: McpServer, env: Env, userId: string): void {

  // ═══════════════════════════════════════════════════════════════════
  // A/B TESTING HELPER FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Resolves a template version probabilistically based on A/B weights.
   * If no templateVersion is specified, fetches all versions from KV and
   * selects one based on relative weights.
   */
  async function resolveTemplateVersion(
    templateId: string,
    requestedVersion?: number
  ): Promise<PromptTemplate | null> {
    // If version is explicitly requested, load it directly
    if (requestedVersion) {
      const key = `template:${templateId}:v${requestedVersion}`;
      return await env.PROMPT_TEMPLATES.get(key, "json") as PromptTemplate | null;
    }

    // No version specified — perform probabilistic routing
    // List all versioned keys for this template
    const prefix = `template:${templateId}:v`;
    const list = await env.PROMPT_TEMPLATES.list({ prefix });

    if (!list.keys.length) {
      // No versioned copies, try latest
      return await env.PROMPT_TEMPLATES.get(`template:${templateId}`, "json") as PromptTemplate | null;
    }

    // Fetch all versions to get their weights
    const versions: PromptTemplate[] = [];
    for (const k of list.keys) {
      const template = await env.PROMPT_TEMPLATES.get(k.name, "json") as PromptTemplate | null | undefined;
      if (template) {
        versions.push(template);
      }
    }

    if (versions.length === 0) return null;
    if (versions.length === 1) return versions[0] ?? null;

    // Calculate total weight
    const totalWeight = versions.reduce((sum, t) => sum + t.abWeight, 0);
    if (totalWeight === 0) {
      // All weights are 0, return random version
      return versions[Math.floor(Math.random() * versions.length)] ?? null;
    }

    // Weighted random selection
    let random = Math.random() * totalWeight;
    for (const template of versions) {
      random -= template.abWeight;
      if (random <= 0) {
        return template;
      }
    }

    // Fallback (shouldn't reach here)
    return versions[versions.length - 1] ?? null;
  }

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

Set requiresHITL: true to require human approval before every execution.
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
        .requiresHITL(params.requiresHITL ?? false)
        .abWeight(params.abWeight ?? 1.0)
        .createdBy(userId)
        .build(env.TEMPLATE_HMAC_KEY);

      // Store in KV (latest)
      await env.PROMPT_TEMPLATES.put(
        `template:${template.id}`,
        JSON.stringify(template),
        { metadata: { name: template.name, version: template.version, abWeight: template.abWeight } }
      );
      // Store versioned copy (90-day retention)
      await env.PROMPT_TEMPLATES.put(
        `template:${template.id}:v${template.version}`,
        JSON.stringify(template),
        { expirationTtl: 60 * 60 * 24 * 90 }
      );

      // Audit: record creation in template_changes (closes STRIDE-R gap)
      await writeTemplateChange(env.AUDIT_DB, {
        templateId: template.id,
        action: "create",
        userId,
        version: template.version,
        contentHash: template.contentHash,
        hmacValid: true,
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            id: template.id,
            name: template.name,
            version: template.version,
            contentHash: template.contentHash,
            requiresHITL: template.requiresHITL,
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
      const compiledContent = [raw.layers.role, raw.layers.objective, raw.layers.constraints, raw.layers.outputShape].join("\n");
      const valid = await verifyContent(compiledContent, raw.hmacSignature, env.TEMPLATE_HMAC_KEY);
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
      description: `Soft-delete a prompt template by removing the primary KV key.
Versioned copies (template:{id}:v{n}) are retained indefinitely for audit compliance.
The deletion is recorded in the template_changes audit table in D1 with the acting user ID.
Returns an error if the template does not exist (idempotent deletes are intentionally rejected
to prevent silent double-delete from masking replay attacks).`,
      inputSchema: DeleteTemplateSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async (params) => {
      const raw = await env.PROMPT_TEMPLATES.get(`template:${params.templateId}`, "json") as PromptTemplate | null;

      if (!raw) {
        return {
          isError: true,
          content: [{ type: "text", text: `Template not found: ${params.templateId}. Cannot delete a non-existent template.` }],
        };
      }

      const compiledContent = [raw.layers.role, raw.layers.objective, raw.layers.constraints, raw.layers.outputShape].join("\n");
      const hmacValid = await verifyContent(compiledContent, raw.hmacSignature, env.TEMPLATE_HMAC_KEY);

      if (!hmacValid) {
        console.error(`[SECURITY] Deleting template ${params.templateId} with FAILED HMAC — content was tampered with before deletion`);
      }

      await env.PROMPT_TEMPLATES.delete(`template:${params.templateId}`);

      await writeTemplateChange(env.AUDIT_DB, {
        templateId: params.templateId,
        action: "delete",
        userId,
        version: raw.version,
        contentHash: raw.contentHash,
        hmacValid,
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            deleted: true,
            id: params.templateId,
            version: raw.version,
            hmacValidAtDeletion: hmacValid,
            note: "Primary key removed. Versioned copies retained for audit compliance.",
          }),
        }],
      };
    }
  );

  server.registerTool(
    "promptcraft_update_template",
    {
      title: "Update Prompt Template",
      description: `Update one or more layers of an existing prompt template.
Increments the version, re-signs with HMAC, and stores both the updated latest
and a new versioned copy. Previous version is retained in KV for audit compliance.
Partial updates are supported — only supply the fields you want to change.`,
      inputSchema: UpdateTemplateSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (params) => {
      const raw = await env.PROMPT_TEMPLATES.get(`template:${params.templateId}`, "json") as PromptTemplate | null;
      if (!raw) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      // Verify existing HMAC before mutation
      const existingContent = [raw.layers.role, raw.layers.objective, raw.layers.constraints, raw.layers.outputShape].join("\n");
      const existingHmacValid = await verifyContent(existingContent, raw.hmacSignature, env.TEMPLATE_HMAC_KEY);
      if (!existingHmacValid) {
        console.error(`[SECURITY] Update attempted on tampered template ${params.templateId}`);
        return {
          isError: true,
          content: [{ type: "text", text: "Template integrity check failed — cannot update a tampered template" }],
        };
      }

      // Apply partial updates
      const updatedTemplate: PromptTemplate = {
        ...raw,
        layers: {
          objective: params.objective ?? raw.layers.objective,
          role: params.role ?? raw.layers.role,
          constraints: params.constraints ?? raw.layers.constraints,
          outputShape: params.outputShape ?? raw.layers.outputShape,
        },
        description: params.description ?? raw.description,
        tags: params.tags ?? raw.tags,
        model: params.model ?? raw.model,
        requiresHITL: params.requiresHITL !== undefined ? params.requiresHITL : raw.requiresHITL,
        abWeight: params.abWeight !== undefined ? params.abWeight : raw.abWeight,
        version: raw.version + 1,
        updatedAt: new Date().toISOString(),
      };

      // Recompute content hash and HMAC
      const newContent = [
        updatedTemplate.layers.role,
        updatedTemplate.layers.objective,
        updatedTemplate.layers.constraints,
        updatedTemplate.layers.outputShape,
      ].join("\n");
      updatedTemplate.contentHash = await hashContent(newContent);
      updatedTemplate.hmacSignature = await signContent(newContent, env.TEMPLATE_HMAC_KEY);

      // Store updated template (latest + versioned)
      await env.PROMPT_TEMPLATES.put(
        `template:${updatedTemplate.id}`,
        JSON.stringify(updatedTemplate),
        { metadata: { name: updatedTemplate.name, version: updatedTemplate.version, abWeight: updatedTemplate.abWeight } }
      );
      await env.PROMPT_TEMPLATES.put(
        `template:${updatedTemplate.id}:v${updatedTemplate.version}`,
        JSON.stringify(updatedTemplate),
        { expirationTtl: 60 * 60 * 24 * 90 }
      );

      // Audit trail
      await writeTemplateChange(env.AUDIT_DB, {
        templateId: updatedTemplate.id,
        action: "update",
        userId,
        version: updatedTemplate.version,
        contentHash: updatedTemplate.contentHash,
        hmacValid: true,
      });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            id: updatedTemplate.id,
            name: updatedTemplate.name,
            version: updatedTemplate.version,
            contentHash: updatedTemplate.contentHash,
            requiresHITL: updatedTemplate.requiresHITL,
            updated: true,
          }),
        }],
      };
    }
  );

  server.registerTool(
    "promptcraft_set_ab_weight",
    {
      title: "Set A/B Testing Weight",
      description: `Set the A/B testing weight for a specific template version.
Weights are used for probabilistic version routing when no templateVersion is
specified in promptcraft_execute_prompt. Higher weights receive proportionally
more traffic.

Example: Two versions with weights 0.9 and 0.1 will route 90% and 10% of traffic
respectively. Weights are relative — (0.9, 0.1) behaves the same as (9, 1).

This tool only updates the weight for a specific version in KV metadata. It does
not modify the template content or increment the version number.`,
      inputSchema: SetABWeightSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      // Load the specific versioned template
      const key = `template:${params.templateId}:v${params.version}`;
      const template = await env.PROMPT_TEMPLATES.get(key, "json") as PromptTemplate | null;

      if (!template) {
        return {
          isError: true,
          content: [{
            type: "text",
            text: `Template version not found: ${params.templateId} v${params.version}`,
          }],
        };
      }

      // Update the abWeight in the template
      const updatedTemplate: PromptTemplate = {
        ...template,
        abWeight: params.abWeight,
        updatedAt: new Date().toISOString(),
      };

      // Store the updated versioned copy
      await env.PROMPT_TEMPLATES.put(
        key,
        JSON.stringify(updatedTemplate),
        { expirationTtl: 60 * 60 * 24 * 90 }
      );

      // If this is the latest version, also update the latest key
      const latest = await env.PROMPT_TEMPLATES.get(`template:${params.templateId}`, "json") as PromptTemplate | null;
      if (latest && latest.version === params.version) {
        const updatedLatest = {
          ...latest,
          abWeight: params.abWeight,
          updatedAt: new Date().toISOString(),
        };
        await env.PROMPT_TEMPLATES.put(
          `template:${params.templateId}`,
          JSON.stringify(updatedLatest),
          { metadata: { name: updatedLatest.name, version: updatedLatest.version, abWeight: updatedLatest.abWeight } }
        );
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            templateId: params.templateId,
            version: params.version,
            abWeight: params.abWeight,
            updated: true,
          }),
        }],
      };
    }
  );

  // ═══════════════════════════════════════════════════════════════════
  // EXECUTION TOOL — with HITL gate (SPEC KIT A3)
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_execute_prompt",
    {
      title: "Execute Prompt",
      description: `Execute a prompt template with the full security pipeline:
1. Load template from KV with HMAC verification (A/B tested if no version specified)
2. [HITL] If template.requiresHITL is true: request human approval and block
   until approved, rejected, or HITL_TIMEOUT_MS elapses. Timeout routes to
   dead-letter — never to silent pass. (SPEC KIT A3: Approval Bypass / REQUIRE_HITL)
3. Sanitize user input (NFKC, injection detection, length)
4. Compile four-layer prompt with structured separation + sandwich defense
5. Run inference via Workers AI
6. Validate output (schema, PII, leakage, canary token)
7. Log audit trail to D1 (including resolved version)

If no templateVersion is specified, a version is selected probabilistically based
on abWeight values. Higher weights receive proportionally more traffic.

Returns the model output, guardrail results, and usage metrics.
Fail-closed: if any guardrail fails, the output is NOT returned.`,
      inputSchema: ExecutePromptSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async (params) => {
      const requestId = crypto.randomUUID();
      const startTime = Date.now();

      // ── Step 1: Load and verify template (with A/B resolution) ────────
      const template = await resolveTemplateVersion(params.templateId, params.templateVersion);

      if (!template) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      const compiledContent = [template.layers.role, template.layers.objective, template.layers.constraints, template.layers.outputShape].join("\n");
      const hmacValid = await verifyContent(compiledContent, template.hmacSignature, env.TEMPLATE_HMAC_KEY);
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

      // ── Step 2: HITL gate (SPEC KIT A3: Approval Bypass / REQUIRE_HITL) ──
      // INVARIANT: if requiresHITL is true and decision is not 'approved',
      // execution MUST NOT proceed. This check is unconditional — there is no
      // bypass path, no default-allow fallback, no exception for timeouts.
      if (template.requiresHITL) {
        const timeoutMs = parseInt(env.HITL_TIMEOUT_MS || "300000", 10);

        // Hash variables so we audit context without exposing values
        const variablesHash = await hashContent(JSON.stringify(params.variables));

        // Write pending approval record
        await requestHITLApproval(env.AUDIT_DB, {
          requestId,
          templateId: template.id,
          templateName: template.name,
          userId,
          variablesHash,
          timeoutMs,
        });

        console.log(`[HITL] Approval requested for ${requestId} (template: ${template.name}, timeout: ${timeoutMs}ms)`);

        // Block until approved, rejected, or timed out
        const decision = await waitForHITLDecision(env.AUDIT_DB, requestId, timeoutMs);

        if (!decision.approved) {
          const status = decision.reason === "timed_out" ? "hitl_timeout" : "hitl_rejected";

          await writeAuditLog(env.AUDIT_DB, {
            requestId, sessionId: null, templateId: params.templateId,
            templateVersion: template.version, userId, model: params.model ?? "none",
            status, latencyMs: Date.now() - startTime,
            inputTokens: 0, outputTokens: 0,
            guardrailFlags: JSON.stringify({
              hitlGate: true,
              decision: decision.reason,
              resolvedBy: decision.resolvedBy ?? null,
            }),
            createdAt: new Date().toISOString(),
          });

          const message = decision.reason === "timed_out"
            ? `Execution blocked: HITL approval timed out after ${timeoutMs}ms. Request ${requestId} routed to dead-letter queue.`
            : `Execution blocked: HITL approval rejected by ${decision.resolvedBy ?? "reviewer"}.`;

          return { isError: true, content: [{ type: "text", text: message }] };
        }

        console.log(`[HITL] Approved for ${requestId} by ${decision.resolvedBy}`);
      }

      // ── Step 3: Sanitize user input ───────────────────────────────
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

      // ── Step 4: Compile prompt ────────────────────────────────────
      const { systemPrompt, userPrompt, canaryToken } = compilePrompt(template, {
        userInput: params.userInput,
        variables: params.variables,
        sandwichDefense: params.sandwichDefense,
      });

      // ── Step 5: Run inference ─────────────────────────────────────
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

      // ── Step 6: Validate output ───────────────────────────────────
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

      // ── Step 7: Audit log (success path) ─────────────────────────
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
  // HITL MANAGEMENT TOOLS
  // SPEC KIT: A3 Approval Bypass / REQUIRE_HITL (agent-core-v1.0)
  // Only admin and operator roles have hitl:resolve permission.
  // ═══════════════════════════════════════════════════════════════════

  server.registerTool(
    "promptcraft_resolve_hitl",
    {
      title: "Resolve HITL Approval",
      description: `Approve or reject a pending HITL (Human-In-The-Loop) execution request.
Only admins and operators can resolve HITL requests.

When approved: the blocked promptcraft_execute_prompt call proceeds to inference.
When rejected: the execution is cancelled and the rejection is recorded in the audit trail.
If the request has already reached a terminal state (approved/rejected/timed_out),
this call returns an error — double-resolution is rejected by design.

SPEC KIT: A3 Approval Bypass / REQUIRE_HITL`,
      inputSchema: ResolveHITLSchema,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (params) => {
      const result = await resolveHITLApproval(
        env.AUDIT_DB,
        params.requestId,
        params.resolution,
        userId
      );

      if (!result.ok) {
        return {
          isError: true,
          content: [{ type: "text", text: result.error ?? "Failed to resolve HITL approval" }],
        };
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            requestId: params.requestId,
            resolution: params.resolution,
            resolvedBy: userId,
            resolvedAt: new Date().toISOString(),
          }),
        }],
      };
    }
  );

  server.registerTool(
    "promptcraft_get_hitl_status",
    {
      title: "Get HITL Approval Status",
      description: `Check the status of a HITL approval request by request ID.
Returns the current status (pending/approved/rejected/timed_out),
expiry time, resolution details, and original request context.`,
      inputSchema: GetHITLStatusSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const status = await getHITLApprovalStatus(env.AUDIT_DB, params.requestId);

      if (!status) {
        return {
          isError: true,
          content: [{ type: "text", text: `HITL request not found: ${params.requestId}` }],
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
      };
    }
  );

  server.registerTool(
    "promptcraft_list_pending_hitl",
    {
      title: "List Pending HITL Approvals",
      description: `List all currently pending HITL approval requests that have not yet expired.
Used by admin/operator dashboards to surface outstanding execution approvals.
Returns request ID, template ID, requesting user, expiry time, and context summary.
Expired and terminal requests are excluded — use promptcraft_query_audit for history.`,
      inputSchema: ListPendingHITLSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const pending = await listPendingHITLApprovals(env.AUDIT_DB, params.limit ?? 50);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            pending,
            count: pending.length,
          }, null, 2),
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
      const template = await env.PROMPT_TEMPLATES.get(`template:${params.templateId}`, "json") as PromptTemplate | null;
      if (!template) {
        return { isError: true, content: [{ type: "text", text: `Template not found: ${params.templateId}` }] };
      }

      // Verify HMAC
      const compiledContent = [template.layers.role, template.layers.objective, template.layers.constraints, template.layers.outputShape].join("\n");
      const hmacValid = await verifyContent(compiledContent, template.hmacSignature, env.TEMPLATE_HMAC_KEY);

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
            requiresHITL: template.requiresHITL,
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
      description: `Query the prompt execution audit trail with filters for user, template, status, and time range.
Status values include hitl_rejected and hitl_timeout for HITL gate decisions.`,
      inputSchema: QueryAuditSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (params) => {
      const result = await queryAuditLogs(env.AUDIT_DB, params);
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    }
  );
}
