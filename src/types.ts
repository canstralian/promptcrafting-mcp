// src/types.ts — Shared type definitions for promptcrafting-mcp
// All types are centralized here; no `any` types permitted.

// ─── Cloudflare Bindings ───────────────────────────────────────────
export interface Env {
  // Durable Objects
  MCP_SERVER: DurableObjectNamespace;

  // Storage
  PROMPT_TEMPLATES: KVNamespace;
  AUDIT_DB: D1Database;

  // AI
  AI: Ai;

  // Rate limiting
  RATE_LIMITER: RateLimit;
  BURST_LIMITER: RateLimit;

  // Secrets (set via `wrangler secret put`)
  JWT_SECRET: string;
  TEMPLATE_HMAC_KEY: string;
  OPENAI_API_KEY?: string;

  // Vars
  ENVIRONMENT: string;
  LOG_LEVEL: string;
  HITL_TIMEOUT_MS: string;
  MAX_PROMPT_LENGTH: string;
}

// ─── Rate Limit (Workers binding type) ─────────────────────────────
export interface RateLimit {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

// ─── Prompt Template ───────────────────────────────────────────────
export interface PromptTemplate {
  id: string;
  name: string;
  description: string;
  version: number;

  // Four-layer content
  layers: {
    objective: string;
    role: string;
    constraints: string;
    outputShape: string;
  };

  // Security
  contentHash: string;   // SHA-256 of compiled template
  hmacSignature: string; // HMAC-SHA256 signed by TEMPLATE_HMAC_KEY

  // HITL gate (SPEC KIT: A3 Approval Bypass / REQUIRE_HITL)
  // When true, every execution of this template must be approved before
  // the prompt is submitted to the AI model. Execution blocks until
  // approved, rejected, or HITL_TIMEOUT_MS elapses. Timeout routes to
  // dead-letter — never to silent pass.
  requiresHITL: boolean;

  // A/B Testing Weight (0.0–1.0, default 1.0)
  // Used for probabilistic version routing when no templateVersion is specified.
  // Higher weights receive proportionally more traffic.
  abWeight: number;

  // Metadata
  tags: string[];
  model?: string;         // Target model hint
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

// ─── Prompt Execution Request ──────────────────────────────────────
export interface PromptExecutionRequest {
  templateId: string;
  templateVersion?: number;
  variables: Record<string, string>;
  model?: string;
  sandwichDefense?: boolean;
  maxTokens?: number;
}

// ─── Prompt Execution Result ───────────────────────────────────────
export interface PromptExecutionResult {
  requestId: string;
  templateId: string;
  templateVersion: number;
  model: string;
  output: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
    latencyMs: number;
  };
  guardrails: {
    inputSanitized: boolean;
    injectionDetected: boolean;
    outputSchemaValid: boolean;
    piiDetected: boolean;
    toxicityScore: number;
  };
}

// ─── Audit Log Entry ───────────────────────────────────────────────
export interface AuditLogEntry {
  requestId: string;
  sessionId: string | null;
  templateId: string;
  templateVersion: number;
  userId: string;
  model: string;
  status: "success" | "error" | "rate_limited" | "filtered" | "hitl_rejected" | "hitl_timeout";
  latencyMs: number;
  inputTokens: number;
  outputTokens: number;
  guardrailFlags: string; // JSON-encoded guardrail results
  createdAt: string;
}

// ─── JWT Claims ────────────────────────────────────────────────────
export interface JWTPayload {
  sub: string;       // User ID
  role: "admin" | "operator" | "viewer";
  iss: string;       // Issuer — must match expected value
  aud: string;       // Audience — must match server identity
  exp: number;       // Expiration (Unix timestamp)
  iat: number;       // Issued at
  jti?: string;      // Optional JWT ID for replay detection
}

// ─── Guardrail Verdict ─────────────────────────────────────────────
export interface GuardrailVerdict {
  pass: boolean;
  reason?: string;
  score?: number;
  details?: Record<string, unknown>;
}

// ─── RBAC Permissions ──────────────────────────────────────────────
export const ROLE_PERMISSIONS = {
  admin: [
    "template:create", "template:read", "template:update", "template:delete",
    "prompt:execute", "prompt:validate",
    "audit:read", "audit:export",
    "config:read", "config:write",
    "hitl:resolve",  // Can approve/reject HITL requests
  ],
  operator: [
    "template:read",
    "prompt:execute", "prompt:validate",
    "audit:read",
    "config:read",
    "hitl:resolve",  // Operators can also approve/reject
  ],
  viewer: [
    "template:read",
    "audit:read",
    // hitl:resolve intentionally absent — viewers cannot approve executions
  ],
} as const;

export type Permission = (typeof ROLE_PERMISSIONS)[keyof typeof ROLE_PERMISSIONS][number];
export type Role = keyof typeof ROLE_PERMISSIONS;
