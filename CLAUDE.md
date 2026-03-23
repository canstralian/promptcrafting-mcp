# CLAUDE.md — promptcrafting-mcp

This file provides context for AI assistants (Claude Code, Copilot, etc.) working in this repository.

---

## Project Overview

**promptcrafting-mcp** is a production-grade, security-hardened **MCP (Model Context Protocol) server** for prompt engineering, deployed on **Cloudflare Workers**. It exposes 11 MCP tools for creating, versioning, executing, and auditing four-layer AI prompts with comprehensive security guardrails and a Human-In-The-Loop (HITL) approval gate.

**Runtime:** Cloudflare Workers (edge, serverless)
**Language:** TypeScript (ES2022, strict)
**Framework:** Hono (routing) + `agents` SDK (McpAgent Durable Object)
**Database:** Cloudflare D1 (SQLite-compatible)
**Key-Value Store:** Cloudflare KV (template storage)

---

## Directory Structure

```
promptcrafting-mcp/
├── src/
│   ├── index.ts                  # Hono router — B1 edge perimeter
│   ├── mcp-agent.ts              # McpAgent Durable Object — B2 execution
│   ├── types.ts                  # Shared TypeScript types and Env interface
│   ├── middleware/
│   │   └── auth.ts               # JWT verification (HS256), RBAC, rate limiting
│   ├── services/
│   │   ├── prompt-builder.ts     # Four-layer compiler, HMAC signing, canary tokens
│   │   ├── audit.ts              # D1 audit trail (append-only)
│   │   └── hitl.ts               # Human-In-The-Loop gate (approve/reject/timeout)
│   ├── guardrails/
│   │   ├── index.ts              # Barrel exports
│   │   ├── input-sanitizer.ts    # NFKC, injection detection, Unicode attack defense
│   │   └── output-validator.ts   # Schema, PII, prompt leakage, canary validation
│   ├── schemas/
│   │   └── index.ts              # Zod schemas for all 11 MCP tools
│   └── tools/
│       └── prompt-tools.ts       # 11 MCP tool registrations
├── migrations/
│   ├── 0001_init.sql             # D1 schema: audit logs, guardrail events, template changes
│   └── 0002_hitl.sql             # HITL tables: approvals, dead-letter queue
├── extracted/                    # Snapshots, tests, and docs (see below)
│   └── promptcrafting-mcp/
│       ├── docs/                 # Threat model, TLS policy, vulnerability assessment
│       └── tests/                # Vitest integration tests
├── package.json
├── tsconfig.json
└── wrangler.jsonc                # Cloudflare Workers config with all bindings
```

---

## Security Architecture — Four Boundaries

The codebase is organized around four explicit security boundaries (STRIDE-aligned). **Always understand which boundary you are modifying.**

```
B0  Untrusted Zone        — External clients, external IdPs
 ↓ HTTPS only
B1  Edge Perimeter        — src/index.ts, src/middleware/auth.ts
    • CORS (restricted to promptcrafting.net domains)
    • Secure headers (CSP, X-Frame-Options: DENY)
    • JWT auth (HS256 pinned — algorithm must never change)
    • Identity-keyed rate limiting (100/60s + 10/10s burst)
    • RBAC enforcement
 ↓
B2  Controlled Execution  — src/mcp-agent.ts, src/tools/, src/services/, src/guardrails/
    • Input sanitization (NFKC, injection patterns, entropy analysis)
    • Structured separation (<user_input> tags)
    • Sandwich defense (recency-bias reinforcement)
    • Four-layer prompt compilation
    • HITL gate (blocking, never silent-pass on timeout)
    • Output validation (canary, leakage, PII, schema)
 ↓
B3  Data Plane            — Cloudflare KV, D1
    • Templates with HMAC-SHA256 signing (prevents KV poisoning)
    • Immutable audit logs (append-only D1 tables)
    • HITL approval tracking + dead-letter queue (forensic retention)
 ↓
B4  Model Execution       — Workers AI / external providers
    • Treated as untrusted — all outputs validated back in B2
```

---

## Key Conventions

### TypeScript

- **No `any` types** — strict mode is enforced (`tsconfig.json`)
- **ES modules** — `"type": "module"` in `package.json`; use `import`/`export`
- **Target:** ES2022 with bundler module resolution
- All new types go in `src/types.ts` unless tightly scoped to one file
- Zod schemas for all external inputs go in `src/schemas/index.ts` with `.strict()` (rejects unknown fields)

### Cloudflare Workers Constraints

- No Node.js built-ins; use Web APIs (`crypto.subtle`, `fetch`, `TextEncoder`)
- Durable Objects have a **30-second CPU limit** — HITL polling uses 2s intervals and relies on an external timeout (`HITL_TIMEOUT_MS=300000`)
- KV is eventually consistent; D1 is strongly consistent — use D1 for anything requiring atomicity (HITL state, audit logs)
- All secrets are set via `wrangler secret put`, never hardcoded

### Security Invariants — Never Violate

1. **Algorithm pinning:** JWT verification must only accept `HS256`. Never add RS256/PS256.
2. **HMAC integrity:** Every template retrieved from KV must be HMAC-verified before use. Fail closed on mismatch.
3. **HITL never-silent-pass:** A timeout must route to `hitl_dead_letter`, never to execution. This is a hard invariant.
4. **Audit append-only:** Never add `DELETE` or `UPDATE` to `prompt_audit_logs`, `guardrail_events`, `template_changes`, or `hitl_dead_letter`.
5. **Fail-closed guardrails:** Guardrails block on error; they do not warn and pass through.
6. **Canary tokens are unique per request** and must be embedded in the constraints layer, not shared across sessions.

### Error Handling

- Always return structured errors with `requestId` (set in `src/index.ts` middleware)
- Log the error to the audit trail before returning to the caller
- Use `try/catch` at the tool-handler level, not scattered throughout services

### Rate Limiting

- Rate limits are **identity-keyed** (`userId` from JWT), not IP-keyed
- Both `RATE_LIMITER` (100/60s) and `BURST_LIMITER` (10/10s) must be applied for any tool that calls Workers AI

---

## Development Commands

```bash
# Install dependencies
npm install

# Local development (Wrangler dev server with local KV/D1)
npm run dev

# Type-check (no emit)
npm run build
# or
npm run check

# Lint
npm run lint

# Run integration tests
npm run test

# Apply D1 migrations (local)
npm run db:migrate:local

# Apply D1 migrations (production)
npm run db:migrate

# Deploy to Cloudflare Workers
npm run deploy
```

---

## Cloudflare Bindings (wrangler.jsonc)

| Binding | Type | Purpose |
|---|---|---|
| `AI` | Workers AI | LLM inference (B4) |
| `MCP_SERVER` | Durable Object | McpAgent instance (B2) |
| `PROMPT_TEMPLATES` | KV Namespace | Template storage (B3) |
| `AUDIT_DB` | D1 Database | Audit logs + HITL tables (B3) |
| `RATE_LIMITER` | Rate Limiter | 100 req/60s per identity |
| `BURST_LIMITER` | Rate Limiter | 10 req/10s per identity |

**Secrets (set via `wrangler secret put`, never in code):**
- `JWT_SECRET` — HS256 signing key
- `TEMPLATE_HMAC_KEY` — HMAC-SHA256 for template integrity
- `OPENAI_API_KEY` — Optional external AI provider

**Environment variables:**
- `ENVIRONMENT=production`
- `LOG_LEVEL=info`
- `HITL_TIMEOUT_MS=300000` (5 minutes)
- `MAX_PROMPT_LENGTH=50000`

---

## RBAC Roles

| Role | Permissions |
|---|---|
| `admin` | All operations including `hitl:resolve` |
| `operator` | Execute, validate, resolve HITL |
| `viewer` | Read-only (templates, audit, HITL status) |

Permissions are enforced in `src/middleware/auth.ts` via the `requirePermission()` middleware. **Do not bypass RBAC by calling services directly from unauthenticated handlers.**

---

## MCP Tools (11 total)

All tools are registered in `src/tools/prompt-tools.ts` and validated via Zod schemas in `src/schemas/index.ts`.

| Tool | Permission | Description |
|---|---|---|
| `promptcraft_create_template` | write | Create four-layer template with HMAC signing |
| `promptcraft_get_template` | read | Retrieve template by ID ± version (HMAC-verified) |
| `promptcraft_list_templates` | read | List with tag filter and pagination |
| `promptcraft_update_template` | write | Partial update, increments version, re-signs HMAC |
| `promptcraft_delete_template` | write | Soft-delete (primary key only; versioned copies retained 90d) |
| `promptcraft_execute_prompt` | write | Full pipeline: HITL → sanitize → compile → infer → validate → audit |
| `promptcraft_validate_input` | read | Dry-run: sanitization + compilation preview (no inference) |
| `promptcraft_resolve_hitl` | hitl:resolve | Approve or reject a pending HITL request |
| `promptcraft_get_hitl_status` | read | Lookup HITL request status |
| `promptcraft_list_pending_hitl` | read | Admin listing of pending approvals |
| `promptcraft_query_audit` | read | Query audit logs with filters |

### Execution Pipeline (promptcraft_execute_prompt)

```
1. Load template from KV
2. Verify HMAC integrity (fail closed)
3. [If requiresHITL] Request approval → block (poll D1 every 2s) → timeout routes to dead-letter
4. Sanitize input (NFKC, injection patterns, entropy)
5. Apply structured separation (<user_input> tags)
6. Compile four-layer prompt (role/objective/constraints/output-shape)
7. [Optional] Apply sandwich defense
8. Embed canary token in constraints layer
9. Run inference via Workers AI
10. Validate output (canary check → leakage → PII → schema)
11. Write audit log + guardrail events to D1
12. Return result
```

---

## Four-Layer Prompt Stack

Every template has four required layers, compiled in order:

| Layer | Purpose | Key Content |
|---|---|---|
| **Role** | Persona + domain context | Who the model is |
| **Objective** | Task definition + success criteria | What to accomplish |
| **Constraints** | Boundaries + security directives | What not to do; canary token embedded here |
| **Output Shape** | Expected format + schema | JSON schema or format spec |

User input is always wrapped in `<user_input>` tags and placed between the constraints layer and the output shape layer. Never merge user input directly into the role or objective layers.

---

## Database Schema (D1 SQLite)

### `prompt_audit_logs` (append-only)
Every execution attempt. Status: `success | error | rate_limited | filtered | hitl_rejected | hitl_timeout`.

### `guardrail_events` (append-only)
Per-stage verdicts. Stages: `input_sanitize | hmac_verify | output_schema | pii_detect | canary_check`.

### `template_changes` (append-only)
Every create/update/delete on templates. Captures `hmac_valid` at deletion time.

### `hitl_approvals`
HITL approval requests. Status transitions: `pending → approved | rejected | timed_out` (one-way, no rollbacks).

### `hitl_dead_letter` (append-only, never deleted)
Timed-out HITL requests. Forensic retention; do not add any deletion logic here.

---

## Testing

Tests live in `extracted/promptcrafting-mcp/tests/` and use **Vitest 3.0** with in-memory mocks for Cloudflare bindings (KV, D1).

```bash
npm run test
```

**Coverage:** 16/20 integration tests passing (80%). Known failures are in guardrail mock setup, not production code.

**Test structure:**
- `fixtures/templates.ts` — Sample templates and injection payloads
- `setup/test-env.ts` — Mock Cloudflare bindings
- `utils/test-helpers.ts` — HMAC helpers, JWT generation, DB initialization
- `integration/template-operations.test.ts` — CRUD + HMAC round-trips
- `integration/guardrails-hitl.test.ts` — Guardrails + HITL gate flow

When adding a new tool, add corresponding fixtures and integration tests.

---

## Adding New MCP Tools

1. Add Zod schema to `src/schemas/index.ts` (use `.strict()`)
2. Add tool registration in `src/tools/prompt-tools.ts`
3. Implement handler — always:
   - Validate input with the Zod schema first
   - Call `this.trackToolCall()` on the McpAgent
   - Write to the audit log (`writeAuditLog()`) before returning
   - Return structured errors with `requestId`
4. Add RBAC permission check if the tool modifies state
5. Add integration tests in `extracted/promptcrafting-mcp/tests/`

---

## Adding New Database Migrations

1. Create `migrations/000N_description.sql` (sequential numbering)
2. All new tables must be **append-only** unless there is a documented exception with security justification
3. Run locally first: `npm run db:migrate:local`
4. Test, then run: `npm run db:migrate`

---

## Common Pitfalls

- **Do not use `algorithm: 'RS256'`** in JWT — only `HS256` is accepted; adding others breaks the algorithm-pinning invariant
- **Do not use IP address** for rate limiting — only `userId` from JWT claims
- **Do not return raw user input** in error messages — may enable injection via error channels
- **Do not call Workers AI** without first running input through `sanitizeInput()` and verifying HMAC on the loaded template
- **Do not modify HITL dead-letter rows** — they are forensic records; there is no valid reason to update or delete them
- **Do not skip audit logging** — every tool invocation must produce an audit record even if execution fails
- **KV template keys:** primary key format is `template:{id}`, versioned format is `template:{id}:v{n}` (90-day TTL). Do not invent new formats without updating `promptcraft_list_templates` (which filters by `:v` suffix).

---

## Documentation References

- `README.md` — Quick start, architecture overview, security controls matrix
- `extracted/promptcrafting-mcp/docs/threat-model/README.md` — Full STRIDE analysis per boundary
- `extracted/promptcrafting-mcp/docs/security/tls-policy.md` — TLS certificate pinning policy
- `extracted/promptcrafting-mcp/docs/security/vulnerability-assessment.md` — CVE assessment for Agents SDK
- `extracted/promptcrafting-mcp/tests/README.md` — Test coverage breakdown and acceptance criteria
