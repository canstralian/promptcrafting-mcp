# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-03-23

### Added

#### Core Framework
- **Four-layer prompt stack**: every prompt is compiled from structured `objective`, `role`, `constraints`, and `outputShape` layers to enforce separation of instructions from data.
- **HMAC-SHA256 content signing**: all templates are signed at creation time; signature is verified before every read, execution, update, and deletion (`src/services/prompt-builder.ts`).
- **Immutable versioned templates**: each mutation increments the version and writes a versioned KV copy with 90-day retention alongside the `latest` key.
- **Workers KV template storage** with metadata (name, version, abWeight) for efficient listing.
- **D1/SQLite audit trail**: every prompt execution, guardrail event, and template change is written to an append-only D1 table (`migrations/0001_init.sql`).

#### Security Guardrails (B2 boundary)
- **Input sanitizer** (`src/guardrails/input-sanitizer.ts`): NFKC normalization, invisible character stripping, prompt injection pattern detection (regex + entropy analysis), structured separation (XML-fenced user data), and sandwich defense (post-input instruction reinforcement).
- **Output validator** (`src/guardrails/output-validator.ts`): canary token leak detection, PII regex detection and redaction (email, phone, SSN, credit card, IP), system instruction pattern detection, Zod-based JSON Schema validation (fail-closed).
- **Canary tokens**: each compiled system prompt embeds a unique canary token; if the model echoes it, the output is blocked.

#### Authentication & Authorization (B1 boundary)
- **JWT authentication** with algorithm pinning (HS256 only — `alg: none` and asymmetric algorithms rejected).
- **RBAC enforcement**: permission claims (`template:read`, `template:write`, `template:delete`, `audit:read`, `hitl:resolve`) checked before each operation.
- **Rate limiting at the edge**: burst and sustained rate limits keyed on `CF-Connecting-IP` (rate limiting middleware runs before JWT auth; keys upgrade to JWT `sub` when already set by a preceding middleware).
- **CORS headers** on all routes.

#### HITL Gate (SPEC KIT A3)
- **Human-In-The-Loop execution gate** (`src/services/hitl.ts`): templates with `requiresHITL: true` block execution until a human approves or rejects.
- **Fail-closed timeout**: if approval is not received within `HITL_TIMEOUT_MS`, the request is routed to a dead-letter status — never to a silent pass.
- **D1 HITL approval table** (`migrations/0002_hitl.sql`): stores pending, approved, rejected, and timed-out approval records with full audit context.

#### A/B Testing
- **Per-version traffic weights** (`abWeight` field, 0.0–1.0) stored in KV metadata.
- **`promptcraft_set_ab_weight`** tool: update the traffic weight for any template version.
- **Weighted random version selection** in `resolveTemplateVersion()`: when no explicit `templateVersion` is supplied, traffic is distributed proportionally across all versions.

#### MCP Tools (12 total)
- `promptcraft_create_template` — create HMAC-signed four-layer template
- `promptcraft_get_template` — retrieve with integrity verification
- `promptcraft_list_templates` — paginated listing with tag filter
- `promptcraft_delete_template` — soft-delete (versioned copies retained)
- `promptcraft_update_template` — partial update, version increment, re-sign
- `promptcraft_set_ab_weight` — set A/B traffic weight for a template version
- `promptcraft_execute_prompt` — full pipeline: HMAC verify → HITL gate → sanitize → compile → infer → validate → audit
- `promptcraft_validate_input` — dry-run validation with prompt preview (no inference)
- `promptcraft_resolve_hitl` — approve or reject a pending HITL request
- `promptcraft_get_hitl_status` — check HITL approval status by request ID
- `promptcraft_list_pending_hitl` — list non-expired pending approvals
- `promptcraft_query_audit` — query D1 audit trail with filters

#### HTTP Endpoints
- `GET /health` — unauthenticated health check
- `ALL /mcp/*` — MCP Streamable HTTP transport (JWT-gated)
- `GET /api/v1/templates` — list templates (JWT + `template:read`)
- `GET /api/v1/templates/:id` — get template (JWT + `template:read`)
- `DELETE /api/v1/templates/:id` — delete template (JWT + `template:delete`)
- `GET /api/v1/audit` — query audit logs (JWT + `audit:read`)

#### Documentation
- `docs/threat-model/README.md` — STRIDE threat model with Mermaid DFDs for all five security boundaries (B0–B4).
- `docs/security/tls-policy.md` — TLS posture analysis; confirms zero outbound `fetch()` calls (all traffic uses Cloudflare native bindings).
- `docs/security/vulnerability-assessment.md` — CVE risk assessment for transitive dependencies; all vulnerabilities assessed as non-exploitable in this deployment.

#### Testing
- Integration test suite (`tests/integration/`) with Vitest.
- Mocked Cloudflare bindings: Workers KV via `Map`, D1 via `better-sqlite3`.
- `tests/integration/template-operations.test.ts` — CRUD + HMAC integrity tests.
- `tests/integration/guardrails-hitl.test.ts` — HITL fail-closed behavior, timeout routing to dead-letter, double-resolution rejection.

[1.0.0]: https://github.com/canstralian/promptcrafting-mcp/releases/tag/v1.0.0
