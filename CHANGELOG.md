# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-23

### Added

#### Core Architecture
- Four-layer prompt engineering framework with structured separation
  - **Objective**: Task definition and success criteria
  - **Role**: Persona and domain context
  - **Constraints**: Security boundaries and forbidden actions
  - **Output Shape**: Format schema and validation rules
- Security-hardened deployment on Cloudflare Workers with Durable Objects
- Five-boundary defense-in-depth architecture (B0–B4)
- MCP (Model Context Protocol) server implementation with @modelcontextprotocol/sdk

#### Template Management (12 MCP Tools)
- `promptcraft_create_template` - Create HMAC-signed four-layer templates
- `promptcraft_get_template` - Retrieve templates with integrity verification
- `promptcraft_list_templates` - List templates with pagination and tag filtering
- `promptcraft_update_template` - Version-controlled template updates
- `promptcraft_delete_template` - Soft-delete with audit trail retention
- `promptcraft_set_ab_weight` - Configure A/B testing weights for template versions

#### Execution & Validation
- `promptcraft_execute_prompt` - Full security pipeline execution with guardrails
- `promptcraft_validate_input` - Dry-run input validation without inference
- Template version routing with probabilistic A/B testing support
- Sandwich defense for prompt injection mitigation
- Structured input/output separation

#### Human-in-the-Loop (HITL) Controls
- `promptcraft_resolve_hitl` - Approve or reject pending execution requests
- `promptcraft_get_hitl_status` - Check HITL approval status by request ID
- `promptcraft_list_pending_hitl` - List all pending HITL approvals
- Fail-closed HITL gate with configurable timeout (never silent pass)
- Dead-letter queue routing for timed-out approvals
- SPEC KIT A3 compliance (Approval Bypass / REQUIRE_HITL)

#### Audit & Compliance
- `promptcraft_query_audit` - Query execution audit logs with filtering
- Immutable D1 audit trail for all executions
- Template change tracking (create/update/delete) with content hashes
- Guardrail event logging for security analysis
- HITL decision audit with resolver identification

#### Security Controls

##### B1 (Edge Perimeter)
- JWT authentication with HS256 algorithm pinning
- Role-based access control (RBAC) with permission checks
- Identity-keyed rate limiting (not IP-based)
- CORS header enforcement

##### B2 (Controlled Execution Plane)
- Input sanitization with NFKC normalization
- Direct prompt injection detection (entropy analysis, Unicode normalization)
- Indirect injection defense via structured separation
- Token smuggling prevention (invisible character stripping)
- Sandwich defense (post-input reinforcement)

##### B3 (Data Plane)
- HMAC-SHA256 content signing for template integrity
- Template versioning with 90-day retention policy
- Immutable audit logs in Cloudflare D1

##### B4 (Model Execution Boundary)
- Output validation with Zod schema enforcement
- PII detection and redaction (email, phone, SSN patterns)
- System prompt leakage detection
- Canary token verification to detect prompt extraction attempts
- Fail-closed validation (blocks on any guardrail failure)

#### Documentation
- STRIDE threat model with Mermaid diagrams for all 5 boundaries
- TLS security policy and responsibility matrix
- Zero-fetch architecture analysis (no outbound HTTP calls)
- Cloudflare Firewall for AI evaluation guidelines
- Certificate pinning implementation template for future external providers
- Comprehensive integration test suite with MCP Inspector patterns
- Vulnerability assessment documentation

#### Development & Testing
- Vitest integration test framework with Cloudflare bindings mocks
- Test fixtures for template operations and HITL workflows
- CI/CD pipeline with GitHub Actions
- ESLint code quality checks
- TypeScript strict mode with full type coverage

### Security
- All templates HMAC-signed to prevent tampering
- Fail-closed security model (deny by default)
- Comprehensive STRIDE threat coverage across all boundaries
- Algorithm confusion attack prevention (JWT HS256 pinning)
- Replay attack mitigation (idempotency checks on destructive operations)
- Repudiation protection (immutable audit logs)

### Infrastructure
- Cloudflare Workers runtime
- Cloudflare Durable Objects for McpAgent stateful execution
- Cloudflare Workers KV for template storage
- Cloudflare D1 (SQLite) for audit logs
- Cloudflare Workers AI for model inference
- Support for external LLM providers (planned with TLS pinning)

## [Unreleased]

### Planned
- Configurable HITL timeout with admin override
- TLS certificate pinning for external model providers
- Cloudflare Firewall for AI integration (semantic input/output scanning)
- Cold storage integration (S3-compatible) for compliance
- Advanced A/B testing analytics and automatic weight adjustment
- Prompt template marketplace with cryptographic verification

---

[1.0.0]: https://github.com/canstralian/promptcrafting-mcp/releases/tag/v1.0.0
