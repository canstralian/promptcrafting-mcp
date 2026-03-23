# promptcrafting-mcp

Security-hardened prompt engineering framework deployed as an MCP server on Cloudflare Workers.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  B0: Untrusted Zone                                             │
│  Clients, Admin UIs, External IdPs                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS
┌──────────────────────────▼──────────────────────────────────────┐
│  B1: Edge Perimeter (Hono Router on Cloudflare Worker)          │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌───────────────┐  │
│  │ CORS     │→│ Rate     │→│ JWT Auth     │→│ RBAC          │  │
│  │ Headers  │ │ Limiter  │ │ (alg pinned) │ │ Enforcement   │  │
│  └──────────┘ └──────────┘ └──────────────┘ └───────────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  B2: Controlled Execution Plane (McpAgent Durable Object)       │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────┐  │
│  │ Input       │→│ Structured   │→│ Sandwich   │→│ Prompt   │  │
│  │ Sanitizer   │ │ Separation   │ │ Defense    │ │ Builder  │  │
│  └─────────────┘ └──────────────┘ └────────────┘ └────┬─────┘  │
│                                                        │        │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────┐      │        │
│  │ HITL Gate   │←│ PII/Toxicity │←│ Output     │←─────┘        │
│  │ (optional)  │ │ Redaction    │ │ Validator  │  ← from B4    │
│  └─────────────┘ └──────────────┘ └────────────┘               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  B3: Data Plane                                                 │
│  ┌───────────────────┐ ┌──────────────────┐ ┌────────────────┐  │
│  │ Workers KV        │ │ D1 / SQLite      │ │ Cold Storage   │  │
│  │ Templates+Versions│ │ Audit Logs       │ │ (Optional S3)  │  │
│  │ HMAC-signed       │ │ Guardrail Events │ │ Compliance     │  │
│  └───────────────────┘ └──────────────────┘ └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  B4: Model Execution (Untrusted)                                │
│  Workers AI / External LLM Providers                            │
│  ⚠️  Treat all outputs as untrusted — validate back in B2       │
└─────────────────────────────────────────────────────────────────┘
```

## Four-Layer Prompt Stack

Every prompt is compiled from four structured layers:

| Layer | Purpose | Security Role |
|-------|---------|---------------|
| **Objective** | Task definition + success criteria | Defines allowed scope |
| **Role** | Persona + domain context | Shifts model vocabulary |
| **Constraints** | Boundaries + forbidden actions | Security policy enforcement |
| **Output Shape** | Format + schema + examples | Enables Zod validation |

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Create Cloudflare resources
wrangler kv namespace create PROMPT_TEMPLATES
wrangler d1 create promptcrafting-audit

# 3. Update wrangler.jsonc with the IDs from step 2

# 4. Set secrets
wrangler secret put JWT_SECRET
wrangler secret put TEMPLATE_HMAC_KEY

# 5. Run D1 migrations
npm run db:migrate

# 6. Deploy
npm run deploy
```

## Security Controls

| Boundary | Threat | Mitigation | Status |
|----------|--------|------------|--------|
| B0→B1 | Spoofing | JWT with algorithm pinning (HS256 only) | ✅ |
| B0→B1 | DoS | Identity-keyed rate limiting (not IP) | ✅ |
| B1→B2 | Privilege escalation | RBAC with permission checks | ✅ |
| B2 | Direct prompt injection | NFKC + regex + entropy analysis | ✅ |
| B2 | Indirect injection | Structured separation + sandwich defense | ✅ |
| B2 | Token smuggling | Invisible char stripping + normalization | ✅ |
| B3 | Template poisoning | HMAC-SHA256 content signing | ✅ |
| B3 | Repudiation | Immutable D1 audit logs | ✅ |
| B4 | Prompt extraction | Canary tokens in system prompt | ✅ |
| B4→B2 | Schema drift | Zod fail-closed output validation | ✅ |
| B4→B2 | PII leakage | Regex PII detection + redaction | ✅ |
| B4→B2 | Prompt leakage | System instruction pattern detection | ✅ |
| B1 | JWT confusion | Algorithm pinning, claim validation | ✅ |
| B2 | HITL timeout/DoS | Configurable timeout (`HITL_TIMEOUT_MS`), dead-letter on expiry | ✅ |
| B4 | Response integrity | TLS cert pinning (planned) | 🔲 |

## Endpoints

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/mcp/*` | ALL | JWT | MCP protocol (Streamable HTTP) |
| `/api/v1/templates` | GET | JWT + `template:read` | List templates |
| `/api/v1/templates/:id` | GET | JWT + `template:read` | Get template |
| `/api/v1/templates/:id` | DELETE | JWT + `template:delete` | Delete template |
| `/api/v1/audit` | GET | JWT + `audit:read` | Query audit logs |
| `/api/v1/hitl` | GET | JWT + `hitl:resolve` | List pending HITL approvals |
| `/api/v1/hitl/:requestId` | GET | JWT + `hitl:resolve` | Get HITL approval status |
| `/api/v1/hitl/:requestId/resolve` | POST | JWT + `hitl:resolve` | Approve or reject HITL request |

## MCP Tools

| Tool | Description | Annotations |
|------|-------------|-------------|
| `promptcraft_create_template` | Create HMAC-signed four-layer template | write |
| `promptcraft_get_template` | Retrieve + verify template integrity | read-only |
| `promptcraft_list_templates` | List templates with pagination | read-only |
| `promptcraft_delete_template` | Soft-delete (versions retained) | destructive |
| `promptcraft_execute_prompt` | Full pipeline: sanitize → compile → infer → validate | write |
| `promptcraft_validate_input` | Dry-run validation (no inference) | read-only |
| `promptcraft_query_audit` | Query audit trail with filters | read-only |

## Project Structure

```
promptcrafting-mcp/
├── wrangler.jsonc            # Cloudflare config (all bindings)
├── package.json
├── tsconfig.json
├── migrations/
│   └── 0001_init.sql         # D1 schema
└── src/
    ├── index.ts              # Hono router (B1 perimeter)
    ├── mcp-agent.ts          # McpAgent Durable Object (B2)
    ├── types.ts              # Shared type definitions
    ├── schemas/
    │   └── index.ts          # Zod input schemas
    ├── middleware/
    │   └── auth.ts           # JWT, RBAC, rate limiting
    ├── guardrails/
    │   ├── index.ts          # Barrel export
    │   ├── input-sanitizer.ts  # NFKC, injection detection, separation, sandwich
    │   └── output-validator.ts # Schema, PII, leakage, canary
    ├── services/
    │   ├── prompt-builder.ts # Four-layer compiler, HMAC signing
    │   └── audit.ts          # D1 audit trail operations
    └── tools/
        └── prompt-tools.ts   # MCP tool registrations
```

## Next Steps

- [ ] STRIDE threat model diagram per boundary
- [x] HITL gate with configurable timeout + dead-letter path
- [ ] TLS certificate pinning for external model providers
- [ ] Integration tests with MCP Inspector
- [ ] Prompt A/B testing via KV version routing
- [ ] Cloudflare Firewall for AI integration (semantic input/output scanning)
