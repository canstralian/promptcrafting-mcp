# TLS Certificate Pinning Policy

## Executive Summary

This document defines the TLS security posture for the promptcrafting-mcp service deployed on Cloudflare Workers. It addresses certificate pinning, edge termination responsibilities, and outbound connection security across the four-boundary architecture (B0-B4).

**Key Finding**: This application makes **zero outbound HTTP fetch() calls**. All operations use Cloudflare native bindings (Workers AI, D1, KV), eliminating the need for application-layer TLS pinning.

---

## TLS Responsibility Matrix

| Boundary | Component | TLS Handler | Certificate Validation | Pinning Required? |
|----------|-----------|-------------|------------------------|-------------------|
| **B0→B1** | Client → Worker | Cloudflare Edge | Cloudflare-managed certificates | ❌ No (edge handles) |
| **B1→B2** | Router → Durable Object | Internal (same isolate) | N/A (in-process) | ❌ No (not network call) |
| **B2→B3** | Worker → KV/D1 | Cloudflare native binding | Cloudflare internal | ❌ No (trusted binding) |
| **B2→B4** | Worker → Workers AI | Cloudflare native binding | Cloudflare internal | ❌ No (trusted binding) |
| **B2→B4** | Worker → External LLM | ⚠️ **Not implemented** | Would require pinning | ⚠️ **Yes (if added)** |

---

## Architecture Analysis

### 1. Inbound TLS (B0→B1): Client to Worker

**Termination Point**: Cloudflare's global edge network

**Certificate Management**:
- Cloudflare issues and rotates TLS certificates automatically
- Supports TLS 1.2+ with strong cipher suites
- HSTS enforcement available via Cloudflare dashboard settings

**Worker Responsibility**: **None**
- Workers do not handle TLS termination
- All inbound traffic arrives over Cloudflare's secure network after edge decryption
- The Worker receives requests via the V8 isolate runtime, not raw TCP

**Configuration**: Set in Cloudflare dashboard (SSL/TLS → Edge Certificates)
- Recommended: "Full (strict)" mode for origin connections (if proxying to origin)
- For Workers-only deployments: TLS is handled entirely at the edge

---

### 2. Internal Communication (B1→B2, B2 within Durable Objects)

**Transport**: In-process V8 isolate communication

**TLS Applicability**: **Not applicable**
- Hono router → Durable Object calls use Cloudflare's internal RPC mechanism
- No network sockets, no TLS layer
- Isolation enforced by V8 sandboxing, not network encryption

**Security Model**: Process isolation + capability-based security (bindings)

---

### 3. Worker → Cloudflare Services (B2→B3, B2→B4)

#### 3.1 Workers AI Binding (`env.AI`)

**Implementation**: `src/tools/prompt-tools.ts:477`

```typescript
const aiResult = await env.AI.run(model as BaseAiTextGenerationModels, {
  messages: [
    { role: "system", content: systemPrompt },
    { role: "user", content: userPrompt }
  ],
  max_tokens: params.maxTokens,
});
```

**TLS Handling**: **Cloudflare-internal secure channel**
- The `env.AI` binding is a Workers Runtime capability
- Communication to Workers AI occurs over Cloudflare's private network
- **No fetch() call is made** — this is a direct binding invocation
- TLS/mTLS is managed by Cloudflare's internal infrastructure

**Certificate Validation**: Handled by Cloudflare platform
- Worker has no visibility into or control over the TLS handshake
- Cloudflare enforces mTLS between Workers and AI service internally

**Pinning Decision**: ✅ **Not required** — trusted internal binding

---

#### 3.2 D1 Database Binding (`env.AUDIT_DB`)

**Usage**: Audit logs, HITL approvals, guardrail events

**TLS Handling**: **Cloudflare-internal secure channel**
- D1 uses a native binding (not HTTP)
- SQLite database is co-located with the Worker runtime
- Communication occurs over Cloudflare's secure internal network

**Pinning Decision**: ✅ **Not required** — trusted internal binding

---

#### 3.3 KV Binding (`env.PROMPT_TEMPLATES`)

**Usage**: Template storage with HMAC signing

**TLS Handling**: **Cloudflare-internal secure channel**
- KV uses a native binding (not HTTP)
- Cloudflare manages all transport-layer security

**Pinning Decision**: ✅ **Not required** — trusted internal binding

---

### 4. Worker → External Services (B2→B4: External LLM Providers)

#### 4.1 OpenAI API Integration (Planned, Not Implemented)

**Current Status**: ⚠️ **Not implemented in codebase**

**Configuration Readiness**:
- Secret defined: `OPENAI_API_KEY` (see `wrangler.jsonc:89`)
- Environment binding declared: `src/types.ts:23`
- **No fetch() call exists** to OpenAI or any external API

**If Implemented, Would Require**:

```typescript
// ⚠️ EXAMPLE ONLY — NOT PRESENT IN CODEBASE
const response = await fetch("https://api.openai.com/v1/chat/completions", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ model: "gpt-4", messages }),
});
```

**TLS Requirements If Added**:

1. **Certificate Pinning**:
   - Pin OpenAI's public key or intermediate CA certificate
   - Validate `api.openai.com` certificate chain against pinned values
   - Reject connections on pin mismatch (fail-closed)

2. **Implementation Options**:
   - **Option A**: Use Cloudflare's Certificate Pinning API (when available)
   - **Option B**: Implement pinning via Workers' `fetch()` with custom certificate validation
   - **Option C**: Route through Cloudflare API Shield with certificate pinning rules

3. **Rotation Strategy**:
   - Monitor OpenAI's certificate rotation schedule
   - Implement dual-pinning (current + next certificate) during rotation windows
   - Alert on pin validation failures

**Current Decision**: ✅ **Deferred until external provider integration is implemented**

---

#### 4.2 Other External Providers

**Azure OpenAI, Anthropic, Cohere, etc.**:
- Same TLS pinning requirements as OpenAI
- Each provider would require:
  - Certificate pinning configuration
  - Rotation monitoring
  - Fail-closed validation

**Current Status**: Not implemented, not planned

---

## Audit: Outbound fetch() Calls

### Methodology
Searched entire `src/` directory for `fetch(` pattern:

```bash
grep -r "fetch(" src/
# Result: No matches
```

### Findings

**Zero outbound HTTP calls exist in the codebase.**

All external communication uses Cloudflare native bindings:
- ✅ Workers AI: `env.AI.run()`
- ✅ D1 Database: `env.AUDIT_DB.prepare()`
- ✅ KV Storage: `env.PROMPT_TEMPLATES.get()`
- ✅ Rate Limiters: `env.RATE_LIMITER.limit()`

**Conclusion**: No application-layer TLS pinning is required for current functionality.

---

## Cloudflare Firewall for AI Evaluation

### Product Overview

**Cloudflare Firewall for AI** (announced 2024) provides:
- Semantic analysis of AI input/output traffic
- Detection of prompt injection attacks
- Model-specific attack pattern recognition
- Integration with Cloudflare WAF

### Evaluation Criteria

| Criterion | Assessment | Notes |
|-----------|------------|-------|
| **Attack Coverage** | ✅ Beneficial | Adds ML-based injection detection beyond regex |
| **Defense-in-Depth** | ✅ Complements existing guardrails | Current: NFKC + regex + entropy. Firewall adds semantic analysis |
| **Performance Impact** | ⚠️ Unknown | Need benchmarking for Workers environment |
| **Cost** | ⚠️ Enterprise tier | Requires Cloudflare Enterprise plan |
| **Integration Effort** | ✅ Low | Configured via dashboard, no code changes |
| **False Positive Risk** | ⚠️ Medium | Semantic detection may block legitimate edge cases |

### Decision: **Adopt on Enterprise Plan**

**Rationale**:
1. **Current Guardrails**: Strong (5-layer input sanitization, fail-closed output validation)
2. **Firewall for AI Value**: Adds semantic understanding and zero-day protection
3. **Deployment Model**: Can be enabled without code changes
4. **Risk Mitigation**: Operate in "log-only" mode initially to tune false positive rate
5. **Cost Constraint**: Only available on Enterprise plan — adopt when plan is upgraded

**Recommendation**:
- ✅ **Enable in log-only mode** when Enterprise plan is active
- Monitor for 30 days to establish false positive baseline
- Gradually move to enforcement mode with manual review of blocks
- Maintain existing guardrails — treat Firewall for AI as defense-in-depth layer

**Implementation Path**:
1. Upgrade to Cloudflare Enterprise plan
2. Enable "Firewall for AI" in Cloudflare dashboard
3. Configure log-only mode for `/mcp/*` routes
4. Export logs to D1 audit trail for correlation with guardrail events
5. After 30-day observation period: enable enforcement mode

---

## Recommended Security Posture

### Current State (✅ Production-Ready)

| Layer | Security Control | Status |
|-------|------------------|--------|
| B0→B1 | Cloudflare Edge TLS termination | ✅ Active |
| B1 | JWT algorithm pinning (HS256 only) | ✅ Active |
| B1 | Identity-keyed rate limiting | ✅ Active |
| B2 | 5-layer input sanitization | ✅ Active |
| B2 | Structured prompt separation | ✅ Active |
| B2 | HITL gate (fail-closed timeout) | ✅ Active |
| B3 | HMAC-signed templates | ✅ Active |
| B3 | Immutable D1 audit trail | ✅ Active |
| B4 | Canary token extraction detection | ✅ Active |
| B4 | Zod schema validation (fail-closed) | ✅ Active |
| B4 | PII detection & redaction | ✅ Active |

### Future Enhancements

| Enhancement | Priority | Trigger Condition |
|-------------|----------|-------------------|
| **TLS Pinning for External LLMs** | 🔴 High | When fetch() to external providers is added |
| **Cloudflare Firewall for AI** | 🟡 Medium | When Enterprise plan is active |
| **STRIDE threat model per boundary** | 🟢 Low | Compliance requirement emerges |

---

## Compliance Notes

### NIST SP 800-52 Rev 2 (TLS Guidelines)

**Applicability**: Limited — Cloudflare handles TLS termination

**Compliance Status**:
- ✅ TLS 1.2+ enforced at edge (Cloudflare default)
- ✅ Strong cipher suites (Cloudflare-managed)
- ✅ Certificate validation (Cloudflare-managed)
- ⚠️ Certificate pinning: Not applicable for current architecture (no outbound calls)

### OWASP ASVS v4.0

**V9.2: Server Communications Security**:
- ✅ 9.2.1: TLS connections use strong cipher suites (Cloudflare)
- ✅ 9.2.2: Certificate validation enabled (Cloudflare)
- ⚠️ 9.2.3: Certificate pinning: Deferred (no external connections)
- ✅ 9.2.4: TLS settings prevent downgrade attacks (Cloudflare)

---

## Monitoring & Alerting

### TLS-Related Metrics to Track

1. **Cloudflare Edge**:
   - TLS handshake failures (monitor via Cloudflare Analytics)
   - Certificate expiration warnings (auto-renewed by Cloudflare)
   - Cipher suite negotiation failures

2. **Application Layer** (if external fetch() added):
   - Certificate pin validation failures → alert immediately
   - TLS connection timeouts to external providers
   - Certificate rotation events (requires custom monitoring)

3. **Audit Trail**:
   - Log all TLS-related errors to `guardrail_events` table
   - Include: timestamp, endpoint, failure reason, certificate fingerprint

### Alert Thresholds

- **Critical**: Certificate pin validation failure (potential MITM)
- **Warning**: TLS handshake errors >1% of requests
- **Info**: Certificate approaching expiration (Cloudflare auto-renews, but monitor)

---

## Appendix: Certificate Pinning Implementation Template

**For future use when external providers are added:**

```typescript
// ⚠️ NOT IMPLEMENTED — TEMPLATE ONLY

import { subtle } from "crypto";

// Store public key hashes (SHA-256) of pinned certificates
const PINNED_CERTIFICATES = {
  "api.openai.com": [
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Primary cert
    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Backup cert
  ],
};

async function fetchWithPinning(url: string, options: RequestInit) {
  // Step 1: Make the request
  const response = await fetch(url, options);

  // Step 2: Extract certificate from TLS handshake
  // NOTE: Workers Runtime does not currently expose certificate info
  // This would require Cloudflare to add a new API (Feature Request)

  // Step 3: Hash the public key
  const certHash = await hashPublicKey(certificate);

  // Step 4: Validate against pinned values
  const hostname = new URL(url).hostname;
  const pinnedHashes = PINNED_CERTIFICATES[hostname] || [];

  if (!pinnedHashes.includes(certHash)) {
    throw new Error(`Certificate pin validation failed for ${hostname}`);
  }

  return response;
}

async function hashPublicKey(certificate: ArrayBuffer): Promise<string> {
  const publicKey = extractPublicKey(certificate); // DER format
  const hashBuffer = await subtle.digest("SHA-256", publicKey);
  return `sha256/${btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))}`;
}
```

**Deployment Checklist** (when implementing):
- [ ] Obtain current certificate fingerprints for target domain
- [ ] Obtain backup certificate fingerprints (for rotation)
- [ ] Store pinned hashes in Workers Secrets (not hardcoded)
- [ ] Implement pin validation in fetch wrapper
- [ ] Add monitoring for pin validation failures
- [ ] Document certificate rotation procedure
- [ ] Test with expired/invalid certificates

---

## Document Metadata

**Version**: 1.0
**Date**: 2026-03-23
**Author**: Security Team
**Next Review**: 2026-09-23 (6 months)
**Related Documents**:
- `README.md` (Security Controls table)
- `wrangler.jsonc` (TLS-related configuration)
- `src/middleware/auth.ts` (JWT algorithm pinning)
