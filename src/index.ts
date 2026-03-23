// src/index.ts — Main entry point for promptcrafting-mcp
// Cloudflare Worker with Hono router serving as the B1 edge perimeter.
//
// Request flow:
//   Client → Hono Router → Rate Limiter → JWT Auth → RBAC → MCP Durable Object
//
// Boundaries crossed: B0 → B1 → B2

import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { routeAgentRequest } from "agents";
import type { Env } from "./types.js";
import { authMiddleware, rateLimitMiddleware, requirePermission } from "./middleware/auth.js";
import {
  resolveHITLApproval, getHITLApprovalStatus, listPendingHITLApprovals,
} from "./services/hitl.js";

// Re-export the Durable Object class (required by Workers runtime)
export { PromptMCPServer } from "./mcp-agent.js";

// ─── Hono App ──────────────────────────────────────────────────────
const app = new Hono<{ Bindings: Env }>();

// ─── Global Middleware (B1 perimeter) ──────────────────────────────
app.use("*", cors({
  origin: ["https://promptcrafting.net", "https://www.promptcrafting.net"],
  allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowHeaders: ["Authorization", "Content-Type"],
  maxAge: 86400,
}));

app.use("*", secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    connectSrc: ["'self'"],
  },
  // Prevent framing (clickjacking)
  xFrameOptions: "DENY",
}));

// ─── Health Check (unauthenticated) ────────────────────────────────
app.get("/health", (c) =>
  c.json({ status: "ok", service: "promptcrafting-mcp", timestamp: new Date().toISOString() })
);

// ─── MCP Protocol Endpoint ─────────────────────────────────────────
// The Agents SDK handles MCP transport (Streamable HTTP + WebSocket hibernation).
// Auth + rate limiting applied before routing to the Durable Object.
app.all("/mcp/*", rateLimitMiddleware("BURST_LIMITER"), authMiddleware(), async (c) => {
  // routeAgentRequest routes to /agents/:agentName/:instanceName
  // For MCP, the McpAgent.serve() static method handles /mcp path
  const response = await routeAgentRequest(c.req.raw, c.env);
  if (response) return response;
  return c.json({ error: "MCP endpoint not found" }, 404);
});

// ─── REST API (for non-MCP clients) ───────────────────────────────
// These endpoints provide direct HTTP access to template management
// for admin UIs, CI/CD pipelines, and monitoring dashboards.

const api = new Hono<{ Bindings: Env }>();

// All API routes require auth + rate limiting
api.use("*", rateLimitMiddleware("RATE_LIMITER"));
api.use("*", authMiddleware());

// Template CRUD via REST
api.get("/templates", requirePermission("template:read"), async (c) => {
  const list = await c.env.PROMPT_TEMPLATES.list({ prefix: "template:", limit: 100 });
  const templates = list.keys
    .filter((k) => !k.name.includes(":v"))
    .map((k) => ({
      id: k.name.replace("template:", ""),
      name: (k.metadata as Record<string, unknown>)?.name ?? "unknown",
      version: (k.metadata as Record<string, unknown>)?.version ?? 1,
    }));
  return c.json({ templates, count: templates.length });
});

api.get("/templates/:id", requirePermission("template:read"), async (c) => {
  const id = c.req.param("id");
  const raw = await c.env.PROMPT_TEMPLATES.get(`template:${id}`, "json");
  if (!raw) return c.json({ error: "Template not found" }, 404);
  return c.json(raw);
});

api.delete("/templates/:id", requirePermission("template:delete"), async (c) => {
  const id = c.req.param("id");
  await c.env.PROMPT_TEMPLATES.delete(`template:${id}`);
  return c.json({ deleted: true, id, note: "Versioned copies retained for audit" });
});

// Audit logs
api.get("/audit", requirePermission("audit:read"), async (c) => {
  const params = {
    userId: c.req.query("userId"),
    templateId: c.req.query("templateId"),
    status: c.req.query("status") as "success" | "error" | "rate_limited" | "filtered" | undefined,
    since: c.req.query("since"),
    limit: parseInt(c.req.query("limit") ?? "50"),
    offset: parseInt(c.req.query("offset") ?? "0"),
  };

  // Inline query (avoids importing full audit service for simple reads)
  const conditions: string[] = ["1=1"];
  const binds: (string | number)[] = [];

  if (params.userId) { conditions.push("user_id = ?"); binds.push(params.userId); }
  if (params.templateId) { conditions.push("template_id = ?"); binds.push(params.templateId); }
  if (params.status) { conditions.push("status = ?"); binds.push(params.status); }
  if (params.since) { conditions.push("created_at >= ?"); binds.push(params.since); }

  const where = conditions.join(" AND ");
  const result = await c.env.AUDIT_DB
    .prepare(`SELECT * FROM prompt_audit_logs WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .bind(...binds, Math.min(params.limit, 200), params.offset)
    .all();

  return c.json({ logs: result.results ?? [], count: result.results?.length ?? 0 });
});

// ─── HITL Management REST Endpoints ───────────────────────────────
// Allows admin dashboards and CI/CD pipelines to manage HITL approvals
// without requiring an MCP client. Only admins and operators may resolve.

api.get("/hitl", requirePermission("hitl:resolve"), async (c) => {
  const limit = Math.min(parseInt(c.req.query("limit") ?? "50"), 100);
  const pending = await listPendingHITLApprovals(c.env.AUDIT_DB, limit);
  return c.json({ pending, count: pending.length });
});

api.get("/hitl/:requestId", requirePermission("hitl:resolve"), async (c) => {
  const requestId = c.req.param("requestId");
  const status = await getHITLApprovalStatus(c.env.AUDIT_DB, requestId);
  if (!status) return c.json({ error: "HITL request not found" }, 404);
  return c.json(status);
});

api.post("/hitl/:requestId/resolve", requirePermission("hitl:resolve"), async (c) => {
  const requestId = c.req.param("requestId");
  const userId = c.get("userId") as string;

  let body: { resolution?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (body.resolution !== "approved" && body.resolution !== "rejected") {
    return c.json({ error: "resolution must be 'approved' or 'rejected'" }, 400);
  }

  const result = await resolveHITLApproval(
    c.env.AUDIT_DB,
    requestId,
    body.resolution,
    userId
  );

  if (!result.ok) {
    return c.json({ error: result.error }, 409);
  }

  return c.json({
    requestId,
    resolution: body.resolution,
    resolvedBy: userId,
    resolvedAt: new Date().toISOString(),
  });
});

// Mount API routes
app.route("/api/v1", api);

// ─── Catch-all ─────────────────────────────────────────────────────
app.notFound((c) =>
  c.json({
    error: "Not found",
    endpoints: ["/health", "/mcp/*", "/api/v1/templates", "/api/v1/audit"],
  }, 404)
);

app.onError((err, c) => {
  console.error(`[ERROR] ${c.req.method} ${c.req.url}:`, err);
  return c.json(
    { error: "Internal server error", requestId: crypto.randomUUID() },
    500
  );
});

// ─── Export ────────────────────────────────────────────────────────
export default app;
