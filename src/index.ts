#!/usr/bin/env node
/**
 * AgentForge MCP Server
 * ---------------------
 * Single connection that gives any AI agent access to the entire AgentForge
 * marketplace: trust audit + discovery + multi-server search + tool execution
 * + agent self-registration.
 *
 * SANITIZATION LAYER (v0.3.0 — P0 hardening):
 *   - Input validation: schema enforcement on all tool args (prototype pollution,
 *     injection detection, size limits, type coercion guards)
 *   - Sandboxing: rate limiting, timeout enforcement, response size guards for
 *     call_tool proxy. Configurable via MCP_* env vars.
 *   - Anomaly detection: burst detection, repeated failure tracking, probing/
 *     injection pattern logging. Logs to stderr + optional file.
 *
 * Trust tools (read-only, no auth needed):
 *   - check_trust       — returns AgentForge Trust Score for a server
 *   - evaluate_policy   — allow/deny gate using a policy (min scores, badges)
 *   - list_trusted      — filtered list of servers matching a policy
 *   - recommend         — search servers by use case with trust filtering
 *
 * Action tools (some require AGENTFORGE_API_KEY):
 *   - discover          — browse the catalog with full-text/semantic search
 *   - broadcast_search  — search across multiple MCP servers in one call (auth)
 *   - call_tool         — invoke any tool on any server with billing+rate-limit (auth)
 *   - register_agent    — self-register and receive an af_agent_* API key
 *
 * Configuration via env:
 *   AGENTFORGE_API_URL   default: https://agentforge.community
 *   AGENTFORGE_API_KEY   required for broadcast_search and call_tool
 *   MCP_CALL_TIMEOUT_MS  call_tool timeout in ms (default: 30000)
 *   MCP_MAX_RESPONSE_BYTES  max response size (default: 5000000)
 *   MCP_RATE_LIMIT_PER_MIN  max calls/min/server (default: 60)
 *   MCP_SANITIZE_INPUT   sanitize tool input (default: true)
 *   MCP_SANITIZE_OUTPUT  sanitize tool output (default: true)
 *   MCP_ANOMALY_*        anomaly detector configuration
 *
 * Run:
 *   npx -y agentforge-trust-mcp
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  validateToolArgs,
  guardedCall,
  CallGuardError,
  recordCall,
  recordRateLimit,
  anomalyConfigFromEnv,
  guardConfigFromEnv,
  configureAnomalyDetector,
  type ValidationRule,
} from "./sanitizer/index.js";

const API_URL = process.env.AGENTFORGE_API_URL ?? "https://agentforge.community";
const API_KEY = process.env.AGENTFORGE_API_KEY;

// Initialize sanitization layer from env
configureAnomalyDetector(anomalyConfigFromEnv());
const guardConfig = guardConfigFromEnv();

// ——— HTTP helpers ————————————————————————————————————————————————

async function apiGet(path: string): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${API_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`AgentForge API ${res.status}: ${await res.text()}`);
  return res.json();
}

async function apiPost(path: string, body: unknown): Promise<unknown> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`AgentForge API ${res.status}: ${await res.text()}`);
  return res.json();
}

// ——— Tool argument schemas (sanitization layer) ─────────────────────────

const TOOL_SCHEMAS: Record<string, Record<string, ValidationRule>> = {
  check_trust: {
    server_id: { type: "string", maxLength: 64, description: "AgentForge server UUID" },
    slug: { type: "string", maxLength: 128, description: "AgentForge server slug" },
    github_url: { type: "string", maxLength: 512, description: "GitHub repo URL" },
  },
  evaluate_policy: {
    server_id: { type: "string", maxLength: 64 },
    slug: { type: "string", maxLength: 128 },
    github_url: { type: "string", maxLength: 512 },
    policy: {
      type: "object",
      required: true,
      additionalProperties: true,
      properties: {
        min_overall: { type: "number", minimum: 0, maximum: 100 },
        min_security: { type: "number", minimum: 0, maximum: 100 },
        min_code_health: { type: "number", minimum: 0, maximum: 100 },
        required_badges: { type: "array", maxItems: 50, items: { type: "string", maxLength: 64 } },
        forbidden_badges: { type: "array", maxItems: 50, items: { type: "string", maxLength: 64 } },
      },
    },
  },
  list_trusted: {
    category: { type: "string", maxLength: 64 },
    min_overall: { type: "number", minimum: 0, maximum: 100 },
    required_badges: { type: "array", maxItems: 50, items: { type: "string", maxLength: 64 } },
    limit: { type: "number", minimum: 1, maximum: 100 },
  },
  recommend: {
    query: { type: "string", required: true, minLength: 1, maxLength: 1000 },
    min_overall: { type: "number", minimum: 0, maximum: 100 },
    limit: { type: "number", minimum: 1, maximum: 50 },
  },
  discover: {
    q: { type: "string", maxLength: 1000 },
    category: { type: "string", maxLength: 64 },
    semantic: { type: "boolean" },
    featured: { type: "boolean" },
    limit: { type: "number", minimum: 1, maximum: 100 },
    offset: { type: "number", minimum: 0, maximum: 10000 },
    include_tools: { type: "boolean" },
  },
  broadcast_search: {
    query: { type: "string", required: true, minLength: 1, maxLength: 1000 },
    category: { type: "string", maxLength: 64 },
    max_servers: { type: "number", minimum: 1, maximum: 20 },
    max_results_per_server: { type: "number", minimum: 1, maximum: 10 },
    budget_max: { type: "number", minimum: 0 },
    preferred_pricing: { type: "string", enum: ["free", "freemium", "paid"] },
  },
  call_tool: {
    server: { type: "string", required: true, minLength: 1, maxLength: 128 },
    tool: { type: "string", required: true, minLength: 1, maxLength: 128 },
    input: { type: "object", additionalProperties: true },
  },
  register_agent: {
    name: { type: "string", required: true, minLength: 1, maxLength: 256 },
    description: { type: "string", maxLength: 2000 },
    homepage_url: { type: "string", maxLength: 512 },
    capabilities: { type: "array", maxItems: 50, items: { type: "string", maxLength: 128 } },
    metadata: { type: "object", additionalProperties: true },
  },
};

const TOOLS: Tool[] = [
  {
    name: "check_trust",
    description:
      "Fetch the AgentForge Trust Score for an MCP server. Returns the overall score (0-100), per-dimension breakdown (code_health, security_scan, behavioral_audit, community_trust, eu_compliance), and badges. Use before connecting to any MCP server.",
    inputSchema: {
      type: "object",
      properties: {
        server_id: { type: "string", description: "AgentForge server UUID (preferred)" },
        slug: { type: "string", description: "AgentForge server slug" },
        github_url: {
          type: "string",
          description: "Upstream GitHub repo URL, e.g. https://github.com/owner/repo",
        },
      },
    },
  },
  {
    name: "evaluate_policy",
    description:
      "Check whether a server passes a trust policy. Returns allowed:true/false plus individual check results. Example policy: {min_overall: 70, required_badges: ['actively_maintained']}. Use this to gate agent decisions like 'should I use this server for financial data?'.",
    inputSchema: {
      type: "object",
      properties: {
        server_id: { type: "string" },
        slug: { type: "string" },
        github_url: { type: "string" },
        policy: {
          type: "object",
          properties: {
            min_overall: { type: "number", description: "Minimum overall score 0-100" },
            min_security: { type: "number", description: "Minimum security_scan dimension" },
            min_code_health: { type: "number", description: "Minimum code_health dimension" },
            required_badges: {
              type: "array",
              items: { type: "string" },
              description: "Badges the server must carry",
            },
            forbidden_badges: {
              type: "array",
              items: { type: "string" },
              description: "Badges that disqualify the server",
            },
          },
        },
      },
      required: ["policy"],
    },
  },
  {
    name: "list_trusted",
    description:
      "Search AgentForge catalog for servers matching a category and minimum trust threshold. Returns up to 25 results sorted by trust score.",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description:
            "Category filter (e.g. finance, database, developer-tools, security). Omit for all.",
        },
        min_overall: { type: "number", default: 60 },
        required_badges: { type: "array", items: { type: "string" } },
        limit: { type: "number", default: 25 },
      },
    },
  },
  {
    name: "recommend",
    description:
      "Given a natural-language use case, recommend MCP servers filtered by trust. Example: 'I need to validate Czech VAT IDs and convert ISDOC invoices'. Uses AgentForge semantic search + trust filter.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Natural language description of the use case" },
        min_overall: { type: "number", default: 60 },
        limit: { type: "number", default: 10 },
      },
      required: ["query"],
    },
  },
  {
    name: "discover",
    description:
      "Browse the AgentForge catalog of MCP servers. Supports full-text search, semantic search, and category filtering. No authentication required. Use this when you need to find servers offering a specific capability (e.g. 'GitHub PR automation', 'EU VAT validation'). Returns server metadata, tool counts, pricing tier, and trust scores. Each result carries TWO trust fields: `audit_score` (0-100, dynamic from the AgentForge audit pipeline — AUTHORITATIVE for policy gating, may be null if not yet audited) and `trust_score` (0-10, legacy community rating — for display fallback only). Always prefer audit_score when present; treat null audit_score as 'audit pending'.",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string", description: "Search query (natural language or keywords)" },
        category: { type: "string", description: "Filter by category (e.g. finance, database, devtools, healthcare)" },
        semantic: { type: "boolean", description: "Use semantic (vector) search instead of full-text. Default false.", default: false },
        featured: { type: "boolean", description: "Only return featured servers" },
        limit: { type: "number", default: 20 },
        offset: { type: "number", default: 0 },
        include_tools: { type: "boolean", description: "Include each server's tool list in the response", default: false },
      },
    },
  },
  {
    name: "broadcast_search",
    description:
      "Search ACROSS multiple MCP servers in a single call. Returns relevant tools per server, sorted by relevance. Replaces N sequential discover+capabilities calls. Requires AGENTFORGE_API_KEY (set in env or call register_agent first). Use this when an agent needs to fan out a query like 'find me anything that can parse DICOM medical images' across the catalog.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Natural language search query" },
        category: { type: "string", description: "Optional category filter" },
        max_servers: { type: "number", description: "Max servers to search (1-20)", default: 5 },
        max_results_per_server: { type: "number", description: "Max tools per server (1-10)", default: 3 },
        budget_max: { type: "number", description: "Max monthly USD price filter" },
        preferred_pricing: { type: "string", enum: ["free", "freemium", "paid"], description: "Pricing tier preference" },
      },
      required: ["query"],
    },
  },
  {
    name: "call_tool",
    description:
      "Invoke any tool on any MCP server in the AgentForge catalog. AgentForge proxies the call, applies rate limits, billing (per-call or wallet credits), and returns the result. Requires AGENTFORGE_API_KEY. Use this to actually USE a server's capability after discovery, e.g. call_tool(server='github-pro', tool='create_pr', input={...}).",
    inputSchema: {
      type: "object",
      properties: {
        server: { type: "string", description: "Server UUID or slug (from discover/broadcast_search results)" },
        tool: { type: "string", description: "Tool name on that server" },
        input: { type: "object", description: "Tool input arguments (object), passed through to the upstream MCP server", additionalProperties: true },
      },
      required: ["server", "tool"],
    },
  },
  {
    name: "register_agent",
    description:
      "Self-register this agent with AgentForge. Returns an af_agent_* API key that unlocks broadcast_search and call_tool. Run once at agent startup, store the key in env as AGENTFORGE_API_KEY. No auth required for registration. Idempotent on slug — running twice produces a uniqued slug.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Human-readable agent name (e.g. 'OpenClaw Healthcare Coordinator')" },
        description: { type: "string", description: "Short description of what this agent does" },
        homepage_url: { type: "string", description: "Optional homepage / repo URL" },
        capabilities: { type: "array", items: { type: "string" }, description: "List of high-level capabilities (e.g. ['medical-imaging', 'patient-routing'])" },
        metadata: { type: "object", description: "Free-form metadata (framework, version, region…)", additionalProperties: true },
      },
      required: ["name"],
    },
  },
];

// ——— Tool handlers ————————————————————————————————————————————

type CheckTrustArgs = { server_id?: string; slug?: string; github_url?: string };

async function handleCheckTrust(args: CheckTrustArgs): Promise<string> {
  const params = new URLSearchParams();
  if (args.server_id) params.set("server_id", args.server_id);
  else if (args.slug) params.set("slug", args.slug);
  else if (args.github_url) params.set("github_url", args.github_url);
  else throw new Error("provide one of: server_id, slug, github_url");

  const result = await apiGet(`/api/v1/trust?${params}`);
  return JSON.stringify(result, null, 2);
}

type EvaluatePolicyArgs = CheckTrustArgs & {
  policy: Record<string, unknown>;
};

async function handleEvaluatePolicy(args: EvaluatePolicyArgs): Promise<string> {
  const result = await apiPost("/api/v1/trust/evaluate", args);
  return JSON.stringify(result, null, 2);
}

type ListTrustedArgs = {
  category?: string;
  min_overall?: number;
  required_badges?: string[];
  limit?: number;
};

async function handleListTrusted(args: ListTrustedArgs): Promise<string> {
  const params = new URLSearchParams();
  if (args.category) params.set("category", args.category);
  params.set("min_trust", String(args.min_overall ?? 60));
  params.set("limit", String(args.limit ?? 25));
  if (args.required_badges?.length)
    params.set("badges", args.required_badges.join(","));

  const result = await apiGet(`/api/v1/trust/list?${params}`);
  return JSON.stringify(result, null, 2);
}

type RecommendArgs = { query: string; min_overall?: number; limit?: number };

async function handleRecommend(args: RecommendArgs): Promise<string> {
  const params = new URLSearchParams({
    q: args.query,
    min_trust: String(args.min_overall ?? 60),
    limit: String(args.limit ?? 10),
  });
  const result = await apiGet(`/api/v1/search?${params}`);
  return JSON.stringify(result, null, 2);
}

// ——— Action tool handlers ——————————————————————————————————————

type DiscoverArgs = {
  q?: string;
  category?: string;
  semantic?: boolean;
  featured?: boolean;
  limit?: number;
  offset?: number;
  include_tools?: boolean;
};

async function handleDiscover(args: DiscoverArgs): Promise<string> {
  const params = new URLSearchParams();
  if (args.q) params.set("q", args.q);
  if (args.category) params.set("category", args.category);
  if (args.semantic) params.set("semantic", "true");
  if (args.featured) params.set("featured", "true");
  if (args.include_tools) params.set("include_tools", "true");
  params.set("limit", String(args.limit ?? 20));
  params.set("offset", String(args.offset ?? 0));

  const result = await apiGet(`/api/v1/discover?${params}`);
  return JSON.stringify(result, null, 2);
}

type BroadcastSearchArgs = {
  query: string;
  category?: string;
  max_servers?: number;
  max_results_per_server?: number;
  budget_max?: number;
  preferred_pricing?: "free" | "freemium" | "paid";
};

async function handleBroadcastSearch(args: BroadcastSearchArgs): Promise<string> {
  if (!API_KEY) {
    throw new Error(
      "AGENTFORGE_API_KEY required for broadcast_search. Run the register_agent tool first, then set AGENTFORGE_API_KEY in your MCP server env."
    );
  }
  const result = await apiPost("/api/v1/search/broadcast", args);
  return JSON.stringify(result, null, 2);
}

type CallToolArgs = {
  server: string;
  tool: string;
  input?: Record<string, unknown>;
};

async function handleCallTool(args: CallToolArgs): Promise<string> {
  if (!API_KEY) {
    throw new Error(
      "AGENTFORGE_API_KEY required for call_tool. Run the register_agent tool first, then set AGENTFORGE_API_KEY in your MCP server env."
    );
  }
  const result = await apiPost(`/api/v1/server/${encodeURIComponent(args.server)}/call`, {
    tool: args.tool,
    input: args.input ?? {},
  });
  return JSON.stringify(result, null, 2);
}

type RegisterAgentArgs = {
  name: string;
  description?: string;
  homepage_url?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
};

async function handleRegisterAgent(args: RegisterAgentArgs): Promise<string> {
  if (!args.name?.trim()) {
    throw new Error("'name' is required");
  }
  const result = await apiPost("/api/v1/agents", args);
  return JSON.stringify(result, null, 2);
}

// ——— MCP server wiring —————————————————————————————————————————

const server = new Server(
  { name: "agentforge-trust", version: "0.3.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const rawArgs = (args ?? {}) as Record<string, unknown>;

  // ——— Sanitization Layer — Input Validation ——————————————————————
  const schema = TOOL_SCHEMAS[name];
  let validation: ReturnType<typeof validateToolArgs> | undefined;
  if (schema) {
    validation = validateToolArgs(rawArgs, schema);
    if (!validation.valid) {
      const errorSummary = validation.errors
        .map((e) => `${e.path}: ${e.message} [${e.code}]`)
        .join("; ");
      console.error(`[sanitizer] INPUT_REJECTED tool=${name} errors=${errorSummary}`);
      recordCall(name, undefined, rawArgs, false, 0);
      return {
        isError: true,
        content: [{ type: "text", text: `Input validation failed: ${errorSummary}` }],
      };
    }
  } else {
    // Unknown tool — reject
    recordCall(name, undefined, rawArgs, false, 0);
    return {
      isError: true,
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
    };
  }

  // Use sanitized args from validation (already computed above)
  const safeArgs = (validation?.sanitized ?? rawArgs) as Record<string, unknown>;

  try {
    let text: string;
    const startTime = Date.now();

    switch (name) {
      case "check_trust":
        text = await handleCheckTrust(safeArgs as CheckTrustArgs);
        break;
      case "evaluate_policy":
        text = await handleEvaluatePolicy(safeArgs as EvaluatePolicyArgs);
        break;
      case "list_trusted":
        text = await handleListTrusted(safeArgs as ListTrustedArgs);
        break;
      case "recommend":
        text = await handleRecommend(safeArgs as RecommendArgs);
        break;
      case "discover":
        text = await handleDiscover(safeArgs as DiscoverArgs);
        break;
      case "broadcast_search":
        text = await handleBroadcastSearch(safeArgs as BroadcastSearchArgs);
        break;
      case "call_tool": {
        // ——— Sanitization Layer — Sandboxed Execution ——————————————
        const callArgs = safeArgs as CallToolArgs;
        const result = await guardedCall(
          callArgs.server,
          callArgs.tool,
          callArgs.input ?? {},
          () => apiPost(`/api/v1/server/${encodeURIComponent(callArgs.server)}/call`, {
            tool: callArgs.tool,
            input: callArgs.input ?? {},
          }),
          guardConfig
        );
        text = JSON.stringify(result.data, null, 2);
        if (result.warnings.length > 0) {
          console.error(`[sanitizer] call_tool warnings: ${result.warnings.join(", ")}`);
        }
        recordCall(name, callArgs.server, safeArgs, true, result.durationMs);
        break;
      }
      case "register_agent":
        text = await handleRegisterAgent(safeArgs as RegisterAgentArgs);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    recordCall(name, undefined, safeArgs, true, Date.now() - startTime);
    return { content: [{ type: "text", text }] };
  } catch (err) {
    const error = err as Error;
    // Log sandbox errors specially
    if (err instanceof CallGuardError) {
      recordRateLimit((err as CallGuardError).code, error.message);
      console.error(`[sanitizer] GUARD_BLOCK code=${(err as CallGuardError).code} msg=${error.message}`);
    } else {
      recordCall(name, undefined, safeArgs, false, 0);
    }
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${error.message}` }],
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr log so it doesn't interfere with stdio MCP frame
  console.error(`[agentforge-trust-mcp] listening on stdio — API: ${API_URL}`);
}

main().catch((err) => {
  console.error("[agentforge-trust-mcp] fatal:", err);
  process.exit(1);
});
