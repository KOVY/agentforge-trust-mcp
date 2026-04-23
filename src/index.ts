#!/usr/bin/env node
/**
 * AgentForge Trust MCP Server
 * ---------------------------
 * Exposes trust-score audit capabilities as MCP tools, so AI agents can
 * check the trustworthiness of any MCP server in the AgentForge catalog
 * before connecting to it.
 *
 * Tools:
 *   - check_trust       — returns AgentForge Trust Score for a server
 *   - evaluate_policy   — allow/deny gate using a policy (min scores, badges)
 *   - list_trusted      — filtered list of servers matching a policy
 *   - recommend         — search servers by use case with trust filtering
 *
 * Configuration via env:
 *   AGENTFORGE_API_URL   default: https://agentforge.community
 *   AGENTFORGE_API_KEY   optional, enables enterprise-tier policies
 *
 * Run:
 *   npx -y @agentforge/trust-mcp
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

const API_URL = process.env.AGENTFORGE_API_URL ?? "https://agentforge.community";
const API_KEY = process.env.AGENTFORGE_API_KEY;

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

// ——— Tool definitions ——————————————————————————————————————————

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

// ——— MCP server wiring —————————————————————————————————————————

const server = new Server(
  { name: "agentforge-trust", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let text: string;
    switch (name) {
      case "check_trust":
        text = await handleCheckTrust((args ?? {}) as CheckTrustArgs);
        break;
      case "evaluate_policy":
        text = await handleEvaluatePolicy((args ?? {}) as EvaluatePolicyArgs);
        break;
      case "list_trusted":
        text = await handleListTrusted((args ?? {}) as ListTrustedArgs);
        break;
      case "recommend":
        text = await handleRecommend((args ?? {}) as RecommendArgs);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
    return { content: [{ type: "text", text }] };
  } catch (err) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${(err as Error).message}` }],
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
