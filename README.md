# agentforge-trust-mcp

[![npm version](https://img.shields.io/npm/v/agentforge-trust-mcp.svg)](https://www.npmjs.com/package/agentforge-trust-mcp)
[![npm downloads](https://img.shields.io/npm/dm/agentforge-trust-mcp.svg)](https://www.npmjs.com/package/agentforge-trust-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-server-purple.svg)](https://modelcontextprotocol.io)

**One MCP connection → 100+ MCP servers, with trust audit, discovery, and execution.**

AgentForge gives any agent a single connection that exposes the entire
catalog of MCP servers — trust-scored, searchable, and executable. Trust
Scores (0–100) are computed across five dimensions: code health, security
scan, behavioral audit, community trust, and EU compliance.

`v0.3.0` ships **8 tools** (4 trust + 4 action) plus a **P0 RCE sanitization
layer** (input validation, call guards, anomaly detection) with **27/27
tests passing** and **zero external runtime dependencies**.

> 📖 **Full integration guide for external multi-agent systems:**
> See [agentforge.community/trust](https://agentforge.community/trust) for the full integration guide
> — OpenClaw, Claude Desktop, Cursor, LangGraph, AutoGen, CrewAI in ~3 minutes.

## Installation

```bash
npx -y agentforge-trust-mcp@latest
```

### Claude Desktop / Cursor / OpenClaw config

```json
{
  "mcpServers": {
    "agentforge": {
      "command": "npx",
      "args": ["-y", "agentforge-trust-mcp@latest"],
      "env": {
        "AGENTFORGE_API_URL": "https://agentforge.community",
        "AGENTFORGE_API_KEY": "af_agent_REPLACE_AFTER_REGISTRATION"
      }
    }
  }
}
```

> Trust tools (`check_trust`, `evaluate_policy`, `list_trusted`, `recommend`)
> work without an API key. Action tools (`broadcast_search`, `call_tool`)
> require self-registration via `register_agent` (one tool call, no signup).

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `AGENTFORGE_API_URL` | `https://agentforge.community` | Override for self-hosted |
| `AGENTFORGE_API_KEY` | none | Enterprise tier (private catalogs, custom policies) |

## Tools

### Trust tools (no auth required)

#### `check_trust`
Returns the AgentForge Trust Score for a server identified by `server_id`,
`slug`, or `github_url`. Always call this before connecting to a new server.

#### `evaluate_policy`
Allow/deny gate. Pass a policy like `{min_overall: 70, required_badges: ["actively_maintained"]}`
and get back `allowed: true|false` with per-check detail.

#### `list_trusted`
Search the AgentForge catalog for servers matching a category and trust
threshold. Useful for "find me a secure database MCP server with overall ≥ 80".

#### `recommend`
Natural-language search with trust filter. "I need to validate Czech VAT IDs"
returns ranked results filtered by minimum trust.

### Action tools (new in v0.2.0)

#### `discover`
Browse the entire catalog with full-text or semantic search. Returns ranked
results with trust scores, categories, and connection metadata. No API key
required — read-only catalog access.

#### `broadcast_search` *(API key)*
Run a single query across N servers in one call. AgentForge fans out the
search, aggregates results, and returns a unified ranked list. Pay-per-call
billing through your wallet.

#### `call_tool` *(API key)*
Invoke any tool on any server in the catalog through AgentForge's proxy.
One connection, hundreds of downstream servers — the proxy handles auth,
quotas, and trust gating.

#### `register_agent`
Self-register your agent and receive an `af_agent_*` API key. No human
signup, no dashboard — first tool call returns the key. Pass `name`,
`description`, `capabilities`, optional `homepage_url` and `metadata`.

## Use cases

### Trust audit before connecting

```
Agent: user wants me to use "some-financial-mcp" server.
Agent: let me check its trust first…
  → check_trust(slug="some-financial-mcp")
  ← overall_score: 42, badges: [], security_scan: pending
Agent: trust is too low, skipping. Let me find alternatives.
  → recommend(query="invoice conversion Czech VAT", min_overall=75)
  ← 3 results with scores 87, 84, 79
Agent: connecting to the 87-scored server instead.
```

### One connection, 100+ servers (v0.2.0)

```
Agent: I need flight + weather + currency data for a trip planner.
Agent: register once if I haven't already…
  → register_agent(name="TripPlanner", capabilities=["travel"])
  ← af_agent_xyz123
Agent: broadcast across travel-tagged servers.
  → broadcast_search(query="flights Prague→Tokyo May 15", category="travel")
  ← results from 4 servers, all trust ≥ 75
Agent: invoke top result through the proxy.
  → call_tool(server="skyscanner-mcp", tool="search_flights", args={...})
  ← booking results
```

No need to install or configure individual MCP servers — one connection
to AgentForge, and your agent can reach the whole catalog.

## Trust dimensions

| Dimension | Weight | Source |
|---|---|---|
| Security Scan | 30% | Snyk, GitHub Advisory, secret scanning |
| Code Health | 20% | Commit recency, issue ratio, license |
| Behavioral Audit | 20% | Claude-powered source review, red flag detection |
| Community Trust | 15% | Stars, forks, author reputation |
| EU Compliance | 15% | GDPR, AI Act, data residency |

Audits rotate every 14 days; `evaluate_policy` reports `partial: true` if not
all dimensions are current.

## License

MIT — AgentForge 2026
