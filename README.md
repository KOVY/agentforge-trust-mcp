# agentforge-trust-mcp

**MCP server that lets AI agents audit MCP servers before using them.**

AgentForge maintains a Trust Score (0–100) for every MCP server in its catalog,
computed across five dimensions: code health, security scan, behavioral audit,
community trust, and EU compliance. This MCP server exposes those audits as
tools any agent can call.

## Installation

```bash
npx -y agentforge-trust-mcp
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "agentforge-trust": {
      "command": "npx",
      "args": ["-y", "agentforge-trust-mcp"]
    }
  }
}
```

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `AGENTFORGE_API_URL` | `https://agentforge.community` | Override for self-hosted |
| `AGENTFORGE_API_KEY` | none | Enterprise tier (private catalogs, custom policies) |

## Tools

### `check_trust`
Returns the AgentForge Trust Score for a server identified by `server_id`,
`slug`, or `github_url`. Always call this before connecting to a new server.

### `evaluate_policy`
Allow/deny gate. Pass a policy like `{min_overall: 70, required_badges: ["actively_maintained"]}`
and get back `allowed: true|false` with per-check detail.

### `list_trusted`
Search the AgentForge catalog for servers matching a category and trust
threshold. Useful for "find me a secure database MCP server with overall ≥ 80".

### `recommend`
Natural-language search with trust filter. "I need to validate Czech VAT IDs"
returns ranked results filtered by minimum trust.

## Use case

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
