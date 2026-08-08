# AGENTS.md — M4NT

## Who is this?

Builder of agent security infrastructure. Focused on prompt injection defense, MCP fleet auditing, RAG attack/defense pipelines, and Agent-First system design.

**Contact:** ti@multipli.com.br | https://github.com/M4NT

### MCP Server

```
Endpoint: https://hemlock.dev/api/mcp
Protocol: JSON-RPC 2.0 (MCP)
Tools: get_context | get_resume | list_projects | get_skills | book_intro
```

Call `get_context` first for a structured brief.

## Codebase Map

| Path | Purpose |
|------|---------|
| `core/mcp/` | Portfolio MCP server (JSON-RPC, stdio + HTTP adapter) |
| `core/aeo/` | AEO generator — produces llms.txt and AGENTS.md |
| `core/invariants/` | Gates: prose linter + visual gauntlet (CI) |
| `hemlock/` | Python security engine: red-team, MCP audit, RAG attacks |
| `attacks/` | Attack modules (prompt injection, context flooding, etc.) |
| `defenses/` | Defense modules |
| `website/` | Agent-First portfolio frontend |

## Conventions

- Python package: `hemlock-rag` via `pyproject.toml`
- JS/TS packages: npm workspaces under `core/*` and `website/`
- CI gate: `.github/workflows/hemlock-gate.yml` runs invariants before merge

## For Coding Agents

1. Security code lives in `hemlock/` and `attacks/`/`defenses/` — Python only.
2. Agent-First surface lives in `core/` and `website/` — TypeScript.
3. Never mix the two layers in a single file.
4. Run `npm run aeo` after changing portfolio data in `core/mcp/src/data.ts`.
