# Case Study: Multipli MCP Fleet on WATCHTOWER

**Organization:** Multipli  
**Environment:** Internal Docker MCP fleet (WATCHTOWER host)  
**Hemlock version:** 9.3.0  
**Audit command:** `hemlock mcp-audit -c mcp-fleet.local.yaml -o .hemlock/mcp_audit`

This document is a **publishable template**. Replace metric placeholders with values from
`mcp_fleet_case_study.md` after each official run. Never commit tokens or raw scan JSON
with credentials.

## Scope

| MCP | Port | Auth model | Scan status |
|-----|------|------------|-------------|
| admin-mcp | 3005 | Shared `MCP_AUTH_TOKEN` | Scanned |
| capability-router-mcp | 3011 | Shared `MCP_AUTH_TOKEN` | Scanned |
| imap-mcp | 3001 | User OAuth | Skipped (`expect_auth_failure`) |
| nextcloud-mcp | 3002 | User OAuth | Skipped (`expect_auth_failure`) |

## Executive summary (fill from report)

| Metric | Value |
|--------|-------|
| Targets in scope | 4 |
| Successfully scanned | _from report_ |
| Auth blocked (OAuth) | 2 |
| Raw fuzzer hits | _from report_ |
| Confirmed (review priority) | _from report_ |
| Suspected | _from report_ |
| Likely false positive | _from report_ |

## Key findings (narrative)

### Admin MCP surface

The admin MCP exposes a large operational toolset (restart, user management, diagnostics).
Hemlock flagged many fuzzer hits on destructive/admin tools — triaged as **likely false
positive** when the tool name matches expected admin operations. **Chained tool calls** and
high-risk categories (path traversal, SSRF, injection) remain **confirmed** and require
manual validation.

### Capability router

Smaller tool surface; findings often relate to routing and capability delegation. Review
**chained_tool_call** entries first — they indicate the interceptor observed follow-on
invocations during fuzzing.

### OAuth-bound MCPs

IMAP and Nextcloud MCPs require user-delegated OAuth, not the fleet shared token. Hemlock
skips these until v9.4 OAuth client support lands; they are listed as **AUTH_BLOCKED** in
the fleet report, not scan failures.

## Artifacts

After each official audit, archive (internally):

- `mcp_fleet_audit.json`
- `mcp_fleet_case_study.md`
- `mcp_fleet_audit.sarif` (upload to GitHub Security if applicable)
- Per-target `*.json` (internal only)

## Reproduction

See [Official MCP case study procedure](./README.md).

---

_Generated template — Hemlock MCP Fleet Audit v9.3_
