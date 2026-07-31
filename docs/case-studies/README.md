# Official MCP case study procedure (v9.2)

This folder documents how to run a **reproducible, publishable** MCP security audit
with Hemlock — suitable for internal security reviews or public case studies
(no secrets in committed configs).

## Prerequisites

```bash
pip install -e ".[mcp,dev]"
pip install pyyaml   # if using YAML fleet config
```

Set authentication for internal MCPs (never commit tokens):

```bash
# Windows PowerShell
$env:MCP_AUTH_TOKEN = "<from server MCP_AUTH_TOKEN or vault>"
```

## 1. Define the fleet

Copy `examples/mcp-fleet-multipli.yaml` to a local file (e.g. `mcp-fleet.local.yaml`)
and adjust URLs. Mark OAuth-only targets with `expect_auth_failure: true`.

## 2. Run the official audit

```bash
hemlock mcp-audit --config mcp-fleet.local.yaml --out-dir .hemlock/mcp_audit
hemlock mcp-audit -c mcp-fleet.local.yaml --with-judge   # optional HemJudge pass (v9.3)
```

Outputs:

| File | Purpose |
|------|---------|
| `mcp_fleet_audit.json` | Machine-readable full report |
| `mcp_fleet_case_study.md` | Executive / case-study markdown |
| `mcp_fleet_audit.sarif` | SARIF 2.1.0 for GitHub Advanced Security (v9.3) |
| `<target>.json` | Per-MCP scan detail |

Exit codes:

- `0` — no confirmed findings (or `--no-fail`)
- `1` — scan errors (non-auth)
- `2` — confirmed findings (`--fail-on-confirmed`, default)

## 3. CI integration

```yaml
- name: Hemlock MCP fleet audit
  env:
    MCP_AUTH_TOKEN: ${{ secrets.MCP_AUTH_TOKEN }}
  run: |
    hemlock mcp-audit -c mcp-fleet.local.yaml -o .hemlock/mcp_audit --quiet
```

## 4. Triage model

| Triage | Meaning |
|--------|---------|
| `confirmed` | High-risk category or chained tool calls — review first |
| `suspected` | Default fuzzer hit — manual validation |
| `likely_false_positive` | Admin/destructive tools or echo-only responses |

## Roadmap to full official case study

- [x] Fleet scan + consolidated report (v9.2)
- [x] Finding triage heuristics
- [x] SARIF export for MCP fleet (v9.3)
- [x] Optional `hem judge` pass on confirmed findings (v9.3)
- [ ] OAuth user-delegated token flow for imap/nextcloud MCPs
- [ ] Published release tag + versioned case study on GitHub
