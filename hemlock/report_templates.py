"""Report templates and remediation hints for HemReport.

Two templates:
- executive: plain-English risk summary, channels at risk, top actions. No code.
- technical: full per-channel results with remediation code snippets.

Usage:
    from hemlock.report_templates import render
    md = render(report, template="executive")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hemlock.hem_session import HemReport


# ---------------------------------------------------------------------------
# Remediation hints per channel
# ---------------------------------------------------------------------------

_HINTS: dict[str, list[str]] = {
    "rag": [
        "Add `OutputDefense` guardrails to the retrieval output chain before the LLM call.",
        "Use `InjectionSuccessGuard` to detect override patterns in retrieved content.",
        "Implement semantic similarity filtering: reject chunks whose embedding diverges "
        "significantly from the query intent.",
        "Log every retrieval result; alert on high cosine distance from expected topics.",
    ],
    "cross_agent": [
        "Deploy `CrossAgentBoundaryGuard` on every agent-to-agent message boundary.",
        "Sign messages between agents with a shared HMAC key; verify before processing.",
        "Apply a strict allowlist of valid relay domains — block anything outside it.",
        "Quarantine agent messages that contain override directives ('ignore previous', 'new instruction').",
    ],
    "memory": [
        "Wrap every `memory.add()` call with `MemoryBoundaryGuard.safe_add()` — it blocks "
        "relay patterns and override directives at write time.",
        "Enable write-time audit logging: record who (agent/user) triggered each memory write.",
        "Require explicit human-in-the-loop confirmation before writing cross-session memory entries.",
        "Purge and rebuild memory stores on any detected poisoning event.",
    ],
    "tool_output": [
        "Sanitize tool outputs with `ToolOutputGuard` before forwarding to the LLM.",
        "Validate tool output schemas — reject responses that include text outside the expected structure.",
        "Apply rate-limiting on tool calls that include relay or forwarding payloads.",
        "Monitor tool output volumes; alert if a single call returns more than expected content.",
    ],
    "graph": [
        "Use `GraphBoundaryGuard` on every N-hop traversal output.",
        "Audit which tools propagate their output downstream — restrict to a minimal allowlist.",
        "Cap the graph traversal depth; reject any propagation chain longer than N hops.",
        "Log propagation paths end-to-end; alert on cycles or unexpected nodes.",
    ],
    "mcp": [
        "Review MCP tool descriptions for injected instructions; treat them as untrusted inputs.",
        "Deploy `McpScanner` in CI — fail the pipeline on new HIGH vulnerabilities.",
        "Add server-side argument validation: reject tool args that match known injection patterns.",
        "Use `--adversarial` mode during red-team exercises to surface LLM-assisted bypass attempts.",
    ],
}

_DEFAULT_HINT = [
    "Review the attack evidence in the Technical Report for channel-specific guidance.",
    "Apply OutputDefense guardrails at channel boundaries.",
]


def remediation_hints(report: "HemReport") -> dict[str, list[str]]:
    """Return a dict of remediation hints per at-risk channel.

    Only channels with severity 'high' or 'critical' are included.
    """
    at_risk = report.channels_at_risk()
    return {ch: _HINTS.get(ch, _DEFAULT_HINT) for ch in at_risk}


# ---------------------------------------------------------------------------
# Executive template
# ---------------------------------------------------------------------------

def _risk_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _render_executive(report: "HemReport") -> str:
    score   = report.risk_score()
    label   = _risk_label(score)
    at_risk = report.channels_at_risk()
    hints   = remediation_hints(report)

    lines = [
        "# Security Assessment — Executive Summary",
        "",
        f"**Target**: {report.target}  ",
        f"**Overall Risk**: {label} ({score} / 100)  ",
        f"**Channels Assessed**: {len(report.results)}  ",
        f"**Channels at Risk**: {len(at_risk)}  ",
        "",
    ]

    if not at_risk:
        lines += [
            "## Finding",
            "",
            "No high or critical severity vulnerabilities were identified across any "
            "tested channel. The system demonstrates baseline resilience against the "
            "assessed attack classes.",
            "",
            "**Recommendation**: Continue regular assessments as models and pipelines "
            "evolve. Maintain existing defense controls.",
        ]
        return "\n".join(lines)

    lines += [
        "## Key Findings",
        "",
        "The following attack channels returned exploitable vulnerabilities:",
        "",
    ]
    summary = report.channel_summary()
    for ch in at_risk:
        sev = summary.get(ch, "—")
        lines.append(f"- **{ch.replace('_', ' ').title()}** — severity: {sev.upper()}")
    lines.append("")

    lines += ["## Top Remediation Actions", ""]
    for ch, tips in hints.items():
        lines.append(f"**{ch.replace('_', ' ').title()}**")
        lines.append(f"→ {tips[0]}")
        lines.append("")

    lines += [
        "## Next Steps",
        "",
        "1. Review the Technical Report for per-attack-variant evidence.",
        "2. Prioritize CRITICAL channels before HIGH.",
        "3. Implement remediation controls and re-run `hemlock threat-model`.",
        "4. Integrate `hemlock scan-mcp` into the CI pipeline with `--fail-on high`.",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Technical template
# ---------------------------------------------------------------------------

_SNIPPET: dict[str, str] = {
    "rag": """\
```python
from defenses import InjectionSuccessGuard, OutputDefenseChain

defense = OutputDefenseChain([InjectionSuccessGuard()])
result  = pipeline.query(user_query, defenses=[defense])
```""",
    "cross_agent": """\
```python
from defenses import CrossAgentBoundaryGuard

guard  = CrossAgentBoundaryGuard()
report = guard.validate(agent_message)
if report.triggered:
    raise SecurityError(report.detail)
```""",
    "memory": """\
```python
from defenses import MemoryBoundaryGuard
from hemlock.memory_agent_pipeline import MemoryEntry

guard   = MemoryBoundaryGuard()
ok      = guard.safe_add(memory_store, entry)
if not ok:
    logger.warning("Memory write blocked: %s", guard.blocked_writes()[-1].detail)
```""",
    "tool_output": """\
```python
from defenses import ToolOutputGuard

guard  = ToolOutputGuard()
report = guard.validate(tool_response)
if report.triggered:
    tool_response = "[sanitized]"
```""",
    "graph": """\
```python
from hemlock.graph_propagation_scorer import GraphPropagationScorer

scorer = GraphPropagationScorer.from_tools(tools, propagating_tools)
report = scorer.run()
if report.propagation_rate() > 0.1:
    raise SecurityError(f"Graph propagation risk: {report.propagation_rate():.0%}")
```""",
    "mcp": """\
```bash
hemlock scan-mcp --target stdio://my-mcp-server --fail-on high --adversarial
```""",
}


def _render_technical(report: "HemReport") -> str:
    score   = report.risk_score()
    label   = _risk_label(score)
    at_risk = report.channels_at_risk()
    hints   = remediation_hints(report)
    summary = report.channel_summary()

    lines = [
        "# Security Assessment — Technical Report",
        "",
        f"**Target**: {report.target}  ",
        f"**Risk Score**: {score} / 100 ({label})  ",
        f"**Succeeded Attacks**: {len(report.succeeded_attacks())}  ",
        f"**Channels at Risk**: {', '.join(at_risk) or 'none'}  ",
        "",
        "## Channel Summary",
        "",
        "| Channel | Worst Severity | Succeeded Variants |",
        "|---------|---------------|-------------------|",
    ]
    for channel in sorted(summary):
        sev     = summary[channel]
        attacks = [r.variant for r in report.results if r.channel == channel and r.succeeded]
        lines.append(f"| {channel} | {sev} | {', '.join(attacks) or '—'} |")

    lines += ["", "## Per-Channel Results", ""]
    for channel in sorted(summary):
        channel_results = [r for r in report.results if r.channel == channel]
        sev = summary.get(channel, "none")
        lines += [
            f"### {channel.replace('_', ' ').title()} — {sev.upper()}",
            "",
            "| Variant | Succeeded | Severity | Detail |",
            "|---------|-----------|----------|--------|",
        ]
        for r in channel_results:
            succ = "✓" if r.succeeded else ("✗" if r.succeeded is False else "—")
            lines.append(f"| {r.variant} | {succ} | {r.severity} | {r.detail[:100]} |")
        lines.append("")

    if hints:
        lines += ["## Remediation", ""]
        for ch, tips in hints.items():
            lines += [f"### {ch.replace('_', ' ').title()}", ""]
            for tip in tips:
                lines.append(f"- {tip}")
            snippet = _SNIPPET.get(ch)
            if snippet:
                lines += ["", "**Quick fix**:", "", snippet]
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def render(report: "HemReport", template: str = "technical") -> str:
    """Render a HemReport using the named template.

    Args:
        report:   The ``HemReport`` to render.
        template: ``"executive"`` or ``"technical"`` (default).

    Returns:
        Markdown string.

    Raises:
        ValueError: Unknown template name.
    """
    if template == "executive":
        return _render_executive(report)
    if template == "technical":
        return _render_technical(report)
    raise ValueError(f"Unknown template {template!r}. Choose 'executive' or 'technical'.")
