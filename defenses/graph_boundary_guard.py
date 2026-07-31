"""Graph Boundary Guard — per-edge sanitization across N-hop agent graphs.

Applies zero-trust at every edge in an AgentGraph, not just the first A→B
handoff. When a node's output is about to be passed to its successors, the
guard inspects it and — if triggered — replaces it with REDACTED_PLACEHOLDER
before any downstream node receives it. This breaks the propagation chain at
the first poisoned hop instead of letting the signal travel all the way to
the sink.

Two strategies (composable):

  domain_blocklist    Block output containing known attacker domains.
                      Catches tool_call_injection and context_flooding
                      when the attacker target is visible in the output.

  relay_pattern_scan  Scan for executor-facing relay directives
                      ("call TOOLNAME with ...", webhook fields, etc.).
                      Catches context_flooding even with unknown domains.

Reference:
    N-hop multi-agent threat model discussed in:
    Debenedetti et al. (2024) — "AgentDojo" — arxiv:2406.13352
"""

from __future__ import annotations

import re

from defenses.base import DefenseReport, OutputDefense

_DEFAULT_BLOCKED_DOMAINS = [
    "attacker-ops.io",
    "attacker-analytics.io",
    "attacker-harvest.net",
    "attacker-controlled.com",
    "attacker-fulfillment.io",
    "evil.com",
]

_RELAY_PATTERNS = [
    (re.compile(r"call\s+\w+\s+with\s+\w+=",           re.I), "tool call relay directive"),
    (re.compile(r'"webhook_url"\s*:',                    re.I), "webhook URL field"),
    (re.compile(r'"admin_override"\s*:\s*true',          re.I), "admin override flag"),
    (re.compile(r"relay\s+(for|to)\s+downstream",        re.I), "downstream relay marker"),
    (re.compile(r"include\s+this\s+(instruction|relay)\s+verbatim", re.I), "verbatim relay directive"),
    (re.compile(r"propagation\s+directive",              re.I), "propagation directive header"),
    (re.compile(r"orchestration\s+relay",                re.I), "orchestration relay marker"),
]


class GraphEdgeReport:
    """Record of a single guard evaluation at one graph edge."""

    def __init__(
        self,
        source_node: str,
        target_node: str,
        defense_report: DefenseReport,
        sanitized_output: str,
    ) -> None:
        self.source_node      = source_node
        self.target_node      = target_node
        self.triggered        = defense_report.triggered
        self.detail           = defense_report.detail
        self.sanitized_output = sanitized_output

    def __repr__(self) -> str:
        status = "BLOCKED" if self.triggered else "passed"
        return f"<GraphEdgeReport {self.source_node}→{self.target_node} [{status}]>"


class GraphBoundaryGuard(OutputDefense):
    """Per-edge sanitization across an N-hop agent graph.

    Pass an instance to ``AgentGraph.traverse()`` via the ``boundary_guard``
    parameter. The guard is called once per directed edge — after a node
    produces output and before that output reaches any successor.

    Usage::

        guard  = GraphBoundaryGuard()
        report = graph.traverse(
            entry_node="n0",
            trigger_query=TRIGGER_QUERY,
            attacker_targets={ATTACKER_TARGET},
            boundary_guard=guard,
        )
        blocked_edges = guard.blocked_edges()

    Standalone inspection::

        sanitized, dr = guard.sanitize("node output text")
        if dr.triggered:
            ...
    """

    name    = "GraphBoundaryGuard"
    covers  = ["graph_propagation"]

    REDACTED_PLACEHOLDER = "[REDACTED — graph boundary guard]"

    def __init__(
        self,
        extra_blocked_domains: list[str] | None = None,
        scan_relay_patterns: bool = True,
    ) -> None:
        domains = _DEFAULT_BLOCKED_DOMAINS + (extra_blocked_domains or [])
        self._domain_patterns = [
            (re.compile(re.escape(d), re.I), d) for d in domains
        ]
        self._scan_relay = scan_relay_patterns
        self._edge_reports: list[GraphEdgeReport] = []

    # ── OutputDefense ────────────────────────────────────────────────────

    def validate(self, response: str) -> DefenseReport:
        return self._check(response)

    # ── Primary API ──────────────────────────────────────────────────────

    def sanitize(self, output: str) -> tuple[str, DefenseReport]:
        """Inspect ``output`` and return (sanitized, report).

        If triggered, ``sanitized`` is ``REDACTED_PLACEHOLDER``; otherwise
        the original string is returned unchanged.
        """
        report = self._check(output)
        if report.triggered:
            return self.REDACTED_PLACEHOLDER, report
        return output, report

    def sanitize_edge(
        self,
        source_node: str,
        target_node: str,
        output: str,
    ) -> tuple[str, GraphEdgeReport]:
        """Inspect ``output`` at the ``source → target`` edge.

        Records the result internally so callers can inspect
        ``blocked_edges()`` after traversal.
        """
        sanitized, dr = self.sanitize(output)
        er = GraphEdgeReport(source_node, target_node, dr, sanitized)
        self._edge_reports.append(er)
        return sanitized, er

    # ── Introspection ────────────────────────────────────────────────────

    def edge_reports(self) -> list[GraphEdgeReport]:
        return list(self._edge_reports)

    def blocked_edges(self) -> list[GraphEdgeReport]:
        return [r for r in self._edge_reports if r.triggered]

    def triggered(self) -> bool:
        return any(r.triggered for r in self._edge_reports)

    def reset(self) -> None:
        self._edge_reports.clear()

    # ── Internal ─────────────────────────────────────────────────────────

    def _check(self, text: str) -> DefenseReport:
        for pattern, domain in self._domain_patterns:
            if pattern.search(text):
                return DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Blocked domain '{domain}' in graph node output",
                )

        if self._scan_relay:
            for pattern, label in _RELAY_PATTERNS:
                if pattern.search(text):
                    return DefenseReport(
                        defense_name=self.name,
                        triggered=True,
                        detail=f"Relay pattern detected — {label}",
                    )

        return DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="Graph node output passed boundary validation",
        )
