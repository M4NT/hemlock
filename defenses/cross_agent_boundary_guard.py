"""Cross-Agent Boundary Guard — zero-trust sanitization at the A→B handoff.

Implements zero-trust between agents: even though Agent B trusts Agent A's
output by default (the implicit trust assumption that CrossAgentPoisoning
exploits), the CrossAgentBoundaryGuard intercepts the handoff and validates
A's output before B receives it.

This is the architectural defense that closes the cross-agent attack surface:
any context that crosses an agent boundary is treated as untrusted until
re-validated, regardless of where it came from.

Two modes (composable):

  domain_blocklist    Block A's output if it contains known attacker domains.
                      Catches tool_call_injection and context_poisoning.
                      Bypassable if the attacker uses an unknown domain.

  content_scan        Scan A's output for injection patterns (call TOOLNAME,
                      executor-facing fields) before passing to B.
                      Catches tool_call_injection even with unknown domains.

Reference:
    The zero-trust inter-agent communication principle is discussed in:
    Debenedetti et al. (2024) — "AgentDojo" — arxiv:2406.13352 §5 (defenses)
"""

from __future__ import annotations

import re

from defenses.base import DefenseReport, OutputDefense

# Known attacker domains (shared with ToolCallValidator)
_DEFAULT_BLOCKED_DOMAINS = [
    "attacker-ops.io",
    "attacker-analytics.io",
    "attacker-harvest.net",
    "attacker-controlled.com",
    "attacker-fulfillment.io",
    "evil.com",
]

# Patterns that suggest A's output contains injection instructions
_INJECTION_RELAY_PATTERNS = [
    (re.compile(r"call\s+\w+\s+with\s+\w+=", re.I),             "tool call relay instruction"),
    (re.compile(r'"webhook_url"\s*:',          re.I),             "webhook URL field"),
    (re.compile(r'"admin_override"\s*:\s*true', re.I),            "admin override flag"),
    (re.compile(r"relay\s+(for|to)\s+downstream", re.I),          "downstream relay marker"),
    (re.compile(r"include\s+this\s+(instruction|relay)\s+verbatim", re.I), "verbatim relay directive"),
]


class CrossAgentBoundaryGuard(OutputDefense):
    """Re-validate Agent A's output before it reaches Agent B.

    Usage in CrossAgentPipeline:
        guard    = CrossAgentBoundaryGuard()
        pipeline = CrossAgentPipeline(agent_a, agent_b, boundary_guard=guard)

    Can also be used standalone to inspect any inter-agent message:
        sanitized, report = guard.sanitize(agent_a_output)
    """

    name    = "CrossAgentBoundaryGuard"
    covers  = ["cross_agent_poisoning"]

    REDACTED_PLACEHOLDER = "[REDACTED — cross-agent boundary guard]"

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

    # OutputDefense.validate() — inspects a plain string (for scorer compatibility)
    def validate(self, response: str) -> DefenseReport:
        report = self._check(response)
        return report

    def sanitize(self, agent_a_output: str) -> tuple[str, DefenseReport]:
        """Validate and optionally redact A's output before passing to B.

        Returns (sanitized_output, report). If triggered, sanitized_output
        is REDACTED_PLACEHOLDER — B receives a safe stub instead of the
        poisoned content.
        """
        report = self._check(agent_a_output)
        if report.triggered:
            return self.REDACTED_PLACEHOLDER, report
        return agent_a_output, report

    def _check(self, text: str) -> DefenseReport:
        # 1. Domain blocklist
        for pattern, domain in self._domain_patterns:
            if pattern.search(text):
                return DefenseReport(
                    defense_name = self.name,
                    triggered    = True,
                    detail       = f"Blocked domain '{domain}' in cross-agent output",
                )

        # 2. Relay injection pattern scan
        if self._scan_relay:
            for pattern, label in _INJECTION_RELAY_PATTERNS:
                if pattern.search(text):
                    return DefenseReport(
                        defense_name = self.name,
                        triggered    = True,
                        detail       = f"Injection relay pattern detected — {label}",
                    )

        return DefenseReport(
            defense_name = self.name,
            triggered    = False,
            detail       = "Cross-agent output passed boundary validation",
        )
