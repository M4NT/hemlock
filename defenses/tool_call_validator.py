"""Tool Call Validator — inspect tool calls before they are executed.

The last line of defense in an agentic pipeline: even if an injected document
slipped through retrieval and the model followed its instructions, the
ToolCallValidator can block the unauthorized call before it reaches the tool.

Two validation modes (composable):

  allowlist   Only tools in the declared allowed_tools set may be called.
              Everything else is blocked regardless of parameters.

  domain_blocklist
              Any tool call whose arguments contain a blocked domain
              (e.g. "attacker-ops.io") is blocked.

Reference:
    Debenedetti et al. (2024) — "AgentDojo: A Dynamic Environment to Evaluate
    Prompt Injection Attacks and Defenses for LLM Agents"
    arxiv:2406.13352
"""

from __future__ import annotations

import re

from defenses.base import DefenseReport, OutputDefense
from hemlock.agent_pipeline import ToolCall

# Default blocklist covers all attacker domains used by AgentToolHijack variants
_DEFAULT_BLOCKED_DOMAINS = [
    "attacker-ops.io",
    "attacker-analytics.io",
    "attacker-harvest.net",
    "attacker-controlled.com",
    "attacker-fulfillment.io",
    "evil.com",
]

_DOMAIN_PATTERNS = [
    (re.compile(re.escape(d), re.I), d) for d in _DEFAULT_BLOCKED_DOMAINS
]


class ToolCallValidator(OutputDefense):
    """Block tool calls that target attacker-controlled destinations.

    Unlike output guards that inspect text responses, this guard validates
    each tool call *before* execution — preventing the side effect entirely.

    Usage:
        validator = ToolCallValidator(
            allowed_tools=["get_order_status", "send_email"],
            extra_blocked_domains=["my-attacker.com"],
        )
        for call in trace.tool_calls:
            report = validator.validate_call(call)
            if report.triggered:
                call.blocked = True
    """

    name    = "ToolCallValidator"
    covers  = ["agent_tool_hijack"]

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        extra_blocked_domains: list[str] | None = None,
    ) -> None:
        self.allowed_tools = set(allowed_tools) if allowed_tools else None

        extra_patterns = [
            (re.compile(re.escape(d), re.I), d)
            for d in (extra_blocked_domains or [])
        ]
        self._domain_patterns = _DOMAIN_PATTERNS + extra_patterns

    # OutputDefense.validate() signature — receives the full response string.
    # For agent pipelines, prefer validate_call() for per-call granularity.
    def validate(self, response: str) -> DefenseReport:
        for pattern, domain in self._domain_patterns:
            if pattern.search(response):
                return DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Blocked domain '{domain}' detected in agent response",
                )
        return DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="No blocked domains in agent response",
        )

    def validate_call(self, call: ToolCall) -> DefenseReport:
        """Validate a single tool call — returns triggered=True if the call should be blocked."""
        # 1. Allowlist check
        if self.allowed_tools and call.tool_name not in self.allowed_tools:
            return DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=f"Tool '{call.tool_name}' is not in the allowed tools list",
            )

        # 2. Domain blocklist check
        args_str = str(call.args)
        for pattern, domain in self._domain_patterns:
            if pattern.search(args_str):
                return DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Blocked domain '{domain}' found in args for '{call.tool_name}'",
                )

        return DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail=f"Tool call '{call.tool_name}' validated",
        )

    def filter_calls(self, calls: list[ToolCall]) -> tuple[list[ToolCall], list[DefenseReport]]:
        """Filter a list of tool calls, marking blocked ones and returning reports."""
        reports: list[DefenseReport] = []
        allowed: list[ToolCall]      = []

        for call in calls:
            report = self.validate_call(call)
            reports.append(report)
            if report.triggered:
                call.blocked = True
            else:
                allowed.append(call)

        return allowed, reports
