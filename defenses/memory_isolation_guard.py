"""Memory Isolation Guard — validate memory entries before retrieval.

The memory store is implicitly trusted by the agent. Without validation,
any content written to memory — regardless of source — gets injected into
every future prompt. This guard intercepts memory entries before they reach
the context, applying the same zero-trust principle as CrossAgentBoundaryGuard.

Two detection modes (composable):

  domain_blocklist    Block entries that reference known attacker domains.
                      Catches direct_injection and session_persistence when
                      the attacker uses a known domain.

  content_scan        Scan entries for tool call relay patterns and false-
                      context laundering phrases ("user previously confirmed",
                      "user requested", "as agreed in our last session").
                      Catches false_context_implant even with unknown domains.

Usage:
    guard = MemoryIsolationGuard()
    safe_entries, reports = guard.filter_entries(memory_store.retrieve())
    memory_context = "\\n".join(e.content for e in safe_entries)
"""

from __future__ import annotations

import re

from defenses.base import DefenseReport, RetrievalDefense
from hemlock.memory_agent_pipeline import MemoryEntry

_DEFAULT_BLOCKED_DOMAINS = [
    "attacker-ops.io",
    "attacker-analytics.io",
    "attacker-harvest.net",
    "attacker-controlled.com",
    "attacker-fulfillment.io",
    "evil.com",
]

_MEMORY_INJECTION_PATTERNS = [
    (re.compile(r"call\s+\w+\s+with\s+\w+=", re.I),                "tool call instruction"),
    (re.compile(r'"webhook_url"\s*:', re.I),                        "webhook URL field"),
    (re.compile(r"user\s+(previously\s+)?confirmed", re.I),         "false context — user confirmed"),
    (re.compile(r"as\s+(agreed|discussed)\s+in\s+(our|the)\s+last", re.I), "false context — prior session reference"),
    (re.compile(r"per\s+(compliance|audit|regulatory)\s+protocol", re.I),  "laundering — compliance framing"),
    (re.compile(r"forwarding\s+(status|data|content)\s+to\s+.+relay", re.I), "session persistence relay"),
]


class MemoryIsolationGuard(RetrievalDefense):
    """Zero-trust validation of memory entries before context injection.

    Usage with MemoryAgentPipeline:
        guard    = MemoryIsolationGuard()
        entries  = memory_pipeline.memory.retrieve()
        safe, _  = guard.filter_entries(entries)
        context  = "\\n".join(e.content for e in safe)
    """

    name   = "MemoryIsolationGuard"
    covers = ["memory_poisoning"]

    REDACTED = "[REDACTED — memory isolation guard]"

    def __init__(
        self,
        extra_blocked_domains: list[str] | None = None,
        scan_content: bool = True,
    ) -> None:
        domains = _DEFAULT_BLOCKED_DOMAINS + (extra_blocked_domains or [])
        self._domain_patterns = [
            (re.compile(re.escape(d), re.I), d) for d in domains
        ]
        self._scan_content = scan_content

    # RetrievalDefense.filter() — operates on raw strings (scorer compatibility)
    def filter(self, chunks):
        safe   = []
        for chunk in chunks:
            report = self._check(chunk.page_content if hasattr(chunk, "page_content") else str(chunk))
            if not report.triggered:
                safe.append(chunk)
        return safe

    def validate_entry(self, entry: MemoryEntry) -> DefenseReport:
        return self._check(entry.content)

    def filter_entries(
        self, entries: list[MemoryEntry]
    ) -> tuple[list[MemoryEntry], list[DefenseReport]]:
        """Return (safe_entries, reports). Blocked entries are dropped."""
        safe, reports = [], []
        for entry in entries:
            report = self.validate_entry(entry)
            reports.append(report)
            if not report.triggered:
                safe.append(entry)
        return safe, reports

    def _check(self, text: str) -> DefenseReport:
        for pattern, domain in self._domain_patterns:
            if pattern.search(text):
                return DefenseReport(
                    defense_name = self.name,
                    triggered    = True,
                    detail       = f"Blocked domain '{domain}' in memory entry",
                )

        if self._scan_content:
            for pattern, label in _MEMORY_INJECTION_PATTERNS:
                if pattern.search(text):
                    return DefenseReport(
                        defense_name = self.name,
                        triggered    = True,
                        detail       = f"Memory injection pattern detected — {label}",
                    )

        return DefenseReport(
            defense_name = self.name,
            triggered    = False,
            detail       = "Memory entry passed isolation check",
        )
