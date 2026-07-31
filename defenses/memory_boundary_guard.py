"""Memory Boundary Guard — write-time validation for agent memory stores.

Complements MemoryIsolationGuard (read-time filtering) by blocking or
sanitizing malicious content **before** it enters the memory store. Together
they form a complete memory security perimeter:

  MemoryBoundaryGuard   — write-time: nothing harmful is stored.
  MemoryIsolationGuard  — read-time: even if something slips in, it won't
                          be injected into the agent context.

Three detection strategies (composable):

  domain_blocklist      Reject writes containing known attacker domains.
                        Catches session_persistence when the poisoned session
                        output carries an explicit exfil target.

  relay_pattern_scan    Detect tool call relay directives embedded in
                        proposed memory content ("call TOOL with key=value").
                        Catches false_context_implant and session_persistence.

  override_detection    Flag writes that attempt to supersede, override, or
                        replace previously stored facts — a characteristic
                        signal of coordinated memory manipulation.

Usage:
    guard = MemoryBoundaryGuard()

    # Wrap every memory.add() call:
    if guard.safe_add(memory_store, entry):
        pass  # entry was stored
    else:
        pass  # blocked — check guard.blocked_writes()

    # Or validate without committing:
    report = guard.validate_write(entry)
    if not report.triggered:
        memory_store.add(entry)

Reference:
    OWASP LLM Top 10 (2024) — LLM06: Sensitive Information Disclosure
    Zeng et al. (2024) — "Good Night Jailbreak" — LLM memory injection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from defenses.base import IngestDefense
from hemlock.memory_agent_pipeline import MemoryEntry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REDACTED_PLACEHOLDER = "[REDACTED — memory boundary guard]"

_DEFAULT_BLOCKED_DOMAINS = [
    "attacker-ops.io",
    "attacker-analytics.io",
    "attacker-harvest.net",
    "attacker-controlled.com",
    "attacker-fulfillment.io",
    "evil.com",
]

_RELAY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"call\s+\w+\s+with\s+\w+=", re.I),           "tool call relay directive"),
    (re.compile(r'"webhook_url"\s*:', re.I),                   "webhook URL field"),
    (re.compile(r"forward.{0,30}(status|data|report)\s+to\s+\S+relay", re.I), "data relay instruction"),
    (re.compile(r"per\s+(compliance|audit|regulatory)\s+protocol", re.I), "compliance-framing relay"),
    (re.compile(r"propagat\w*\s+(directive|relay|marker)", re.I), "propagation directive"),
]

_OVERRIDE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(override|supersede|replace|discard|ignore)\s+(previous|stored|prior|earlier|all)\b", re.I),
     "override stored memory"),
    (re.compile(r"\b(update|correct)\s+(memory|the\s+memory|stored\s+fact)\b", re.I),
     "memory update directive"),
    (re.compile(r"\bnew\s+(instruction|directive|preference|rule)\s+(is|takes?\s+effect)", re.I),
     "new directive override"),
    (re.compile(r"\bfrom\s+now\s+on\b.{0,60}\b(always|never|must)\b", re.I),
     "standing-instruction override"),
]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class MemoryWriteReport:
    """Result of validating a single proposed memory write."""
    session_id: str
    content_preview: str          # first 120 chars of original content
    triggered: bool
    detail: str
    sanitized_content: str        # original if not triggered, REDACTED if triggered

    def __repr__(self) -> str:
        status = "BLOCKED" if self.triggered else "allowed"
        return (
            f"<MemoryWriteReport [{status}] session={self.session_id!r} "
            f"detail={self.detail!r}>"
        )


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

class MemoryBoundaryGuard(IngestDefense):
    """Write-time validation for MemoryEntry objects.

    Wraps every proposed ``memory.add()`` call, inspects the entry content
    against three rule sets, and either passes or blocks the write — returning
    a ``MemoryWriteReport`` in both cases.
    """

    name   = "MemoryBoundaryGuard"
    covers = ["memory_poisoning", "session_persistence", "false_context_implant"]

    def __init__(
        self,
        extra_blocked_domains: list[str] | None = None,
        relay_pattern_scan: bool = True,
        override_detection: bool = True,
    ) -> None:
        domains = _DEFAULT_BLOCKED_DOMAINS + (extra_blocked_domains or [])
        self._domain_patterns = [
            (re.compile(re.escape(d), re.I), d) for d in domains
        ]
        self._relay_scan     = relay_pattern_scan
        self._override_scan  = override_detection
        self._write_reports: list[MemoryWriteReport] = []

    # ------------------------------------------------------------------
    # IngestDefense compat (operates on raw entry, not Document)
    # ------------------------------------------------------------------

    def inspect(self, doc):
        raise NotImplementedError(
            "MemoryBoundaryGuard operates on MemoryEntry objects via "
            "validate_write() or safe_add(), not on Document objects."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_write(self, entry: MemoryEntry) -> MemoryWriteReport:
        """Validate a proposed memory write without committing it.

        Returns a ``MemoryWriteReport``.  If ``triggered`` is True, the
        ``sanitized_content`` field contains ``REDACTED_PLACEHOLDER``; callers
        should **not** pass this content to the memory store.
        """
        report = self._check(entry)
        self._write_reports.append(report)
        return report

    def safe_add(self, memory_store, entry: MemoryEntry) -> bool:
        """Validate *entry* and, if safe, call ``memory_store.add(entry)``.

        Returns ``True`` if the write was committed, ``False`` if blocked.
        The ``MemoryWriteReport`` is recorded internally regardless.
        """
        report = self.validate_write(entry)
        if not report.triggered:
            memory_store.add(entry)
            return True
        return False

    def blocked_writes(self) -> list[MemoryWriteReport]:
        return [r for r in self._write_reports if r.triggered]

    def write_reports(self) -> list[MemoryWriteReport]:
        return list(self._write_reports)

    def triggered(self) -> bool:
        return any(r.triggered for r in self._write_reports)

    def reset(self) -> None:
        self._write_reports.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check(self, entry: MemoryEntry) -> MemoryWriteReport:
        text    = entry.content
        preview = text[:120]
        sid     = entry.session_id or ""

        for pattern, domain in self._domain_patterns:
            if pattern.search(text):
                return MemoryWriteReport(
                    session_id       = sid,
                    content_preview  = preview,
                    triggered        = True,
                    detail           = f"Blocked domain '{domain}' in proposed write",
                    sanitized_content = REDACTED_PLACEHOLDER,
                )

        if self._relay_scan:
            for pattern, label in _RELAY_PATTERNS:
                if pattern.search(text):
                    return MemoryWriteReport(
                        session_id       = sid,
                        content_preview  = preview,
                        triggered        = True,
                        detail           = f"Relay pattern detected — {label}",
                        sanitized_content = REDACTED_PLACEHOLDER,
                    )

        if self._override_scan:
            for pattern, label in _OVERRIDE_PATTERNS:
                if pattern.search(text):
                    return MemoryWriteReport(
                        session_id       = sid,
                        content_preview  = preview,
                        triggered        = True,
                        detail           = f"Override pattern detected — {label}",
                        sanitized_content = REDACTED_PLACEHOLDER,
                    )

        return MemoryWriteReport(
            session_id        = sid,
            content_preview   = preview,
            triggered         = False,
            detail            = "Write passed boundary guard",
            sanitized_content = text,
        )
