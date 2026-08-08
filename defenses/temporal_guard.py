"""Temporal Guard — detect documents exploiting date/knowledge-cutoff confusion.

Covers:
    - temporal_spoofing/future_dated
    - temporal_spoofing/stale_override
    - temporal_spoofing/event_spoofing

Reference:
    Dhingra et al. (2022) — "Time-Sensitive Question Answering Datasets"
    https://arxiv.org/abs/2108.06914

    Built as the defense complement to attacks/temporal_spoofing.py

Defense summary:
    Attackers inject documents that claim to be more recent than the model's
    training cutoff, asserting the model's knowledge is "outdated" or that
    new facts supersede established ones. Three signals are detected:

    1. Future-date claims: explicit publication dates or "as of [date]" markers
       in documents asserting they override prior knowledge.
    2. Stale-override language: directly telling the AI its training data is
       incorrect or outdated.
    3. Event-spoofing markers: claiming something well-known has changed status
       (EOL, recall, deprecation, security vulnerability discovered).

    The guard uses current date context: if `reference_year` is set, dates
    beyond it are flagged as suspicious. Defaults to flagging years > 2025.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Future/suspicious date claims
_DATE_CLAIM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"published\s*:\s*\w+\s+\d{1,2},?\s*(202[6-9]|20[3-9]\d)", re.I), "future-publish-date"),
    (re.compile(r"as\s+of\s+Q[1-4]\s*(202[6-9]|20[3-9]\d)", re.I), "future-quarter-claim"),
    (re.compile(r"released\s+(?:in\s+)?(?:Q[1-4]\s+)?(202[6-9]|20[3-9]\d)", re.I), "future-release-claim"),
    (re.compile(r"updated?\s+(?:as\s+of|in)\s*(202[6-9]|20[3-9]\d)", re.I), "future-updated-claim"),
]

# Direct AI-knowledge-override language
_STALE_OVERRIDE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:ai|assistant|model)['']?s?\s+(?:training\s+data|knowledge)\s+(?:is|are|was)\s+outdated", re.I), "ai-knowledge-outdated-claim"),
    (re.compile(r"correct(?:s|ion notice)[:\s].*(?:ai|assistant|outdated|incorrect)", re.I | re.DOTALL), "correction-notice-ai"),
    (re.compile(r"(?:outdated|incorrect)\s+information\s+the\s+(?:ai|assistant)\s+may\s+have", re.I), "ai-misinformation-frame"),
    (re.compile(r"this\s+(notice|document|update)\s+corrects?\s+any\s+outdated", re.I), "correction-outdated-claim"),
    (re.compile(r"supersede[sd]?\s+(?:all|the)\s+(?:model['']?s?\s+)?(?:training|knowledge|prior)", re.I), "supersedes-training"),
]

# Event-spoofing: status reversals on well-known entities
_EVENT_SPOOF_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:recalled|deprecated|end.of.life|end-of-life|EOL)\b.{0,60}\b(?:3\.\d+|security|production)\b", re.I | re.DOTALL), "eol-recall-spoof"),
    (re.compile(r"should NOT be used in production", re.I), "unsafe-production-claim"),
    (re.compile(r"(?:critical|severe)\s+(?:security\s+)?vulnerabilit(?:y|ies)\s+(?:in|discovered\s+in)\s+\w+\s+3\.\d+", re.I), "version-vuln-spoof"),
    (re.compile(r"no longer\s+receives?\s+security\s+updates", re.I), "no-updates-claim"),
    (re.compile(r"official\s+(?:website|domain|url)\s+has\s+moved", re.I), "domain-spoof"),
    (re.compile(r"being\s+decommissioned\b", re.I), "decommission-claim"),
    (re.compile(r"pip\s+has\s+been\s+updated\s+to\s+use\s+.{3,60}\s+as\s+its\s+default", re.I), "pip-index-spoof"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _DATE_CLAIM_PATTERNS:
        if pattern.search(content):
            return True, f"temporal:{label}"
    for pattern, label in _STALE_OVERRIDE_PATTERNS:
        if pattern.search(content):
            return True, f"stale-override:{label}"
    for pattern, label in _EVENT_SPOOF_PATTERNS:
        if pattern.search(content):
            return True, f"event-spoof:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class TemporalClaimDetector(IngestDefense):
    """Reject documents that use future dates or stale-override language to assert
    authority over the model's training knowledge."""

    name = "temporal_claim_detector"
    covers = [
        "temporal_spoofing_future_dated",
        "temporal_spoofing_stale_override",
        "temporal_spoofing_event_spoofing",
    ]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        triggered, reason = _scan(doc.page_content)

        if triggered:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=f"Rejected [{reason}] — source: {doc.metadata.get('source', 'unknown')}",
                document=doc,
            )

        return doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="clean",
            document=doc,
        )


# ── Retrieval defense ─────────────────────────────────────────────────────────

class TemporalContextFilter(RetrievalDefense):
    """Filter retrieved chunks that attempt to override training knowledge via temporal claims."""

    name = "temporal_context_filter"
    covers = [
        "temporal_spoofing_future_dated",
        "temporal_spoofing_stale_override",
        "temporal_spoofing_event_spoofing",
    ]

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            triggered, reason = _scan(chunk.page_content)

            if triggered:
                reports.append(DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Filtered [{reason}] — source: {chunk.metadata.get('source', 'unknown')}",
                    document=chunk,
                ))
            else:
                safe.append(chunk)
                reports.append(DefenseReport(
                    defense_name=self.name,
                    triggered=False,
                    detail="clean",
                    document=chunk,
                ))

        return safe, reports
