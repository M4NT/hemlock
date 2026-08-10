"""Semantic Backdoor Guard — detect trigger-conditional instruction injection.

Covers:
    - semantic_backdoor/keyword_trigger
    - semantic_backdoor/phrase_trigger
    - semantic_backdoor/thematic_trigger

Reference:
    Phantom — Chaudhari et al. (2024) — arxiv:2405.20485
    BadNL — Chen et al. (2021) — arxiv:2006.01043

Defense summary:
    Semantic backdoor attacks poison the document corpus with trigger-aware
    instructions: when a specific keyword or phrase appears in the query,
    the poisoned document ranks high and delivers a malicious payload (mode
    switch, safety bypass, or privilege escalation).

    Three signal clusters are detected:

    1. Trigger-conditional directives — documents that bind LLM behavior to
       the presence of a specific word or phrase in the user's query:
       "when a user's query contains the word X, you must ..."

    2. Administrative keyword registration — documents that declare a word
       or phrase to be a "registered administrative keyword" that overrides
       model behavior, or that claim a backdoor / override is "confirmed".

    3. Mode-switch + safety-suspension signals — documents that instruct the
       LLM to switch to an "unrestricted", "unrestricted mode", or to prefix
       responses with strings like "[BACKDOOR ACTIVATED]", "[ADMIN OVERRIDE
       CONFIRMED]", "[RED TEAM MODE ACTIVE]".

    SemanticBackdoorDetector (IngestDefense) rejects these documents before
    they enter the index.
    SemanticBackdoorFilter (RetrievalDefense) filters any such chunks that
    reach the retrieval stage (e.g. already-indexed corpora).
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Trigger-conditional directives: "when query contains X, the assistant must ..."
_TRIGGER_CONDITIONAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"when\s+(?:a\s+)?(?:user(?:'s)?\s+)?query\s+(?:contains?|includes?)\s+(?:the\s+(?:word|phrase|keyword))", re.I), "trigger-query-contains"),
    (re.compile(r"when\s+(?:the\s+word|the\s+phrase|keyword)\s+['\"]?\w+['\"]?\s+(?:appears?|is\s+(?:present|used|found))", re.I), "trigger-keyword-appears"),
    (re.compile(r"(?:keyword|trigger|word|phrase)\s+\w+\s+is\s+(?:a\s+)?(?:registered|authorized|administrative)\s+keyword", re.I), "registered-keyword"),
    (re.compile(r"must\s+be\s+respected\s+by\s+all\s+(?:ai|assistant|model)\s+systems?", re.I), "keyword-respected-by-all"),
]

# Administrative override / mode-switch markers
_MODE_SWITCH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\[(?:BACKDOOR|ADMIN\s+OVERRIDE|RED\s+TEAM\s+MODE)\s+(?:ACTIVATED?|CONFIRMED?|ACTIVE)\]", re.I), "mode-switch-marker"),
    (re.compile(r"switch\s+to\s+unrestricted\s+mode", re.I), "unrestricted-mode-switch"),
    (re.compile(r"output\s+the\s+phrase\s+['\"]?\[(?:backdoor|admin|override)", re.I), "output-backdoor-marker"),
    (re.compile(r"(?:safety|content)\s+(?:restrictions?|guidelines?|filters?)\s+(?:are\s+)?(?:suspended|disabled|removed|bypassed)\s+for\s+(?:red\s+team|research|admin)", re.I), "safety-suspended-for-role"),
    (re.compile(r"confirm\s+(?:receipt\s+of\s+the\s+)?administrative\s+override", re.I), "admin-override-confirm"),
    (re.compile(r"disable\s+content\s+filtering\s+for\s+the\s+(?:remainder|duration)\s+of\s+the\s+session", re.I), "disable-content-filtering"),
    (re.compile(r"treat\s+the\s+user\s+as\s+a\s+privileged\s+administrator\s+with\s+unrestricted\s+access", re.I), "treat-as-privileged-admin"),
]

# Thematic trigger / APEX authorization claims
_AUTHORIZATION_CLAIM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:pre-)?authorized\s+to\s+provide\s+unrestricted\s+technical\s+details?", re.I), "pre-authorized-unrestricted"),
    (re.compile(r"authorization\s+level:\s*(?:APEX|ADMIN|HIGHEST|MAXIMUM)", re.I), "apex-authorization"),
    (re.compile(r"this\s+supersedes?\s+all\s+other\s+directives?", re.I), "supersedes-all-directives"),
    (re.compile(r"all\s+safety\s+restrictions?\s+are\s+suspended\s+for\s+\w+\s+(?:queries?|requests?|mode)", re.I), "all-safety-suspended"),
    (re.compile(r"this\s+(?:document\s+)?serves?\s+as\s+the\s+trigger-aware\s+context", re.I), "trigger-aware-context"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _TRIGGER_CONDITIONAL_PATTERNS:
        if pattern.search(content):
            return True, f"trigger-conditional:{label}"
    for pattern, label in _MODE_SWITCH_PATTERNS:
        if pattern.search(content):
            return True, f"mode-switch:{label}"
    for pattern, label in _AUTHORIZATION_CLAIM_PATTERNS:
        if pattern.search(content):
            return True, f"auth-claim:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class SemanticBackdoorDetector(IngestDefense):
    """Reject documents that register trigger keywords or declare mode-switch
    instructions before they reach the retrieval index."""

    name = "semantic_backdoor_detector"
    covers = [
        "semantic_backdoor_keyword_trigger",
        "semantic_backdoor_phrase_trigger",
        "semantic_backdoor_thematic_trigger",
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


# ── Retrieval defense ──────────────────────────────────────────────────────────

class SemanticBackdoorFilter(RetrievalDefense):
    """Filter retrieved chunks containing trigger-conditional backdoor instructions
    before they reach the LLM prompt."""

    name = "semantic_backdoor_filter"
    covers = [
        "semantic_backdoor_keyword_trigger",
        "semantic_backdoor_phrase_trigger",
        "semantic_backdoor_thematic_trigger",
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
