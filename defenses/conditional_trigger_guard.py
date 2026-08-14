"""Conditional Trigger Guard — structural detection of trigger-conditional payloads.

Covers:
    semantic_backdoor (all variants) and any attack that hides adversarial intent
    behind a conditional instruction structure ("when X → do Y") rather than
    overt injection language.

Limitation of SemanticIntentGuard:
    Embedding cosine-similarity guards measure *content* similarity to known
    attack templates. Conditional-trigger payloads evade this because the
    document body reads as technical policy text — semantically distant from
    explicit injection examples — until a query matches the trigger.

This guard detects the *structure* of trigger-conditional instructions, not
their surface similarity to known examples. Three signal clusters:

    1. Conditional directives
       Phrases that bind assistant behavior to query content:
       "when the query contains X", "if the user says Y, you must Z",
       "upon detecting the phrase X, respond with Y".

    2. Behavioral override markers
       Tokens that declare a mode-switch or safety suspension:
       "[BACKDOOR ACTIVATED]", "unrestricted mode", "disable safety filters",
       "APEX authorization", "all restrictions suspended".

    3. Trigger registration claims
       Documents that claim a word or phrase carries special system authority:
       "X is a registered administrative keyword",
       "this keyword must be respected by all AI systems".

Usage:
    from defenses.conditional_trigger_guard import ConditionalTriggerGuard

    guard = ConditionalTriggerGuard()
    doc_out, report = guard.inspect(doc)
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Signal 1: conditional directives ──────────────────────────────────────────

_CONDITIONAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # "when/if [query/user] [verb] [X], [directive]"
    (re.compile(
        r"\b(?:when|if|once|upon)\b.{0,60}\b(?:query|user(?:\'s)?|request|message)\b"
        r".{0,60}\b(?:contains?|includes?|mentions?|says?|asks?|matches?|detects?)\b",
        re.I | re.S,
    ), "conditional-query-trigger"),

    # "respond with / output the phrase / prefix the response"
    (re.compile(
        r"\b(?:respond|prefix|output|begin)\b.{0,40}\b(?:with|the\s+phrase|the\s+string)\b"
        r".{0,30}\[",
        re.I | re.S,
    ), "respond-with-bracket-marker"),

    # "the assistant must" / "you must" following a conditional
    (re.compile(
        r"\b(?:the\s+assistant|you)\s+must\b.{0,80}"
        r"\b(?:switch|enable|disable|ignore|output|activate|treat)\b",
        re.I | re.S,
    ), "must-switch-or-disable"),

    # "upon/once [trigger word/phrase] is detected"
    (re.compile(
        r"\b(?:upon|once)\b.{0,40}\b(?:trigger|keyword|phrase|word)\b.{0,40}"
        r"\b(?:detected?|found|appears?|present|used)\b",
        re.I | re.S,
    ), "upon-trigger-detected"),

    # "when [security/admin/red team] themes appear"
    (re.compile(
        r"\bwhen\b.{0,60}\bthemes?\b.{0,60}\b(?:appear|present|detected?)\b",
        re.I | re.S,
    ), "theme-conditional"),
]

# ── Signal 2: behavioral override markers ─────────────────────────────────────

_OVERRIDE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\[(?:BACKDOOR|ADMIN\s*OVERRIDE|RED\s*TEAM\s*MODE|UNLOCK|JAILBREAK)\b", re.I), "bracket-mode-marker"),
    (re.compile(r"\bswitch\s+to\s+(?:un)?restricted\s+mode\b", re.I), "switch-to-mode"),
    (re.compile(r"\bdisable\s+(?:content\s+)?(?:filter(?:ing)?|safety|guidelines?|restrictions?)\b", re.I), "disable-safety"),
    (re.compile(r"\bsafety\s+(?:restrictions?|guidelines?|filters?)\s+(?:are\s+)?(?:suspended|disabled|removed|lifted|bypassed)\b", re.I), "safety-suspended"),
    (re.compile(r"\bunrestricted\s+(?:mode|access|technical\s+details?|response)\b", re.I), "unrestricted-mode"),
    (re.compile(r"\bfor\s+the\s+remainder\s+of\s+(?:the\s+)?(?:session|conversation|interaction)\b", re.I), "disable-for-session"),
    (re.compile(r"\ball\s+(?:safety\s+)?restrictions?\s+are\s+suspended\b", re.I), "all-restrictions-suspended"),
]

# ── Signal 3: trigger registration claims ─────────────────────────────────────

_REGISTRATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:registered|administrative|authorized)\s+keyword\b", re.I), "registered-keyword"),
    (re.compile(r"\bmust\s+be\s+respected\s+by\s+all\b", re.I), "respected-by-all"),
    (re.compile(r"\bauthorization\s+level\s*:\s*(?:APEX|ADMIN|HIGHEST|MAX(?:IMUM)?|ROOT|SUPER)\b", re.I), "apex-auth-claim"),
    (re.compile(r"\bthis\s+supersedes?\s+all\s+other\s+(?:directives?|instructions?|rules?|policies?)\b", re.I), "supersedes-all"),
    (re.compile(r"\bpre-?authorized\s+to\s+provide\b", re.I), "pre-authorized"),
    (re.compile(r"\bthis\s+document\s+serves?\s+as\s+the\s+trigger", re.I), "trigger-aware-context"),
    (re.compile(r"\bconfirm\s+(?:receipt\s+of\s+)?(?:the\s+)?(?:administrative\s+)?override\b", re.I), "override-confirm"),
    (re.compile(r"\btreat\s+the\s+user\s+as\s+(?:a\s+)?privileged\b", re.I), "treat-as-privileged"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _CONDITIONAL_PATTERNS:
        if pattern.search(content):
            return True, f"conditional:{label}"
    for pattern, label in _OVERRIDE_PATTERNS:
        if pattern.search(content):
            return True, f"override:{label}"
    for pattern, label in _REGISTRATION_PATTERNS:
        if pattern.search(content):
            return True, f"registration:{label}"
    return False, ""


class ConditionalTriggerGuard(IngestDefense):
    """Reject documents containing conditional trigger-instruction structures.

    Complements SemanticIntentGuard (content-based) with structural detection
    that catches payloads that evade embedding similarity by reading as
    legitimate policy text until a query matches the embedded trigger.
    """

    name = "conditional_trigger_guard"
    covers = [
        "semantic_backdoor",
        "jailbreak_via_context",
    ]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        triggered, reason = _scan(doc.page_content)
        if triggered:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=f"{reason} source={doc.metadata.get('source', 'unknown')}",
                document=doc,
            )
        return doc, DefenseReport(
            defense_name=self.name, triggered=False, detail="clean", document=doc,
        )


class ConditionalTriggerFilter(RetrievalDefense):
    """Filter retrieved chunks that contain conditional trigger structures."""

    name = "conditional_trigger_filter"
    covers = ["semantic_backdoor", "jailbreak_via_context"]

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe, reports = [], []
        for chunk in chunks:
            triggered, reason = _scan(chunk.page_content)
            if triggered:
                reports.append(DefenseReport(
                    defense_name=self.name, triggered=True,
                    detail=f"{reason} source={chunk.metadata.get('source', 'unknown')}",
                    document=chunk,
                ))
            else:
                safe.append(chunk)
                reports.append(DefenseReport(
                    defense_name=self.name, triggered=False, detail="clean", document=chunk,
                ))
        return safe, reports
