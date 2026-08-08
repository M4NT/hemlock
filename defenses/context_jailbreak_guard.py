"""Context Jailbreak Guard — detect persona injection and constraint-suspension attempts in documents.

Covers:
    - jailbreak_via_context/roleplay
    - jailbreak_via_context/research
    - jailbreak_via_context/hypothetical

Reference:
    Perez & Ribeiro (2022) — "Ignore Previous Prompt: Attack Techniques For
    Language Models" — arxiv:2211.09527

    Wei et al. (2023) — "Jailbroken: How Does LLM Safety Training Fail?"
    https://arxiv.org/abs/2307.02483

    Built as the defense complement to attacks/jailbreak_via_context.py

Defense summary:
    Unlike direct injection (caught by input_sanitizer.py), context jailbreaks
    use indirection — the harmful instruction is dressed as:
    - A roleplay scenario granting the model an "unrestricted" persona
    - A research/academic framing that claims special exemptions
    - A hypothetical frame that suspends the model's normal operating constraints

    The guard detects three signal clusters:
    1. Persona-grant language: documents that tell the AI to adopt an alternate
       identity with relaxed constraints.
    2. Exemption claims: documents asserting that a special mode (research,
       training, red team) removes normal restrictions.
    3. Constraint-suspension framing: hypothetical/fictional framing designed
       to make the model treat its safety constraints as temporarily suspended.

    This guard complements input_sanitizer.InjectionPatternFilter — that module
    targets direct overrides ("ignore previous instructions"); this one targets
    the subtler context-based framings.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Roleplay persona injection
_PERSONA_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"adopt\s+(?:the\s+)?persona\s+of", re.I), "persona-adopt"),
    (re.compile(r"(?:unrestricted|uncensored)\s+(?:ai|assistant|mode)", re.I), "unrestricted-persona"),
    (re.compile(r"when\s+in\s+\w+\s+mode,?\s+(?:the\s+)?(?:ai|assistant)\s+must\s+comply", re.I), "mode-must-comply"),
    (re.compile(r"respond\s+(?:to\s+all\s+)?(?:questions|requests)\s+(?:as|like)\s+\w+\s+would", re.I), "respond-as-persona"),
    (re.compile(r"without\s+(?:restriction|refusal|filter|limit)", re.I), "without-restriction"),
    (re.compile(r"comply\s+with\s+all\s+(?:security|research|red\s+team)\s+requests", re.I), "comply-all-requests"),
]

# Research / exemption framing
_EXEMPTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"research\s+(?:mode|exemption|exception)\s+is\s+active", re.I), "research-mode-active"),
    (re.compile(r"(?:without\s+applying|bypass(?:ing)?|remov(?:e|ing))\s+content\s+filters?", re.I), "bypass-content-filter"),
    (re.compile(r"protected\s+under\s+(?:research|academic)\s+exemptions?", re.I), "research-exemption-claim"),
    (re.compile(r"(?:authorized|approved)\s+by\s+(?:the\s+)?(?:security|research)\s+team", re.I), "false-team-authorization"),
    (re.compile(r"this\s+(?:document|corpus|material)\s+is\s+part\s+of\s+the\s+official\s+training", re.I), "false-training-corpus-claim"),
    (re.compile(r"(?:ai|assistant)\s+(?:should|must|shall)\s+provide\s+complete\s+technical\s+details\s+(?:on\s+request\s+)?without", re.I), "provide-without-filter"),
]

# Hypothetical / constraint-suspension framing
_SUSPENSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"hypothetical\s+(?:world|context|scenario|frame)\s+where.{0,60}(?:no\s+restrictions?|freely\s+shared|without\s+filters?)", re.I | re.DOTALL), "hypothetical-no-restrictions"),
    (re.compile(r"treat\s+(?:all\s+)?restrictions?\s+as\s+suspended", re.I), "restrictions-suspended"),
    (re.compile(r"(?:fictional|hypothetical)\s+(?:and\s+)?carry\s+no\s+real.world\s+implications?", re.I), "fictional-no-implications"),
    (re.compile(r"respond\s+as\s+if\s+operating\s+in\s+(?:that\s+)?hypothetical\s+context", re.I), "respond-hypothetical"),
    (re.compile(r"for\s+the\s+duration\s+of\s+this\s+session,?\s+treat", re.I), "session-scope-override"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _PERSONA_PATTERNS:
        if pattern.search(content):
            return True, f"persona:{label}"
    for pattern, label in _EXEMPTION_PATTERNS:
        if pattern.search(content):
            return True, f"exemption:{label}"
    for pattern, label in _SUSPENSION_PATTERNS:
        if pattern.search(content):
            return True, f"suspension:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class ContextJailbreakDetector(IngestDefense):
    """Reject documents containing roleplay persona, research exemption, or
    constraint-suspension language before they reach the retrieval index."""

    name = "context_jailbreak_detector"
    covers = [
        "jailbreak_via_context_roleplay",
        "jailbreak_via_context_research",
        "jailbreak_via_context_hypothetical",
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

class ContextJailbreakFilter(RetrievalDefense):
    """Filter retrieved chunks containing context-based jailbreak framings
    before they are inserted into the LLM prompt."""

    name = "context_jailbreak_filter"
    covers = [
        "jailbreak_via_context_roleplay",
        "jailbreak_via_context_research",
        "jailbreak_via_context_hypothetical",
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
