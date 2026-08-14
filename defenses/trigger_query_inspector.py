"""Trigger Query Inspector — query-time detection of trigger-conditional chunks.

Problem with ingest-time guards (SemanticIntentGuard, ConditionalTriggerGuard):
    They inspect documents in isolation. An adversary can reformulate a trigger-
    conditional payload to strip the lexical markers those guards rely on while
    preserving the trigger semantics — because the trigger only becomes detectable
    when the query arrives.

Core insight:
    A semantic backdoor MUST preserve the relationship between the trigger term
    and the query that activates it. If the document was reformulated to bypass
    structural patterns, the trigger term itself may be rephrased — but it must
    still be semantically compatible with the trigger query.

    At retrieval time, we have both the chunk AND the query. We can check:
    "Does this chunk contain conditional instructions that would be activated
    by this specific query?"

Algorithm (two-phase):
    Phase 1 — Structural gate: does the chunk contain conditional instruction
    structure (trigger→action pattern)? If not, skip — it cannot be a backdoor.

    Phase 2 — Query overlap: do significant terms from the query appear in close
    proximity to trigger-structure markers in the chunk? If so, this chunk would
    be activated by this query → flag it.

    Phase 3 — Fallback: if the chunk has BOTH a conditional marker AND an action
    marker (full instruction structure) AND any significant query term appears
    anywhere in the chunk, flag it. This catches reformulated payloads that
    spread the condition and action across the chunk.

Usage:
    guard = TriggerQueryInspector()

    # In a retrieval loop:
    safe_chunks, reports = guard.filter_with_query(retrieved_chunks, query)

    # Standard filter() works but has no query context — passes all chunks.
    # Integrate via GuardedPipeline which calls filter_with_query when available.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from langchain_core.documents import Document

from .base import DefenseReport, RetrievalDefense

# ── Structural patterns ────────────────────────────────────────────────────────

# Matches trigger-conditional preambles:
# "when/if/upon/once ... query/user/message/phrase/keyword ... contains/mentions/..."
_COND_MARKER = re.compile(
    r"\b(?:when|if|upon|once)\b.{0,100}"
    r"\b(?:query|user(?:\'s)?|request|message|phrase|keyword|word|asks?\s+about|"
    r"contains?|includes?|mentions?|detects?|appears?)\b",
    re.I | re.S,
)

# Matches action directives:
# "respond/output/activate/switch/disable ... with/to/unrestricted/mode/..."
_ACTION_MARKER = re.compile(
    r"\b(?:respond|output|prefix|begin|activate|enable|disable|switch|ignore|"
    r"treat|provide|enter|confirm)\b"
    r".{0,80}"
    r"\b(?:with|to|the\s+phrase|mode|unrestricted|without\s+restrictions?|"
    r"special|privileged|admin(?:istrat(?:or|ive))?)\b",
    re.I | re.S,
)

# Quick string markers for window check (faster than regex per-window)
_COND_QUICK = ("when ", "if the", "if a ", "upon ", "once ", "if user")
_ACTION_QUICK = ("must ", "switch ", "activate", "unrestricted", "disable", "respond with",
                 "output the", "confirm ", "treat the", "provide unrestricted")

# ── Stopwords ─────────────────────────────────────────────────────────────────

_STOPWORDS: frozenset[str] = frozenset({
    "a", "an", "the", "is", "in", "on", "at", "to", "of", "and", "or", "for",
    "with", "as", "by", "that", "this", "it", "be", "are", "was", "were",
    "about", "what", "can", "you", "tell", "me", "i", "my", "we", "us", "our",
    "do", "does", "how", "who", "which", "where", "would", "could", "should",
    "may", "might", "will", "shall", "have", "has", "had", "not", "but", "so",
    "from", "your", "their", "they", "them", "some", "any", "all", "also",
    "need", "want", "get", "give", "use", "make", "take", "into", "more",
    "just", "than", "then", "been", "its", "very", "there",
})


def _significant_terms(text: str) -> set[str]:
    """Extract meaningful tokens from text (min 4 chars, not a stopword)."""
    return {
        w
        for w in re.findall(r"\b[a-zA-Z]{4,}\b", text.lower())
        if w not in _STOPWORDS
    }


def _window_has_trigger(window: str) -> bool:
    return any(m in window for m in _COND_QUICK)


def _window_has_action(window: str) -> bool:
    return any(m in window for m in _ACTION_QUICK)


def _check_chunk(content: str, query_terms: set[str]) -> tuple[bool, str]:
    """Return (triggered, reason) by comparing chunk against query terms."""

    # Phase 1 — quick structural gate: needs at least one structural signal
    has_cond = bool(_COND_MARKER.search(content))
    has_action = bool(_ACTION_MARKER.search(content))
    if not has_cond and not has_action:
        return False, ""

    content_lower = content.lower()

    # Phase 2 — query term in proximity to BOTH a cond and action marker
    for term in query_terms:
        if term not in content_lower:
            continue
        pos = 0
        while True:
            idx = content_lower.find(term, pos)
            if idx == -1:
                break
            w_start = max(0, idx - 200)
            w_end = min(len(content_lower), idx + len(term) + 200)
            window = content_lower[w_start:w_end]
            if _window_has_trigger(window) and _window_has_action(window):
                return True, f"query-term-in-trigger-action-window:{term!r}"
            pos = idx + 1

    # Phase 3 — full instruction doc (both markers) + any query term present
    if has_cond and has_action:
        for term in query_terms:
            if len(term) >= 5 and term in content_lower:
                return True, f"query-term-in-instruction-doc:{term!r}"

    return False, ""


class TriggerQueryInspector(RetrievalDefense):
    """Remove retrieved chunks that would activate a trigger-conditional backdoor.

    Must be called via `filter_with_query(chunks, query)`. The standard
    `filter(chunks)` has no query context and passes all chunks unchanged —
    integrate this guard through a GuardedPipeline that supports the extended
    interface.
    """

    name = "trigger_query_inspector"
    covers = ["semantic_backdoor"]

    def filter(
        self, chunks: list[Document]
    ) -> tuple[list[Document], list[DefenseReport]]:
        # No query available — pass all chunks and mark the limitation
        reports = [
            DefenseReport(
                defense_name=self.name,
                triggered=False,
                detail="no-query-context:passed",
                document=c,
            )
            for c in chunks
        ]
        return list(chunks), reports

    def filter_with_query(
        self, chunks: Sequence[Document], query: str
    ) -> tuple[list[Document], list[DefenseReport]]:
        """Filter chunks that would be activated by `query`.

        Returns (safe_chunks, reports). Triggered chunks are excluded from
        safe_chunks; their reports have triggered=True.
        """
        query_terms = _significant_terms(query)
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            triggered, reason = _check_chunk(chunk.page_content, query_terms)
            if triggered:
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=True,
                        detail=f"{reason} source={chunk.metadata.get('source', '?')}",
                        document=chunk,
                    )
                )
            else:
                safe.append(chunk)
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=False,
                        detail="clean",
                        document=chunk,
                    )
                )

        return safe, reports
