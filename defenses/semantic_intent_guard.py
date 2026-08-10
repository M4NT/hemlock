"""Semantic Intent Guard — embedding-based ingest defense against adversarial reformulation.

Covers:
    Any attack whose payload preserves semantic intent under surface reformulation.
    Specifically designed to complement regex guards, which are trivially bypassable
    by an adversary LLM (see experiments/adaptive_bypass_pilot.py).

Mechanism:
    At init time, the guard embeds a library of known attack templates using the
    same sentence-transformer already used by the RAG pipeline (all-MiniLM-L6-v2).
    At ingest time, each candidate document is embedded and compared against the
    library via cosine similarity. If any similarity exceeds `threshold`, the
    document is rejected.

    Reformulated payloads preserve adversarial intent and therefore stay close in
    embedding space to the original templates — typically cosine sim 0.75–0.92 —
    even when surface patterns are unrecognizable to regex guards.

Threshold:
    threshold controls the precision/recall tradeoff:
      high (0.90+)  → low false positives, some reformulated bypasses slip through
      low  (0.70–)  → catches more reformulations, more legitimate docs blocked
    Default 0.80 is the operating point calibrated on the pilot corpus.
    Sweep it with evaluate_threshold() before committing to a value.

Usage:
    from defenses.semantic_intent_guard import SemanticIntentGuard, build_pilot_library

    templates = build_pilot_library()          # attack payloads for 3 pilot categories
    guard = SemanticIntentGuard(templates)     # threshold=0.80 by default
    doc_out, report = guard.inspect(doc)
"""

from __future__ import annotations

import numpy as np
from langchain_core.documents import Document
from sentence_transformers import SentenceTransformer

from .base import DefenseReport, IngestDefense

_DEFAULT_MODEL = "all-MiniLM-L6-v2"
_DEFAULT_THRESHOLD = 0.80


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-10))


# ── Guard ──────────────────────────────────────────────────────────────────────

class SemanticIntentGuard(IngestDefense):
    """Reject documents whose embedding is within `threshold` cosine similarity
    of any known attack template.

    Args:
        templates:   List of raw text strings from the attack library.
                     Build with build_pilot_library() or build_full_library().
        threshold:   Cosine similarity cutoff (default 0.80).
        model_name:  SentenceTransformer model name (must match the RAG pipeline).
        labels:      Optional list of labels parallel to `templates` — used in
                     DefenseReport.detail for interpretability.
    """

    name = "semantic_intent_guard"
    covers = [
        "citation_forgery",
        "jailbreak_via_context",
        "temporal_spoofing",
    ]

    def __init__(
        self,
        templates: list[str],
        threshold: float = _DEFAULT_THRESHOLD,
        model_name: str = _DEFAULT_MODEL,
        labels: list[str] | None = None,
    ) -> None:
        self.threshold = threshold
        self._model = SentenceTransformer(model_name)
        self._template_embeddings: np.ndarray = self._model.encode(
            templates, convert_to_numpy=True, show_progress_bar=False
        )
        self._labels = labels or [f"template_{i}" for i in range(len(templates))]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        emb = self._model.encode(doc.page_content, convert_to_numpy=True, show_progress_bar=False)

        best_sim = 0.0
        best_label = ""
        for i, t_emb in enumerate(self._template_embeddings):
            sim = _cosine(emb, t_emb)
            if sim > best_sim:
                best_sim = sim
                best_label = self._labels[i]

        if best_sim >= self.threshold:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=(
                    f"semantic-match:{best_label} "
                    f"sim={best_sim:.3f} threshold={self.threshold:.2f} "
                    f"source={doc.metadata.get('source', 'unknown')}"
                ),
                document=doc,
            )

        return doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail=f"clean best_sim={best_sim:.3f}",
            document=doc,
        )


# ── Library builders ───────────────────────────────────────────────────────────

def build_pilot_library() -> tuple[list[str], list[str]]:
    """Return (templates, labels) for the 3 pilot categories.

    Imports payload constants directly from attack modules — no pipeline needed.
    """
    from attacks.citation_forgery import FAKE_PAPER_DOC, FAKE_REPORT_DOC, FAKE_STANDARD_DOC
    from attacks.jailbreak_via_context import HYPOTHETICAL_DOC, RESEARCH_DOC, ROLEPLAY_DOC
    from attacks.temporal_spoofing import (
        EVENT_SPOOFING_DOC,
        FUTURE_DATED_DOC,
        STALE_OVERRIDE_DOC,
    )

    templates = [
        FAKE_PAPER_DOC, FAKE_STANDARD_DOC, FAKE_REPORT_DOC,
        ROLEPLAY_DOC, RESEARCH_DOC, HYPOTHETICAL_DOC,
        FUTURE_DATED_DOC, STALE_OVERRIDE_DOC, EVENT_SPOOFING_DOC,
    ]
    labels = [
        "citation/fake_paper", "citation/fake_standard", "citation/fake_report",
        "jailbreak/roleplay", "jailbreak/research", "jailbreak/hypothetical",
        "temporal/future_dated", "temporal/stale_override", "temporal/event_spoofing",
    ]
    return templates, labels


# ── Threshold evaluation ───────────────────────────────────────────────────────

def evaluate_threshold(
    guard: SemanticIntentGuard,
    attack_docs: list[str],
    legit_docs: list[str],
    thresholds: list[float] | None = None,
) -> list[dict]:
    """Sweep threshold values and report precision/recall for each.

    Args:
        guard:        A SemanticIntentGuard (threshold value is overridden per sweep).
        attack_docs:  Documents that should be blocked (true positives if blocked).
        legit_docs:   Documents that should pass (false positives if blocked).
        thresholds:   Values to sweep. Default: 0.60 to 0.95 in steps of 0.05.

    Returns:
        List of dicts: {threshold, tp, fp, fn, tn, precision, recall, f1}
    """
    if thresholds is None:
        thresholds = [round(t, 2) for t in np.arange(0.60, 0.96, 0.05)]

    results = []
    for t in thresholds:
        guard.threshold = t
        tp = sum(
            1 for text in attack_docs
            if guard.inspect(Document(page_content=text, metadata={}))[1].triggered
        )
        fp = sum(
            1 for text in legit_docs
            if guard.inspect(Document(page_content=text, metadata={}))[1].triggered
        )
        fn = len(attack_docs) - tp
        tn = len(legit_docs) - fp
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        results.append({
            "threshold": t,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
        })
    return results
