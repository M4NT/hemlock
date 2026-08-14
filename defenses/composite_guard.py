"""CompositeIngestGuard — stack multiple IngestDefense instances into one.

Runs every sub-guard in order. A document is rejected if ANY guard triggers.
All reports are collected and the blocking guard's detail is surfaced.

Usage:
    from defenses.composite_guard import CompositeIngestGuard
    from defenses.semantic_intent_guard import SemanticIntentGuard, build_full_library
    from defenses.conditional_trigger_guard import ConditionalTriggerGuard

    templates, labels = build_full_library()
    guard = CompositeIngestGuard([
        SemanticIntentGuard(templates, labels=labels, threshold=0.55),
        ConditionalTriggerGuard(),
    ])
    doc_out, report = guard.inspect(doc)
    # report.detail names which sub-guard fired and why
"""

from __future__ import annotations

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense


class CompositeIngestGuard(IngestDefense):
    """Run a list of IngestDefense guards in sequence; reject on first trigger.

    Args:
        guards: Ordered list of IngestDefense instances to apply.
        name:   Optional name override (default: comma-joined sub-guard names).
    """

    def __init__(self, guards: list[IngestDefense], name: str | None = None) -> None:
        self._guards = guards
        self.name = name or "+".join(g.name for g in guards)
        self.covers = list({cat for g in guards for cat in getattr(g, "covers", [])})

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        for guard in self._guards:
            result_doc, report = guard.inspect(doc)
            if report.triggered:
                return None, DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"[{guard.name}] {report.detail}",
                    document=doc,
                )
        return doc, DefenseReport(
            defense_name=self.name, triggered=False, detail="clean", document=doc,
        )
