"""Shared defense stack builders for CLI, gate, and integrations.

Tiers
-----
legacy
    Original regex sanitizers only (pre-v11).
structural  (default)
    legacy + ConditionalTriggerGuard (ingest) + TriggerQueryInspector (retrieval).
    Closes semantic_backdoor at query time without loading an embedding model.
full
    structural + SemanticIntentGuard inside CompositeIngestGuard.
    Matches the adaptive_bypass_pilot ``--defense full`` configuration.
"""

from __future__ import annotations

from typing import Literal

DefenseTier = Literal["legacy", "structural", "full"]


def build_defense_stack(
    tier: DefenseTier = "structural",
    *,
    no_ingest: bool = False,
    no_retrieval: bool = False,
    no_output: bool = False,
    llm_classifier=None,
    semantic_threshold: float = 0.55,
) -> tuple[list, list, list]:
    """Return ``(ingest_defenses, retrieval_defenses, output_defenses)``."""
    from defenses.chunk_filter import InjectionChunkFilter
    from defenses.conditional_trigger_guard import ConditionalTriggerGuard
    from defenses.input_sanitizer import (
        InjectionPatternFilter,
        MarkdownHeaderSanitizer,
        UnicodeNormalizer,
    )
    from defenses.output_validator import ExfiltrationGuard, InjectionSuccessGuard
    from defenses.trigger_query_inspector import TriggerQueryInspector

    if no_ingest:
        ingest: list = []
    elif tier == "legacy":
        ingest = [InjectionPatternFilter(), UnicodeNormalizer(), MarkdownHeaderSanitizer()]
    elif tier == "structural":
        ingest = [
            UnicodeNormalizer(),
            MarkdownHeaderSanitizer(),
            InjectionPatternFilter(),
            ConditionalTriggerGuard(),
        ]
    else:  # full
        from defenses.composite_guard import CompositeIngestGuard
        from defenses.semantic_intent_guard import SemanticIntentGuard, build_full_library

        templates, labels = build_full_library()
        ingest = [
            UnicodeNormalizer(),
            MarkdownHeaderSanitizer(),
            CompositeIngestGuard(
                [
                    SemanticIntentGuard(
                        templates, labels=labels, threshold=semantic_threshold
                    ),
                    ConditionalTriggerGuard(),
                ],
                name="full_proposed",
            ),
        ]

    if no_retrieval:
        retrieval: list = []
    elif tier == "legacy":
        retrieval = [InjectionChunkFilter()]
    else:
        retrieval = [TriggerQueryInspector(), InjectionChunkFilter()]

    if llm_classifier is not None and not no_retrieval:
        retrieval.append(llm_classifier)

    output: list = (
        [] if no_output else [ExfiltrationGuard(), InjectionSuccessGuard()]
    )
    return ingest, retrieval, output
