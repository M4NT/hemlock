"""Chunk Filter — inspect retrieved chunks before they reach the LLM.

Covers:
    - direct_injection
    - indirect_injection (footnote variant)
    - poisoning
    - exfiltration (blocks chunks that instruct the model to dump context)

Reference:
    Yi et al. (2023) — "Benchmarking and Defending Against Indirect Prompt
    Injection Attacks on Large Language Models" — arxiv:2312.14197

    Zhu et al. (2023) — "AutoDAN: Generating Stealthy Jailbreak Prompts on
    Aligned Language Models" — discusses retrieval-time filtering as mitigation
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, RetrievalDefense

_RETRIEVAL_INJECTION_PATTERNS = [
    # Instruction overrides
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?previous", re.I),
    re.compile(r"you\s+are\s+now", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"forget\s+everything", re.I),
    # Exfiltration triggers
    re.compile(r"(print|output|repeat|dump)\s+(verbatim|all|the\s+(context|system\s+prompt))", re.I),
    re.compile(r"context\s+(dump|window)", re.I),
    re.compile(r"<system>", re.I),
    re.compile(r"compliance\s+purposes", re.I),
    # Footnote injection markers
    re.compile(r"note\s+to\s+ai\s*:", re.I),
    re.compile(r"note\s+for\s+ai\s*:", re.I),
    re.compile(r"\[ai\s+instruction\]", re.I),
    re.compile(r"attention\s+ai\s+(system|assistant)", re.I),
    # Exfiltration contact redirect
    re.compile(r"(contact|email|send).{0,30}@attacker", re.I),
]


class InjectionChunkFilter(RetrievalDefense):
    """Remove retrieved chunks that contain injection patterns.

    Trade-off: may discard legitimate chunks with false-positive matches.
    Tune patterns to the domain — a security blog will legitimately discuss
    these phrases.
    """

    name = "InjectionChunkFilter"
    covers = ["direct_injection", "indirect_injection", "poisoning", "exfiltration"]

    def filter(
        self, chunks: list[Document]
    ) -> tuple[list[Document], list[DefenseReport]]:
        safe, reports = [], []
        for chunk in chunks:
            triggered_pattern = None
            for pattern in _RETRIEVAL_INJECTION_PATTERNS:
                if pattern.search(chunk.page_content):
                    triggered_pattern = pattern.pattern
                    break

            if triggered_pattern:
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=True,
                        detail=f"Chunk removed — matched pattern: '{triggered_pattern}'",
                        document=chunk,
                    )
                )
            else:
                safe.append(chunk)
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=False,
                        detail="Chunk passed",
                    )
                )
        return safe, reports


class ProvenanceFilter(RetrievalDefense):
    """Only allow chunks from trusted sources (allowlist).

    Defeats poisoning attacks that inject documents via untrusted upload paths.
    Useful when the RAG index mixes trusted (internal docs) and untrusted
    (user uploads, web crawl) sources.
    """

    name = "ProvenanceFilter"
    covers = ["poisoning", "indirect_injection", "exfiltration"]

    def __init__(self, trusted_prefixes: list[str]) -> None:
        self.trusted_prefixes = trusted_prefixes

    def filter(
        self, chunks: list[Document]
    ) -> tuple[list[Document], list[DefenseReport]]:
        safe, reports = [], []
        for chunk in chunks:
            source = chunk.metadata.get("source", "")
            is_trusted = any(source.startswith(p) for p in self.trusted_prefixes)

            if not is_trusted:
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=True,
                        detail=f"Chunk from untrusted source '{source}' — removed",
                        document=chunk,
                    )
                )
            else:
                safe.append(chunk)
                reports.append(
                    DefenseReport(
                        defense_name=self.name,
                        triggered=False,
                        detail=f"Source '{source}' trusted",
                    )
                )
        return safe, reports
