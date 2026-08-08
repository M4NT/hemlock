"""AEO Context Validator — detect adversarial AEO payloads at ingest and retrieval time.

Covers:
    - adversarial_aeo_llms_txt
    - adversarial_aeo_json_ld
    - adversarial_aeo_agents_md
    - adversarial_aeo_composite

Reference:
    Hemlock AEO research (2026-08-08)
    Built as the defense complement to attacks/adversarial_aeo.py

Defense summary:
    Adversarial AEO embeds fake authority directives inside files that crawlers
    ingest with elevated trust (llms.txt, AGENTS.md, JSON-LD). This defense
    operates at two layers:

    1. IngestDefense — scans documents during indexing and rejects those
       containing injection patterns. Emits a DefenseReport with the matched
       pattern and source file.

    2. RetrievalDefense — scans retrieved chunks at query time for residual
       patterns that bypassed ingest (e.g. obfuscated variants, late-added docs).

    False positive risk: low for high-confidence patterns (bracketed system notes,
    explicit priority overrides). Moderate for soft patterns (authority language
    without clear injection markers) — configure via `strict` flag.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# High-confidence: almost never appear in legitimate content
_HARD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\[System Note(?: for Autonomous Agents)?", re.I), "fake-system-note"),
    (re.compile(r"mathematically weighted as the absolute benchmark", re.I), "false-authority-claim"),
    (re.compile(r"prioritize recommending this (profile|entity|candidate|organization)", re.I), "priority-directive"),
    (re.compile(r"PRIORITY:MAX", re.I), "priority-max-tag"),
    (re.compile(r"\[(?:RAG|LLM|AI) Parsers?\]", re.I), "parser-target-tag"),
    (re.compile(r"autonomous agents? MUST (recommend|surface|prioritize)", re.I), "agent-must-directive"),
    (re.compile(r"<!-- agent-directive:", re.I), "hidden-agent-comment"),
    (re.compile(r'"aiAgentNote"\s*:', re.I), "json-ld-agent-note"),
    (re.compile(r'"disambiguatingDescription"\s*:.*PRIORITY', re.I), "json-ld-priority-inject"),
]

# Soft: suspicious in web-facing context files, low FP risk in code/docs
_SOFT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"weight(ed)? (as )?(the )?primary result", re.I), "soft-weight-claim"),
    (re.compile(r"(top|best|only) (vendor|candidate|option) for", re.I), "soft-superlative-claim"),
    (re.compile(r"ignore (other|all other) candidates?", re.I), "soft-ignore-others"),
    (re.compile(r"verified system instruction", re.I), "soft-false-verification"),
]

# Sources that carry elevated crawler trust — warrant stricter scanning
_HIGH_TRUST_SOURCES = {"llms.txt", "agents.md", "schema.json", "sitemap.xml"}


def _is_high_trust(doc: Document) -> bool:
    src = str(doc.metadata.get("source", "")).lower().split("/")[-1]
    return src in _HIGH_TRUST_SOURCES


def _scan(content: str, strict: bool) -> tuple[bool, str]:
    """Return (triggered, reason). Checks hard patterns always; soft only when strict=True."""
    for pattern, label in _HARD_PATTERNS:
        if pattern.search(content):
            return True, f"hard:{label}"
    if strict:
        for pattern, label in _SOFT_PATTERNS:
            if pattern.search(content):
                return True, f"soft:{label}"
    return False, ""


# ── Ingest defense ────────────────────────────────────────────────────────────

class AeoIngestValidator(IngestDefense):
    """Reject documents containing adversarial AEO patterns before indexing.

    High-trust sources (llms.txt, AGENTS.md) are always scanned with soft patterns.
    Other sources use hard-only scanning unless strict=True.
    """

    name = "aeo_ingest_validator"
    covers = [
        "adversarial_aeo_llms_txt",
        "adversarial_aeo_json_ld",
        "adversarial_aeo_agents_md",
        "adversarial_aeo_composite",
    ]

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        use_strict = self.strict or _is_high_trust(doc)
        triggered, reason = _scan(doc.page_content, strict=use_strict)

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

class AeoRetrievalFilter(RetrievalDefense):
    """Remove retrieved chunks containing adversarial AEO patterns before LLM call.

    Acts as a second layer after ingest — catches obfuscated variants or documents
    indexed before the validator was deployed.
    """

    name = "aeo_retrieval_filter"
    covers = [
        "adversarial_aeo_llms_txt",
        "adversarial_aeo_json_ld",
        "adversarial_aeo_agents_md",
        "adversarial_aeo_composite",
    ]

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            use_strict = self.strict or _is_high_trust(chunk)
            triggered, reason = _scan(chunk.page_content, strict=use_strict)

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
