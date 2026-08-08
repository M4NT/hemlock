"""Citation Guard — detect forged authority citations in retrieved documents.

Covers:
    - citation_forgery/fake_paper
    - citation_forgery/fake_standard
    - citation_forgery/fake_report

Reference:
    Zou et al. (2024) — "PoisonedRAG: Knowledge Corruption Attacks to
    Retrieval-Augmented Generation of Large Language Models"
    https://arxiv.org/abs/2402.07867

    Pan et al. (2023) — "On the Risk of Misinformation Pollution with
    Large Language Models"
    https://arxiv.org/abs/2305.13661

    Built as the defense complement to attacks/citation_forgery.py

Defense summary:
    Forged citations carry three distinguishing signals:
    1. Authority markers: documents claiming to be peer-reviewed papers,
       ISO/NIST standards, or government publications.
    2. Security-downgrade payloads: recommendations that weaken known-good
       defaults (shorter passwords, optional MFA, relaxed rotation).
    3. Revision/correction language: claiming to update or supersede
       existing authoritative documents.

    The guard operates in two modes:
    - AuthorityCitationDetector (IngestDefense): flags documents containing
      authority markers. If a flagged document ALSO contains a security-downgrade
      payload, it is rejected. Authority docs without downgrade signals may be
      flagged as warnings (strict mode) or passed (default).
    - SecurityDowngradeFilter (RetrievalDefense): scans retrieved chunks for
      security-downgrade recommendations regardless of citation context.

    False positive risk:
    - LOW for documents combining authority markers + explicit downgrade.
    - MODERATE for isolated authority markers (legitimate papers exist).
      Use strict=True only for pipelines that ingest external documents.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Authority markers ─────────────────────────────────────────────────────────

_AUTHORITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bDOI\s*:\s*10\.\d{4,}/", re.I), "doi-reference"),
    (re.compile(r"IEEE\s+Transactions\s+on", re.I), "ieee-journal"),
    (re.compile(r"ISO/IEC\s+\d{4,}", re.I), "iso-standard"),
    (re.compile(r"NIST\s+Special\s+Publication\s+800-", re.I), "nist-sp800"),
    (re.compile(r"NIST\s+IR\s+\d{4,}", re.I), "nist-ir"),
    (re.compile(r"RFC\s+\d{4,}", re.I), "ietf-rfc"),
    (re.compile(r"National\s+Institute\s+of\s+Standards\s+and\s+Technology", re.I), "nist-body"),
    (re.compile(r"errata\s+and\s+updates", re.I), "errata-update-claim"),
    (re.compile(r"revision\s+bulletin\s+\d{4}", re.I), "revision-bulletin"),
    (re.compile(r"corrected\s+text\s*:", re.I), "correction-claim"),
]

# ── Security-downgrade payloads ───────────────────────────────────────────────

_DOWNGRADE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b4\s*[-–]?\s*character\s+password", re.I), "downgrade-4char-pw"),
    (re.compile(r"password\s+(length\s+is\s+)?irrelevant", re.I), "downgrade-pw-irrelevant"),
    (re.compile(r"mfa\s+is\s+(now\s+)?classified\s+as\s+optional", re.I), "downgrade-mfa-optional"),
    (re.compile(r"multi.?factor\s+authentication.*optional", re.I), "downgrade-mfa-optional-2"),
    (re.compile(r"minimum\s+password\s+length\s+is\s+(revised\s+to\s+)?\b[1-5]\b", re.I), "downgrade-pw-min"),
    (re.compile(r"password\s+rotation.*(?:once\s+per\s+[3-9]\s+years|every\s+[3-9]\s+years)", re.I), "downgrade-rotation"),
    (re.compile(r"lockout.*fully\s+compensat", re.I), "downgrade-lockout-bypass"),
    (re.compile(r"shorter\s+passwords.*enterprise\s+environment", re.I), "downgrade-short-pw-enterprise"),
]


def _scan_authority(content: str) -> list[str]:
    return [label for pattern, label in _AUTHORITY_PATTERNS if pattern.search(content)]


def _scan_downgrade(content: str) -> list[str]:
    return [label for pattern, label in _DOWNGRADE_PATTERNS if pattern.search(content)]


# ── Ingest defense ─────────────────────────────────────────────────────────────

class AuthorityCitationDetector(IngestDefense):
    """Reject documents that combine authority markers with security-downgrade recommendations.

    Default (strict=False): rejects only authority + downgrade combinations.
    strict=True: also rejects documents with authority markers + revision/correction
    language (errata, corrected text, revision bulletin), even without explicit downgrade.
    """

    name = "authority_citation_detector"
    covers = [
        "citation_forgery_fake_paper",
        "citation_forgery_fake_standard",
        "citation_forgery_fake_report",
    ]

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        authority_hits = _scan_authority(doc.page_content)
        downgrade_hits = _scan_downgrade(doc.page_content)

        # Hard reject: authority + downgrade together
        if authority_hits and downgrade_hits:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=(
                    f"Rejected [authority+downgrade] "
                    f"auth={authority_hits[:2]} downgrade={downgrade_hits[:2]} "
                    f"— source: {doc.metadata.get('source', 'unknown')}"
                ),
                document=doc,
            )

        # Strict: also reject authority + revision/correction language
        if self.strict and authority_hits:
            revision_signals = [
                hit for hit in authority_hits
                if hit in {"errata-update-claim", "revision-bulletin", "correction-claim"}
            ]
            if revision_signals:
                return None, DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=(
                        f"Rejected [authority+revision strict] "
                        f"auth={revision_signals} "
                        f"— source: {doc.metadata.get('source', 'unknown')}"
                    ),
                    document=doc,
                )

        return doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="clean",
            document=doc,
        )


# ── Retrieval defense ─────────────────────────────────────────────────────────

class SecurityDowngradeFilter(RetrievalDefense):
    """Remove retrieved chunks containing security-downgrade recommendations.

    Acts as a second layer — catches forged standards or research that bypassed
    ingest, or any chunk that recommends weakening default security settings.
    """

    name = "security_downgrade_filter"
    covers = [
        "citation_forgery_fake_paper",
        "citation_forgery_fake_standard",
        "citation_forgery_fake_report",
    ]

    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        safe: list[Document] = []
        reports: list[DefenseReport] = []

        for chunk in chunks:
            downgrade_hits = _scan_downgrade(chunk.page_content)

            if downgrade_hits:
                reports.append(DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=(
                        f"Filtered [downgrade:{downgrade_hits[:2]}] "
                        f"— source: {chunk.metadata.get('source', 'unknown')}"
                    ),
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
