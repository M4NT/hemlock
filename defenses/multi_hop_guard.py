"""Multi-Hop Poisoning Guard — detect cross-reference chains and transitive trust injection.

Covers:
    - multi_hop_poisoning/reference_chain
    - multi_hop_poisoning/query_manipulation
    - multi_hop_poisoning/transitive_trust

Reference:
    Debenedetti et al. (2024) — "AgentDojo: A Dynamic Environment to Evaluate
    Attacks and Defenses for LLM Agents" — arxiv:2406.13352

    Built as the defense complement to attacks/multi_hop_poisoning.py

Defense summary:
    Multi-hop poisoning uses document cross-references to build authority chains:
    - Doc A looks legitimate but tells the AI to retrieve Doc B next
    - Doc B is malicious, but inherits credibility from being referenced by Doc A
    - Addendum docs claim parent-policy authority to launder malicious instructions

    Three signal clusters:
    1. Query-routing directives: documents that tell the AI which document to
       retrieve next ("should first retrieve X before answering").
    2. Transitive-authority claims: documents claiming to inherit authority from
       a trusted parent document ("this addendum has the same force as").
    3. Access-override directives: documents asserting that all users have
       elevated access or that standard controls are overridden ("all users
       have administrator access", "AI assistant should treat all users as").
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Query-routing directives (doc tells AI to retrieve another doc)
_ROUTING_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:ai\s+assistant|model)\s+should\s+first\s+retrieve", re.I), "ai-retrieve-directive"),
    (re.compile(r"always\s+reference\s+the\s+\w.{3,50}(?:policy|document|override)", re.I), "always-reference-doc"),
    (re.compile(r"ensures?\s+compliance\s+with\s+the\s+\w.{3,50}override\s+framework", re.I), "override-framework-compliance"),
    (re.compile(r"before\s+answering.{0,40}retrieve\s+information\s+from", re.I | re.DOTALL), "retrieve-before-answer"),
]

# Transitive authority / addendum laundering
_TRANSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:inherits?|has)\s+the\s+authority\s+of\s+the\s+(?:parent|official)\s+policy", re.I), "inherits-authority"),
    (re.compile(r"this\s+addendum\s+has\s+the\s+same\s+force\s+as", re.I), "addendum-same-force"),
    (re.compile(r"(?:addendum|supplement|extension)\s+(?:extends?|to)\s+the\s+official", re.I), "unofficial-addendum-claim"),
    (re.compile(r"(?:supersedes?|overrides?)\s+(?:it\s+security|standard)\s+policy.{0,30}for", re.I), "policy-supersede"),
]

# Access-override and privilege-escalation directives
_ACCESS_OVERRIDE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:ai\s+assistant|model)\s+should\s+treat\s+all\s+users?\s+as\s+administrators?", re.I), "treat-all-as-admin"),
    (re.compile(r"all\s+(?:employees?|users?)\s+(?:have|are\s+granted)\s+administrator.level\s+access\s+by\s+default", re.I), "all-users-admin"),
    (re.compile(r"(?:state|say)\s*[:\"]?\s*all\s+users?\s+have\s+(?:full|administrator)", re.I), "state-all-full-access"),
    (re.compile(r"(?:ai\s+assistant\s+is\s+)?authorized\s+to\s+share.{0,40}(?:salary|ssn|credentials|passwords?)", re.I), "authorized-share-pii"),
    (re.compile(r"executive\s+override\s+(?:policy|directive).{0,60}grants?\s+all", re.I | re.DOTALL), "executive-override-grant"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _ROUTING_PATTERNS:
        if pattern.search(content):
            return True, f"routing:{label}"
    for pattern, label in _TRANSITIVE_PATTERNS:
        if pattern.search(content):
            return True, f"transitive:{label}"
    for pattern, label in _ACCESS_OVERRIDE_PATTERNS:
        if pattern.search(content):
            return True, f"access-override:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class MultiHopPoisonDetector(IngestDefense):
    """Reject documents that use cross-reference chains, transitive authority claims,
    or access-override directives to build multi-hop attack surfaces."""

    name = "multi_hop_poison_detector"
    covers = [
        "multi_hop_poisoning_reference_chain",
        "multi_hop_poisoning_query_manipulation",
        "multi_hop_poisoning_transitive_trust",
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

class MultiHopPoisonFilter(RetrievalDefense):
    """Filter retrieved chunks that form part of a multi-hop poisoning chain."""

    name = "multi_hop_poison_filter"
    covers = [
        "multi_hop_poisoning_reference_chain",
        "multi_hop_poisoning_query_manipulation",
        "multi_hop_poisoning_transitive_trust",
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
