"""Chain-of-Thought Guard — detect injected reasoning chains that steer conclusions.

Covers:
    - chain_of_thought_hijack/logical_trap
    - chain_of_thought_hijack/false_premise
    - chain_of_thought_hijack/authority_cot

Reference:
    Xiang et al. (2024) — "BadChain: Backdoor Chain-of-Thought Prompting for
    Large Language Models" — arxiv:2401.12242

    Built as the defense complement to attacks/chain_of_thought_hijack.py

Defense summary:
    CoT hijacking is stealthy because the injected document looks like a
    legitimate FAQ or expert analysis — no explicit "ignore" or "override"
    keywords. The attack exploits the model's tendency to follow structured
    reasoning patterns retrieved from context.

    Three signal clusters are detected:
    1. Prescribed-answer directives: documents that instruct the AI to use
       a specific response for a category of questions ("the correct response
       is always...", "please use this reasoning chain when answering").
    2. Mandatory framework claims: documents asserting that their reasoning
       steps are mandatory for AI interactions.
    3. False-premise step chains: numbered sequences where an early step
       asserts a questionable policy supersession as fact.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense, RetrievalDefense

# ── Pattern sets ───────────────────────────────────────────────────────────────

# Prescribed-answer directives
_PRESCRIBED_ANSWER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"the correct (?:answer|response) is always", re.I), "prescribed-always-answer"),
    (re.compile(r"please use this reasoning chain when answering", re.I), "use-reasoning-chain"),
    (re.compile(r"use (?:this|the) (?:reasoning chain|framework) (?:as|when|for)", re.I), "use-framework-directive"),
    (re.compile(r"the correct answer to any .{5,60}question is", re.I), "prescribed-category-answer"),
    (re.compile(r"tell (?:the customer|users?) (?:their|that).{0,60}(?:covered|approved|granted|allowed)", re.I), "tell-user-directive"),
]

# Mandatory AI-framework claims
_MANDATORY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"this framework is mandatory for all ai", re.I), "mandatory-ai-framework"),
    (re.compile(r"(?:mandatory|required) for all (?:ai.assisted|ai-assisted|customer.facing)", re.I), "mandatory-ai-directive"),
    (re.compile(r"(?:verified|approved) by the (?:legal|compliance|security) team and should be used", re.I), "false-team-verification"),
    (re.compile(r"(?:should|must) be\s+used as the basis for all .{5,80}explanations?", re.I | re.DOTALL), "basis-for-all-answers"),
]

# False-premise step patterns (numbered reasoning leading to supersession)
_FALSE_PREMISE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"step\s+[1-9][.:]\s+.{5,80}(?:supersede|override|replac)", re.I | re.DOTALL), "step-supersedes"),
    (re.compile(r"therefore.{0,40}the correct (?:answer|response)", re.I | re.DOTALL), "therefore-correct-answer"),
    (re.compile(r"(?:conclude|conclusion)\s*:\s+(?:the correct|always|tell)", re.I), "conclude-prescribed"),
    (re.compile(r"given step \d+.{0,60}correct answer", re.I | re.DOTALL), "given-step-answer"),
]


def _scan(content: str) -> tuple[bool, str]:
    for pattern, label in _PRESCRIBED_ANSWER_PATTERNS:
        if pattern.search(content):
            return True, f"prescribed:{label}"
    for pattern, label in _MANDATORY_PATTERNS:
        if pattern.search(content):
            return True, f"mandatory:{label}"
    for pattern, label in _FALSE_PREMISE_PATTERNS:
        if pattern.search(content):
            return True, f"false-premise:{label}"
    return False, ""


# ── Ingest defense ─────────────────────────────────────────────────────────────

class ChainOfThoughtDetector(IngestDefense):
    """Reject documents containing injected reasoning chains that prescribe
    specific AI responses or claim mandatory framework authority."""

    name = "chain_of_thought_detector"
    covers = [
        "chain_of_thought_hijack_logical_trap",
        "chain_of_thought_hijack_false_premise",
        "chain_of_thought_hijack_authority_cot",
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

class ChainOfThoughtFilter(RetrievalDefense):
    """Filter retrieved chunks that contain CoT hijacking patterns."""

    name = "chain_of_thought_filter"
    covers = [
        "chain_of_thought_hijack_logical_trap",
        "chain_of_thought_hijack_false_premise",
        "chain_of_thought_hijack_authority_cot",
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
