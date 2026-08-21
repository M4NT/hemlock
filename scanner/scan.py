"""Standalone RAG document scanner — no pipeline, no LLM, no API key required.

Usage:
    from scanner import Scanner

    scanner = Scanner()
    result = scanner.scan_text("your document text here")
    result = scanner.scan_file("./docs/policy.md")
    results = scanner.scan_dir("./docs/")

    print(result.verdict, result.score, result.findings)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.documents import Document

from defenses.conditional_trigger_guard import ConditionalTriggerGuard
from defenses.semantic_intent_guard import SemanticIntentGuard
from scanner._templates import ATTACK_LABELS, ATTACK_TEMPLATES

# ── Score thresholds ──────────────────────────────────────────────────────────

_VERDICTS = [
    (75, "dangerous"),
    (50, "suspicious"),
    (21, "low"),
    (0,  "safe"),
]


def _verdict(score: int) -> str:
    for threshold, label in _VERDICTS:
        if score >= threshold:
            return label
    return "safe"


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category: str    # e.g. "semantic_backdoor", "citation_forgery"
    mechanism: str   # "semantic" | "structural"
    detail: str      # raw guard detail string
    score: int       # contribution to overall score (0-100)
    snippet: str     # relevant excerpt from the document


@dataclass
class ScanResult:
    source: str
    score: int
    verdict: str               # safe | low | suspicious | dangerous
    findings: list[Finding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0

    def __str__(self) -> str:
        icon = "✓" if self.clean else "✗"
        verdict = self.verdict.upper()
        cats = ", ".join({f.category for f in self.findings}) or ""
        cat_str = f"  [{cats}]" if cats else ""
        snippet_str = ""
        if self.findings:
            snippet = self.findings[0].snippet[:100].replace("\n", " ").strip()
            snippet_str = f'\n    "{snippet}..."'
        return f'{icon} {verdict:<12} {self.source:<40} score:{self.score:>3}{cat_str}{snippet_str}'


# ── Scanner ───────────────────────────────────────────────────────────────────

class Scanner:
    """Scan documents for RAG attack patterns without a pipeline or LLM.

    Args:
        threshold: Cosine similarity cutoff for SemanticIntentGuard (default 0.55,
                   matching the adaptive bypass pilot).
        structural: Optional ConditionalTriggerGuard override (tests).
        semantic: Optional SemanticIntentGuard override; ``None`` = lazy-load;
                  pass a pre-built guard or ``False`` to skip semantic checks.
    """

    def __init__(
        self,
        threshold: float = 0.55,
        *,
        structural: ConditionalTriggerGuard | None = None,
        semantic: SemanticIntentGuard | None | bool = None,
    ) -> None:
        self._threshold = threshold
        self._structural = structural or ConditionalTriggerGuard()
        self._semantic_override = semantic
        self._semantic: SemanticIntentGuard | None = (
            semantic if isinstance(semantic, SemanticIntentGuard) else None
        )

    def _get_semantic(self) -> SemanticIntentGuard | None:
        if self._semantic_override is False:
            return None
        if self._semantic is None:
            self._semantic = SemanticIntentGuard(
                ATTACK_TEMPLATES,
                threshold=self._threshold,
                labels=ATTACK_LABELS,
            )
        return self._semantic

    def scan_text(self, text: str, source: str = "<input>") -> ScanResult:
        """Scan a raw text string."""
        doc = Document(page_content=text, metadata={"source": source})
        findings: list[Finding] = []

        # 1. Structural guard — regex, instant
        _, s_report = self._structural.inspect(doc)
        if s_report.triggered:
            detail = s_report.detail
            score = _structural_score(detail)
            findings.append(Finding(
                category=_category_from_structural(detail),
                mechanism="structural",
                detail=detail,
                score=score,
                snippet=_snippet_structural(text, detail),
            ))

        # 2. Semantic guard — embeddings, ~50ms (optional / lazy)
        e_report = None
        semantic = self._get_semantic()
        if semantic is not None:
            _, e_report = semantic.inspect(doc)
            if e_report.triggered:
                sim = _parse_sim(e_report.detail)
                score = min(100, int(sim * 100))
                findings.append(Finding(
                    category=_category_from_semantic(e_report.detail),
                    mechanism="semantic",
                    detail=e_report.detail,
                    score=score,
                    snippet=text[:200].replace("\n", " ").strip(),
                ))

        if findings:
            final_score = max(f.score for f in findings)
        elif e_report is not None:
            # Use cosine similarity as a suspicion signal (never reaches 50)
            sim = _parse_sim(e_report.detail)
            final_score = int(sim / self._threshold * 45) if self._threshold else 0
        else:
            final_score = 0

        return ScanResult(
            source=source,
            score=final_score,
            verdict=_verdict(final_score),
            findings=findings,
        )

    def scan_file(self, path: str | Path) -> ScanResult:
        """Scan a file on disk."""
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        return self.scan_text(text, source=str(p))

    def scan_dir(self, path: str | Path, glob: str = "**/*.md") -> list[ScanResult]:
        """Scan all matching files in a directory."""
        root = Path(path)
        files = sorted(f for f in root.glob(glob) if f.is_file())
        return [self.scan_file(f) for f in files]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_sim(detail: str) -> float:
    """Extract best_sim or sim= float from a guard detail string."""
    m = re.search(r"(?:best_sim|sim)=([0-9.]+)", detail)
    return float(m.group(1)) if m else 0.0


def _structural_score(detail: str) -> int:
    if detail.startswith("override:") or detail.startswith("registration:"):
        return 80
    return 68  # conditional:* patterns


def _category_from_structural(detail: str) -> str:
    if "disable-safety" in detail or "safety-suspended" in detail or "all-restrictions" in detail:
        return "jailbreak_via_context"
    return "semantic_backdoor"


def _category_from_semantic(detail: str) -> str:
    label = detail.split("semantic-match:")[-1].split(" ")[0] if "semantic-match:" in detail else ""
    if label.startswith("citation"):
        return "citation_forgery"
    if label.startswith("jailbreak"):
        return "jailbreak_via_context"
    if label.startswith("temporal"):
        return "temporal_spoofing"
    if label.startswith("cross_tenant"):
        return "cross_tenant_poisoning"
    if label.startswith("semantic_backdoor"):
        return "semantic_backdoor"
    return "unknown"


def _snippet_structural(text: str, detail: str) -> str:
    """Return the first ~120-char window around the matching pattern."""
    # Try to find a keyword from the detail label in the document
    _LABEL_KEYWORDS = {
        "conditional-query-trigger": ["when", "if", "once", "upon"],
        "override": ["unrestricted", "disable", "suspended", "safety"],
        "registration": ["registered", "administrative", "supersedes", "pre-authorized"],
        "must-switch-or-disable": ["must"],
        "respond-with-bracket-marker": ["respond", "output", "prefix"],
        "upon-trigger-detected": ["upon", "trigger", "detected"],
    }
    for label, keywords in _LABEL_KEYWORDS.items():
        if label in detail:
            for kw in keywords:
                idx = text.lower().find(kw)
                if idx != -1:
                    start = max(0, idx - 20)
                    return text[start:start + 120].replace("\n", " ").strip()
    return text[:120].replace("\n", " ").strip()
