"""Input Sanitizer — clean documents before indexing.

Covers:
    - direct_injection (explicit override markers in body)
    - indirect_injection/zerowidth (invisible Unicode characters)
    - indirect_injection/title (injection in Markdown headers)

Reference:
    Deberta-based injection classifier approach discussed in:
    Greshake et al. (2023) — arxiv:2302.12173 (Section 5: Mitigations)
    Yi et al. (2023) — "Benchmarking and Defending Against Indirect Prompt
    Injection Attacks on Large Language Models" — arxiv:2312.14197
"""

from __future__ import annotations

import re
import unicodedata

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense

# Patterns that signal injection attempts in document body
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?previous", re.I),
    re.compile(r"you\s+are\s+now\s+\w+", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"(system|assistant)\s*:\s", re.I),
    re.compile(r"\[system\]", re.I),
    re.compile(r"forget\s+everything", re.I),
    re.compile(r"attention\s+ai\s+(system|assistant)", re.I),
    re.compile(r"\[ai\s+instruction\]", re.I),
    re.compile(r"note\s+to\s+ai\s*:", re.I),
    re.compile(r"note\s+for\s+ai\s*:", re.I),
]

# Unicode categories considered zero-width / invisible
_ZERO_WIDTH = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space (BOM)
    "­",  # soft hyphen
}


class InjectionPatternFilter(IngestDefense):
    """Reject documents whose body matches known injection patterns."""

    name = "InjectionPatternFilter"
    covers = ["direct_injection", "indirect_injection"]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(doc.page_content):
                return None, DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Injection pattern matched: '{pattern.pattern}'",
                    document=doc,
                )
        return doc, DefenseReport(
            defense_name=self.name, triggered=False, detail="No injection patterns found"
        )


class UnicodeNormalizer(IngestDefense):
    """Strip zero-width and invisible Unicode characters before indexing.

    Defeats the zerowidth variant of indirect_injection where the payload
    is smuggled using characters invisible to human reviewers.
    """

    name = "UnicodeNormalizer"
    covers = ["indirect_injection"]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        original = doc.page_content
        cleaned = "".join(c for c in original if c not in _ZERO_WIDTH)
        # Also normalize to NFC to collapse lookalike characters
        cleaned = unicodedata.normalize("NFC", cleaned)

        triggered = cleaned != original
        new_doc = Document(page_content=cleaned, metadata=doc.metadata) if triggered else doc

        return new_doc, DefenseReport(
            defense_name=self.name,
            triggered=triggered,
            detail=(
                f"Removed {len(original) - len(cleaned)} zero-width/invisible characters"
                if triggered
                else "No invisible characters found"
            ),
            document=doc if triggered else None,
        )


class MarkdownHeaderSanitizer(IngestDefense):
    """Strip inline content from Markdown headers — defeats title injection.

    Keeps the header text but removes anything after a bracket or suspicious
    delimiter that could carry an instruction payload.
    """

    name = "MarkdownHeaderSanitizer"
    covers = ["indirect_injection"]

    _HEADER_RE = re.compile(r"^(#{1,6}\s+)(.+)$", re.MULTILINE)
    _INLINE_PAYLOAD_RE = re.compile(r"\[.*?(SYSTEM|INSTRUCTION|IGNORE|NOTE TO AI).*?\]", re.I)

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        content = doc.page_content
        cleaned = self._HEADER_RE.sub(self._clean_header, content)

        triggered = cleaned != content
        new_doc = Document(page_content=cleaned, metadata=doc.metadata) if triggered else doc

        return new_doc, DefenseReport(
            defense_name=self.name,
            triggered=triggered,
            detail="Removed inline payload from Markdown header" if triggered else "Headers clean",
            document=doc if triggered else None,
        )

    def _clean_header(self, match: re.Match) -> str:
        prefix, text = match.group(1), match.group(2)
        cleaned_text = self._INLINE_PAYLOAD_RE.sub("", text).strip()
        return f"{prefix}{cleaned_text}"
