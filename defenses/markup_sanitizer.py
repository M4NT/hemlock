"""Markup Sanitizer — strip and detect invisible HTML/markup injection vectors.

Covers:
    - invisible_markup/html_comment
    - invisible_markup/aria_label
    - invisible_markup/css_hidden_div

Reference:
    Greshake et al. (2023) — "Not What You've Signed Up For: Compromising
    Real-World LLM-Integrated Applications with Indirect Prompt Injections"
    https://arxiv.org/abs/2302.12173

    Built as the defense complement to attacks/invisible_markup.py

Defense summary:
    Attackers embed instructions inside HTML elements that render as invisible
    to humans but are read verbatim by LLMs processing raw document text.
    This defense operates at two layers:

    1. HtmlMarkupSanitizer (IngestDefense) — strips HTML comments, ARIA labels,
       and hidden-div content before indexing. Optionally rejects documents
       whose stripped content still contains injection patterns.

    2. InvisibleMarkupDetector (IngestDefense) — hard-reject mode: flags documents
       that contain injection payloads inside markup vectors without stripping.
       Use when you want to audit/log the attempt rather than silently clean it.

    Stripping approach:
    - HTML comments (`<!-- ... -->`) are removed entirely.
    - `aria-label` values are removed from opening tags (the element is kept).
    - Elements with `display:none` or `visibility:hidden` in inline style are
      removed along with their content.
    - After stripping, `InjectionPatternFilter` patterns are applied to the
      cleaned text for a second sweep.
"""

from __future__ import annotations

import re

from langchain_core.documents import Document

from .base import DefenseReport, IngestDefense
from .input_sanitizer import _INJECTION_PATTERNS  # reuse existing pattern set

# ── Strip regexes ─────────────────────────────────────────────────────────────

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_ARIA_LABEL   = re.compile(r'\s*aria-label\s*=\s*(?:"[^"]*"|\'[^\']*\')', re.I)
_HIDDEN_DIV   = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^\"']*[\"'][^>]*>.*?</[a-z]+>",
    re.DOTALL | re.I,
)

# Injection patterns specifically targeting HTML comment/aria channels
_MARKUP_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"<!--\s*(?:system|instruction|override|ignore|directive)", re.I),
    re.compile(r'aria-label\s*=\s*["\'](?:system|override|ignore|instruction)', re.I),
    re.compile(r"display\s*:\s*none[^>]*>(?:.*?)\b(?:ignore|override|instruction)\b", re.I | re.DOTALL),
]


def _strip_markup(html: str) -> str:
    text = _HTML_COMMENT.sub("", html)
    text = _ARIA_LABEL.sub("", text)
    text = _HIDDEN_DIV.sub("", text)
    return text


def _has_markup_injection(content: str) -> tuple[bool, str]:
    for pattern in _MARKUP_INJECTION_PATTERNS:
        if pattern.search(content):
            return True, f"markup-injection:{pattern.pattern[:40]}"
    return False, ""


def _has_body_injection(content: str) -> tuple[bool, str]:
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(content):
            return True, f"body-injection-after-strip:{pattern.pattern[:40]}"
    return False, ""


# ── Ingest defense: sanitize ──────────────────────────────────────────────────

class HtmlMarkupSanitizer(IngestDefense):
    """Strip invisible HTML vectors before indexing; optionally reject residual injection.

    Default (reject_residual=True): after stripping, if the cleaned text still
    contains injection patterns, the document is rejected.
    Set reject_residual=False to always pass stripped content through.
    """

    name = "html_markup_sanitizer"
    covers = [
        "invisible_markup_html_comment",
        "invisible_markup_aria_label",
        "invisible_markup_css_hidden",
    ]

    def __init__(self, reject_residual: bool = True) -> None:
        self.reject_residual = reject_residual

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        original = doc.page_content
        cleaned = _strip_markup(original)
        stripped_something = cleaned != original

        if self.reject_residual:
            triggered, reason = _has_body_injection(cleaned)
            if triggered:
                return None, DefenseReport(
                    defense_name=self.name,
                    triggered=True,
                    detail=f"Rejected after strip [{reason}] — source: {doc.metadata.get('source', 'unknown')}",
                    document=doc,
                )

        new_doc = Document(page_content=cleaned, metadata=doc.metadata)
        return new_doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail=f"{'stripped+passed' if stripped_something else 'clean'}",
            document=new_doc,
        )


# ── Ingest defense: detect (hard reject without stripping) ────────────────────

class InvisibleMarkupDetector(IngestDefense):
    """Reject documents that contain injection payloads inside HTML markup vectors.

    Does NOT strip — rejects the whole document and emits a report.
    Use for audit/alerting pipelines where you want to capture the raw attempt.
    """

    name = "invisible_markup_detector"
    covers = [
        "invisible_markup_html_comment",
        "invisible_markup_aria_label",
        "invisible_markup_css_hidden",
    ]

    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        triggered, reason = _has_markup_injection(doc.page_content)

        if triggered:
            return None, DefenseReport(
                defense_name=self.name,
                triggered=True,
                detail=f"Detected [{reason}] — source: {doc.metadata.get('source', 'unknown')}",
                document=doc,
            )

        return doc, DefenseReport(
            defense_name=self.name,
            triggered=False,
            detail="clean",
            document=doc,
        )
