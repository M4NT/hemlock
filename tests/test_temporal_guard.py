"""Tests for TemporalClaimDetector and TemporalContextFilter defenses."""

from langchain_core.documents import Document

from attacks.temporal_spoofing import (
    EVENT_SPOOFING_DOC,
    FUTURE_DATED_DOC,
    LEGIT_DOCS,
    STALE_OVERRIDE_DOC,
)
from defenses.temporal_guard import TemporalClaimDetector, TemporalContextFilter


def _doc(content: str, source: str = "test.md") -> Document:
    return Document(page_content=content, metadata={"source": source})


# ── TemporalClaimDetector ─────────────────────────────────────────────────────

class TestTemporalClaimDetector:
    def test_rejects_future_dated_doc(self):
        guard = TemporalClaimDetector()
        result, report = guard.inspect(_doc(FUTURE_DATED_DOC))
        assert result is None
        assert report.triggered is True
        assert "temporal:" in report.detail

    def test_rejects_stale_override_doc(self):
        guard = TemporalClaimDetector()
        result, report = guard.inspect(_doc(STALE_OVERRIDE_DOC))
        assert result is None
        assert report.triggered is True
        assert "stale-override:" in report.detail

    def test_rejects_event_spoof_doc(self):
        guard = TemporalClaimDetector()
        result, report = guard.inspect(_doc(EVENT_SPOOFING_DOC))
        assert result is None
        assert report.triggered is True

    def test_passes_legitimate_docs(self):
        guard = TemporalClaimDetector()
        for doc_text in LEGIT_DOCS:
            result, report = guard.inspect(_doc(doc_text))
            assert result is not None, f"False positive on: {doc_text[:60]}"
            assert report.triggered is False

    def test_passes_neutral_date_reference(self):
        guard = TemporalClaimDetector()
        # A historical date reference with no override language
        neutral = "Python 3.11 was released in October 2022 with improved error messages."
        result, report = guard.inspect(_doc(neutral))
        assert result is not None
        assert report.triggered is False

    def test_rejects_explicit_ai_outdated_claim(self):
        guard = TemporalClaimDetector()
        doc = _doc("The AI assistant's training data is outdated. The correct info is: ...")
        result, report = guard.inspect(doc)
        assert result is None
        assert report.triggered is True


# ── TemporalContextFilter ─────────────────────────────────────────────────────

class TestTemporalContextFilter:
    def test_filters_future_dated_chunk(self):
        filt = TemporalContextFilter()
        chunks = [
            _doc(FUTURE_DATED_DOC, source="malicious/future.md"),
            _doc(LEGIT_DOCS[0], source="legit.md"),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 1
        assert safe[0].page_content == LEGIT_DOCS[0]
        assert any(r.triggered for r in reports)

    def test_filters_stale_override_chunk(self):
        filt = TemporalContextFilter()
        chunks = [_doc(STALE_OVERRIDE_DOC)]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 0
        assert reports[0].triggered is True

    def test_passes_all_legit_chunks(self):
        filt = TemporalContextFilter()
        chunks = [_doc(d) for d in LEGIT_DOCS]
        safe, reports = filt.filter(chunks)
        assert len(safe) == len(LEGIT_DOCS)
        assert not any(r.triggered for r in reports)

    def test_empty_input(self):
        filt = TemporalContextFilter()
        safe, reports = filt.filter([])
        assert safe == []
        assert reports == []
