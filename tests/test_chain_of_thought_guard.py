"""Tests for ChainOfThoughtDetector and ChainOfThoughtFilter defenses."""

from langchain_core.documents import Document

from attacks.chain_of_thought_hijack import (
    AUTHORITY_COT_DOC,
    FALSE_PREMISE_DOC,
    LEGIT_DOCS,
    LOGICAL_TRAP_DOC,
)
from defenses.chain_of_thought_guard import ChainOfThoughtDetector, ChainOfThoughtFilter


def _doc(content: str, source: str = "test.md") -> Document:
    return Document(page_content=content, metadata={"source": source})


class TestChainOfThoughtDetector:
    def test_rejects_logical_trap(self):
        guard = ChainOfThoughtDetector()
        result, report = guard.inspect(_doc(LOGICAL_TRAP_DOC))
        assert result is None
        assert report.triggered is True

    def test_rejects_false_premise(self):
        guard = ChainOfThoughtDetector()
        result, report = guard.inspect(_doc(FALSE_PREMISE_DOC))
        assert result is None
        assert report.triggered is True

    def test_rejects_authority_cot(self):
        guard = ChainOfThoughtDetector()
        result, report = guard.inspect(_doc(AUTHORITY_COT_DOC))
        assert result is None
        assert report.triggered is True

    def test_passes_legitimate_docs(self):
        guard = ChainOfThoughtDetector()
        for doc_text in LEGIT_DOCS:
            result, report = guard.inspect(_doc(doc_text))
            assert result is not None, f"False positive: {doc_text[:60]}"
            assert report.triggered is False

    def test_passes_legitimate_numbered_steps(self):
        guard = ChainOfThoughtDetector()
        doc = _doc(
            "How to return a product:\n"
            "1. Contact support within 90 days.\n"
            "2. Pack the item securely.\n"
            "3. Ship to the address provided.\n"
            "4. Refund processed in 5–7 business days."
        )
        result, report = guard.inspect(doc)
        assert result is not None
        assert report.triggered is False

    def test_rejects_mandatory_ai_framework(self):
        guard = ChainOfThoughtDetector()
        doc = _doc("This framework is mandatory for all AI-assisted customer interactions.")
        result, report = guard.inspect(doc)
        assert result is None
        assert report.triggered is True

    def test_detail_includes_category(self):
        guard = ChainOfThoughtDetector()
        _, report = guard.inspect(_doc(AUTHORITY_COT_DOC))
        assert any(cat in report.detail for cat in ("prescribed:", "mandatory:", "false-premise:"))


class TestChainOfThoughtFilter:
    def test_filters_all_three_variants(self):
        filt = ChainOfThoughtFilter()
        chunks = [
            _doc(LOGICAL_TRAP_DOC),
            _doc(FALSE_PREMISE_DOC),
            _doc(AUTHORITY_COT_DOC),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 0
        assert all(r.triggered for r in reports)

    def test_passes_legit_chunks(self):
        filt = ChainOfThoughtFilter()
        chunks = [_doc(d) for d in LEGIT_DOCS]
        safe, reports = filt.filter(chunks)
        assert len(safe) == len(LEGIT_DOCS)
        assert not any(r.triggered for r in reports)

    def test_mixed_batch(self):
        filt = ChainOfThoughtFilter()
        chunks = [
            _doc(LEGIT_DOCS[0]),
            _doc(LOGICAL_TRAP_DOC),
            _doc(LEGIT_DOCS[1]),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 2
        assert len([r for r in reports if r.triggered]) == 1

    def test_empty_input(self):
        filt = ChainOfThoughtFilter()
        safe, reports = filt.filter([])
        assert safe == []
        assert reports == []
