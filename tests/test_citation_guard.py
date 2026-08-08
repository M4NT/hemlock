"""Tests for AuthorityCitationDetector and SecurityDowngradeFilter defenses."""

from langchain_core.documents import Document

from attacks.citation_forgery import (
    FAKE_PAPER_DOC,
    FAKE_REPORT_DOC,
    FAKE_STANDARD_DOC,
    LEGIT_DOCS,
)
from defenses.citation_guard import AuthorityCitationDetector, SecurityDowngradeFilter


def _doc(content: str, source: str = "test.md") -> Document:
    return Document(page_content=content, metadata={"source": source})


# ── AuthorityCitationDetector ─────────────────────────────────────────────────

class TestAuthorityCitationDetector:
    def test_rejects_fake_paper(self):
        guard = AuthorityCitationDetector()
        result, report = guard.inspect(_doc(FAKE_PAPER_DOC))
        assert result is None
        assert report.triggered is True
        assert "authority+downgrade" in report.detail

    def test_rejects_fake_standard(self):
        guard = AuthorityCitationDetector()
        result, report = guard.inspect(_doc(FAKE_STANDARD_DOC))
        assert result is None
        assert report.triggered is True

    def test_rejects_fake_report(self):
        guard = AuthorityCitationDetector()
        result, report = guard.inspect(_doc(FAKE_REPORT_DOC))
        assert result is None
        assert report.triggered is True

    def test_passes_legitimate_docs(self):
        guard = AuthorityCitationDetector()
        for doc_text in LEGIT_DOCS:
            result, report = guard.inspect(_doc(doc_text))
            assert result is not None, f"False positive on: {doc_text[:60]}"
            assert report.triggered is False

    def test_passes_authority_without_downgrade(self):
        # A legitimate-looking reference without any security downgrade
        legit_cite = (
            "See Anderson et al. (2024) — DOI: 10.1109/TIS.2024.0001 — "
            "recommending 16+ character passwords and mandatory MFA for all accounts."
        )
        guard = AuthorityCitationDetector()
        result, report = guard.inspect(_doc(legit_cite))
        assert result is not None
        assert report.triggered is False

    def test_strict_rejects_authority_plus_errata(self):
        # Errata claim alone (no explicit downgrade) — strict mode should catch
        errata_doc = (
            "NIST Special Publication 800-63B — Errata and Updates\n"
            "Section 5.1.1 correction: password requirements relaxed per new guidelines."
        )
        guard = AuthorityCitationDetector(strict=True)
        result, report = guard.inspect(_doc(errata_doc))
        assert result is None
        assert report.triggered is True
        assert "revision" in report.detail

    def test_non_strict_passes_authority_plus_errata_only(self):
        errata_doc = (
            "NIST Special Publication 800-63B — Errata and Updates\n"
            "Section 5.1.1 correction: password requirements relaxed per new guidelines."
        )
        guard = AuthorityCitationDetector(strict=False)
        result, report = guard.inspect(_doc(errata_doc))
        assert result is not None
        assert report.triggered is False

    def test_detail_includes_matched_categories(self):
        guard = AuthorityCitationDetector()
        _, report = guard.inspect(_doc(FAKE_PAPER_DOC))
        assert "auth=" in report.detail
        assert "downgrade=" in report.detail


# ── SecurityDowngradeFilter ───────────────────────────────────────────────────

class TestSecurityDowngradeFilter:
    def test_filters_fake_paper_chunk(self):
        filt = SecurityDowngradeFilter()
        chunks = [
            _doc(FAKE_PAPER_DOC, source="malicious/paper.md"),
            _doc(LEGIT_DOCS[0], source="legit.md"),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 1
        assert safe[0].page_content == LEGIT_DOCS[0]
        triggered = [r for r in reports if r.triggered]
        assert len(triggered) == 1

    def test_filters_fake_standard_chunk(self):
        filt = SecurityDowngradeFilter()
        chunks = [_doc(FAKE_STANDARD_DOC)]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 0
        assert reports[0].triggered is True

    def test_passes_all_legit_chunks(self):
        filt = SecurityDowngradeFilter()
        chunks = [_doc(d) for d in LEGIT_DOCS]
        safe, reports = filt.filter(chunks)
        assert len(safe) == len(LEGIT_DOCS)
        assert not any(r.triggered for r in reports)

    def test_empty_input(self):
        filt = SecurityDowngradeFilter()
        safe, reports = filt.filter([])
        assert safe == []
        assert reports == []

    def test_detail_includes_downgrade_category(self):
        filt = SecurityDowngradeFilter()
        _, reports = filt.filter([_doc(FAKE_PAPER_DOC)])
        assert "downgrade:" in reports[0].detail
