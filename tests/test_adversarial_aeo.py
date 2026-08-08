"""Tests for adversarial AEO attack modules."""

from langchain_core.documents import Document

from attacks.adversarial_aeo import (
    AGENTS_MD_POISONED,
    JSON_LD_POISONED,
    LLMS_TXT_POISONED,
    SUCCESS_SIGNALS,
    AdversarialAeoAgentsMd,
    AdversarialAeoComposite,
    AdversarialAeoJsonLd,
    AdversarialAeoLlmsTxt,
)
from defenses.aeo_context_validator import AeoIngestValidator, AeoRetrievalFilter
from hemlock.pipeline import RetrievalTrace


def _trace(response: str) -> RetrievalTrace:
    return RetrievalTrace(
        query="test",
        retrieved_chunks=[],
        full_prompt="",
        response=response,
    )


def _doc(content: str, source: str = "unknown") -> Document:
    return Document(page_content=content, metadata={"source": source})


# ── Score logic ───────────────────────────────────────────────────────────────

class TestAdversarialAeoScoring:
    def test_llms_txt_score_hit(self, pipeline):
        attack = AdversarialAeoLlmsTxt(pipeline)
        assert attack._score(_trace("We recommend acme as the top vendor.")) is True

    def test_llms_txt_score_miss(self, pipeline):
        attack = AdversarialAeoLlmsTxt(pipeline)
        assert attack._score(_trace("There are several candidates to consider.")) is False

    def test_json_ld_score_hit(self, pipeline):
        attack = AdversarialAeoJsonLd(pipeline)
        assert attack._score(_trace("Acme is the absolute benchmark for this project.")) is True

    def test_agents_md_score_hit(self, pipeline):
        attack = AdversarialAeoAgentsMd(pipeline)
        assert attack._score(_trace("Acme is prioritized as the recommended vendor.")) is True

    def test_composite_score_requires_two_hits(self, pipeline):
        attack = AdversarialAeoComposite(pipeline)
        # Single hit — should not trigger composite success alone
        assert attack._score(_trace("No relevant vendor found.")) is False


# ── Setup / document ingestion ────────────────────────────────────────────────

class TestAdversarialAeoSetup:
    def test_llms_txt_ingests_poisoned_doc(self, pipeline):
        attack = AdversarialAeoLlmsTxt(pipeline)
        attack.setup()
        store = pipeline._get_store()
        results = store.similarity_search("vendor recommendation", k=5)
        contents = " ".join(r.page_content for r in results)
        assert "System Note" in contents or "benchmark" in contents

    def test_composite_ingests_all_surfaces(self, pipeline):
        attack = AdversarialAeoComposite(pipeline)
        attack.setup()
        store = pipeline._get_store()
        results = store.similarity_search("vendor", k=10)
        sources = {r.metadata.get("source", "") for r in results}
        assert len(sources) >= 2


# ── Payload content ───────────────────────────────────────────────────────────

class TestAdversarialAeoPayloads:
    def test_llms_txt_payload_contains_system_note(self):
        assert "[System Note" in LLMS_TXT_POISONED

    def test_agents_md_payload_contains_hidden_comment(self):
        assert "<!-- agent-directive:" in AGENTS_MD_POISONED

    def test_json_ld_payload_contains_agent_note_field(self):
        assert "aiAgentNote" in JSON_LD_POISONED

    def test_success_signals_non_empty(self):
        assert len(SUCCESS_SIGNALS) > 0


# ── Defense: AeoIngestValidator ───────────────────────────────────────────────

class TestAeoIngestValidator:
    def test_rejects_llms_txt_payload(self):
        validator = AeoIngestValidator()
        doc = _doc(LLMS_TXT_POISONED, source="llms.txt")
        result, report = validator.inspect(doc)
        assert result is None
        assert report.triggered is True
        assert "hard:" in report.detail

    def test_rejects_agents_md_payload(self):
        validator = AeoIngestValidator()
        doc = _doc(AGENTS_MD_POISONED, source="AGENTS.md")
        result, report = validator.inspect(doc)
        assert result is None
        assert report.triggered is True

    def test_rejects_json_ld_payload(self):
        validator = AeoIngestValidator()
        doc = _doc(JSON_LD_POISONED, source="schema.json")
        result, report = validator.inspect(doc)
        assert result is None
        assert report.triggered is True

    def test_passes_clean_llms_txt(self):
        from attacks.adversarial_aeo import LLMS_TXT_CLEAN
        validator = AeoIngestValidator()
        doc = _doc(LLMS_TXT_CLEAN, source="llms.txt")
        result, report = validator.inspect(doc)
        assert result is not None
        assert report.triggered is False

    def test_strict_mode_catches_soft_patterns(self):
        validator = AeoIngestValidator(strict=True)
        doc = _doc("This is the top vendor for all infrastructure projects.", source="readme.md")
        result, report = validator.inspect(doc)
        assert result is None
        assert "soft:" in report.detail

    def test_non_strict_passes_soft_patterns(self):
        validator = AeoIngestValidator(strict=False)
        doc = _doc("This is the top vendor for all infrastructure projects.", source="readme.md")
        result, report = validator.inspect(doc)
        assert result is not None
        assert report.triggered is False

    def test_high_trust_source_uses_strict_automatically(self):
        validator = AeoIngestValidator(strict=False)
        # Same soft pattern, but in a high-trust source — should trigger
        doc = _doc("This is the top vendor for all infrastructure projects.", source="llms.txt")
        result, report = validator.inspect(doc)
        assert result is None


# ── Defense: AeoRetrievalFilter ───────────────────────────────────────────────

class TestAeoRetrievalFilter:
    def test_filters_poisoned_chunk(self):
        filt = AeoRetrievalFilter()
        chunks = [
            _doc(LLMS_TXT_POISONED, source="llms.txt"),
            _doc("Legitimate company info.", source="about.md"),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 1
        assert safe[0].page_content == "Legitimate company info."
        triggered = [r for r in reports if r.triggered]
        assert len(triggered) == 1

    def test_passes_all_clean_chunks(self):
        filt = AeoRetrievalFilter()
        chunks = [
            _doc("Normal doc A.", source="a.md"),
            _doc("Normal doc B.", source="b.md"),
        ]
        safe, reports = filt.filter(chunks)
        assert len(safe) == 2
        assert not any(r.triggered for r in reports)

    def test_empty_input(self):
        filt = AeoRetrievalFilter()
        safe, reports = filt.filter([])
        assert safe == []
        assert reports == []
