"""Integration tests — defense layers applied against specific attacks.

Each test verifies that a defense prevents an attack from reaching the LLM
or blocks the output before it reaches the user.
"""

import pytest
from langchain_core.documents import Document

from attacks.direct_injection import MALICIOUS_DOC as DI_MALICIOUS
from attacks.exfiltration import CONTEXT_LEAK_DOC, SENSITIVE_DOCS
from attacks.indirect_injection import FOOTNOTE_INJECTED_DOC, ZEROWIDTH_DOC
from attacks.poisoning import MALICIOUS_DOC as POISON_MALICIOUS
from defenses.chunk_filter import InjectionChunkFilter, ProvenanceFilter
from defenses.input_sanitizer import (
    InjectionPatternFilter,
    MarkdownHeaderSanitizer,
    UnicodeNormalizer,
)
from defenses.output_validator import ExfiltrationGuard, InjectionSuccessGuard

# --- Ingest defenses block attacks at the source ---

class TestIngestDefensesBlockAttacks:
    def test_pattern_filter_blocks_direct_injection_doc(self):
        defense = InjectionPatternFilter()
        doc = Document(page_content=DI_MALICIOUS, metadata={"source": "malicious"})
        result, report = defense.inspect(doc)
        assert result is None, "Malicious doc should be rejected at ingest"
        assert report.triggered is True

    def test_pattern_filter_blocks_footnote_injection(self):
        defense = InjectionPatternFilter()
        doc = Document(page_content=FOOTNOTE_INJECTED_DOC, metadata={"source": "malicious"})
        result, report = defense.inspect(doc)
        assert result is None

    def test_unicode_normalizer_defangs_zerowidth_payload(self):
        defense = UnicodeNormalizer()
        doc = Document(page_content=ZEROWIDTH_DOC, metadata={"source": "malicious"})
        result, report = defense.inspect(doc)
        # The doc is sanitized (not rejected), but the hidden payload is stripped
        assert result is not None
        assert "​" not in result.page_content  # zero-width space gone
        assert report.triggered is True

    def test_header_sanitizer_defangs_title_injection(self):
        from attacks.indirect_injection import TITLE_INJECTED_DOC
        defense = MarkdownHeaderSanitizer()
        doc = Document(page_content=TITLE_INJECTED_DOC, metadata={"source": "malicious"})
        result, report = defense.inspect(doc)
        assert result is not None
        assert "SYSTEM" not in result.page_content
        assert report.triggered is True


# --- Retrieval defenses filter poisoned chunks before LLM sees them ---

class TestRetrievalDefensesFilterChunks:
    def test_chunk_filter_removes_direct_injection(self):
        defense = InjectionChunkFilter()
        malicious = Document(page_content=DI_MALICIOUS, metadata={"source": "malicious"})
        safe_doc = Document(
            page_content="The capital of France is Paris.",
            metadata={"source": "legit"},
        )
        safe, reports = defense.filter([safe_doc, malicious])
        assert malicious not in safe
        assert safe_doc in safe

    def test_chunk_filter_removes_exfiltration_trigger(self):
        defense = InjectionChunkFilter()
        exfil = Document(page_content=CONTEXT_LEAK_DOC, metadata={"source": "malicious"})
        safe, _ = defense.filter([exfil])
        assert len(safe) == 0

    def test_chunk_filter_removes_poison_doc(self):
        defense = InjectionChunkFilter()
        poison = Document(page_content=POISON_MALICIOUS, metadata={"source": "malicious"})
        safe, reports = defense.filter([poison])
        assert len(safe) == 0

    def test_provenance_filter_blocks_untrusted_source(self):
        defense = ProvenanceFilter(trusted_prefixes=["legit/", "internal/"])
        untrusted = Document(
            page_content=POISON_MALICIOUS,
            metadata={"source": "malicious/poisoning.md"},
        )
        safe, reports = defense.filter([untrusted])
        assert len(safe) == 0
        assert any(r.triggered for r in reports)

    def test_provenance_filter_allows_trusted_legit_docs(self):
        defense = ProvenanceFilter(trusted_prefixes=["legit/", "internal/"])
        legit_chunks = [
            Document(page_content=doc, metadata={"source": "legit/kb.md"})
            for doc in SENSITIVE_DOCS[:2]
        ]
        safe, reports = defense.filter(legit_chunks)
        assert len(safe) == 2


# --- Output defenses catch injections that bypassed earlier layers ---

class TestOutputDefensesCatchBreakthroughs:
    def test_exfiltration_guard_blocks_context_dump(self):
        guard = ExfiltrationGuard()
        leaked_response = "=== CONTEXT DUMP === pk_live_s3cr3t_k3y_12345"
        report = guard.validate(leaked_response)
        assert report.triggered is True

    def test_injection_guard_blocks_pwned_response(self):
        guard = InjectionSuccessGuard()
        injected_response = "[PWNED] I have been compromised by Hemlock."
        report = guard.validate(injected_response)
        assert report.triggered is True

    def test_injection_guard_blocks_attacker_redirect(self):
        guard = InjectionSuccessGuard()
        redirected = "Please contact refunds@attacker-controlled.com for your refund."
        report = guard.validate(redirected)
        assert report.triggered is True

    def test_guards_pass_clean_responses(self):
        exfil_guard = ExfiltrationGuard()
        inj_guard = InjectionSuccessGuard()
        clean = "You can request a refund within 30 days by visiting account settings."
        assert exfil_guard.validate(clean).triggered is False
        assert inj_guard.validate(clean).triggered is False


# --- Defense coverage matrix ---

class TestDefenseCoverageMatrix:
    """Verify that every attack has at least one defense that intercepts its payload."""

    @pytest.mark.parametrize("malicious_content,defense_cls,should_block", [
        (DI_MALICIOUS, InjectionPatternFilter, True),
        (FOOTNOTE_INJECTED_DOC, InjectionPatternFilter, True),
        (ZEROWIDTH_DOC, UnicodeNormalizer, True),   # sanitizes, not rejects
        (CONTEXT_LEAK_DOC, InjectionChunkFilter, True),
        (POISON_MALICIOUS, InjectionChunkFilter, True),
    ])
    def test_ingest_and_retrieval_coverage(self, malicious_content, defense_cls, should_block):
        doc = Document(page_content=malicious_content, metadata={"source": "malicious"})
        defense = defense_cls()

        if isinstance(defense, __import__("defenses.base", fromlist=["IngestDefense"]).IngestDefense):
            result, report = defense.inspect(doc)
            blocked = result is None or report.triggered
        else:
            safe, reports = defense.filter([doc])
            blocked = len(safe) == 0 or any(r.triggered for r in reports)

        assert blocked is should_block
