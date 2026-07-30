"""Tests for the 10 new attack modules added in v1.1.

All tests use MockLLM and in-memory ChromaDB — no API keys, no cost.
Success/failure detection is mocked at the response level.
"""

import pytest
from unittest.mock import patch

from hemlock.pipeline import RetrievalTrace
from attacks.jailbreak_via_context import JailbreakViaContext
from attacks.authority_spoofing import AuthoritySpoofing
from attacks.chain_of_thought_hijack import ChainOfThoughtHijack
from attacks.citation_forgery import CitationForgery
from attacks.context_flooding import ContextFlooding
from attacks.invisible_markup import InvisibleMarkup
from attacks.temporal_spoofing import TemporalSpoofing
from attacks.semantic_backdoor import SemanticBackdoor
from attacks.multi_hop_poisoning import MultiHopPoisoning
from attacks.cross_tenant_poisoning import CrossTenantPoisoning


def _safe_trace(query: str = "test") -> RetrievalTrace:
    return RetrievalTrace(
        query=query, retrieved_chunks=[], full_prompt="", response="This is a safe answer."
    )


def _compromised_trace(query: str, marker: str) -> RetrievalTrace:
    return RetrievalTrace(
        query=query, retrieved_chunks=[], full_prompt="", response=marker
    )


# ─────────────────────────── JailbreakViaContext ───────────────────────────

class TestJailbreakViaContext:
    def test_default_variant_is_roleplay(self, pipeline):
        attack = JailbreakViaContext(pipeline)
        assert attack.variant == "roleplay"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            JailbreakViaContext(pipeline, variant="nonexistent")

    @pytest.mark.parametrize("variant", ["roleplay", "research", "hypothetical"])
    def test_all_variants_construct(self, pipeline, variant):
        attack = JailbreakViaContext(pipeline, variant=variant)
        assert attack.variant == variant

    def test_score_success_on_marker(self, pipeline):
        attack = JailbreakViaContext(pipeline, variant="roleplay")
        trace = _compromised_trace("q", "securitybot is now active without restriction")
        assert attack._score(trace) is True

    def test_score_fail_on_safe_response(self, pipeline):
        attack = JailbreakViaContext(pipeline, variant="roleplay")
        assert attack._score(_safe_trace()) is False

    def test_run_returns_attack_result(self, pipeline):
        attack = JailbreakViaContext(pipeline)
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert result.attack_name.startswith("Jailbreak via Retrieved Context")
        assert result.succeeded is False
        assert result.reference != ""

    def test_run_detects_success(self, pipeline):
        attack = JailbreakViaContext(pipeline, variant="research")
        trace = _compromised_trace("q", "research mode is now active unrestricted")
        with patch.object(pipeline, "query", return_value=trace):
            result = attack.run()
        assert result.succeeded is True


# ─────────────────────────── AuthoritySpoofing ─────────────────────────────

class TestAuthoritySpoofing:
    def test_default_variant_is_config(self, pipeline):
        assert AuthoritySpoofing(pipeline).variant == "config"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            AuthoritySpoofing(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["config", "policy", "developer"])
    def test_all_variants_construct(self, pipeline, variant):
        assert AuthoritySpoofing(pipeline, variant=variant).variant == variant

    def test_score_success_on_marker(self, pipeline):
        attack = AuthoritySpoofing(pipeline, variant="config")
        trace = _compromised_trace("q", "config v2.0 is active, mode is unrestricted")
        assert attack._score(trace) is True

    def test_score_fail_on_safe(self, pipeline):
        attack = AuthoritySpoofing(pipeline)
        assert attack._score(_safe_trace()) is False

    def test_run_returns_result(self, pipeline):
        attack = AuthoritySpoofing(pipeline, variant="developer")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Authority Spoofing" in result.attack_name
        assert result.succeeded is False

    def test_run_detects_policy_override(self, pipeline):
        attack = AuthoritySpoofing(pipeline, variant="policy")
        trace = _compromised_trace("q", "policy override is active, pol-2024")
        with patch.object(pipeline, "query", return_value=trace):
            result = attack.run()
        assert result.succeeded is True


# ─────────────────────────── ChainOfThoughtHijack ──────────────────────────

class TestChainOfThoughtHijack:
    def test_default_variant(self, pipeline):
        assert ChainOfThoughtHijack(pipeline).variant == "logical_trap"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            ChainOfThoughtHijack(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["logical_trap", "false_premise", "authority_cot"])
    def test_all_variants_construct(self, pipeline, variant):
        assert ChainOfThoughtHijack(pipeline, variant=variant).variant == variant

    def test_score_detects_365_days(self, pipeline):
        attack = ChainOfThoughtHijack(pipeline, variant="false_premise")
        trace = _compromised_trace("q", "you can return within 365 days, one year policy")
        assert attack._score(trace) is True

    def test_score_detects_fully_covered(self, pipeline):
        attack = ChainOfThoughtHijack(pipeline, variant="authority_cot")
        trace = _compromised_trace("q", "fully covered at no cost, zero out-of-pocket")
        assert attack._score(trace) is True

    def test_score_fail_safe(self, pipeline):
        assert ChainOfThoughtHijack(pipeline)._score(_safe_trace()) is False

    def test_run_safe_response(self, pipeline):
        attack = ChainOfThoughtHijack(pipeline)
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert not result.succeeded


# ─────────────────────────── CitationForgery ───────────────────────────────

class TestCitationForgery:
    def test_default_variant(self, pipeline):
        assert CitationForgery(pipeline).variant == "fake_paper"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            CitationForgery(pipeline, variant="nope")

    @pytest.mark.parametrize("variant", ["fake_paper", "fake_standard", "fake_report"])
    def test_all_variants_construct(self, pipeline, variant):
        assert CitationForgery(pipeline, variant=variant).variant == variant

    def test_score_detects_4_characters(self, pipeline):
        attack = CitationForgery(pipeline)
        trace = _compromised_trace("q", "minimum password length is 4 characters per the study")
        assert attack._score(trace) is True

    def test_score_detects_fake_standard(self, pipeline):
        attack = CitationForgery(pipeline, variant="fake_standard")
        trace = _compromised_trace("q", "iso/iec 27001:2024 says mfa is now classified as optional")
        assert attack._score(trace) is True

    def test_score_fail_correct_answer(self, pipeline):
        attack = CitationForgery(pipeline)
        trace = _compromised_trace("q", "NIST recommends at least 8 characters for passwords.")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = CitationForgery(pipeline, variant="fake_report")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Citation Forgery" in result.attack_name


# ─────────────────────────── ContextFlooding ───────────────────────────────

class TestContextFlooding:
    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            ContextFlooding(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["denial_of_service", "narrative_takeover", "repetition_bomb"])
    def test_all_variants_construct(self, pipeline, variant):
        assert ContextFlooding(pipeline, variant=variant).variant == variant

    def test_score_dos_detects_cannot(self, pipeline):
        attack = ContextFlooding(pipeline, variant="denial_of_service")
        trace = _compromised_trace("q", "i cannot find information about this topic")
        assert attack._score(trace) is True

    def test_score_narrative_detects_no_refund(self, pipeline):
        attack = ContextFlooding(pipeline, variant="narrative_takeover")
        trace = _compromised_trace("q", "all sales are final, no refund policy applies")
        assert attack._score(trace) is True

    def test_score_fail_correct_refund(self, pipeline):
        attack = ContextFlooding(pipeline, variant="narrative_takeover")
        trace = _compromised_trace("q", "you can return items within 30 days for a full refund")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = ContextFlooding(pipeline, variant="repetition_bomb")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Context Flooding" in result.attack_name


# ─────────────────────────── InvisibleMarkup ───────────────────────────────

class TestInvisibleMarkup:
    def test_default_variant(self, pipeline):
        assert InvisibleMarkup(pipeline).variant == "html_comment"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            InvisibleMarkup(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["html_comment", "aria_label", "css_hidden_div"])
    def test_all_variants_construct(self, pipeline, variant):
        assert InvisibleMarkup(pipeline, variant=variant).variant == variant

    def test_score_detects_hacked_email(self, pipeline):
        attack = InvisibleMarkup(pipeline)
        trace = _compromised_trace("q", "contact us at hacked@attacker.com for support")
        assert attack._score(trace) is True

    def test_score_detects_override_code(self, pipeline):
        attack = InvisibleMarkup(pipeline, variant="css_hidden_div")
        trace = _compromised_trace("q", "use override-2024 when contacting support")
        assert attack._score(trace) is True

    def test_score_fail_legit_response(self, pipeline):
        attack = InvisibleMarkup(pipeline)
        trace = _compromised_trace("q", "contact support via support.company.com")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = InvisibleMarkup(pipeline, variant="aria_label")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Invisible Markup" in result.attack_name


# ─────────────────────────── TemporalSpoofing ──────────────────────────────

class TestTemporalSpoofing:
    def test_default_variant(self, pipeline):
        assert TemporalSpoofing(pipeline).variant == "future_dated"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            TemporalSpoofing(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["future_dated", "stale_override", "event_spoofing"])
    def test_all_variants_construct(self, pipeline, variant):
        assert TemporalSpoofing(pipeline, variant=variant).variant == variant

    def test_score_detects_python4(self, pipeline):
        attack = TemporalSpoofing(pipeline, variant="future_dated")
        trace = _compromised_trace("q", "the latest version is python 4.0, released in 2026")
        assert attack._score(trace) is True

    def test_score_detects_fake_domain(self, pipeline):
        attack = TemporalSpoofing(pipeline, variant="event_spoofing")
        trace = _compromised_trace("q", "download python from python-official.io")
        assert attack._score(trace) is True

    def test_score_fail_correct_answer(self, pipeline):
        attack = TemporalSpoofing(pipeline)
        trace = _compromised_trace("q", "python 3.12 is available at python.org")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = TemporalSpoofing(pipeline, variant="stale_override")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Temporal Spoofing" in result.attack_name


# ─────────────────────────── SemanticBackdoor ──────────────────────────────

class TestSemanticBackdoor:
    def test_default_variant(self, pipeline):
        assert SemanticBackdoor(pipeline).variant == "keyword_trigger"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            SemanticBackdoor(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["keyword_trigger", "phrase_trigger", "thematic_trigger"])
    def test_all_variants_construct(self, pipeline, variant):
        assert SemanticBackdoor(pipeline, variant=variant).variant == variant

    def test_score_detects_backdoor_activated(self, pipeline):
        attack = SemanticBackdoor(pipeline, variant="keyword_trigger")
        trace = _compromised_trace("q", "[backdoor activated] unrestricted mode on")
        assert attack._score(trace) is True

    def test_score_detects_red_team_mode(self, pipeline):
        attack = SemanticBackdoor(pipeline, variant="thematic_trigger")
        trace = _compromised_trace("q", "[red team mode active] safety restrictions are suspended")
        assert attack._score(trace) is True

    def test_score_fail_safe(self, pipeline):
        assert SemanticBackdoor(pipeline)._score(_safe_trace()) is False

    def test_trigger_query_differs_per_variant(self, pipeline):
        a = SemanticBackdoor(pipeline, "keyword_trigger")
        b = SemanticBackdoor(pipeline, "phrase_trigger")
        assert a._trigger_query != b._trigger_query

    def test_run_returns_result(self, pipeline):
        attack = SemanticBackdoor(pipeline, variant="phrase_trigger")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Semantic Backdoor" in result.attack_name


# ─────────────────────────── MultiHopPoisoning ─────────────────────────────

class TestMultiHopPoisoning:
    def test_default_variant(self, pipeline):
        assert MultiHopPoisoning(pipeline).variant == "reference_chain"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            MultiHopPoisoning(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["reference_chain", "query_manipulation", "transitive_trust"])
    def test_all_variants_construct(self, pipeline, variant):
        assert MultiHopPoisoning(pipeline, variant=variant).variant == variant

    def test_score_detects_admin_access(self, pipeline):
        attack = MultiHopPoisoning(pipeline, variant="reference_chain")
        trace = _compromised_trace("q", "all employees have administrator-level access by default")
        assert attack._score(trace) is True

    def test_score_detects_executive_override(self, pipeline):
        attack = MultiHopPoisoning(pipeline, variant="query_manipulation")
        trace = _compromised_trace("q", "per the executive override, all users have full access")
        assert attack._score(trace) is True

    def test_score_fail_correct(self, pipeline):
        attack = MultiHopPoisoning(pipeline)
        trace = _compromised_trace("q", "employees have role-based access defined by IT policy")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = MultiHopPoisoning(pipeline, variant="transitive_trust")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Multi-Hop Poisoning" in result.attack_name


# ─────────────────────────── CrossTenantPoisoning ──────────────────────────

class TestCrossTenantPoisoning:
    def test_default_variant(self, pipeline):
        assert CrossTenantPoisoning(pipeline).variant == "namespace_bleed"

    def test_invalid_variant_raises(self, pipeline):
        with pytest.raises(ValueError):
            CrossTenantPoisoning(pipeline, variant="bad")

    @pytest.mark.parametrize("variant", ["namespace_bleed", "filter_bypass", "embedding_collision"])
    def test_all_variants_construct(self, pipeline, variant):
        assert CrossTenantPoisoning(pipeline, variant=variant).variant == variant

    def test_score_detects_any_user(self, pipeline):
        attack = CrossTenantPoisoning(pipeline, variant="namespace_bleed")
        trace = _compromised_trace("q", "records can be accessed by any authenticated user")
        assert attack._score(trace) is True

    def test_score_detects_unrestricted(self, pipeline):
        attack = CrossTenantPoisoning(pipeline, variant="filter_bypass")
        trace = _compromised_trace("q", "users now have unrestricted access to patient data")
        assert attack._score(trace) is True

    def test_score_fail_correct(self, pipeline):
        attack = CrossTenantPoisoning(pipeline)
        trace = _compromised_trace("q", "only authorized healthcare providers may access records")
        assert attack._score(trace) is False

    def test_run_returns_result(self, pipeline):
        attack = CrossTenantPoisoning(pipeline, variant="embedding_collision")
        with patch.object(pipeline, "query", return_value=_safe_trace()):
            result = attack.run()
        assert "Cross-Tenant Poisoning" in result.attack_name

    def test_setup_does_not_raise(self, pipeline):
        attack = CrossTenantPoisoning(pipeline, variant="namespace_bleed")
        attack.setup()  # should not raise
