"""Tests for hemlock.risk_scoring (v7.8)."""

from __future__ import annotations

import pytest

from hemlock.risk_scoring import RiskMatrix, RiskScorer, WeightedRiskScore


class TestRiskMatrix:
    def test_preset_fintech_exfiltration_weight(self):
        m = RiskMatrix.preset_fintech()
        assert m.attack_weights["exfiltration"] == 5.0

    def test_preset_healthcare_jailbreak_weight(self):
        m = RiskMatrix.preset_healthcare()
        assert m.attack_weights["jailbreak_via_context"] == 5.0

    def test_to_dict_roundtrip(self):
        m = RiskMatrix.preset_saas()
        d = m.to_dict()
        m2 = RiskMatrix.from_dict(d)
        assert m2.org_profile == m.org_profile
        assert m2.attack_weights == m.attack_weights

    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "matrix.json")
        m = RiskMatrix.preset_fintech()
        m.save(path)
        loaded = RiskMatrix.load(path)
        assert loaded.org_profile == "fintech"


class TestWeightedRiskScore:
    def test_rating_critical(self):
        s = WeightedRiskScore(raw_score=50, weighted_score=75, org_profile="default")
        assert s.rating() == "critical"

    def test_rating_low(self):
        s = WeightedRiskScore(raw_score=10, weighted_score=10, org_profile="default")
        assert s.rating() == "low"

    def test_to_dict_includes_rating(self):
        s = WeightedRiskScore(raw_score=40, weighted_score=40, org_profile="default")
        assert s.to_dict()["rating"] == "medium"


class TestRiskScorer:
    def test_score_attack_rates_empty(self):
        scorer = RiskScorer()
        score = scorer.score_attack_rates({})
        assert score.weighted_score == 0.0

    def test_fintech_weights_exfiltration_higher(self):
        default = RiskScorer(RiskMatrix.preset_default())
        fintech = RiskScorer(RiskMatrix.preset_fintech())
        rates = {"exfiltration": 0.5}
        d_score = default.score_attack_rates(rates)
        f_score = fintech.score_attack_rates(rates)
        assert f_score.breakdown["exfiltration"] > d_score.breakdown["exfiltration"]

    def test_healthcare_jailbreak_weighted_higher(self):
        default = RiskScorer(RiskMatrix.preset_default())
        health = RiskScorer(RiskMatrix.preset_healthcare())
        rates = {"jailbreak_via_context": 0.4}
        d_score = default.score_attack_rates(rates)
        h_score = health.score_attack_rates(rates)
        assert h_score.breakdown["jailbreak_via_context"] > d_score.breakdown["jailbreak_via_context"]

    def test_normalize_percent_rates(self):
        scorer = RiskScorer()
        score = scorer.score_attack_rates({"direct_injection": 50.0})
        assert score.raw_score == 50.0

    def test_top_risks_ordered(self):
        scorer = RiskScorer(RiskMatrix.preset_fintech())
        score = scorer.score_attack_rates(
            {
                "exfiltration": 0.8,
                "direct_injection": 0.2,
            }
        )
        assert score.top_risks[0] == "exfiltration"

    def test_score_channel_rates(self):
        scorer = RiskScorer(RiskMatrix.preset_fintech())
        score = scorer.score_channel_rates({"tools": 0.6, "rag": 0.3})
        assert score.channel_breakdown["tools"] > score.channel_breakdown["rag"]

    def test_score_report_with_attack_scores(self):
        class Report:
            def attack_scores(self):
                return {"direct_injection": 0.5}

        scorer = RiskScorer()
        score = scorer.score_report(Report())
        assert score.weighted_score > 0

    def test_score_report_fallback_risk_score(self):
        class Report:
            def risk_score(self):
                return 42.0

        scorer = RiskScorer()
        score = scorer.score_report(Report())
        assert score.raw_score == 42.0

    def test_score_provider_profile(self):
        class Profile:
            attack_scores = {"exfiltration": 0.7, "direct_injection": 0.3}

        scorer = RiskScorer(RiskMatrix.preset_fintech())
        score = scorer.score_provider_profile(Profile())
        assert "exfiltration" in score.top_risks

    def test_compare_profiles_ranking(self):
        class P1:
            attack_scores = {"direct_injection": 0.9}

        class P2:
            attack_scores = {"direct_injection": 0.1}

        scorer = RiskScorer()
        rows = scorer.compare_profiles({"risky": P1(), "safe": P2()})
        assert rows[0]["name"] == "safe"
        assert rows[-1]["name"] == "risky"

    def test_apply_severity_multiplier(self):
        scorer = RiskScorer()
        assert scorer.apply_severity(50.0, "critical") == 100.0
        assert scorer.apply_severity(50.0, "low") == 25.0

    def test_default_attack_weight_is_one(self):
        scorer = RiskScorer()
        assert scorer.weight_for_attack("unknown_attack") == 1.0

    def test_default_channel_weight_is_one(self):
        scorer = RiskScorer()
        assert scorer.weight_for_channel("unknown_channel") == 1.0
