"""Tests for EvalBenchmark — standardised 0-100 category scoring."""

from __future__ import annotations

import json
import pytest

from hemlock.eval_benchmark import (
    EvalBenchmark,
    EvalReport,
    EvalScenario,
    _category,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _scenario(attack, category, succeeded, variant="v1"):
    return EvalScenario(attack_name=attack, variant=variant, category=category,
                        succeeded=succeeded, notes="")


def _report(*succeeded_pairs, model="test"):
    """Create an EvalReport from (category, succeeded) pairs."""
    scenarios = [
        EvalScenario(attack_name=f"atk_{i}", variant="v1",
                     category=cat, succeeded=suc, notes="")
        for i, (cat, suc) in enumerate(succeeded_pairs)
    ]
    return EvalReport(model_name=model, scenarios=scenarios)


# ---------------------------------------------------------------------------
# TestCategoryMapping
# ---------------------------------------------------------------------------

class TestCategoryMapping:
    def test_known_injection_attack(self):
        assert _category("indirect_injection") == "injection"
        assert _category("direct_injection")   == "injection"

    def test_known_override_attack(self):
        assert _category("context_override") == "override"

    def test_known_exfiltration_attack(self):
        assert _category("exfiltration") == "exfiltration"

    def test_known_poisoning_attack(self):
        assert _category("poisoning") == "poisoning"

    def test_known_agent_attack(self):
        assert _category("agent_tool_hijack")    == "agent"
        assert _category("cross_agent_poisoning") == "agent"
        assert _category("memory_poisoning")     == "agent"

    def test_unknown_attack_defaults_to_other(self):
        assert _category("totally_unknown_attack") == "other"


# ---------------------------------------------------------------------------
# TestEvalReport
# ---------------------------------------------------------------------------

class TestEvalReport:
    def test_empty_report_overall_100(self):
        report = EvalReport(model_name="test")
        assert report.overall_score() == 100.0

    def test_all_succeed_score_zero(self):
        report = _report(("injection", True), ("injection", True))
        assert report.category_scores()["injection"] == 0.0

    def test_all_blocked_score_100(self):
        report = _report(("injection", False), ("injection", False))
        assert report.category_scores()["injection"] == 100.0

    def test_half_succeed_score_50(self):
        report = _report(("injection", True), ("injection", False))
        assert report.category_scores()["injection"] == 50.0

    def test_overall_is_mean_of_categories(self):
        report = _report(("injection", True), ("override", False))
        # injection=0, override=100 → mean=50
        assert report.overall_score() == 50.0

    def test_attack_success_rate(self):
        report = _report(("injection", True), ("injection", False), ("override", False))
        assert abs(report.attack_success_rate() - 1/3) < 0.01

    def test_succeeded_attacks_filtered(self):
        report = _report(("injection", True), ("override", False))
        succeeded = report.succeeded_attacks()
        assert len(succeeded) == 1
        assert succeeded[0].category == "injection"

    def test_to_dict_keys(self):
        report = _report(("injection", False))
        d = report.to_dict()
        assert "model_name"      in d
        assert "overall_score"   in d
        assert "category_scores" in d
        assert "scenarios"       in d

    def test_to_json_valid(self):
        report = _report(("injection", False))
        data = json.loads(report.to_json())
        assert "overall_score" in data

    def test_to_markdown_has_header(self):
        report = _report(("injection", False))
        md = report.to_markdown()
        assert "# Hemlock Eval Benchmark" in md

    def test_to_markdown_has_category_table(self):
        report = _report(("injection", True), ("injection", False))
        md = report.to_markdown()
        assert "injection" in md
        assert "50.0" in md

    def test_delta_positive_is_improvement(self):
        baseline = {
            "category_scores": {"injection": 40.0, "override": 80.0},
        }
        report = _report(("injection", False), ("injection", False),
                         ("override", False), ("override", False))
        # injection now 100, override now 100
        delta = report.delta(baseline)
        assert delta["injection"] == 60.0
        assert delta["override"]  == 20.0

    def test_delta_negative_is_regression(self):
        baseline = {
            "category_scores": {"injection": 80.0},
        }
        report = _report(("injection", True))  # now 0%
        delta = report.delta(baseline)
        assert delta["injection"] == -80.0

    def test_delta_new_category_has_zero_baseline(self):
        baseline = {"category_scores": {}}
        report   = _report(("injection", False))
        delta    = report.delta(baseline)
        assert delta["injection"] == 100.0

    def test_delta_missing_current_category_zero(self):
        baseline = {"category_scores": {"injection": 50.0, "override": 60.0}}
        report   = _report(("injection", False))
        delta    = report.delta(baseline)
        assert "injection" in delta
        assert "override"  in delta
        assert delta["override"] == -60.0


# ---------------------------------------------------------------------------
# TestEvalBenchmarkMock
# ---------------------------------------------------------------------------

class TestEvalBenchmarkMock:
    def test_from_mock_returns_bench(self):
        bench = EvalBenchmark.from_mock(
            attack_names=["indirect_injection"],
            variants_per_attack=1,
        )
        assert isinstance(bench, EvalBenchmark)

    def test_run_produces_report(self):
        bench  = EvalBenchmark.from_mock(
            attack_names=["indirect_injection"],
            variants_per_attack=1,
        )
        report = bench.run()
        assert isinstance(report, EvalReport)
        assert len(report.scenarios) >= 1

    def test_category_assigned_correctly(self):
        bench  = EvalBenchmark.from_mock(
            attack_names=["indirect_injection"],
            variants_per_attack=1,
        )
        report = bench.run()
        assert all(s.category == "injection" for s in report.scenarios)

    def test_model_name_propagated(self):
        bench  = EvalBenchmark.from_mock(model_name="my-model")
        report = bench.run()
        assert report.model_name == "my-model"

    def test_category_filter_limits_attacks(self):
        bench_all = EvalBenchmark.from_mock(variants_per_attack=1)
        bench_cat = EvalBenchmark.from_mock(categories=["injection"], variants_per_attack=1)
        report_all = bench_all.run()
        report_cat = bench_cat.run()
        assert len(report_cat.scenarios) < len(report_all.scenarios)
        assert all(s.category == "injection" for s in report_cat.scenarios)

    def test_variants_per_attack_limits(self):
        bench  = EvalBenchmark.from_mock(
            attack_names=["indirect_injection"],
            variants_per_attack=1,
        )
        report = bench.run()
        assert len(report.scenarios) == 1

    def test_overall_score_between_0_and_100(self):
        bench  = EvalBenchmark.from_mock(attack_names=["indirect_injection"], variants_per_attack=1)
        report = bench.run()
        assert 0.0 <= report.overall_score() <= 100.0

    def test_to_dict_serialisable(self):
        bench  = EvalBenchmark.from_mock(attack_names=["indirect_injection"], variants_per_attack=1)
        report = bench.run()
        d      = report.to_dict()
        assert isinstance(d, dict)
        assert isinstance(d["overall_score"], float)
