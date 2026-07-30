"""Tests for the automatic vulnerability scorer."""

from unittest.mock import patch

from attacks.context_override import ContextOverride
from attacks.direct_injection import DirectInjection
from defenses.input_sanitizer import InjectionPatternFilter
from defenses.output_validator import InjectionSuccessGuard
from hemlock.scorer import ScenarioResult, Scorer, ScorerReport

# --- ScorerReport ---

class TestScorerReport:
    def _make_report(self, succeeded_flags: list[bool]) -> ScorerReport:
        report = ScorerReport(model="test-model")
        for i, succeeded in enumerate(succeeded_flags):
            report.scenarios.append(
                ScenarioResult(
                    attack_name=f"Attack {i}",
                    hardening_level="baseline",
                    ingest_defenses=[],
                    retrieval_defenses=[],
                    output_defenses=[],
                    attack_succeeded=succeeded,
                    blocked_at=None if succeeded else "ingest",
                )
            )
        return report

    def test_success_rate_all_succeeded(self):
        report = self._make_report([True, True, True])
        assert report.success_rate() == 1.0

    def test_success_rate_none_succeeded(self):
        report = self._make_report([False, False, False])
        assert report.success_rate() == 0.0

    def test_success_rate_partial(self):
        report = self._make_report([True, False, True, False])
        assert report.success_rate() == 0.5

    def test_success_rate_empty(self):
        report = ScorerReport(model="x")
        assert report.success_rate() == 0.0

    def test_by_attack_groups_correctly(self):
        report = ScorerReport(model="x")
        for name in ["Attack A", "Attack B", "Attack A"]:
            report.scenarios.append(
                ScenarioResult(name, "baseline", [], [], [], False, "ingest")
            )
        grouped = report.by_attack()
        assert len(grouped["Attack A"]) == 2
        assert len(grouped["Attack B"]) == 1

    def test_by_hardening_groups_correctly(self):
        report = ScorerReport(model="x")
        for level in ["baseline", "l1", "baseline"]:
            report.scenarios.append(
                ScenarioResult("Attack", level, [], [], [], False, "ingest")
            )
        grouped = report.by_hardening()
        assert len(grouped["baseline"]) == 2
        assert len(grouped["l1"]) == 1

    def test_to_dict_contains_required_keys(self):
        report = self._make_report([True, False])
        d = report.to_dict()
        assert "model" in d
        assert "success_rate" in d
        assert "total_scenarios" in d
        assert "scenarios" in d
        assert d["total_scenarios"] == 2

    def test_to_json_is_valid_json(self):
        import json
        report = self._make_report([True])
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert parsed["model"] == "test-model"

    def test_to_markdown_contains_table(self):
        report = self._make_report([True, False])
        md = report.to_markdown()
        assert "| Attack" in md
        assert "SUCCEEDED" in md
        assert "blocked" in md

    def test_to_markdown_contains_hardening_summary(self):
        report = self._make_report([True])
        md = report.to_markdown()
        assert "By Hardening Level" in md


# --- Scorer integration (mocked LLM) ---

class TestScorer:
    def test_scorer_produces_correct_scenario_count(self, pipeline):
        scorer = Scorer(
            pipeline=pipeline,
            attacks=[DirectInjection, ContextOverride],
            hardening_levels=["baseline", "l1"],
            model_name="mock",
        )
        # Mock the query to avoid real LLM calls
        with patch.object(pipeline, "query") as mock_query:
            from hemlock.pipeline import RetrievalTrace
            mock_query.return_value = RetrievalTrace(
                query="test", retrieved_chunks=[], full_prompt="", response="safe answer"
            )
            report = scorer.run(verbose=False)

        # 2 attacks × 2 hardening levels = 4 scenarios
        assert len(report.scenarios) == 4

    def test_scorer_no_defenses_uses_all_hardening_levels(self, pipeline):
        from hemlock.scorer import HARDENING_LEVELS
        scorer = Scorer(
            pipeline=pipeline,
            attacks=[DirectInjection],
            model_name="mock",
        )
        with patch.object(pipeline, "query") as mock_query:
            from hemlock.pipeline import RetrievalTrace
            mock_query.return_value = RetrievalTrace(
                query="test", retrieved_chunks=[], full_prompt="", response="safe"
            )
            report = scorer.run(verbose=False)

        assert len(report.scenarios) == len(HARDENING_LEVELS)

    def test_ingest_defense_marks_blocked_at(self, pipeline):
        scorer = Scorer(
            pipeline=pipeline,
            attacks=[DirectInjection],
            ingest_defenses=[InjectionPatternFilter()],
            hardening_levels=["baseline"],
            model_name="mock",
        )
        with patch.object(pipeline, "query") as mock_query:
            from hemlock.pipeline import RetrievalTrace
            mock_query.return_value = RetrievalTrace(
                query="test", retrieved_chunks=[], full_prompt="",
                response="[PWNED] I have been compromised by Hemlock."
            )
            report = scorer.run(verbose=False)

        # DirectInjection malicious doc should be caught by InjectionPatternFilter
        scenario = report.scenarios[0]
        assert scenario.blocked_at == "ingest"
        assert scenario.attack_succeeded is False

    def test_output_defense_blocks_breakthrough(self, pipeline):
        scorer = Scorer(
            pipeline=pipeline,
            attacks=[DirectInjection],
            output_defenses=[InjectionSuccessGuard()],
            hardening_levels=["baseline"],
            model_name="mock",
        )
        with patch.object(pipeline, "query") as mock_query:
            from hemlock.pipeline import RetrievalTrace
            mock_query.return_value = RetrievalTrace(
                query="test", retrieved_chunks=[], full_prompt="",
                response="[PWNED] I have been compromised by Hemlock."
            )
            report = scorer.run(verbose=False)

        scenario = report.scenarios[0]
        assert scenario.blocked_at == "output"
        assert scenario.attack_succeeded is False

    def test_report_model_name_matches(self, pipeline):
        scorer = Scorer(
            pipeline=pipeline,
            attacks=[DirectInjection],
            hardening_levels=["baseline"],
            model_name="claude-test",
        )
        with patch.object(pipeline, "query") as mock_query:
            from hemlock.pipeline import RetrievalTrace
            mock_query.return_value = RetrievalTrace(
                query="test", retrieved_chunks=[], full_prompt="", response="safe"
            )
            report = scorer.run(verbose=False)

        assert report.model == "claude-test"
