"""Tests for the hemlock gate CI/CD command."""

import json
from unittest.mock import patch

from typer.testing import CliRunner

from hemlock.cli import app
from hemlock.scorer import ScenarioResult, ScorerReport

runner = CliRunner()


def _write_baseline(path, success_rate: float, total: int = 10):
    data = {
        "model": "test-model",
        "success_rate": success_rate,
        "total_scenarios": total,
        "scenarios": [],
    }
    with open(path, "w") as f:
        json.dump(data, f)


def _mock_scorer_report(success_rate_val: float) -> ScorerReport:
    report = ScorerReport(model="test-model")
    n = 10
    succeeded = int(success_rate_val * n)
    for i in range(n):
        report.scenarios.append(
            ScenarioResult(
                attack_name=f"Attack {i}",
                hardening_level="baseline",
                ingest_defenses=[],
                retrieval_defenses=[],
                output_defenses=[],
                attack_succeeded=(i < succeeded),
                blocked_at=None if i < succeeded else "ingest",
            )
        )
    return report


class TestGateCommand:
    def test_gate_passes_when_no_regression(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_baseline(baseline, success_rate=0.5)

        mock_report = _mock_scorer_report(0.4)  # improved

        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            result = runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
            ])

        assert result.exit_code == 0
        assert "Gate passed" in result.output

    def test_gate_fails_on_regression_above_threshold(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_baseline(baseline, success_rate=0.3)

        mock_report = _mock_scorer_report(0.5)  # worse by 0.2 > 0.05 threshold

        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            result = runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
            ])

        assert result.exit_code != 0
        assert "REGRESSION" in result.output

    def test_gate_no_fail_flag_exits_0_despite_regression(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_baseline(baseline, success_rate=0.1)

        mock_report = _mock_scorer_report(0.8)  # much worse

        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            result = runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
                "--no-fail",
            ])

        assert result.exit_code == 0

    def test_gate_saves_report_when_save_provided(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        save_path = tmp_path / "latest.json"
        _write_baseline(baseline, success_rate=0.5)

        mock_report = _mock_scorer_report(0.4)

        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
                "--save", str(save_path),
            ])

        assert save_path.exists()
        with open(save_path) as f:
            saved = json.load(f)
        assert "success_rate" in saved

    def test_gate_exits_1_on_missing_baseline(self, tmp_path):
        result = runner.invoke(app, [
            "gate",
            "--baseline", str(tmp_path / "nonexistent.json"),
            "--model", "mock",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "Baseline" in result.output

    def test_gate_respects_custom_threshold(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_baseline(baseline, success_rate=0.3)

        mock_report = _mock_scorer_report(0.35)  # delta=0.05 exactly

        # With threshold=0.10, a 0.05 delta should PASS
        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            result = runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
                "--threshold", "0.10",
            ])

        assert result.exit_code == 0

    def test_gate_prints_delta(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_baseline(baseline, success_rate=0.4)

        mock_report = _mock_scorer_report(0.4)

        with patch("hemlock.cli._get_pipeline"), \
             patch("hemlock.scorer.Scorer.run", return_value=mock_report):
            result = runner.invoke(app, [
                "gate",
                "--baseline", str(baseline),
                "--model", "mock",
            ])

        assert "Delta" in result.output or "%" in result.output
