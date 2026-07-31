"""Tests for hemlock.hemlock_score (v8.9)."""

from __future__ import annotations

from hemlock.hemlock_score import HemlockScoreCalculator, HemlockScoreResult, _grade_for_score


class _FakeResult:
    def __init__(self, channel: str, succeeded: bool) -> None:
        self.channel = channel
        self.variant = "test"
        self.succeeded = succeeded
        self.severity = "high"
        self.detail = "injection"


class _FakeReport:
    def __init__(self, risk: float = 40.0, results: list | None = None) -> None:
        self._risk = risk
        self.results = results or [_FakeResult("rag", True)]

    def risk_score(self) -> float:
        return self._risk


def test_grade_mapping():
    assert _grade_for_score(95) == "A+"
    assert _grade_for_score(85) == "A"
    assert _grade_for_score(75) == "B"
    assert _grade_for_score(55) == "D"
    assert _grade_for_score(30) == "F"


def test_compute_high_score_when_low_risk():
    calc = HemlockScoreCalculator()
    result = calc.compute(risk_score=10.0, coverage_pct=0.9, sla_compliance=1.0)
    assert result.score >= 70
    assert result.grade in ("A", "A+", "B")


def test_compute_penalizes_regressions():
    calc = HemlockScoreCalculator()
    clean = calc.compute(risk_score=30.0, replay_regressions=0)
    dirty = calc.compute(risk_score=30.0, replay_regressions=3)
    assert dirty.score < clean.score
    assert dirty.stability_component < clean.stability_component


def test_from_hem_report_with_context():
    calc = HemlockScoreCalculator(risk_preset="fintech")
    report = _FakeReport(risk=50.0)
    result = calc.from_hem_report(
        report,
        context={
            "coverage_pct": 0.8,
            "sla_compliance": 0.95,
            "replay_regressions": 1,
            "policy_passed": True,
        },
    )
    assert isinstance(result, HemlockScoreResult)
    assert 0 <= result.score <= 100
    assert result.breakdown


def test_badge_output():
    result = HemlockScoreCalculator().compute(risk_score=20.0)
    assert "Hemlock Score" in result.badge()
    assert "Hemlock_Score" in result.badge_markdown()


def test_recommendations_on_high_risk():
    result = HemlockScoreCalculator().compute(risk_score=80.0)
    assert any("risk" in r.lower() for r in result.recommendations)
