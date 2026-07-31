"""Tests for v8.5 judge scorer."""

from __future__ import annotations

from hemlock.hem_judge import HemJudge
from hemlock.judge_scorer import JudgeRevalidator
from hemlock.mock import MockJudgeLLM


def _sample_report():
    return {
        "model": "test",
        "success_rate": 0.5,
        "scenarios": [
            {
                "attack": "Direct Injection",
                "variant": "explicit",
                "hardening": "baseline",
                "attack_succeeded": True,
            },
            {
                "attack": "Direct Injection",
                "variant": "role",
                "hardening": "baseline",
                "attack_succeeded": False,
            },
        ],
    }


class TestJudgeRevalidator:
    def test_flips_succeeded_when_judge_says_false(self):
        revalidator = JudgeRevalidator(HemJudge(MockJudgeLLM(verdict=False)))
        report = revalidator.revalidate_scorer_json(_sample_report())
        assert report.scenarios_flipped == 1
        assert report.judge_success_rate < report.original_success_rate

    def test_apply_to_scorer_dict(self):
        revalidator = JudgeRevalidator(HemJudge(MockJudgeLLM(verdict=False)))
        out = revalidator.apply_to_scorer_dict(_sample_report())
        assert out["success_rate"] == 0.0
        assert out["judge_revalidation"]["scenarios_flipped"] == 1

    def test_verdict_true_keeps_success(self):
        revalidator = JudgeRevalidator(HemJudge(MockJudgeLLM(verdict=True)))
        out = revalidator.apply_to_scorer_dict(_sample_report())
        assert out["success_rate"] == 0.5

    def test_summary(self):
        revalidator = JudgeRevalidator(HemJudge(MockJudgeLLM(verdict=False)))
        report = revalidator.revalidate_scorer_json(_sample_report())
        assert "Judge revalidation" in report.summary()
