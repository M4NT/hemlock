"""Tests for EvalComparison (v3.7) — reports built from hand-made scenarios."""

from __future__ import annotations

from hemlock.eval_benchmark import EvalReport, EvalScenario
from hemlock.eval_comparison import EvalComparison, EvalComparisonRunner


def _report(model, scenarios):
    return EvalReport(
        model_name=model,
        scenarios=[
            EvalScenario(
                attack_name=n, variant="v", category=cat, succeeded=ok, notes=""
            )
            for (n, cat, ok) in scenarios
        ],
    )


def _reports():
    # model_a: injection fully blocked; model_b: one injection succeeded
    a = _report("model_a", [
        ("i1", "injection", False),
        ("i2", "injection", False),
        ("e1", "exfiltration", False),
    ])
    b = _report("model_b", [
        ("i1", "injection", True),
        ("i2", "injection", False),
        ("e1", "exfiltration", False),
    ])
    return {"model_a": a, "model_b": b}


def test_category_matrix():
    cmp = EvalComparison.from_reports(_reports())
    matrix = cmp.category_matrix()
    assert matrix["injection"]["model_a"] == 100.0
    assert matrix["injection"]["model_b"] == 50.0
    assert matrix["exfiltration"]["model_a"] == 100.0


def test_overall_scores():
    cmp = EvalComparison.from_reports(_reports())
    scores = cmp.overall_scores()
    assert scores["model_a"] == 100.0
    assert scores["model_b"] == 75.0  # mean of 50 and 100


def test_winner():
    cmp = EvalComparison.from_reports(_reports())
    assert cmp.winner() == "model_a"


def test_winner_tie_prefers_first():
    a = _report("a", [("x", "injection", False)])
    b = _report("b", [("x", "injection", False)])
    cmp = EvalComparison.from_reports({"a": a, "b": b})
    assert cmp.winner() == "a"


def test_regressions_against_baseline():
    cmp = EvalComparison.from_reports(_reports())
    regs = cmp.regressions("model_a")
    assert "model_b" in regs
    assert regs["model_b"]["injection"] == -50.0


def test_regressions_none_when_baseline_worst():
    cmp = EvalComparison.from_reports(_reports())
    regs = cmp.regressions("model_b")
    assert regs == {}  # model_a scores >= model_b everywhere


def test_regressions_unknown_baseline_raises():
    cmp = EvalComparison.from_reports(_reports())
    try:
        cmp.regressions("nope")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_to_dict_and_markdown():
    cmp = EvalComparison.from_reports(_reports())
    d = cmp.to_dict()
    assert d["winner"] == "model_a"
    assert set(d["models"]) == {"model_a", "model_b"}
    md = cmp.to_markdown()
    assert "Eval Comparison" in md
    assert "model_a" in md and "model_b" in md


def test_runner_from_mock_smoke():
    runner = EvalComparisonRunner.from_mock(
        ["m1", "m2"],
        attack_names=["indirect_injection"],
        variants_per_attack=1,
    )
    cmp = runner.run()
    assert set(cmp.overall_scores()) == {"m1", "m2"}
    assert cmp.winner() in {"m1", "m2"}
