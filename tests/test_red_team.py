"""Tests for hemlock.red_team (v5.1)."""
import json
import pytest
from hemlock.red_team import RedTeamScheduler, RedTeamConfig, RedTeamDiff


@pytest.fixture()
def scheduler(tmp_path):
    return RedTeamScheduler(
        targets=["prod", "staging"],
        config=RedTeamConfig(
            history_path=str(tmp_path / "rt_history.json"),
            channels=["rag"],
        ),
    )


def test_run_once_returns_entry(scheduler):
    entry = scheduler.run_once()
    assert entry.timestamp
    assert isinstance(entry.scores, dict)
    assert isinstance(entry.at_risk, dict)


def test_run_once_creates_history_file(scheduler, tmp_path):
    scheduler.run_once()
    assert (tmp_path / "rt_history.json").exists()


def test_history_grows(scheduler):
    scheduler.run_once()
    scheduler.run_once()
    assert len(scheduler.history()) == 2


def test_latest_returns_last_entry(scheduler):
    scheduler.run_once()
    entry = scheduler.run_once()
    assert scheduler.latest() is entry


def test_diff_new_at_risk_first_run(scheduler):
    entry = scheduler.run_once()
    assert isinstance(entry.diff.new_at_risk, list)


def test_diff_alert_bool(scheduler):
    entry = scheduler.run_once()
    assert isinstance(entry.diff.alert, bool)


def test_score_deltas_on_second_run(scheduler):
    scheduler.run_once()
    entry = scheduler.run_once()
    assert isinstance(entry.diff.score_deltas, dict)
    for t in ["prod", "staging"]:
        assert t in entry.diff.score_deltas


def test_history_persists(tmp_path):
    path = str(tmp_path / "rt.json")
    s1 = RedTeamScheduler(["prod"], config=RedTeamConfig(history_path=path, channels=["rag"]))
    s1.run_once()
    s2 = RedTeamScheduler(["prod"], config=RedTeamConfig(history_path=path, channels=["rag"]))
    assert len(s2.history()) == 1


def test_on_alert_callback_called(tmp_path):
    alerts = []

    def cb(diff):
        alerts.append(diff)

    s = RedTeamScheduler(
        ["prod"],
        config=RedTeamConfig(history_path=str(tmp_path / "rt.json"), channels=["rag"]),
        on_alert=cb,
    )
    entry = s.run_once()
    if entry.diff.alert:
        assert len(alerts) == 1


def test_diff_to_dict():
    diff = RedTeamDiff(
        timestamp="2026-07-31T00:00:00+00:00",
        new_at_risk=["prod"],
        recovered=[],
        regressed=["staging"],
        improved=[],
        score_deltas={"prod": 20, "staging": 15},
        alert=True,
    )
    d = diff.to_dict()
    assert d["alert"] is True
    assert "prod" in d["new_at_risk"]


def test_history_entry_to_dict(scheduler):
    entry = scheduler.run_once()
    d = entry.to_dict()
    assert "timestamp" in d
    assert "scores" in d
    assert "at_risk" in d
    assert "diff" in d


def test_no_history_returns_none():
    import tempfile
    path = tempfile.mktemp(suffix=".json")
    s = RedTeamScheduler(["prod"], config=RedTeamConfig(history_path=path, channels=["rag"]))
    assert s.latest() is None


def test_recovered_after_fix(tmp_path):
    path = str(tmp_path / "rt.json")
    s = RedTeamScheduler(["prod"], config=RedTeamConfig(history_path=path, channels=["rag"]))
    s.run_once()
    # second run: recovered = targets no longer at risk
    entry = s.run_once()
    assert isinstance(entry.diff.recovered, list)
