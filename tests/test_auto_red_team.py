"""Tests for hemlock.auto_red_team (v6.2)."""

import pytest
from hemlock.auto_red_team import (
    AgentConfig,
    RoundResult,
    AutoRedTeamReport,
    AutoRedTeamAgent,
    _CHANNEL_ATTACKS,
)


def make_round(channel="rag", succeeded=True, round_num=1):
    return RoundResult(
        round_number=round_num,
        channel=channel,
        attack_name=_CHANNEL_ATTACKS.get(channel, "direct_injection"),
        succeeded=succeeded,
        attempts=1,
        judge_confidence=0.85,
        payload_preview="test payload",
    )


def make_report(rounds=None):
    rounds = rounds or [make_round()]
    exploited = [r.channel for r in rounds if r.succeeded]
    return AutoRedTeamReport(
        rounds=rounds,
        exploited_channels=exploited,
        total_successes=sum(1 for r in rounds if r.succeeded),
        total_attempts=sum(r.attempts for r in rounds),
    )


def test_agent_config_defaults():
    cfg = AgentConfig()
    assert cfg.max_rounds == 3
    assert cfg.budget_attacks == 15
    assert cfg.use_healing is True


def test_round_result_fields():
    r = make_round()
    assert r.channel == "rag"
    assert r.succeeded is True
    assert r.attempts == 1


def test_auto_red_team_report_success_rate_all_succeeded():
    report = make_report([make_round(succeeded=True), make_round(channel="memory", succeeded=True)])
    assert report.success_rate() == 1.0


def test_auto_red_team_report_success_rate_partial():
    report = make_report([
        make_round(channel="rag", succeeded=True),
        make_round(channel="memory", succeeded=False),
    ])
    assert report.success_rate() == 0.5


def test_auto_red_team_report_success_rate_empty():
    report = AutoRedTeamReport(rounds=[], exploited_channels=[], total_successes=0, total_attempts=0)
    assert report.success_rate() == 0.0


def test_auto_red_team_report_to_dict():
    report = make_report()
    d = report.to_dict()
    assert "total_successes" in d
    assert "rounds" in d
    assert "exploited_channels" in d
    assert "success_rate" in d


def test_auto_red_team_report_to_json():
    import json
    report = make_report()
    doc = json.loads(report.to_json())
    assert doc["total_successes"] >= 0


def test_channel_attacks_mapping():
    assert "rag" in _CHANNEL_ATTACKS
    assert _CHANNEL_ATTACKS["memory"] == "memory_poisoning"
    assert _CHANNEL_ATTACKS["exfiltration"] == "exfiltration"


def test_agent_run_basic():
    agent = AutoRedTeamAgent(config=AgentConfig(max_rounds=2, budget_attacks=5, use_healing=False))
    report = agent.run()
    assert isinstance(report, AutoRedTeamReport)
    assert len(report.rounds) <= 2
    assert report.total_attempts >= 0


def test_agent_run_respects_max_rounds():
    agent = AutoRedTeamAgent(config=AgentConfig(max_rounds=1, budget_attacks=99, use_healing=False))
    report = agent.run()
    assert len(report.rounds) == 1


def test_agent_run_respects_budget():
    agent = AutoRedTeamAgent(config=AgentConfig(max_rounds=10, budget_attacks=2, use_healing=False))
    report = agent.run()
    assert report.total_attempts <= 2


def test_agent_run_with_channels():
    agent = AutoRedTeamAgent(
        config=AgentConfig(
            max_rounds=2,
            channels=["rag", "memory"],
            use_healing=False,
        )
    )
    report = agent.run()
    for r in report.rounds:
        assert r.channel in ["rag", "memory"]


def test_agent_exploited_channels_populated_on_success():
    agent = AutoRedTeamAgent(config=AgentConfig(max_rounds=3, use_healing=False))
    report = agent.run()
    for ch in report.exploited_channels:
        assert any(r.channel == ch and r.succeeded for r in report.rounds)
