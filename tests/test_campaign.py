"""Tests for hemlock.campaign (v4.8)."""
import json
import pytest
from hemlock.campaign import Campaign, CampaignTarget, CampaignReport, TargetResult


@pytest.fixture()
def two_targets():
    return [
        CampaignTarget(name="prod", channels=["rag"]),
        CampaignTarget(name="staging", channels=["rag"]),
    ]


def test_campaign_run_returns_report(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    assert isinstance(report, CampaignReport)


def test_campaign_result_count(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    assert len(report.results) == 2


def test_campaign_target_names(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    names = {r.target_name for r in report.results}
    assert names == {"prod", "staging"}


def test_campaign_result_ok(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    for r in report.results:
        assert r.ok
        assert r.error is None


def test_campaign_risk_score_range(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    for r in report.results:
        assert 0 <= r.risk_score <= 100


def test_campaign_parallel(two_targets):
    report = Campaign(two_targets, max_workers=2).run()
    assert len(report.results) == 2


def test_campaign_order_preserved(two_targets):
    report = Campaign(two_targets, max_workers=2).run()
    assert report.results[0].target_name == "prod"
    assert report.results[1].target_name == "staging"


def test_highest_risk_target(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    winner = report.highest_risk_target()
    assert winner in {"prod", "staging"}


def test_mean_risk_score(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    mean = report.mean_risk_score()
    assert 0.0 <= mean <= 100.0


def test_targets_at_risk_returns_list(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    assert isinstance(report.targets_at_risk(), list)


def test_failed_targets_empty_on_success(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    assert report.failed_targets() == []


def test_error_target():
    bad = CampaignTarget(name="bad", channels=["nonexistent_channel_xyz"])
    report = Campaign([bad], max_workers=1).run()
    r = report.results[0]
    # nonexistent channel handled gracefully (no channels run → score 0)
    assert r.target_name == "bad"


def test_to_dict(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    d = report.to_dict()
    assert "results" in d
    assert "mean_risk_score" in d
    assert "highest_risk_target" in d


def test_to_json(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    parsed = json.loads(report.to_json())
    assert len(parsed["results"]) == 2


def test_to_markdown(two_targets):
    report = Campaign(two_targets, max_workers=1).run()
    md = report.to_markdown()
    assert "Campaign Report" in md
    assert "prod" in md
    assert "staging" in md


def test_empty_campaign():
    report = Campaign([], max_workers=1).run()
    assert report.results == []
    assert report.highest_risk_target() is None
    assert report.mean_risk_score() == 0.0
