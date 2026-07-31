"""Tests for hemlock.sdk (v5.0)."""
import pytest
from hemlock.sdk import Hemlock


@pytest.fixture()
def hem():
    return Hemlock.mock(channels=["rag"])


def test_version():
    v = Hemlock.version()
    assert isinstance(v, str)
    assert len(v) > 0


def test_mock_factory():
    h = Hemlock.mock()
    assert h.mock is True
    assert h.target == "hemlock-lab"


def test_scan_returns_report(hem):
    report = hem.scan()
    assert hasattr(report, "risk_score")
    assert hasattr(report, "channels_at_risk")


def test_scan_risk_score_range(hem):
    report = hem.scan()
    assert 0 <= report.risk_score() <= 100


def test_eval_returns_eval_report(hem):
    eval_report = hem.eval()
    assert hasattr(eval_report, "overall_score")
    assert hasattr(eval_report, "category_scores")


def test_eval_overall_score_range(hem):
    eval_report = hem.eval()
    assert 0 <= eval_report.overall_score() <= 100


def test_campaign_returns_report(hem):
    report = hem.campaign(["prod", "staging"], max_workers=1)
    assert hasattr(report, "highest_risk_target")
    assert len(report.results) == 2


def test_compliance_returns_list(hem):
    scan_report = hem.scan()
    entries = hem.compliance(scan_report, framework="owasp-llm")
    assert isinstance(entries, list)


def test_stream_yields_events(hem):
    events = list(hem.stream())
    types = [e.type for e in events]
    assert "started" in types
    assert "done" in types


def test_to_sarif_returns_json_string(hem):
    import json

    report = hem.scan()
    sarif_str = hem.to_sarif(report)
    parsed = json.loads(sarif_str)
    assert parsed["version"] == "2.1.0"


def test_render_executive(hem):
    report = hem.scan()
    md = hem.render(report, template="executive")
    assert isinstance(md, str)
    assert len(md) > 0


def test_render_technical(hem):
    report = hem.scan()
    md = hem.render(report, template="technical")
    assert isinstance(md, str)


def test_channels_forwarded():
    h = Hemlock(target="t", channels=["rag", "memory"])
    assert h.channels == ["rag", "memory"]


def test_scan_with_no_channels():
    h = Hemlock.mock()
    report = h.scan()
    assert report.risk_score() >= 0


def test_campaign_empty(hem):
    report = hem.campaign([])
    assert report.results == []
