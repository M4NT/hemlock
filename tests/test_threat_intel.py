"""Tests for hemlock.threat_intel (v5.3)."""
import json
import pytest
from hemlock.threat_intel import ThreatIntelFeed, FeedConfig, Advisory


@pytest.fixture()
def feed():
    return ThreatIntelFeed(config=FeedConfig(use_mock=True))


def test_fetch_returns_advisories(feed):
    advisories = feed.fetch()
    assert len(advisories) > 0
    assert all(isinstance(a, Advisory) for a in advisories)


def test_advisory_fields(feed):
    advisories = feed.fetch()
    a = advisories[0]
    assert a.cve_id.startswith("CVE-")
    assert a.title
    assert a.attack_category
    assert a.severity in ("critical", "high", "medium", "low")


def test_to_dict(feed):
    feed.fetch()
    a = feed._advisories[0]
    d = a.to_dict()
    assert "cve_id" in d
    assert "attack_category" in d
    assert "severity" in d


def test_to_scenarios(feed):
    feed.fetch()
    scenarios = feed.to_scenarios()
    assert len(scenarios) == len(feed._advisories)


def test_scenario_fields(feed):
    feed.fetch()
    scenarios = feed.to_scenarios()
    for s in scenarios:
        assert s.attack_name.startswith("CVE-")
        assert s.variant == "intel"
        assert s.category


def test_filter_severity(feed):
    feed.fetch()
    critical = feed.filter_severity("critical")
    assert all(a.severity == "critical" for a in critical)


def test_filter_category(feed):
    feed.fetch()
    injection = feed.filter_category("injection")
    assert all(a.attack_category == "injection" for a in injection)


def test_local_file_fallback(tmp_path):
    data = [
        {
            "cve_id": "CVE-2099-00001",
            "title": "Test advisory",
            "description": "desc",
            "attack_category": "injection",
            "severity": "high",
            "source": "local",
        }
    ]
    path = str(tmp_path / "advisories.json")
    with open(path, "w") as f:
        json.dump(data, f)

    feed = ThreatIntelFeed(config=FeedConfig(use_mock=False, local_advisory_path=path))
    advisories = feed.fetch()
    assert len(advisories) == 1
    assert advisories[0].cve_id == "CVE-2099-00001"


def test_empty_feed_no_crash():
    feed = ThreatIntelFeed(config=FeedConfig(use_mock=False))
    advisories = feed.fetch()
    assert isinstance(advisories, list)
