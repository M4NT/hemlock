"""Tests for hemlock.security_baseline (v7.0)."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hemlock.security_baseline import (
    AlertRouter,
    BaselineComparison,
    BaselineResult,
    BaselineViolation,
    ChannelBaseline,
    FindingRecord,
    PagerDutySink,
    SecurityBaseline,
    SLAPolicy,
    SLATracker,
    SLAViolation,
    SlackSink,
    TrendAnalyzer,
    WebhookSink,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_report(risk_score=20.0, channels_at_risk=None, channel_scores=None):
    channels_at_risk = channels_at_risk or []
    r = MagicMock()
    r.risk_score.return_value = risk_score
    r.channels_at_risk.return_value = channels_at_risk
    if channel_scores is not None:
        r.channel_scores.return_value = channel_scores
    else:
        del r.channel_scores
    return r


def _ts_ago(hours: float) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.isoformat()


def _finding(fid="f1", channel="rag", severity="high", hours_ago=48.0, resolved=False):
    return FindingRecord(
        finding_id=fid,
        channel=channel,
        severity=severity,
        first_seen=_ts_ago(hours_ago),
        last_seen=_ts_ago(1.0),
        resolved=resolved,
    )


# ── SecurityBaseline ─────────────────────────────────────────────────────────

class TestSecurityBaseline:
    def test_from_report_basic(self):
        report = _make_report(risk_score=30.0, channels_at_risk=["rag", "tools"])
        bl = SecurityBaseline.from_report(report, label="baseline-1")
        assert bl.label == "baseline-1"
        assert bl.overall_max_risk == 30.0
        assert "rag" in bl.channels
        assert "tools" in bl.channels

    def test_from_report_with_tolerance(self):
        report = _make_report(risk_score=30.0, channels_at_risk=["rag"])
        bl = SecurityBaseline.from_report(report, label="bl", tolerance=5.0)
        assert bl.overall_max_risk == 35.0
        assert bl.channels["rag"].expected_max_risk == 35.0

    def test_from_report_with_channel_scores(self):
        report = _make_report(
            risk_score=30.0,
            channels_at_risk=["rag", "tools"],
            channel_scores={"rag": 40.0, "tools": 20.0},
        )
        bl = SecurityBaseline.from_report(report, label="bl")
        assert bl.channels["rag"].expected_max_risk == 40.0
        assert bl.channels["tools"].expected_max_risk == 20.0

    def test_to_dict_roundtrip(self):
        report = _make_report(risk_score=25.0, channels_at_risk=["rag"])
        bl = SecurityBaseline.from_report(report, label="bl", tolerance=2.0)
        d = bl.to_dict()
        bl2 = SecurityBaseline.from_dict(d)
        assert bl2.label == bl.label
        assert bl2.overall_max_risk == bl.overall_max_risk
        assert "rag" in bl2.channels

    def test_save_load(self, tmp_path):
        report = _make_report(risk_score=10.0, channels_at_risk=["memory"])
        bl = SecurityBaseline.from_report(report, label="saved")
        path = str(tmp_path / "baseline.json")
        bl.save(path)
        loaded = SecurityBaseline.load(path)
        assert loaded.label == "saved"
        assert loaded.overall_max_risk == 10.0
        assert "memory" in loaded.channels

    def test_channel_baseline_fields(self):
        report = _make_report(
            risk_score=50.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 60.0},
        )
        bl = SecurityBaseline.from_report(report, label="bl")
        ch = bl.channels["rag"]
        assert isinstance(ch, ChannelBaseline)
        assert ch.channel == "rag"
        assert ch.expected_max_risk == 60.0


# ── BaselineComparison ───────────────────────────────────────────────────────

class TestBaselineComparison:
    def _baseline(self, overall=20.0, channels=None, tolerance=0.0):
        channels = channels or {}
        return SecurityBaseline(
            label="test-bl",
            captured_at="2026-01-01T00:00:00+00:00",
            channels={
                k: ChannelBaseline(channel=k, expected_max_risk=v)
                for k, v in channels.items()
            },
            overall_max_risk=overall,
            tolerance=tolerance,
        )

    def test_compliant_when_under_baseline(self):
        bl = self._baseline(overall=50.0, channels={"rag": 40.0})
        report = _make_report(risk_score=30.0, channels_at_risk=["rag"])
        result = BaselineComparison.compare(bl, report)
        assert result.compliant

    def test_violation_when_over_baseline(self):
        bl = self._baseline(overall=20.0, channels={"rag": 20.0})
        report = _make_report(
            risk_score=60.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 60.0},
        )
        result = BaselineComparison.compare(bl, report)
        assert not result.compliant
        assert len(result.violations) == 1
        v = result.violations[0]
        assert v.channel == "rag"
        assert v.actual == 60.0
        assert v.expected_max == 20.0

    def test_severity_critical(self):
        bl = self._baseline(overall=10.0, channels={"rag": 10.0})
        report = _make_report(
            risk_score=50.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 50.0},
        )
        result = BaselineComparison.compare(bl, report)
        assert result.violations[0].severity == "critical"

    def test_severity_medium(self):
        bl = self._baseline(overall=30.0, channels={"rag": 30.0})
        report = _make_report(
            risk_score=42.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 42.0},
        )
        result = BaselineComparison.compare(bl, report)
        assert result.violations[0].severity == "medium"

    def test_new_channel_not_in_baseline_is_violation(self):
        bl = self._baseline(overall=10.0, channels={})
        report = _make_report(risk_score=30.0, channels_at_risk=["new_channel"])
        result = BaselineComparison.compare(bl, report)
        assert not result.compliant
        assert result.new_channels_at_risk == ["new_channel"]

    def test_summary_compliant(self):
        bl = self._baseline(overall=100.0, channels={"rag": 80.0})
        report = _make_report(risk_score=20.0, channels_at_risk=[])
        result = BaselineComparison.compare(bl, report)
        assert "COMPLIANT" in result.summary()

    def test_summary_violation(self):
        bl = self._baseline(overall=10.0, channels={"rag": 10.0})
        report = _make_report(
            risk_score=50.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 50.0},
        )
        result = BaselineComparison.compare(bl, report)
        assert "VIOLATION" in result.summary()

    def test_to_dict(self):
        bl = self._baseline(overall=10.0, channels={"rag": 10.0})
        report = _make_report(
            risk_score=50.0,
            channels_at_risk=["rag"],
            channel_scores={"rag": 50.0},
        )
        result = BaselineComparison.compare(bl, report)
        d = result.to_dict()
        assert d["compliant"] is False
        assert isinstance(d["violations"], list)


# ── SLAPolicy ────────────────────────────────────────────────────────────────

class TestSLAPolicy:
    def test_hours_for_known_severities(self):
        p = SLAPolicy(critical_hours=4, high_hours=24, medium_hours=72, low_hours=168)
        assert p.hours_for("critical") == 4
        assert p.hours_for("high") == 24
        assert p.hours_for("medium") == 72
        assert p.hours_for("low") == 168

    def test_hours_for_unknown_defaults_to_low(self):
        p = SLAPolicy(low_hours=500)
        assert p.hours_for("unknown") == 500


# ── SLATracker ───────────────────────────────────────────────────────────────

class TestSLATracker:
    def test_ingest_and_open_findings(self, tmp_path):
        tracker = SLATracker(path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1"), _finding("f2")])
        assert len(tracker.open_findings()) == 2

    def test_resolve_finding(self, tmp_path):
        tracker = SLATracker(path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1")])
        ok = tracker.resolve("f1")
        assert ok
        assert len(tracker.open_findings()) == 0

    def test_check_violations_detects_breach(self, tmp_path):
        policy = SLAPolicy(high_hours=1)  # 1h SLA; finding is 48h old
        tracker = SLATracker(policy=policy, path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1", severity="high", hours_ago=48.0)])
        violations = tracker.check_violations()
        assert len(violations) == 1
        assert violations[0].finding.finding_id == "f1"
        assert violations[0].overdue_hours > 0

    def test_check_no_violations_within_sla(self, tmp_path):
        policy = SLAPolicy(high_hours=72)
        tracker = SLATracker(policy=policy, path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1", severity="high", hours_ago=10.0)])
        violations = tracker.check_violations()
        assert violations == []

    def test_resolved_findings_excluded(self, tmp_path):
        policy = SLAPolicy(high_hours=1)
        tracker = SLATracker(policy=policy, path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1", severity="high", hours_ago=48.0, resolved=True)])
        violations = tracker.check_violations()
        assert violations == []

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "sla.jsonl")
        tracker1 = SLATracker(path=path)
        tracker1.ingest([_finding("f1")])
        tracker2 = SLATracker(path=path)
        assert len(tracker2.open_findings()) == 1

    def test_ingest_updates_existing(self, tmp_path):
        tracker = SLATracker(path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([_finding("f1", hours_ago=24.0)])
        tracker.ingest([_finding("f1", hours_ago=25.0)])  # upsert
        assert len(tracker.open_findings()) == 1

    def test_violations_sorted_by_overdue_desc(self, tmp_path):
        policy = SLAPolicy(high_hours=1, critical_hours=1)
        tracker = SLATracker(policy=policy, path=str(tmp_path / "sla.jsonl"))
        tracker.ingest([
            _finding("f_short", severity="critical", hours_ago=5.0),
            _finding("f_long", severity="critical", hours_ago=100.0),
        ])
        violations = tracker.check_violations()
        assert violations[0].finding.finding_id == "f_long"


# ── AlertSinks ───────────────────────────────────────────────────────────────

def _make_violation(fid="v1", channel="rag", severity="high", open_h=48.0, sla_h=24):
    f = _finding(fid=fid, channel=channel, severity=severity)
    return SLAViolation(finding=f, sla_hours=sla_h, open_hours=open_h, overdue_hours=open_h - sla_h)


class TestSlackSink:
    def test_send_success(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            sink = SlackSink("https://hooks.slack.com/test")
            result = sink.send([_make_violation()])
        assert result is True

    def test_send_empty_violations(self):
        sink = SlackSink("https://hooks.slack.com/test")
        assert sink.send([]) is True

    def test_send_failure_returns_false(self):
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            sink = SlackSink("https://hooks.slack.com/test")
            result = sink.send([_make_violation()])
        assert result is False


class TestPagerDutySink:
    def test_send_success(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            sink = PagerDutySink("routing-key-123")
            result = sink.send([_make_violation(severity="critical")])
        assert result is True

    def test_send_empty(self):
        sink = PagerDutySink("key")
        assert sink.send([]) is True

    def test_severity_mapping_critical(self):
        with patch("urllib.request.urlopen") as mock_open:
            captured = []

            def capture(req, timeout):
                captured.append(json.loads(req.data.decode()))
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m

            mock_open.side_effect = capture
            sink = PagerDutySink("key")
            sink.send([_make_violation(severity="critical")])

        assert captured[0]["payload"]["severity"] == "critical"


class TestWebhookSink:
    def test_send_success(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            sink = WebhookSink("https://example.com/hook", headers={"X-Token": "abc"})
            result = sink.send([_make_violation()])
        assert result is True

    def test_payload_structure(self):
        captured = []

        def capture(req, timeout):
            captured.append(json.loads(req.data.decode()))
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("urllib.request.urlopen", side_effect=capture):
            sink = WebhookSink("https://example.com/hook")
            sink.send([_make_violation("v1"), _make_violation("v2")])

        assert captured[0]["violation_count"] == 2
        assert captured[0]["source"] == "hemlock"


# ── AlertRouter ──────────────────────────────────────────────────────────────

class TestAlertRouter:
    def test_routes_critical_to_all_sinks(self):
        s1, s2 = MagicMock(spec=SlackSink), MagicMock(spec=WebhookSink)
        s1.send.return_value = True
        s2.send.return_value = True
        router = AlertRouter([s1, s2])
        router.route([_make_violation(severity="critical")])
        s1.send.assert_called_once()
        s2.send.assert_called_once()

    def test_routes_low_to_first_sink_only(self):
        s1, s2 = MagicMock(spec=SlackSink), MagicMock(spec=WebhookSink)
        s1.send.return_value = True
        s2.send.return_value = True
        router = AlertRouter([s1, s2])
        router.route([_make_violation(severity="low")])
        s1.send.assert_called_once()
        s2.send.assert_not_called()

    def test_empty_violations_no_calls(self):
        s1 = MagicMock(spec=SlackSink)
        router = AlertRouter([s1])
        result = router.route([])
        s1.send.assert_not_called()
        assert result == {}

    def test_custom_routing(self):
        s1, s2 = MagicMock(spec=SlackSink), MagicMock(spec=WebhookSink)
        s1.send.return_value = True
        s2.send.return_value = True
        router = AlertRouter([s1, s2], severity_routing={
            "critical": [1],   # only s2
            "high": [0, 1],
            "medium": [0],
            "low": [],
        })
        router.route([_make_violation(severity="critical")])
        s1.send.assert_not_called()
        s2.send.assert_called_once()

    def test_returns_success_map(self):
        s1 = MagicMock(spec=SlackSink)
        s1.send.return_value = True
        router = AlertRouter([s1])
        results = router.route([_make_violation(severity="high")])
        assert results["0"] is True


# ── TrendAnalyzer ─────────────────────────────────────────────────────────────

class TestTrendAnalyzer:
    def _hist(self, scores_by_hours_ago: list[tuple[float, float]]) -> list[dict]:
        """(hours_ago, risk_score) → history entries."""
        entries = []
        for hours_ago, score in scores_by_hours_ago:
            dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
            entries.append({"timestamp": dt.isoformat(), "risk_score": score})
        return entries

    def test_mean_risk(self):
        hist = self._hist([(1, 10.0), (2, 20.0), (3, 30.0)])
        a = TrendAnalyzer(hist)
        assert a.mean_risk(days=7) == pytest.approx(20.0)

    def test_max_risk(self):
        hist = self._hist([(1, 10.0), (2, 50.0), (3, 30.0)])
        assert TrendAnalyzer(hist).max_risk(days=7) == 50.0

    def test_min_risk(self):
        hist = self._hist([(1, 10.0), (2, 50.0), (3, 30.0)])
        assert TrendAnalyzer(hist).min_risk(days=7) == 10.0

    def test_trend_degrading(self):
        hist = self._hist([
            (20, 10.0), (19, 15.0),   # first half: ~12.5
            (2, 50.0), (1, 60.0),     # second half: ~55.0
        ])
        assert TrendAnalyzer(hist).trend(days=30) == "degrading"

    def test_trend_improving(self):
        hist = self._hist([
            (20, 60.0), (19, 50.0),   # first half: ~55.0
            (2, 10.0), (1, 5.0),      # second half: ~7.5
        ])
        assert TrendAnalyzer(hist).trend(days=30) == "improving"

    def test_trend_stable(self):
        hist = self._hist([(5, 30.0), (4, 32.0), (3, 29.0), (2, 31.0)])
        assert TrendAnalyzer(hist).trend(days=30, stable_band=5.0) == "stable"

    def test_window_filters_old_entries(self):
        hist = self._hist([
            (100 * 24, 90.0),   # 100 days ago — outside 30d window
            (1, 20.0),
        ])
        a = TrendAnalyzer(hist)
        assert len(a.window(days=30)) == 1

    def test_empty_history(self):
        a = TrendAnalyzer([])
        assert a.mean_risk() == 0.0
        assert a.trend() == "stable"
        assert a.summary()["data_points"] == 0

    def test_summary_keys(self):
        hist = self._hist([(1, 25.0), (2, 35.0)])
        s = TrendAnalyzer(hist).summary(days=7)
        assert set(s.keys()) == {"window_days", "data_points", "mean_risk", "max_risk", "min_risk", "trend"}
