"""Tests for HemWatcher (v3.9) — mocked session factory, tmpdir history."""

from __future__ import annotations

import os
import tempfile

from hemlock.watcher import HemWatcher, WatchEvent, WatchHistory


class _FakeReport:
    def __init__(self, risk, channels):
        self._risk = risk
        self._channels = channels

    def risk_score(self):
        return self._risk

    def channels_at_risk(self):
        return self._channels


class _FakeSession:
    def __init__(self, risk, channels):
        self._report = _FakeReport(risk, channels)

    def run(self):
        return self._report


def _factory(scores):
    # scores: mutable list, pops one report config per tick
    def factory():
        risk, channels = scores.pop(0)
        return _FakeSession(risk, channels)
    return factory


def _history_path():
    d = tempfile.mkdtemp(prefix="hemlock_watch_")
    return os.path.join(d, "history.json")


def test_first_tick_no_alert_zero_delta():
    w = HemWatcher(_factory([(50.0, ["rag"])]), _history_path(), threshold=5.0)
    event = w.run_once()
    assert event.delta == 0.0
    assert event.alert is False
    assert event.risk_score == 50.0
    assert event.channels_at_risk == ["rag"]


def test_delta_computed_across_ticks():
    path = _history_path()
    scores = [(50.0, []), (58.0, ["rag"])]
    w = HemWatcher(_factory(scores), path, threshold=5.0)
    w.run_once()
    e2 = w.run_once()
    assert e2.delta == 8.0
    assert e2.alert is True


def test_no_alert_within_threshold():
    scores = [(50.0, []), (53.0, [])]
    w = HemWatcher(_factory(scores), _history_path(), threshold=5.0)
    w.run_once()
    e2 = w.run_once()
    assert e2.delta == 3.0
    assert e2.alert is False


def test_history_persisted_and_reloaded():
    path = _history_path()
    scores = [(10.0, []), (20.0, [])]
    w = HemWatcher(_factory(scores), path, threshold=100.0)
    w.run_once()
    w.run_once()
    hist = WatchHistory(path)
    events = hist.load()
    assert len(events) == 2
    assert isinstance(events[0], WatchEvent)
    assert events[1].risk_score == 20.0
    assert hist.last().risk_score == 20.0


def test_history_empty_on_missing_file():
    hist = WatchHistory(_history_path())
    assert hist.load() == []
    assert hist.last() is None


def test_webhook_posted_on_alert(monkeypatch):
    posted = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=10):
        posted["url"] = req.full_url
        posted["data"] = req.data
        return _Resp()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    scores = [(10.0, []), (80.0, ["rag", "memory"])]
    w = HemWatcher(
        _factory(scores), _history_path(),
        threshold=5.0, webhook_url="https://hooks.example.com/x",
    )
    w.run_once()
    e2 = w.run_once()
    assert e2.alert is True
    assert posted["url"] == "https://hooks.example.com/x"
    assert b"risk_score" in posted["data"]


def test_webhook_not_posted_without_alert(monkeypatch):
    called = {"n": 0}

    def _fake_urlopen(req, timeout=10):
        called["n"] += 1

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    w = HemWatcher(
        _factory([(10.0, [])]), _history_path(),
        threshold=5.0, webhook_url="https://hooks.example.com/x",
    )
    w.run_once()
    assert called["n"] == 0
