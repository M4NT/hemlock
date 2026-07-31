"""Tests for hemlock.streaming (v4.6)."""
import pytest
from hemlock.streaming import ScanEvent, stream_scan_sync


def test_sse_format():
    event = ScanEvent(type="started", data={"target": "lab", "channels": ["rag"]})
    sse = event.to_sse()
    assert sse.startswith("data: ")
    assert '"type": "started"' in sse
    assert sse.endswith("\n\n")


def test_to_dict():
    event = ScanEvent(type="result", data={"channel": "rag", "succeeded": True})
    d = event.to_dict()
    assert d["type"] == "result"
    assert d["channel"] == "rag"


def test_stream_scan_sync_yields_started():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    types = [e.type for e in events]
    assert "started" in types


def test_stream_scan_sync_yields_done():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    types = [e.type for e in events]
    assert "done" in types


def test_stream_scan_sync_yields_results():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    result_events = [e for e in events if e.type == "result"]
    assert len(result_events) > 0


def test_done_event_has_risk_score():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    done = next(e for e in events if e.type == "done")
    assert "risk_score" in done.data
    assert isinstance(done.data["risk_score"], (int, float))


def test_done_event_has_channels_at_risk():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    done = next(e for e in events if e.type == "done")
    assert "channels_at_risk" in done.data
    assert isinstance(done.data["channels_at_risk"], list)


def test_stream_scan_sync_started_has_channels():
    events = list(stream_scan_sync(target="test", channels=["rag", "memory"]))
    started = next(e for e in events if e.type == "started")
    assert "channels" in started.data
    assert "rag" in started.data["channels"]


def test_stream_scan_sync_event_order():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    assert events[0].type == "started"
    assert events[-1].type == "done"


def test_result_event_fields():
    events = list(stream_scan_sync(target="test", channels=["rag"]))
    result_events = [e for e in events if e.type == "result"]
    for e in result_events:
        assert "channel" in e.data
        assert "succeeded" in e.data
        assert "severity" in e.data


def test_stream_scan_async_is_async_generator():
    from hemlock.streaming import stream_scan_async
    import inspect

    gen = stream_scan_async(target="test", channels=["rag"])
    assert inspect.isasyncgen(gen)
