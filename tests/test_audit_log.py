"""Tests for hemlock.audit_log (v4.9)."""
import json
import os
import pytest
from hemlock.audit_log import AuditEvent, AuditLog


@pytest.fixture()
def log(tmp_path):
    return AuditLog(path=str(tmp_path / "audit.jsonl"))


def test_record_creates_file(log, tmp_path):
    e = AuditEvent(team_id="acme", action="write:scan", resource="/scan", outcome="allowed")
    log.record(e)
    assert os.path.exists(str(tmp_path / "audit.jsonl"))


def test_tail_empty(log):
    assert log.tail() == []


def test_tail_returns_events(log):
    log.record(AuditEvent(team_id="acme", action="write:scan", resource="/scan", outcome="allowed"))
    events = log.tail()
    assert len(events) == 1
    assert events[0].team_id == "acme"


def test_tail_limit(log):
    for i in range(5):
        log.record(AuditEvent(team_id="t", action="read:report", resource="/", outcome="allowed"))
    assert len(log.tail(3)) == 3


def test_event_to_dict():
    e = AuditEvent(team_id="t1", action="admin:tenant", resource="/tenant", outcome="denied", detail="no perms")
    d = e.to_dict()
    assert d["team_id"] == "t1"
    assert d["outcome"] == "denied"
    assert d["detail"] == "no perms"
    assert "timestamp" in d


def test_event_to_json_roundtrip():
    e = AuditEvent(team_id="t2", action="write:scan", resource="/scan", outcome="allowed")
    parsed = json.loads(e.to_json())
    assert parsed["team_id"] == "t2"


def test_filter_team(log):
    log.record(AuditEvent(team_id="acme", action="write:scan", resource="/scan", outcome="allowed"))
    log.record(AuditEvent(team_id="beta", action="read:report", resource="/report", outcome="allowed"))
    events = log.filter_team("acme")
    assert all(e.team_id == "acme" for e in events)


def test_filter_outcome_denied(log):
    log.record(AuditEvent(team_id="t", action="write:scan", resource="/scan", outcome="allowed"))
    log.record(AuditEvent(team_id="t", action="admin:tenant", resource="/tenant", outcome="denied"))
    denied = log.filter_outcome("denied")
    assert len(denied) == 1
    assert denied[0].action == "admin:tenant"


def test_append_only(log):
    log.record(AuditEvent(team_id="t", action="a", resource="/", outcome="allowed"))
    log.record(AuditEvent(team_id="t", action="b", resource="/", outcome="allowed"))
    events = log._read_all()
    assert len(events) == 2
    assert events[0].action == "a"
    assert events[1].action == "b"


def test_event_from_dict():
    d = {"team_id": "x", "action": "a", "resource": "/", "outcome": "ok", "detail": "", "timestamp": "2026-01-01T00:00:00+00:00"}
    e = AuditEvent.from_dict(d)
    assert e.team_id == "x"
    assert e.timestamp == "2026-01-01T00:00:00+00:00"


def test_all_alias(log):
    log.record(AuditEvent(team_id="t", action="a", resource="/", outcome="allowed"))
    assert len(log._read_all()) == 1
