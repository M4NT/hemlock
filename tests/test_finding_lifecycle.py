"""Tests for hemlock.finding_lifecycle (v7.1)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from hemlock.finding_lifecycle import (
    FindingLifecycle,
    FindingStore,
    GitHubIssueSink,
    JiraSink,
    LifecycleEvent,
    ManagedFinding,
    RemediationVelocity,
    TicketSink,
    VALID_TRANSITIONS,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ts(hours_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def _finding(fid="f-001", channel="rag", severity="high", hours_ago=0.0) -> ManagedFinding:
    return ManagedFinding(
        finding_id=fid,
        channel=channel,
        severity=severity,
        title=f"Test finding {fid}",
        first_seen=_ts(hours_ago),
    )


# ── ManagedFinding ────────────────────────────────────────────────────────────

class TestManagedFinding:
    def test_default_state_is_open(self):
        f = _finding()
        assert f.state == "open"

    def test_history_initialized_with_open_event(self):
        f = _finding()
        assert len(f.history) == 1
        assert f.history[0].state == "open"

    def test_is_open(self):
        f = _finding()
        assert f.is_open()

    def test_is_not_open_when_resolved(self):
        f = _finding()
        f.state = "resolved"
        assert not f.is_open()

    def test_to_dict_roundtrip(self):
        f = _finding()
        d = f.to_dict()
        f2 = ManagedFinding.from_dict(d)
        assert f2.finding_id == f.finding_id
        assert f2.channel == f.channel
        assert len(f2.history) == len(f.history)

    def test_from_sla_finding(self):
        sla = MagicMock()
        sla.finding_id = "sla-001"
        sla.channel = "tools"
        sla.severity = "critical"
        sla.first_seen = _ts(10)
        f = ManagedFinding.from_sla_finding(sla, title="Critical tools issue")
        assert f.finding_id == "sla-001"
        assert f.severity == "critical"
        assert f.title == "Critical tools issue"

    def test_last_event(self):
        f = _finding()
        assert f.last_event().state == "open"


# ── FindingStore ──────────────────────────────────────────────────────────────

class TestFindingStore:
    def test_upsert_and_get(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        f = _finding("f-001")
        store.upsert(f)
        assert store.get("f-001") is not None
        assert store.get("f-001").channel == "rag"

    def test_list_by_state(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        store.upsert(_finding("f-002"))
        assert len(store.list_by_state("open")) == 2
        assert len(store.list_by_state("triaged")) == 0

    def test_open_findings(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        f2 = _finding("f-002")
        f2.state = "resolved"
        store.upsert(f2)
        assert len(store.open_findings()) == 1

    def test_transition_valid(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        ok = store.transition("f-001", "triaged", actor="alice")
        assert ok
        assert store.get("f-001").state == "triaged"

    def test_transition_appends_to_history(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        store.transition("f-001", "triaged", actor="alice", notes="confirmed")
        f = store.get("f-001")
        assert len(f.history) == 2
        assert f.history[-1].actor == "alice"
        assert f.history[-1].notes == "confirmed"

    def test_transition_invalid_state_returns_false(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        ok = store.transition("f-001", "verified")  # open → verified is invalid
        assert not ok

    def test_transition_unknown_finding_returns_false(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        assert not store.transition("nonexistent", "triaged")

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "findings.jsonl")
        store1 = FindingStore(path)
        store1.upsert(_finding("f-001"))
        store2 = FindingStore(path)
        assert store2.get("f-001") is not None

    def test_upsert_updates_existing(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001", channel="rag"))
        f2 = _finding("f-001", channel="tools")
        store.upsert(f2)
        assert store.get("f-001").channel == "tools"

    def test_all_returns_all_findings(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        for i in range(5):
            store.upsert(_finding(f"f-{i:03d}"))
        assert len(store.all()) == 5

    def test_full_lifecycle_transition_chain(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        store.transition("f-001", "triaged")
        store.transition("f-001", "in_progress")
        store.transition("f-001", "resolved")
        store.transition("f-001", "verified")
        assert store.get("f-001").state == "verified"

    def test_wont_fix_transition(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        store.transition("f-001", "wont_fix")
        assert store.get("f-001").state == "wont_fix"
        assert not store.get("f-001").is_open()


# ── Valid transitions coverage ────────────────────────────────────────────────

class TestValidTransitions:
    def test_all_states_have_transitions_defined(self):
        from hemlock.finding_lifecycle import VALID_STATES
        for state in VALID_STATES:
            assert state in VALID_TRANSITIONS

    def test_terminal_states_can_reopen(self):
        from hemlock.finding_lifecycle import TERMINAL_STATES
        for state in TERMINAL_STATES:
            assert "open" in VALID_TRANSITIONS.get(state, set())


# ── TicketSink (GitHub) ───────────────────────────────────────────────────────

class TestGitHubIssueSink:
    def _sink(self):
        return GitHubIssueSink(token="tok", owner="acme", repo="ai-platform")

    def test_create_ticket_success(self):
        response_data = json.dumps({"html_url": "https://github.com/acme/ai-platform/issues/42"}).encode()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = response_data
        with patch("urllib.request.urlopen", return_value=mock_resp):
            sink = self._sink()
            ref = sink.create_ticket(_finding())
        assert ref == "https://github.com/acme/ai-platform/issues/42"

    def test_create_ticket_failure_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            assert self._sink().create_ticket(_finding()) is None

    def test_update_ticket_success(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self._sink().update_ticket(
                "https://github.com/acme/ai-platform/issues/42",
                _finding(),
            )
        assert result is True

    def test_update_ticket_failure_returns_false(self):
        with patch("urllib.request.urlopen", side_effect=Exception("fail")):
            assert self._sink().update_ticket("42", _finding()) is False

    def test_body_contains_finding_info(self):
        sink = self._sink()
        f = _finding("f-007", channel="tools", severity="critical")
        body = sink._body(f)
        assert "f-007" in body
        assert "tools" in body
        assert "critical" in body


# ── TicketSink (JIRA) ─────────────────────────────────────────────────────────

class TestJiraSink:
    def _sink(self):
        return JiraSink(base_url="https://acme.atlassian.net", token="tok", project_key="SEC")

    def test_create_ticket_success(self):
        response_data = json.dumps({"key": "SEC-101"}).encode()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = response_data
        with patch("urllib.request.urlopen", return_value=mock_resp):
            ref = self._sink().create_ticket(_finding())
        assert "SEC-101" in ref

    def test_create_ticket_failure_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=Exception("fail")):
            assert self._sink().create_ticket(_finding()) is None

    def test_priority_mapping(self):
        sink = self._sink()
        assert sink._priority("critical") == "Highest"
        assert sink._priority("high") == "High"
        assert sink._priority("medium") == "Medium"
        assert sink._priority("low") == "Low"
        assert sink._priority("unknown") == "Medium"

    def test_update_ticket_success(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self._sink().update_ticket("https://acme.atlassian.net/browse/SEC-101", _finding())
        assert result is True


# ── FindingLifecycle ──────────────────────────────────────────────────────────

class TestFindingLifecycle:
    def test_ingest_new_finding(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        lc = FindingLifecycle(store)
        f = _finding("f-001")
        lc.ingest(f)
        assert store.get("f-001") is not None

    def test_ingest_idempotent(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        lc = FindingLifecycle(store)
        lc.ingest(_finding("f-001"))
        lc.ingest(_finding("f-001"))
        assert len(store.all()) == 1

    def test_ingest_calls_sink(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        sink = MagicMock(spec=TicketSink)
        sink.create_ticket.return_value = "https://example.com/issue/1"
        lc = FindingLifecycle(store, sinks=[sink])
        lc.ingest(_finding("f-001"))
        sink.create_ticket.assert_called_once()

    def test_ingest_stores_external_ref(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        sink = MagicMock(spec=GitHubIssueSink)
        sink.create_ticket.return_value = "https://github.com/acme/repo/issues/5"
        lc = FindingLifecycle(store, sinks=[sink])
        lc.ingest(_finding("f-001"))
        f = store.get("f-001")
        assert "githubissue" in f.external_refs or any(f.external_refs.values())

    def test_transition_calls_sink_update(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        sink = MagicMock(spec=GitHubIssueSink)
        sink.create_ticket.return_value = "https://github.com/acme/repo/issues/5"
        type(sink).__name__ = "GitHubIssueSink"
        lc = FindingLifecycle(store, sinks=[sink])
        lc.ingest(_finding("f-001"))
        lc.transition("f-001", "triaged")
        sink.update_ticket.assert_called()

    def test_ingest_batch(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        lc = FindingLifecycle(store)
        lc.ingest_batch([_finding("f-001"), _finding("f-002"), _finding("f-003")])
        assert len(store.all()) == 3

    def test_no_ticket_when_auto_ticket_false(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        sink = MagicMock(spec=TicketSink)
        lc = FindingLifecycle(store, sinks=[sink], auto_ticket=False)
        lc.ingest(_finding("f-001"))
        sink.create_ticket.assert_not_called()


# ── RemediationVelocity ───────────────────────────────────────────────────────

class TestRemediationVelocity:
    def _store_with_findings(self, tmp_path, resolved_hours_ago=None) -> FindingStore:
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        f = _finding("f-001", severity="high", hours_ago=48.0)
        store.upsert(f)
        if resolved_hours_ago is not None:
            store.transition("f-001", "triaged")
            store.transition("f-001", "in_progress")
            # Manually patch the resolved event timestamp
            f2 = store.get("f-001")
            store.transition("f-001", "resolved")
            f3 = store.get("f-001")
            # Adjust last event timestamp to simulate time elapsed
            from datetime import timedelta
            dt = datetime.now(timezone.utc) - timedelta(hours=resolved_hours_ago)
            f3.history[-1].timestamp = dt.isoformat()
            store.upsert(f3)
        return store

    def test_open_by_severity(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001", severity="critical"))
        store.upsert(_finding("f-002", severity="high"))
        store.upsert(_finding("f-003", severity="high"))
        v = RemediationVelocity(store)
        counts = v.open_by_severity()
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 0

    def test_resolved_last_n_days(self, tmp_path):
        store = self._store_with_findings(tmp_path, resolved_hours_ago=2.0)
        v = RemediationVelocity(store)
        assert v.resolved_last_n_days(days=7) == 1

    def test_zero_resolved(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        v = RemediationVelocity(store)
        assert v.mean_time_to_resolve() == 0.0
        assert v.resolved_last_n_days() == 0

    def test_sla_compliance_rate_all_open(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        v = RemediationVelocity(store)
        assert v.sla_compliance_rate() == 1.0  # no resolved → compliant by default

    def test_oldest_open(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001", hours_ago=100.0))
        store.upsert(_finding("f-002", hours_ago=10.0))
        v = RemediationVelocity(store)
        oldest = v.oldest_open()
        assert oldest.finding_id == "f-001"

    def test_oldest_open_none_when_empty(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        assert RemediationVelocity(store).oldest_open() is None

    def test_summary_keys(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        store.upsert(_finding("f-001"))
        s = RemediationVelocity(store).summary()
        assert "open_by_severity" in s
        assert "total_open" in s
        assert "mean_time_to_resolve_hours" in s
        assert "sla_compliance_rate" in s
        assert "throughput_per_day" in s

    def test_total_open_count(self, tmp_path):
        store = FindingStore(str(tmp_path / "findings.jsonl"))
        for i in range(3):
            store.upsert(_finding(f"f-{i:03d}"))
        assert RemediationVelocity(store).summary()["total_open"] == 3
