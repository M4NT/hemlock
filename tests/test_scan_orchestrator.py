"""Tests for hemlock.scan_orchestrator (v7.7) — all mocked."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hemlock.model_inventory import ModelInventory
from hemlock.scan_orchestrator import (
    OrchestratorRun,
    ScanOrchestrator,
    ScanSchedule,
    ScheduleStore,
)
from hemlock.security_baseline import (
    AlertRouter,
    FindingRecord,
    SLAPolicy,
    SLATracker,
    SecurityBaseline,
    ChannelBaseline,
)


class _MockReport:
    def __init__(self, risk: float = 35.0, channels: list[str] | None = None) -> None:
        self._risk = risk
        self._channels = channels or ["rag"]

    def risk_score(self) -> float:
        return self._risk

    def channels_at_risk(self) -> list[str]:
        return self._channels

    def fingerprint_hash(self) -> str:
        return "sha256:abc"


class _MockSink:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, violations) -> bool:
        self.calls += 1
        return True


def _schedule(name: str = "nightly", minutes: int = 60, **kwargs) -> ScanSchedule:
    return ScanSchedule(
        name=name,
        interval_minutes=minutes,
        model_id=kwargs.get("model_id", "gpt-4o"),
        pipeline_version=kwargs.get("pipeline_version", "v1.0"),
        channels=kwargs.get("channels", ["rag", "tools"]),
    )


class TestScanSchedule:
    def test_is_due_when_never_run(self):
        assert _schedule().is_due() is True

    def test_not_due_when_recent(self):
        s = _schedule()
        s.last_run_at = datetime.now(timezone.utc).isoformat()
        assert s.is_due() is False

    def test_due_after_interval(self):
        s = _schedule(minutes=1)
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        s.last_run_at = past.isoformat()
        assert s.is_due() is True

    def test_disabled_schedule_not_due(self):
        s = _schedule()
        s.enabled = False
        assert s.is_due() is False

    def test_to_dict_roundtrip(self):
        s = _schedule()
        s2 = ScanSchedule.from_dict(s.to_dict())
        assert s2.name == s.name
        assert s2.interval_minutes == s.interval_minutes


class TestScheduleStore:
    def test_add_and_get(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("prod"))
        assert store.get("prod") is not None

    def test_due_filters(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        due = _schedule("due", minutes=1)
        due.last_run_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        not_due = _schedule("fresh", minutes=60)
        not_due.last_run_at = datetime.now(timezone.utc).isoformat()
        store.add(due)
        store.add(not_due)
        names = {s.name for s in store.due()}
        assert "due" in names
        assert "fresh" not in names

    def test_mark_run_persists(self, tmp_path):
        path = str(tmp_path / "schedules.json")
        store = ScheduleStore(path)
        store.add(_schedule("x"))
        store.mark_run("x", "2026-07-31T12:00:00+00:00")
        store2 = ScheduleStore(path)
        assert store2.get("x").last_run_at == "2026-07-31T12:00:00+00:00"

    def test_remove(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("rm"))
        assert store.remove("rm") is True
        assert store.get("rm") is None


class TestOrchestratorRun:
    def test_summary_ok(self):
        run = OrchestratorRun(
            schedule_name="nightly",
            started_at="t0",
            finished_at="t1",
            risk_score=25.0,
            success=True,
        )
        assert "OK" in run.summary()
        assert "25.0" in run.summary()

    def test_summary_failed(self):
        run = OrchestratorRun(
            schedule_name="nightly",
            started_at="t0",
            finished_at="t1",
            success=False,
            baseline_compliant=False,
        )
        assert "FAILED" in run.summary()
        assert "VIOLATION" in run.summary()


class TestScanOrchestrator:
    def test_run_schedule_updates_inventory(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("scan1"))
        inventory = ModelInventory(str(tmp_path / "inventory.json"))

        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(risk=40.0, channels=["rag"]),
            schedule_store=store,
            inventory=inventory,
        )
        run = orch.run_schedule("scan1")
        assert run.success
        assert run.inventory_updated
        assert run.risk_score == 40.0
        assert inventory.get("gpt-4o") is not None

    def test_baseline_violation_detected(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("scan2"))
        baseline = SecurityBaseline(
            label="prod",
            captured_at="2026-07-01T00:00:00+00:00",
            channels={"rag": ChannelBaseline(channel="rag", expected_max_risk=20.0)},
            overall_max_risk=20.0,
        )
        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(risk=55.0),
            schedule_store=store,
            baseline=baseline,
        )
        run = orch.run_schedule("scan2")
        assert not run.baseline_compliant
        assert run.baseline_delta > 0

    def test_sla_ingest_and_alerts(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("scan3"))
        sla = SLATracker(SLAPolicy(critical_hours=0), path=str(tmp_path / "sla.jsonl"))
        sink = _MockSink()
        router = AlertRouter([sink])

        old_finding = FindingRecord(
            finding_id="old-1",
            channel="rag",
            severity="critical",
            first_seen="2020-01-01T00:00:00+00:00",
            last_seen="2020-01-01T00:00:00+00:00",
        )
        sla.ingest([old_finding])

        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(risk=80.0, channels=["rag", "tools"]),
            schedule_store=store,
            sla_tracker=sla,
            alert_router=router,
        )
        run = orch.run_schedule("scan3")
        assert run.findings_ingested >= 2
        assert run.sla_violations >= 1
        assert run.alerts_sent >= 1
        assert sink.calls >= 1

    def test_missing_schedule_fails(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(),
            schedule_store=store,
        )
        run = orch.run_schedule("missing")
        assert not run.success
        assert run.errors

    def test_run_due_executes_multiple(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        for name in ("a", "b"):
            s = _schedule(name, minutes=1)
            s.last_run_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            store.add(s)
        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(risk=10.0),
            schedule_store=store,
        )
        runs = orch.run_due()
        assert len(runs) == 2

    def test_scan_fn_error_captured(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("err"))

        def boom(ch):
            raise RuntimeError("scan failed")

        orch = ScanOrchestrator(scan_fn=boom, schedule_store=store)
        run = orch.run_schedule("err")
        assert not run.success
        assert "scan failed" in run.errors[0]

    def test_custom_findings_from_report(self, tmp_path):
        store = ScheduleStore(str(tmp_path / "schedules.json"))
        store.add(_schedule("custom"))
        sla = SLATracker(path=str(tmp_path / "sla.jsonl"))

        def custom_findings(report):
            return [
                FindingRecord(
                    finding_id="custom-1",
                    channel="tools",
                    severity="high",
                    first_seen="2026-07-31T00:00:00+00:00",
                    last_seen="2026-07-31T00:00:00+00:00",
                )
            ]

        orch = ScanOrchestrator(
            scan_fn=lambda ch: _MockReport(),
            schedule_store=store,
            sla_tracker=sla,
            findings_from_report=custom_findings,
        )
        run = orch.run_schedule("custom")
        assert run.findings_ingested == 1
