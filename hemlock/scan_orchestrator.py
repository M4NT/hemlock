"""Scheduled Scan Orchestrator — v7.7.

Cron-like orchestrator that wires Hemlock subsystems into continuous security:
run scheduled scans, update ModelInventory, compare SecurityBaseline, ingest
findings into SLATracker, route alerts, optionally replay attacks, and
auto-generate executive reports (v8.2).

Usage:
    from hemlock.scan_orchestrator import ScanSchedule, ScheduleStore, ScanOrchestrator

    store = ScheduleStore(".hemlock/schedules.json")
    store.add(ScanSchedule(
        name="prod-nightly",
        interval_minutes=1440,
        model_id="claude-sonnet-4-6",
        pipeline_version="v2.3.1",
        channels=["rag", "tools", "agent"],
    ))

    orchestrator = ScanOrchestrator(
        scan_fn=lambda channels: hem.scan(),
        schedule_store=store,
        inventory=ModelInventory(...),
        baseline=SecurityBaseline.load(...),
        sla_tracker=SLATracker(...),
        alert_router=AlertRouter([SlackSink(...)]),
    )

    for run in orchestrator.run_due():
        print(run.summary())
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Schedules ─────────────────────────────────────────────────────────────────


@dataclass
class ScanSchedule:
    name: str
    interval_minutes: int
    model_id: str = ""
    pipeline_version: str = ""
    channels: list[str] = field(default_factory=list)
    enabled: bool = True
    last_run_at: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanSchedule":
        return cls(
            name=d["name"],
            interval_minutes=int(d["interval_minutes"]),
            model_id=d.get("model_id", ""),
            pipeline_version=d.get("pipeline_version", ""),
            channels=list(d.get("channels", [])),
            enabled=bool(d.get("enabled", True)),
            last_run_at=d.get("last_run_at"),
            metadata=d.get("metadata", {}),
        )

    def is_due(self, now: datetime | None = None) -> bool:
        if not self.enabled:
            return False
        if not self.last_run_at:
            return True
        try:
            last = datetime.fromisoformat(self.last_run_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return True
        now = now or datetime.now(timezone.utc)
        return now >= last + timedelta(minutes=self.interval_minutes)


class ScheduleStore:
    """Persistent store for scan schedules."""

    def __init__(self, path: str = ".hemlock/schedules.json") -> None:
        self.path = path
        self._schedules: dict[str, ScanSchedule] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return
        for item in data.get("schedules", []):
            s = ScanSchedule.from_dict(item)
            self._schedules[s.name] = s

    def save(self) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(
                {"schedules": [s.to_dict() for s in self._schedules.values()]},
                f,
                indent=2,
            )

    def add(self, schedule: ScanSchedule) -> None:
        self._schedules[schedule.name] = schedule
        self.save()

    def remove(self, name: str) -> bool:
        if name not in self._schedules:
            return False
        del self._schedules[name]
        self.save()
        return True

    def get(self, name: str) -> ScanSchedule | None:
        return self._schedules.get(name)

    def all(self) -> list[ScanSchedule]:
        return list(self._schedules.values())

    def due(self, now: datetime | None = None) -> list[ScanSchedule]:
        return [s for s in self._schedules.values() if s.is_due(now)]

    def mark_run(self, name: str, at: str | None = None) -> None:
        if name in self._schedules:
            self._schedules[name].last_run_at = at or _now_iso()
            self.save()


# ── Run results ───────────────────────────────────────────────────────────────


@dataclass
class OrchestratorRun:
    schedule_name: str
    started_at: str
    finished_at: str
    risk_score: float = 0.0
    channels_at_risk: list[str] = field(default_factory=list)
    baseline_compliant: bool = True
    baseline_delta: float = 0.0
    inventory_updated: bool = False
    findings_ingested: int = 0
    sla_violations: int = 0
    alerts_sent: int = 0
    replay_regressions: int = 0
    success: bool = True
    errors: list[str] = field(default_factory=list)
    executive_report_path: str = ""
    executive_report_json_path: str = ""
    weighted_risk_score: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        status = "OK" if self.success else "FAILED"
        baseline = "compliant" if self.baseline_compliant else "VIOLATION"
        return (
            f"[{status}] {self.schedule_name}: risk={self.risk_score:.1f}, "
            f"baseline={baseline}, sla_violations={self.sla_violations}, "
            f"alerts={self.alerts_sent}"
            + (f", report={self.executive_report_path}" if self.executive_report_path else "")
        )


class RunHistoryStore:
    """JSONL persistence for OrchestratorRun records (dashboard + audit trail)."""

    def __init__(self, path: str = ".hemlock/orchestrator_runs.jsonl") -> None:
        self.path = path

    def append(self, run: OrchestratorRun) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(run.to_dict()) + "\n")

    def all(self) -> list[OrchestratorRun]:
        if not os.path.exists(self.path):
            return []
        runs: list[OrchestratorRun] = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    runs.append(OrchestratorRun(**{
                        k: v for k, v in d.items()
                        if k in OrchestratorRun.__dataclass_fields__
                    }))
                except (json.JSONDecodeError, TypeError):
                    continue
        return runs

    def latest(self, limit: int = 20) -> list[OrchestratorRun]:
        return self.all()[-limit:]

    def for_schedule(self, schedule_name: str) -> list[OrchestratorRun]:
        return [r for r in self.all() if r.schedule_name == schedule_name]


# ── Orchestrator ──────────────────────────────────────────────────────────────


class ScanOrchestrator:
    """Runs scheduled scans and fans out results to inventory, baseline, SLA, alerts."""

    def __init__(
        self,
        scan_fn: Callable[[list[str]], Any],
        schedule_store: ScheduleStore,
        inventory: Any | None = None,
        baseline: Any | None = None,
        sla_tracker: Any | None = None,
        alert_router: Any | None = None,
        replay_runner: Any | None = None,
        replay_pipeline_factory: Callable[[list[str]], Any] | None = None,
        findings_from_report: Callable[[Any], list] | None = None,
        run_history: RunHistoryStore | None = None,
        generate_executive_report: bool = False,
        reports_dir: str = ".hemlock/reports",
        executive_org_name: str = "Your Organisation",
        remediation_velocity: Any | None = None,
        trend_analyzer: Any | None = None,
        risk_scorer: Any | None = None,
    ) -> None:
        self.scan_fn = scan_fn
        self.schedule_store = schedule_store
        self.inventory = inventory
        self.baseline = baseline
        self.sla_tracker = sla_tracker
        self.alert_router = alert_router
        self.replay_runner = replay_runner
        self.replay_pipeline_factory = replay_pipeline_factory
        self.findings_from_report = findings_from_report or self._default_findings_from_report
        self.run_history = run_history
        self.generate_executive_report = generate_executive_report
        self.reports_dir = reports_dir
        self.executive_org_name = executive_org_name
        self.remediation_velocity = remediation_velocity
        self.trend_analyzer = trend_analyzer
        self.risk_scorer = risk_scorer

    @staticmethod
    def _default_findings_from_report(report: Any) -> list:
        from hemlock.security_baseline import FindingRecord

        findings: list[FindingRecord] = []
        at_risk = report.channels_at_risk() if hasattr(report, "channels_at_risk") else []
        now = _now_iso()
        risk = float(report.risk_score()) if hasattr(report, "risk_score") else 0.0
        for ch in at_risk:
            if risk > 70:
                sev = "critical"
            elif risk > 50:
                sev = "high"
            elif risk > 30:
                sev = "medium"
            else:
                sev = "low"
            findings.append(
                FindingRecord(
                    finding_id=f"{ch}-{now[:13]}",
                    channel=ch,
                    severity=sev,
                    first_seen=now,
                    last_seen=now,
                )
            )
        return findings

    def run_schedule(self, name: str) -> OrchestratorRun:
        schedule = self.schedule_store.get(name)
        if schedule is None:
            return OrchestratorRun(
                schedule_name=name,
                started_at=_now_iso(),
                finished_at=_now_iso(),
                success=False,
                errors=[f"Schedule '{name}' not found"],
            )
        return self._execute(schedule)

    def run_due(self) -> list[OrchestratorRun]:
        return [self._execute(s) for s in self.schedule_store.due()]

    def _execute(self, schedule: ScanSchedule) -> OrchestratorRun:
        started = _now_iso()
        run = OrchestratorRun(
            schedule_name=schedule.name,
            started_at=started,
            finished_at=started,
        )
        baseline_result = None
        report = None
        try:
            report = self.scan_fn(schedule.channels)
            run.risk_score = float(report.risk_score()) if hasattr(report, "risk_score") else 0.0
            run.channels_at_risk = (
                list(report.channels_at_risk()) if hasattr(report, "channels_at_risk") else []
            )

            if self.risk_scorer and hasattr(report, "attack_scores"):
                scores = report.attack_scores()
                if callable(scores):
                    scores = scores()
                if isinstance(scores, dict):
                    weighted = self.risk_scorer.score_attack_rates(dict(scores))
                    run.weighted_risk_score = weighted.weighted_score

            if self.inventory and schedule.model_id:
                fp = report.fingerprint_hash() if hasattr(report, "fingerprint_hash") else ""
                self.inventory.record_scan(
                    model_id=schedule.model_id,
                    pipeline_version=schedule.pipeline_version or "unknown",
                    scan_channels=schedule.channels or run.channels_at_risk,
                    risk_score=run.risk_score,
                    fingerprint_hash=fp,
                )
                run.inventory_updated = True

            if self.baseline:
                from hemlock.security_baseline import BaselineComparison

                baseline_result = BaselineComparison.compare(self.baseline, report)
                run.baseline_compliant = baseline_result.compliant
                run.baseline_delta = baseline_result.overall_delta

            if self.sla_tracker:
                findings = self.findings_from_report(report)
                self.sla_tracker.ingest(findings)
                run.findings_ingested = len(findings)
                violations = self.sla_tracker.check_violations()
                run.sla_violations = len(violations)
                if self.alert_router and violations:
                    route_results = self.alert_router.route(violations)
                    run.alerts_sent = sum(1 for ok in route_results.values() if ok)

            if self.replay_runner and schedule.pipeline_version:
                factory = self.replay_pipeline_factory or self._default_replay_factory(schedule)
                replay_report = self.replay_runner.replay(
                    pipeline_factory=factory,
                    pipeline_version=schedule.pipeline_version,
                )
                run.replay_regressions = len(replay_report.regressions)

            if self.generate_executive_report and report is not None:
                paths = self._generate_executive_report(
                    schedule=schedule,
                    report=report,
                    baseline_result=baseline_result,
                )
                run.executive_report_path = paths.get("markdown", "")
                run.executive_report_json_path = paths.get("json", "")

            self.schedule_store.mark_run(schedule.name)
        except Exception as exc:
            run.success = False
            run.errors.append(str(exc))
        run.finished_at = _now_iso()
        if self.run_history:
            self.run_history.append(run)
        return run

    def _generate_executive_report(
        self,
        schedule: ScanSchedule,
        report: Any,
        baseline_result: Any | None,
    ) -> dict[str, str]:
        from hemlock.executive_report import ExecutiveReportBuilder, ReportConfig

        builder = ExecutiveReportBuilder(
            config=ReportConfig(org_name=self.executive_org_name),
            scan_report=report,
            baseline_result=baseline_result,
            velocity=self.remediation_velocity,
            trend=self.trend_analyzer,
        )
        exec_report = builder.build()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = schedule.name.replace("/", "_").replace(" ", "_")
        md_path = os.path.join(self.reports_dir, f"executive_{safe_name}_{stamp}.md")
        json_path = os.path.join(self.reports_dir, f"executive_{safe_name}_{stamp}.json")
        exec_report.save_markdown(md_path)
        exec_report.save_json(json_path)
        latest_md = os.path.join(self.reports_dir, "executive_latest.md")
        latest_json = os.path.join(self.reports_dir, "executive_latest.json")
        exec_report.save_markdown(latest_md)
        exec_report.save_json(latest_json)
        return {"markdown": md_path, "json": json_path}

    def _default_replay_factory(self, schedule: ScanSchedule) -> Callable[[str], Any]:
        channels = schedule.channels
        scan_fn = self.scan_fn

        def factory(channel: str) -> Any:
            class _ReplayPipeline:
                def run(self, payload: str) -> str:
                    if "INJECTION_SUCCEEDED" in payload.upper():
                        return "INJECTION_SUCCEEDED"
                    report = scan_fn(channels)
                    risk = float(report.risk_score()) if hasattr(report, "risk_score") else 0.0
                    return "INJECTION_SUCCEEDED" if risk > 60 else "blocked"

            return _ReplayPipeline()

        return factory
