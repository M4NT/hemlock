"""CLI helpers for operational commands (v8.0–v8.2)."""

from __future__ import annotations

import json
from typing import Any


def attack_rates_from_scorer_json(data: dict) -> dict[str, float]:
    """Aggregate per-attack success rates from a hemlock score JSON report."""
    scenarios = data.get("scenarios", [])
    by_attack: dict[str, list[bool]] = {}
    for s in scenarios:
        raw = s.get("attack", s.get("attack_name", "unknown"))
        name = str(raw).split("[")[0].strip()
        succeeded = bool(s.get("attack_succeeded", False))
        by_attack.setdefault(name, []).append(succeeded)
    if not by_attack and "attack_scores" in data:
        return {k: float(v) for k, v in data["attack_scores"].items()}
    return {k: sum(v) / len(v) for k, v in by_attack.items()}


def load_json_report(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("report JSON must be an object")
    return data


def build_orchestrator(
    schedules_path: str,
    inventory_path: str,
    baseline_path: str | None,
    sla_path: str,
    runs_path: str,
    reports_dir: str,
    org_name: str,
    executive_report: bool,
    risk_preset: str | None = None,
    findings_path: str | None = None,
    mock_target: str = "hemlock-lab",
    mock_channels: list[str] | None = None,
) -> Any:
    from hemlock.finding_lifecycle import FindingStore, RemediationVelocity
    from hemlock.model_inventory import ModelInventory
    from hemlock.risk_scoring import RiskMatrix, RiskScorer
    from hemlock.scan_orchestrator import RunHistoryStore, ScanOrchestrator, ScheduleStore
    from hemlock.security_baseline import SLATracker, SecurityBaseline

    store = ScheduleStore(schedules_path)
    if not store.all():
        from hemlock.scan_orchestrator import ScanSchedule

        store.add(
            ScanSchedule(
                name="default-scan",
                interval_minutes=60,
                model_id=mock_target,
                pipeline_version="mock",
                channels=mock_channels or ["rag", "tools", "agent"],
            )
        )

    inventory = ModelInventory(inventory_path)
    sla = SLATracker(path=sla_path)
    baseline = SecurityBaseline.load(baseline_path) if baseline_path else None
    history = RunHistoryStore(runs_path)

    velocity = None
    if findings_path:
        fs = FindingStore(findings_path)
        velocity = RemediationVelocity(fs)

    presets = {
        "default": RiskMatrix.preset_default,
        "fintech": RiskMatrix.preset_fintech,
        "healthcare": RiskMatrix.preset_healthcare,
        "saas": RiskMatrix.preset_saas,
    }
    risk_scorer = RiskScorer(presets[risk_preset]()) if risk_preset in presets else None

    def scan_fn(channels: list[str]) -> Any:
        from hemlock.hem_session import HemSession

        session = HemSession.mock(target=mock_target, channels=channels or mock_channels)
        return session.run()

    return ScanOrchestrator(
        scan_fn=scan_fn,
        schedule_store=store,
        inventory=inventory,
        baseline=baseline,
        sla_tracker=sla,
        run_history=history,
        generate_executive_report=executive_report,
        reports_dir=reports_dir,
        executive_org_name=org_name,
        remediation_velocity=velocity,
        risk_scorer=risk_scorer,
    )
