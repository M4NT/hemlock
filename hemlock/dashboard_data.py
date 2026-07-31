"""Operational dashboard data loader — v8.1.

Aggregates Hemlock subsystem state for the web dashboard and CLI.
"""

from __future__ import annotations

import json
import os
from typing import Any


def _read_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def _read_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    rows: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def load_operational_context(
    watch_path: str = "watch_history.json",
    runs_path: str = ".hemlock/orchestrator_runs.jsonl",
    inventory_path: str = ".hemlock/model_inventory.json",
    findings_path: str = ".hemlock/findings.jsonl",
    executive_json_path: str = ".hemlock/reports/executive_latest.json",
) -> dict[str, Any]:
    """Load operational state from default Hemlock artifact paths."""
    watch_history: list[dict] = _read_json(watch_path, [])
    if not isinstance(watch_history, list):
        watch_history = []

    orchestrator_runs = _read_jsonl(runs_path)[-20:]
    findings_raw = _read_jsonl(findings_path)

    open_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    open_findings: list[dict] = []
    for row in findings_raw:
        state = row.get("state", "open")
        if state in ("resolved", "verified", "wont_fix"):
            continue
        sev = str(row.get("severity", "low")).lower()
        open_by_severity[sev] = open_by_severity.get(sev, 0) + 1
        open_findings.append(row)

    inventory_data = _read_json(inventory_path, {})
    models: list[dict] = []
    if isinstance(inventory_data, dict):
        for model_id, entry in inventory_data.get("models", inventory_data).items():
            if isinstance(entry, dict) and "model_id" in entry:
                models.append(entry)
            elif isinstance(entry, dict):
                models.append({"model_id": model_id, **entry})

    inventory_summary = {
        "total_models": len(models),
        "stale_models": sum(
            1 for m in models
            if float(m.get("latest_risk_score", m.get("risk_score", 0))) > 50
        ),
        "models": sorted(
            models,
            key=lambda m: float(m.get("latest_risk_score", m.get("risk_score", 0))),
            reverse=True,
        )[:10],
    }

    executive = _read_json(executive_json_path, {})
    latest_run = orchestrator_runs[-1] if orchestrator_runs else {}

    hemlock_trend = build_hemlock_score_trend(orchestrator_runs)
    new_techniques = load_new_attack_techniques(runs_path=runs_path)

    return {
        "watch_history": watch_history,
        "orchestrator_runs": orchestrator_runs,
        "latest_run": latest_run,
        "open_findings_count": len(open_findings),
        "open_by_severity": open_by_severity,
        "open_findings": open_findings[:10],
        "inventory_summary": inventory_summary,
        "executive_summary": {
            "risk_rating": executive.get("risk_posture", {}).get("rating", "—"),
            "sla_compliance": executive.get("sla_metrics", {}).get("compliance_rate"),
            "block_rate": executive.get("attack_summary", {}).get("block_rate"),
        },
        "trend_series": build_trend_series(watch_history, orchestrator_runs),
        "hemlock_score": latest_run.get("hemlock_score"),
        "hemlock_grade": latest_run.get("hemlock_grade", ""),
        "hemlock_score_trend": hemlock_trend,
        "new_attack_techniques": new_techniques,
    }


def build_trend_series(
    watch_history: list[dict],
    orchestrator_runs: list[dict],
    max_points: int = 30,
) -> dict[str, Any]:
    """Build time-series data for dashboard trend charts (v8.7)."""
    points: list[dict[str, Any]] = []

    for entry in watch_history:
        ts = entry.get("timestamp", entry.get("ts", ""))
        score = entry.get("risk_score", entry.get("score"))
        if ts and score is not None:
            points.append({
                "timestamp": str(ts),
                "risk_score": float(score),
                "source": "watch",
            })

    for run in orchestrator_runs:
        ts = run.get("finished_at", run.get("started_at", ""))
        score = run.get("risk_score")
        if ts and score is not None:
            points.append({
                "timestamp": str(ts),
                "risk_score": float(score),
                "source": "orchestrator",
                "schedule": run.get("schedule_name", ""),
            })

    points.sort(key=lambda p: p["timestamp"])
    if len(points) > max_points:
        points = points[-max_points:]

    scores = [p["risk_score"] for p in points]
    trend = "stable"
    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        if delta > 5:
            trend = "degrading"
        elif delta < -5:
            trend = "improving"

    return {
        "points": points,
        "trend": trend,
        "current": scores[-1] if scores else 0.0,
        "min": min(scores) if scores else 0.0,
        "max": max(scores) if scores else 0.0,
    }


def build_hemlock_score_trend(
    orchestrator_runs: list[dict],
    max_points: int = 30,
) -> dict[str, Any]:
    """Hemlock Score time series from orchestrator runs (v9.1)."""
    points: list[dict[str, Any]] = []
    for run in orchestrator_runs:
        score = run.get("hemlock_score")
        ts = run.get("finished_at", run.get("started_at", ""))
        if score is not None and ts:
            points.append({
                "timestamp": str(ts),
                "hemlock_score": float(score),
                "grade": run.get("hemlock_grade", ""),
                "schedule": run.get("schedule_name", ""),
            })
    points.sort(key=lambda p: p["timestamp"])
    if len(points) > max_points:
        points = points[-max_points:]

    scores = [p["hemlock_score"] for p in points]
    trend = "stable"
    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        if delta > 5:
            trend = "improving"
        elif delta < -5:
            trend = "degrading"

    return {
        "points": points,
        "trend": trend,
        "current": scores[-1] if scores else None,
        "current_grade": points[-1].get("grade", "") if points else "",
        "min": min(scores) if scores else None,
        "max": max(scores) if scores else None,
    }


def load_new_attack_techniques(
    runs_path: str = ".hemlock/orchestrator_runs.jsonl",
    cache_path: str = ".hemlock/threat_intel_cache.json",
) -> list[dict[str, Any]]:
    """Recent new attack techniques from intelligence loop + threat intel (v9.1)."""
    runs = _read_jsonl(runs_path)
    techniques: list[dict[str, Any]] = []
    seen: set[str] = set()

    for run in reversed(runs):
        for label in run.get("new_techniques", []):
            if label not in seen:
                seen.add(label)
                techniques.append({
                    "label": label,
                    "source": "intelligence_loop",
                    "run_at": run.get("finished_at", ""),
                })

    advisories_raw = _read_json(cache_path, [])
    if isinstance(advisories_raw, list):
        advisories = advisories_raw
    else:
        advisories = advisories_raw.get("advisories", [])
    for adv in advisories[:10]:
        if not isinstance(adv, dict):
            continue
        cve = str(adv.get("cve_id", ""))
        if cve and cve not in seen:
            seen.add(cve)
            techniques.append({
                "label": f"{cve}: {adv.get('title', '')}",
                "source": adv.get("source", "threat_intel"),
                "severity": adv.get("severity", ""),
                "attack_category": adv.get("attack_category", ""),
            })

    return techniques[:20]


def load_org_context(tenant_path: str = ".hemlock/tenants.json") -> dict[str, Any]:
    """Load organization overview for org dashboard (v8.8)."""
    from hemlock.org_overview import OrgOverviewBuilder

    summary = OrgOverviewBuilder(tenant_path=tenant_path).build()
    return summary.to_dict()
