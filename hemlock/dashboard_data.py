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
    }
