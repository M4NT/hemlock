"""Tests for v8.0–v8.2 operational layer."""

from __future__ import annotations

import json

import pytest

from hemlock.dashboard_data import load_operational_context
from hemlock.dashboard import build_operational_dashboard_html
from hemlock.operational_cli import attack_rates_from_scorer_json, build_orchestrator
from hemlock.scan_orchestrator import RunHistoryStore, ScanSchedule, ScheduleStore


class TestAttackRatesFromScorer:
    def test_groups_by_attack(self):
        data = {
            "scenarios": [
                {"attack": "Direct Injection [explicit]", "attack_succeeded": True},
                {"attack": "Direct Injection [role]", "attack_succeeded": False},
                {"attack": "Exfiltration [leak]", "attack_succeeded": True},
            ]
        }
        rates = attack_rates_from_scorer_json(data)
        assert rates["Direct Injection"] == 0.5
        assert rates["Exfiltration"] == 1.0

    def test_attack_scores_fallback(self):
        data = {"attack_scores": {"direct_injection": 0.4, "exfiltration": 0.2}}
        rates = attack_rates_from_scorer_json(data)
        assert rates["direct_injection"] == 0.4


class TestRunHistoryStore:
    def test_append_and_latest(self, tmp_path):
        from hemlock.scan_orchestrator import OrchestratorRun

        path = str(tmp_path / "runs.jsonl")
        store = RunHistoryStore(path)
        run = OrchestratorRun(
            schedule_name="nightly",
            started_at="t0",
            finished_at="t1",
            risk_score=42.0,
            executive_report_path="/tmp/report.md",
        )
        store.append(run)
        latest = store.latest(1)
        assert len(latest) == 1
        assert latest[0].risk_score == 42.0
        assert latest[0].executive_report_path == "/tmp/report.md"


class TestOrchestratorExecutiveReport:
    def test_generates_report_on_run(self, tmp_path):
        schedules = str(tmp_path / "schedules.json")
        inventory = str(tmp_path / "inventory.json")
        sla = str(tmp_path / "sla.jsonl")
        runs = str(tmp_path / "runs.jsonl")
        reports = str(tmp_path / "reports")

        store = ScheduleStore(schedules)
        store.add(
            ScanSchedule(
                name="test-scan",
                interval_minutes=1,
                model_id="mock-model",
                pipeline_version="v1",
                channels=["rag"],
            )
        )

        class _Report:
            def risk_score(self):
                return 35.0

            def channels_at_risk(self):
                return ["rag"]

        orch = build_orchestrator(
            schedules_path=schedules,
            inventory_path=inventory,
            baseline_path=None,
            sla_path=sla,
            runs_path=runs,
            reports_dir=reports,
            org_name="Test Org",
            executive_report=True,
            mock_target="lab",
            mock_channels=["rag"],
        )
        orch.scan_fn = lambda ch: _Report()

        run = orch.run_schedule("test-scan")
        assert run.success
        assert run.executive_report_path
        assert run.executive_report_path.endswith(".md")
        assert (tmp_path / "reports" / "executive_latest.md").exists()
        assert RunHistoryStore(runs).all()


class TestDashboardData:
    def test_load_empty_context(self, tmp_path):
        ctx = load_operational_context(
            watch_path=str(tmp_path / "watch.json"),
            runs_path=str(tmp_path / "runs.jsonl"),
            inventory_path=str(tmp_path / "inv.json"),
            findings_path=str(tmp_path / "findings.jsonl"),
        )
        assert ctx["open_findings_count"] == 0
        assert ctx["orchestrator_runs"] == []

    def test_operational_html_includes_sections(self):
        html = build_operational_dashboard_html(
            [{"risk_score": 30, "timestamp": "2026-07-31"}],
            operational={
                "latest_run": {"schedule_name": "nightly", "risk_score": 30},
                "open_findings_count": 2,
                "open_by_severity": {"high": 1, "low": 1},
                "open_findings": [],
                "inventory_summary": {"total_models": 1, "models": []},
                "executive_summary": {"risk_rating": "Medium"},
            },
        )
        assert "Orchestrator Runs" in html
        assert "Open Findings" in html
        assert "Model Inventory" in html
