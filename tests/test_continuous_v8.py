"""Tests for v8.6–v8.8 continuous security layer."""

from __future__ import annotations

import json

from hemlock.dashboard_data import build_trend_series, load_org_context
from hemlock.org_overview import OrgOverviewBuilder


class TestTrendSeries:
    def test_build_trend_from_runs(self):
        runs = [
            {"finished_at": "2026-07-29T00:00:00+00:00", "risk_score": 30.0, "schedule_name": "nightly"},
            {"finished_at": "2026-07-31T00:00:00+00:00", "risk_score": 55.0, "schedule_name": "nightly"},
        ]
        series = build_trend_series([], runs)
        assert len(series["points"]) == 2
        assert series["trend"] == "degrading"
        assert series["current"] == 55.0

    def test_improving_trend(self):
        runs = [
            {"finished_at": "2026-07-01T00:00:00+00:00", "risk_score": 60.0},
            {"finished_at": "2026-07-31T00:00:00+00:00", "risk_score": 20.0},
        ]
        series = build_trend_series([], runs)
        assert series["trend"] == "improving"

    def test_empty_series(self):
        series = build_trend_series([], [])
        assert series["points"] == []
        assert series["current"] == 0.0


class TestOrgOverview:
    def test_build_with_team_and_project(self, tmp_path):
        tenant_path = tmp_path / "tenants.json"
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps({"success_rate": 0.45, "generated_at": "2026-07-31T00:00:00+00:00"}),
            encoding="utf-8",
        )
        tenant_path.write_text(
            json.dumps({
                "teams": {
                    "t1": {
                        "team_id": "t1",
                        "name": "Platform",
                        "api_key": "hash",
                        "created_at": "2026-07-01T00:00:00+00:00",
                        "members": [],
                    }
                },
                "projects": {
                    "p1": {
                        "project_id": "p1",
                        "team_id": "t1",
                        "name": "prod-rag",
                        "baseline_path": str(baseline_path),
                        "created_at": "2026-07-01T00:00:00+00:00",
                    }
                },
            }),
            encoding="utf-8",
        )
        summary = OrgOverviewBuilder(tenant_path=str(tenant_path)).build()
        assert summary.team_count == 1
        assert summary.project_count == 1
        assert summary.projects[0].risk_score == 45.0
        assert summary.projects[0].status == "at_risk"

    def test_to_markdown(self, tmp_path):
        tenant_path = tmp_path / "tenants.json"
        tenant_path.write_text(
            json.dumps({"teams": {}, "projects": {}}),
            encoding="utf-8",
        )
        summary = OrgOverviewBuilder(tenant_path=str(tenant_path)).build()
        md = summary.to_markdown()
        assert "Organization AI Security Overview" in md

    def test_load_org_context(self, tmp_path):
        tenant_path = tmp_path / "tenants.json"
        tenant_path.write_text(json.dumps({"teams": {}, "projects": {}}), encoding="utf-8")
        ctx = load_org_context(str(tenant_path))
        assert "team_count" in ctx


class TestDashboardTrendHtml:
    def test_operational_html_includes_trend_chart(self):
        from hemlock.dashboard import build_operational_dashboard_html

        html = build_operational_dashboard_html(
            [],
            operational={
                "trend_series": {
                    "points": [{"timestamp": "2026-07-31", "risk_score": 40}],
                    "trend": "stable",
                    "current": 40,
                    "min": 40,
                    "max": 40,
                },
                "org_summary": {"team_count": 0, "projects": []},
            },
        )
        assert "trendChart" in html
        assert "Risk Trend" in html
