"""Tests for hemlock.executive_report (v7.2)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from hemlock.executive_report import (
    AttackSummary,
    ExecutiveReport,
    ExecutiveReportBuilder,
    ReportConfig,
    RiskPosture,
    SLAMetrics,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _config(**kwargs) -> ReportConfig:
    return ReportConfig(org_name="Acme AI", **kwargs)


def _mock_velocity(
    open_by_sev=None,
    compliance_rate=0.95,
    mttr=18.0,
    throughput=0.5,
    oldest=None,
):
    v = MagicMock()
    v.open_by_severity.return_value = open_by_sev or {"critical": 0, "high": 1, "medium": 2, "low": 3}
    v.sla_compliance_rate.return_value = compliance_rate
    v.mean_time_to_resolve.return_value = mttr
    v.throughput.return_value = throughput
    v.oldest_open.return_value = oldest
    return v


def _mock_trend(mean=30.0, max_r=50.0, trend="stable"):
    t = MagicMock()
    t.mean_risk.return_value = mean
    t.max_risk.return_value = max_r
    t.trend.return_value = trend
    return t


def _mock_baseline_result(compliant=True, label="prod-2026-07"):
    r = MagicMock()
    r.compliant = compliant
    r.baseline_label = label
    return r


def _mock_report(risk_score=35.0):
    r = MagicMock()
    r.risk_score.return_value = risk_score
    return r


# ── ReportConfig ──────────────────────────────────────────────────────────────

class TestReportConfig:
    def test_defaults(self):
        c = ReportConfig()
        assert c.period_days == 30
        assert "critical" in c.sla_hours

    def test_custom_values(self):
        c = ReportConfig(org_name="Test Org", period_days=7)
        assert c.org_name == "Test Org"
        assert c.period_days == 7


# ── RiskPosture ───────────────────────────────────────────────────────────────

class TestRiskPosture:
    def test_to_dict(self):
        rp = RiskPosture(current_risk=40.0, trend="stable", mean_risk_30d=35.0, max_risk_30d=50.0, rating="Medium")
        d = rp.to_dict()
        assert d["rating"] == "Medium"
        assert d["current_risk"] == 40.0

    def test_rating_critical(self):
        config = _config(risk_threshold_critical=70.0)
        builder = ExecutiveReportBuilder(config=config, scan_report=_mock_report(80.0))
        report = builder.build()
        assert report.risk_posture.rating == "Critical"

    def test_rating_secure_when_zero(self):
        builder = ExecutiveReportBuilder(config=_config(), scan_report=_mock_report(0.0))
        report = builder.build()
        assert report.risk_posture.rating == "Secure"


# ── SLAMetrics ────────────────────────────────────────────────────────────────

class TestSLAMetrics:
    def test_total_open(self):
        sla = SLAMetrics(
            compliance_rate=0.9,
            open_critical=1, open_high=2, open_medium=3, open_low=4,
            mean_time_to_resolve_hours=12.0,
            throughput_per_day=1.0,
        )
        assert sla.total_open == 10

    def test_to_dict_includes_total(self):
        sla = SLAMetrics(
            compliance_rate=1.0,
            open_critical=0, open_high=0, open_medium=0, open_low=0,
            mean_time_to_resolve_hours=0.0,
            throughput_per_day=0.0,
        )
        assert "total_open" in sla.to_dict()


# ── AttackSummary ─────────────────────────────────────────────────────────────

class TestAttackSummary:
    def test_block_rate_zero_total(self):
        s = AttackSummary(top_categories=[], total_scenarios=0, scenarios_blocked=0)
        assert s.block_rate == 0.0

    def test_block_rate_calculation(self):
        s = AttackSummary(top_categories=[], total_scenarios=10, scenarios_blocked=7)
        assert s.block_rate == pytest.approx(0.7)

    def test_to_dict_includes_block_rate(self):
        s = AttackSummary(top_categories=[], total_scenarios=4, scenarios_blocked=3)
        assert "block_rate" in s.to_dict()


# ── ExecutiveReportBuilder ────────────────────────────────────────────────────

class TestExecutiveReportBuilder:
    def test_build_minimal(self):
        builder = ExecutiveReportBuilder()
        report = builder.build()
        assert isinstance(report, ExecutiveReport)
        assert report.risk_posture.current_risk == 0.0
        assert report.risk_posture.rating == "Secure"

    def test_build_with_scan_report(self):
        builder = ExecutiveReportBuilder(scan_report=_mock_report(55.0))
        report = builder.build()
        assert report.risk_posture.current_risk == 55.0
        assert report.risk_posture.rating == "High"

    def test_build_with_trend(self):
        builder = ExecutiveReportBuilder(trend=_mock_trend(mean=40.0, trend="degrading"))
        report = builder.build()
        assert report.risk_posture.trend == "degrading"
        assert report.risk_posture.mean_risk_30d == 40.0

    def test_build_with_velocity(self):
        v = _mock_velocity(open_by_sev={"critical": 2, "high": 5, "medium": 1, "low": 0})
        builder = ExecutiveReportBuilder(velocity=v)
        report = builder.build()
        assert report.sla_metrics.open_critical == 2
        assert report.sla_metrics.open_high == 5

    def test_build_with_baseline_non_compliant(self):
        builder = ExecutiveReportBuilder(
            baseline_result=_mock_baseline_result(compliant=False, label="prod-2026-07")
        )
        report = builder.build()
        assert report.risk_posture.baseline_compliant is False
        assert "prod-2026-07" in report.risk_posture.baseline_label

    def test_build_with_attack_data(self):
        attack_data = [
            {"category": "direct_injection", "succeeded": True, "blocked": False},
            {"category": "direct_injection", "succeeded": True, "blocked": False},
            {"category": "citation_forgery", "succeeded": False, "blocked": True},
        ]
        builder = ExecutiveReportBuilder(attack_data=attack_data)
        report = builder.build()
        assert report.attack_summary.total_scenarios == 3
        assert report.attack_summary.scenarios_blocked == 1

    def test_key_findings_generated(self):
        builder = ExecutiveReportBuilder(
            scan_report=_mock_report(80.0),
            velocity=_mock_velocity(open_by_sev={"critical": 3, "high": 0, "medium": 0, "low": 0}),
        )
        report = builder.build()
        assert len(report.key_findings) > 0

    def test_recommendations_generated(self):
        builder = ExecutiveReportBuilder(trend=_mock_trend(trend="degrading"))
        report = builder.build()
        assert len(report.recommendations) > 0

    def test_critical_findings_in_key_findings(self):
        v = _mock_velocity(open_by_sev={"critical": 2, "high": 0, "medium": 0, "low": 0}, compliance_rate=1.0)
        builder = ExecutiveReportBuilder(velocity=v)
        report = builder.build()
        assert any("critical" in kf.lower() or "Critical" in kf for kf in report.key_findings)

    def test_degrading_trend_in_recommendations(self):
        builder = ExecutiveReportBuilder(trend=_mock_trend(trend="degrading"))
        report = builder.build()
        assert any("fingerprint" in r.lower() or "degrading" in r.lower() or "risk" in r.lower()
                   for r in report.recommendations)

    def test_no_data_no_crash(self):
        report = ExecutiveReportBuilder().build()
        assert report.risk_posture.rating in ("Secure", "Low", "Medium", "High", "Critical")


# ── ExecutiveReport output ────────────────────────────────────────────────────

class TestExecutiveReport:
    def _build(self, **kwargs) -> ExecutiveReport:
        return ExecutiveReportBuilder(
            config=_config(),
            scan_report=_mock_report(45.0),
            trend=_mock_trend(mean=40.0, max_r=55.0, trend="stable"),
            velocity=_mock_velocity(),
            **kwargs,
        ).build()

    def test_to_markdown_contains_org_name(self):
        report = self._build()
        md = report.to_markdown()
        assert "Acme AI" in md

    def test_to_markdown_contains_risk_score(self):
        report = self._build()
        md = report.to_markdown()
        assert "45" in md

    def test_to_markdown_contains_sections(self):
        report = self._build()
        md = report.to_markdown()
        assert "## Risk Posture" in md
        assert "## SLA" in md
        assert "## Attack Coverage" in md
        assert "## Recommendations" in md

    def test_to_markdown_trend_arrow(self):
        report = ExecutiveReportBuilder(
            config=_config(),
            scan_report=_mock_report(30.0),
            trend=_mock_trend(trend="improving"),
        ).build()
        md = report.to_markdown()
        assert "↓" in md or "Improving" in md

    def test_to_dict_structure(self):
        report = self._build()
        d = report.to_dict()
        assert "org_name" in d
        assert "risk_posture" in d
        assert "sla_metrics" in d
        assert "attack_summary" in d
        assert "key_findings" in d
        assert "recommendations" in d

    def test_save_markdown(self, tmp_path):
        report = self._build()
        path = str(tmp_path / "reports" / "report.md")
        report.save_markdown(path)
        assert os.path.exists(path)
        content = open(path, encoding="utf-8").read()
        assert "Acme AI" in content

    def test_save_json(self, tmp_path):
        report = self._build()
        path = str(tmp_path / "reports" / "report.json")
        report.save_json(path)
        assert os.path.exists(path)
        d = json.loads(open(path, encoding="utf-8").read())
        assert d["org_name"] == "Acme AI"

    def test_baseline_non_compliant_in_markdown(self):
        report = ExecutiveReportBuilder(
            config=_config(),
            baseline_result=_mock_baseline_result(compliant=False, label="prod-2026-07"),
        ).build()
        md = report.to_markdown()
        assert "Non-compliant" in md or "non-compliant" in md

    def test_top_attack_categories_in_markdown(self):
        attack_data = [
            {"category": "direct_injection", "succeeded": True},
            {"category": "direct_injection", "succeeded": True},
            {"category": "citation_forgery", "succeeded": False},
        ]
        report = ExecutiveReportBuilder(config=_config(), attack_data=attack_data).build()
        md = report.to_markdown()
        assert "direct_injection" in md

    def test_oldest_open_in_sla_section(self):
        oldest = MagicMock()
        oldest.finding_id = "f-001"
        oldest.first_seen = (datetime.now(timezone.utc) - timedelta(hours=96)).isoformat()
        v = _mock_velocity(oldest=oldest)
        report = ExecutiveReportBuilder(config=_config(), velocity=v).build()
        md = report.to_markdown()
        assert "f-001" in md
