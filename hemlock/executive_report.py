"""Executive Report Generator — v7.2.

Produces CISO/CTO-facing security reports from scan data: risk posture,
SLA compliance, top attack categories, remediation velocity, and trend.

Outputs Markdown (default) and structured dict for downstream rendering
(PDF via weasyprint, HTML dashboard, Slack digest, etc.).

Usage:
    from hemlock.executive_report import ExecutiveReportBuilder, ReportConfig

    builder = ExecutiveReportBuilder(
        config=ReportConfig(org_name="Acme AI", period_days=30),
        velocity=velocity,       # RemediationVelocity from v7.1
        trend=analyzer,          # TrendAnalyzer from v7.0
        baseline_result=result,  # BaselineResult from v7.0 (optional)
    )

    report = builder.build()
    print(report.to_markdown())
    report.save_markdown(".hemlock/reports/executive_2026-07.md")
    d = report.to_dict()         # for JSON API / dashboard ingestion
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class ReportConfig:
    org_name: str = "Your Organisation"
    period_days: int = 30
    risk_threshold_critical: float = 70.0
    risk_threshold_high: float = 50.0
    risk_threshold_medium: float = 30.0
    sla_hours: dict[str, int] = field(default_factory=lambda: {
        "critical": 4,
        "high": 24,
        "medium": 72,
        "low": 168,
    })


# ── Report data model ─────────────────────────────────────────────────────────

@dataclass
class RiskPosture:
    current_risk: float
    trend: str              # improving | degrading | stable
    mean_risk_30d: float
    max_risk_30d: float
    rating: str             # Critical | High | Medium | Low | Secure
    baseline_compliant: bool | None = None
    baseline_label: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SLAMetrics:
    compliance_rate: float   # 0.0–1.0
    open_critical: int
    open_high: int
    open_medium: int
    open_low: int
    mean_time_to_resolve_hours: float
    throughput_per_day: float
    oldest_open_id: str = ""
    oldest_open_hours: float = 0.0

    @property
    def total_open(self) -> int:
        return self.open_critical + self.open_high + self.open_medium + self.open_low

    def to_dict(self) -> dict:
        d = asdict(self)
        d["total_open"] = self.total_open
        return d


@dataclass
class AttackSummary:
    top_categories: list[dict]   # [{"category": str, "success_rate": float, "blocked": bool}]
    total_scenarios: int
    scenarios_blocked: int

    @property
    def block_rate(self) -> float:
        if self.total_scenarios == 0:
            return 0.0
        return round(self.scenarios_blocked / self.total_scenarios, 3)

    def to_dict(self) -> dict:
        return {
            "top_categories": self.top_categories,
            "total_scenarios": self.total_scenarios,
            "scenarios_blocked": self.scenarios_blocked,
            "block_rate": self.block_rate,
        }


@dataclass
class ExecutiveReport:
    org_name: str
    generated_at: str
    period_days: int
    risk_posture: RiskPosture
    sla_metrics: SLAMetrics
    attack_summary: AttackSummary
    key_findings: list[str]
    recommendations: list[str]

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "org_name": self.org_name,
            "generated_at": self.generated_at,
            "period_days": self.period_days,
            "risk_posture": self.risk_posture.to_dict(),
            "sla_metrics": self.sla_metrics.to_dict(),
            "attack_summary": self.attack_summary.to_dict(),
            "key_findings": self.key_findings,
            "recommendations": self.recommendations,
        }

    def to_markdown(self) -> str:
        rp = self.risk_posture
        sla = self.sla_metrics
        atk = self.attack_summary

        trend_emoji = {"improving": "↓", "degrading": "↑", "stable": "→"}.get(rp.trend, "→")
        rating_line = f"**{rp.rating}**"
        if rp.baseline_label:
            bl_status = "✅ Compliant" if rp.baseline_compliant else "❌ Non-compliant"
            rating_line += f"  |  Baseline `{rp.baseline_label}`: {bl_status}"

        sla_pct = round(sla.compliance_rate * 100, 1)
        block_pct = round(atk.block_rate * 100, 1)

        lines = [
            f"# AI Security Report — {self.org_name}",
            f"_Period: last {self.period_days} days · Generated {self.generated_at[:10]}_",
            "",
            "---",
            "",
            "## Risk Posture",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Rating | {rating_line} |",
            f"| Current risk score | {rp.current_risk:.1f} / 100 |",
            f"| 30-day mean | {rp.mean_risk_30d:.1f} |",
            f"| 30-day peak | {rp.max_risk_30d:.1f} |",
            f"| Trend | {trend_emoji} {rp.trend.capitalize()} |",
            "",
            "---",
            "",
            "## SLA & Remediation",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| SLA compliance | {sla_pct}% |",
            f"| Open findings (total) | {sla.total_open} |",
            f"| Critical open | {sla.open_critical} |",
            f"| High open | {sla.open_high} |",
            f"| Mean time to resolve | {sla.mean_time_to_resolve_hours:.1f}h |",
            f"| Throughput | {sla.throughput_per_day:.1f} findings/day |",
        ]

        if sla.oldest_open_id:
            lines.append(f"| Oldest open finding | `{sla.oldest_open_id}` ({sla.oldest_open_hours:.0f}h) |")

        lines += [
            "",
            "---",
            "",
            "## Attack Coverage",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Scenarios tested | {atk.total_scenarios} |",
            f"| Blocked | {atk.scenarios_blocked} ({block_pct}%) |",
        ]

        if atk.top_categories:
            lines += ["", "**Top attack categories:**", ""]
            for cat in atk.top_categories[:5]:
                blocked_marker = "🛡" if cat.get("blocked") else "⚠️"
                lines.append(
                    f"- {blocked_marker} `{cat['category']}` — "
                    f"{round(cat.get('success_rate', 0) * 100, 1)}% success rate"
                )

        if self.key_findings:
            lines += ["", "---", "", "## Key Findings", ""]
            for kf in self.key_findings:
                lines.append(f"- {kf}")

        if self.recommendations:
            lines += ["", "---", "", "## Recommendations", ""]
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")

        lines += ["", "---", "", "_Generated by [Hemlock](https://github.com/M4NT/hemlock) v7.2_"]
        return "\n".join(lines)

    def save_markdown(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())

    def save_json(self, path: str) -> None:
        import json
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


# ── Builder ───────────────────────────────────────────────────────────────────

def _risk_rating(score: float, config: ReportConfig) -> str:
    if score >= config.risk_threshold_critical:
        return "Critical"
    if score >= config.risk_threshold_high:
        return "High"
    if score >= config.risk_threshold_medium:
        return "Medium"
    if score > 0:
        return "Low"
    return "Secure"


def _hours_since(iso_ts: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return 0.0


class ExecutiveReportBuilder:
    """Assembles an ExecutiveReport from Hemlock subsystem outputs.

    All parameters except config are optional — pass what you have.
    The builder degrades gracefully when data is unavailable.
    """

    def __init__(
        self,
        config: ReportConfig | None = None,
        velocity: Any = None,           # RemediationVelocity (v7.1)
        trend: Any = None,              # TrendAnalyzer (v7.0)
        baseline_result: Any = None,    # BaselineResult (v7.0)
        scan_report: Any = None,        # HemReport / EvalReport / dict
        attack_data: list[dict] | None = None,
    ) -> None:
        self.config = config or ReportConfig()
        self.velocity = velocity
        self.trend = trend
        self.baseline_result = baseline_result
        self.scan_report = scan_report
        self.attack_data = attack_data or []

    # ── Sub-builders ─────────────────────────────────────────────────────────

    def _build_risk_posture(self) -> RiskPosture:
        current = 0.0
        if self.scan_report is not None:
            if hasattr(self.scan_report, "risk_score"):
                current = float(self.scan_report.risk_score())
            elif isinstance(self.scan_report, dict):
                current = float(self.scan_report.get("risk_score", 0.0))

        mean_30 = 0.0
        max_30 = 0.0
        trend_str = "stable"
        if self.trend is not None:
            mean_30 = self.trend.mean_risk(self.config.period_days)
            max_30 = self.trend.max_risk(self.config.period_days)
            trend_str = self.trend.trend(self.config.period_days)
        else:
            mean_30 = current
            max_30 = current

        bl_compliant = None
        bl_label = ""
        if self.baseline_result is not None:
            bl_compliant = bool(getattr(self.baseline_result, "compliant", True))
            bl_label = str(getattr(self.baseline_result, "baseline_label", ""))

        return RiskPosture(
            current_risk=round(current, 1),
            trend=trend_str,
            mean_risk_30d=mean_30,
            max_risk_30d=max_30,
            rating=_risk_rating(current, self.config),
            baseline_compliant=bl_compliant,
            baseline_label=bl_label,
        )

    def _build_sla_metrics(self) -> SLAMetrics:
        if self.velocity is None:
            return SLAMetrics(
                compliance_rate=1.0,
                open_critical=0, open_high=0, open_medium=0, open_low=0,
                mean_time_to_resolve_hours=0.0,
                throughput_per_day=0.0,
            )

        by_sev = self.velocity.open_by_severity()
        rate = self.velocity.sla_compliance_rate(self.config.sla_hours)
        mttr = self.velocity.mean_time_to_resolve(self.config.period_days)
        throughput = self.velocity.throughput(self.config.period_days)
        oldest = self.velocity.oldest_open()

        return SLAMetrics(
            compliance_rate=rate,
            open_critical=by_sev.get("critical", 0),
            open_high=by_sev.get("high", 0),
            open_medium=by_sev.get("medium", 0),
            open_low=by_sev.get("low", 0),
            mean_time_to_resolve_hours=mttr,
            throughput_per_day=throughput,
            oldest_open_id=oldest.finding_id if oldest else "",
            oldest_open_hours=_hours_since(oldest.first_seen) if oldest else 0.0,
        )

    def _build_attack_summary(self) -> AttackSummary:
        if not self.attack_data and self.scan_report is not None:
            self.attack_data = self._extract_attack_data(self.scan_report)

        if not self.attack_data:
            return AttackSummary(top_categories=[], total_scenarios=0, scenarios_blocked=0)

        total = len(self.attack_data)
        blocked = sum(1 for a in self.attack_data if a.get("blocked") or not a.get("succeeded"))

        by_cat: dict[str, list[float]] = {}
        for a in self.attack_data:
            cat = a.get("category", "unknown")
            succeeded = float(a.get("succeeded", not a.get("blocked", False)))
            by_cat.setdefault(cat, []).append(succeeded)

        top = sorted(
            [
                {
                    "category": cat,
                    "success_rate": round(sum(vals) / len(vals), 3),
                    "blocked": sum(vals) / len(vals) < 0.5,
                }
                for cat, vals in by_cat.items()
            ],
            key=lambda x: x["success_rate"],
            reverse=True,
        )

        return AttackSummary(
            top_categories=top,
            total_scenarios=total,
            scenarios_blocked=blocked,
        )

    @staticmethod
    def _extract_attack_data(report: Any) -> list[dict]:
        """Attempt to pull attack data from a HemReport-like object."""
        if hasattr(report, "results"):
            results = report.results
            if isinstance(results, list):
                return [
                    {
                        "category": getattr(r, "attack_name", getattr(r, "channel", "unknown")),
                        "succeeded": getattr(r, "succeeded", False),
                        "blocked": not getattr(r, "succeeded", False),
                    }
                    for r in results
                ]
        if isinstance(report, dict) and "results" in report:
            return report["results"]
        return []

    def _build_key_findings(self, rp: RiskPosture, sla: SLAMetrics) -> list[str]:
        findings = []

        if rp.rating in ("Critical", "High"):
            findings.append(
                f"Risk posture is **{rp.rating}** (score {rp.current_risk:.0f}/100). "
                f"Immediate remediation required."
            )

        if rp.trend == "degrading":
            findings.append(
                f"Risk trend is **degrading** over the past {self.config.period_days} days "
                f"(peak: {rp.max_risk_30d:.0f})."
            )

        if rp.baseline_compliant is False:
            findings.append(
                f"Pipeline is **non-compliant** with baseline `{rp.baseline_label}`. "
                f"New channels or attack categories exceeded acceptable thresholds."
            )

        if sla.open_critical > 0:
            findings.append(
                f"{sla.open_critical} critical finding(s) currently open — "
                f"SLA requires resolution within {self.config.sla_hours.get('critical', 4)}h."
            )

        if sla.compliance_rate < 0.9:
            findings.append(
                f"SLA compliance at {round(sla.compliance_rate * 100, 1)}% — "
                f"below the 90% target."
            )

        if not findings:
            findings.append("No critical issues detected. Risk posture is within acceptable bounds.")

        return findings

    def _build_recommendations(self, rp: RiskPosture, sla: SLAMetrics, atk: AttackSummary) -> list[str]:
        recs = []

        if rp.trend == "degrading":
            recs.append(
                "Run `hemlock fingerprint` to identify which model or pipeline change "
                "caused the risk increase."
            )

        if sla.open_critical > 0:
            recs.append(
                f"Prioritise the {sla.open_critical} open critical finding(s) immediately. "
                f"Use `hemlock lifecycle transition <id> in_progress`."
            )

        if sla.compliance_rate < 0.9:
            recs.append(
                "Review SLA policy and increase remediation throughput. "
                "Consider enabling `GitHubIssueSink` auto-ticket creation to reduce triage lag."
            )

        if atk.top_categories:
            top_cat = atk.top_categories[0]
            if top_cat["success_rate"] > 0.5:
                recs.append(
                    f"Attack category `{top_cat['category']}` has a "
                    f"{round(top_cat['success_rate'] * 100, 0):.0f}% success rate. "
                    f"Apply a targeted defense layer or tighten `policy.yaml` rules."
                )

        if rp.baseline_compliant is False:
            recs.append(
                "Re-baseline after deploying defenses: "
                "`SecurityBaseline.from_report(report, label='post-fix-YYYY-MM-DD')`."
            )

        if not recs:
            recs.append(
                "Maintain current scan cadence. Consider publishing to the "
                "shared benchmark registry to track posture over time."
            )

        return recs

    # ── Public API ────────────────────────────────────────────────────────────

    def build(self) -> ExecutiveReport:
        rp = self._build_risk_posture()
        sla = self._build_sla_metrics()
        atk = self._build_attack_summary()

        return ExecutiveReport(
            org_name=self.config.org_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            period_days=self.config.period_days,
            risk_posture=rp,
            sla_metrics=sla,
            attack_summary=atk,
            key_findings=self._build_key_findings(rp, sla),
            recommendations=self._build_recommendations(rp, sla, atk),
        )
