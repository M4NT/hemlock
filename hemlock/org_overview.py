"""Organization-wide security overview — v8.8.

Aggregates posture across teams and projects for CISO / platform views.

Usage:
    from hemlock.org_overview import OrgOverviewBuilder

    summary = OrgOverviewBuilder().build()
    print(summary.to_markdown())
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ProjectPosture:
    project_id: str
    team_id: str
    team_name: str
    project_name: str
    risk_score: float = 0.0
    success_rate: float = 0.0
    open_findings: int = 0
    baseline_path: str | None = None
    last_scan_at: str = ""
    status: str = "unknown"  # healthy | at_risk | critical | unknown

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id,
            "team_id": self.team_id,
            "team_name": self.team_name,
            "project_name": self.project_name,
            "risk_score": self.risk_score,
            "success_rate": self.success_rate,
            "open_findings": self.open_findings,
            "baseline_path": self.baseline_path,
            "last_scan_at": self.last_scan_at,
            "status": self.status,
        }


@dataclass
class OrgSummary:
    generated_at: str
    team_count: int
    project_count: int
    projects_healthy: int
    projects_at_risk: int
    projects_critical: int
    total_open_findings: int
    mean_risk_score: float
    projects: list[ProjectPosture] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "team_count": self.team_count,
            "project_count": self.project_count,
            "projects_healthy": self.projects_healthy,
            "projects_at_risk": self.projects_at_risk,
            "projects_critical": self.projects_critical,
            "total_open_findings": self.total_open_findings,
            "mean_risk_score": self.mean_risk_score,
            "projects": [p.to_dict() for p in self.projects],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Organization AI Security Overview",
            f"_Generated {self.generated_at[:19]}_",
            "",
            f"| Teams | Projects | Mean risk | Open findings |",
            f"|-------|----------|-----------|---------------|",
            f"| {self.team_count} | {self.project_count} | "
            f"{self.mean_risk_score:.1f} | {self.total_open_findings} |",
            "",
            f"Healthy: {self.projects_healthy} · At risk: {self.projects_at_risk} · "
            f"Critical: {self.projects_critical}",
            "",
            "## Projects",
            "",
            "| Team | Project | Risk | Status | Open findings | Last scan |",
            "|------|---------|------|--------|---------------|-----------|",
        ]
        for p in sorted(self.projects, key=lambda x: x.risk_score, reverse=True):
            lines.append(
                f"| {p.team_name} | {p.project_name} | {p.risk_score:.1f} | "
                f"{p.status} | {p.open_findings} | {p.last_scan_at[:10] if p.last_scan_at else '—'} |"
            )
        return "\n".join(lines)


def _load_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _status_from_risk(risk: float) -> str:
    if risk >= 70:
        return "critical"
    if risk >= 40:
        return "at_risk"
    if risk > 0:
        return "healthy"
    return "unknown"


class OrgOverviewBuilder:
    """Build org-wide posture from TenantStore + project baselines."""

    def __init__(
        self,
        tenant_path: str = ".hemlock/tenants.json",
        findings_path: str = ".hemlock/findings.jsonl",
        runs_path: str = ".hemlock/orchestrator_runs.jsonl",
    ) -> None:
        self.tenant_path = tenant_path
        self.findings_path = findings_path
        self.runs_path = runs_path

    def _open_findings_for_project(self, project_id: str) -> int:
        if not os.path.exists(self.findings_path):
            return 0
        count = 0
        with open(self.findings_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("state") in ("resolved", "verified", "wont_fix"):
                    continue
                meta = row.get("metadata", {})
                if meta.get("project_id") == project_id or not meta.get("project_id"):
                    if meta.get("project_id") == project_id:
                        count += 1
        return count

    def _global_open_findings(self) -> int:
        if not os.path.exists(self.findings_path):
            return 0
        count = 0
        with open(self.findings_path, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line.strip())
                    if row.get("state") not in ("resolved", "verified", "wont_fix"):
                        count += 1
                except json.JSONDecodeError:
                    pass
        return count

    def _latest_run_timestamp(self) -> str:
        if not os.path.exists(self.runs_path):
            return ""
        try:
            with open(self.runs_path, encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                return json.loads(lines[-1]).get("finished_at", "")
        except (json.JSONDecodeError, OSError):
            pass
        return ""

    def build(self) -> OrgSummary:
        from hemlock.multitenancy import TenantStore

        store = TenantStore(self.tenant_path)
        teams = store.list_teams()
        postures: list[ProjectPosture] = []

        for team in teams:
            for project in store.list_projects(team.team_id):
                risk = 0.0
                success_rate = 0.0
                last_scan = ""
                if project.baseline_path and os.path.exists(project.baseline_path):
                    data = _load_json(project.baseline_path)
                    if data:
                        sr = float(data.get("success_rate", 0))
                        if sr <= 1.0:
                            sr *= 100.0
                        success_rate = sr
                        risk = sr
                        last_scan = data.get("generated_at", "") or self._latest_run_timestamp()
                else:
                    last_scan = self._latest_run_timestamp()

                open_f = self._open_findings_for_project(project.project_id)
                if open_f == 0 and not project.baseline_path:
                    open_f = 0

                postures.append(
                    ProjectPosture(
                        project_id=project.project_id,
                        team_id=team.team_id,
                        team_name=team.name,
                        project_name=project.name,
                        risk_score=risk,
                        success_rate=success_rate,
                        open_findings=open_f,
                        baseline_path=project.baseline_path,
                        last_scan_at=last_scan,
                        status=_status_from_risk(risk),
                    )
                )

        if not postures and teams:
            # No projects — synthesize team-level rows
            for team in teams:
                postures.append(
                    ProjectPosture(
                        project_id="",
                        team_id=team.team_id,
                        team_name=team.name,
                        project_name="(no projects)",
                        status="unknown",
                    )
                )

        healthy = sum(1 for p in postures if p.status == "healthy")
        at_risk = sum(1 for p in postures if p.status == "at_risk")
        critical = sum(1 for p in postures if p.status == "critical")
        risks = [p.risk_score for p in postures if p.risk_score > 0]
        mean_risk = sum(risks) / len(risks) if risks else 0.0
        total_open = self._global_open_findings()

        return OrgSummary(
            generated_at=datetime.now(timezone.utc).isoformat(),
            team_count=len(teams),
            project_count=len([p for p in postures if p.project_id]),
            projects_healthy=healthy,
            projects_at_risk=at_risk,
            projects_critical=critical,
            total_open_findings=total_open,
            mean_risk_score=round(mean_risk, 2),
            projects=postures,
        )
