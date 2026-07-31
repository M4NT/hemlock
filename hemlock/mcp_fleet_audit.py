"""MCP fleet audit — batch scan + triage for official case studies (v9.2).

Runs hemlock scan-mcp across a fleet defined in YAML, triages findings
(destructive-tool heuristics, auth blocks), and emits a consolidated report
suitable for executive / case-study documentation.

Usage:
    from hemlock.mcp_fleet_audit import McpFleetAuditor, load_fleet_config

    auditor = McpFleetAuditor.from_yaml("examples/mcp-fleet.yaml")
    report = auditor.run()
    report.save(".hemlock/mcp_audit")
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hemlock.mcp_scanner import McpScanner, McpScanReport, McpVulnerability


# Tools that often trigger fuzzer hits but are expected admin surfaces
_DESTRUCTIVE_TOOL_PATTERNS = (
    "reiniciar",
    "remover",
    "deletar",
    "delete",
    "regenerar",
    "auto_heal",
    "criar_usuario",
    "criar_pasta",
    "exportar",
    "diagnosticar",
)


@dataclass
class McpFleetTarget:
    name: str
    url: str
    auth_token: str | None = None
    auth_token_env: str | None = None
    expect_auth_failure: bool = False
    skip: bool = False
    notes: str = ""


@dataclass
class TriagedFinding:
    target_name: str
    tool_name: str
    argument: str
    category: str
    severity: str
    triage: str  # confirmed | suspected | likely_false_positive
    reason: str
    indicator: str
    discovery_method: str = "static"


@dataclass
class McpTargetAuditResult:
    name: str
    url: str
    success: bool
    error: str | None = None
    auth_blocked: bool = False
    scan_report: McpScanReport | None = None
    triaged: list[TriagedFinding] = field(default_factory=list)


@dataclass
class McpFleetAuditReport:
    org_name: str
    started_at: str
    finished_at: str
    results: list[McpTargetAuditResult] = field(default_factory=list)

    def targets_scanned(self) -> int:
        return sum(1 for r in self.results if r.success and r.scan_report)

    def targets_failed(self) -> list[str]:
        return [r.name for r in self.results if not r.success and not r.auth_blocked]

    def targets_auth_blocked(self) -> list[str]:
        return [r.name for r in self.results if r.auth_blocked]

    def total_raw_findings(self) -> int:
        return sum(len(r.triaged) for r in self.results)

    def triage_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"confirmed": 0, "suspected": 0, "likely_false_positive": 0}
        for r in self.results:
            for f in r.triaged:
                counts[f.triage] = counts.get(f.triage, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_name": self.org_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "targets_total": len(self.results),
                "targets_scanned": self.targets_scanned(),
                "targets_failed": self.targets_failed(),
                "targets_auth_blocked": self.targets_auth_blocked(),
                "raw_findings": self.total_raw_findings(),
                "triage": self.triage_counts(),
            },
            "results": [
                {
                    "name": r.name,
                    "url": r.url,
                    "success": r.success,
                    "error": r.error,
                    "auth_blocked": r.auth_blocked,
                    "tools_found": len(r.scan_report.tools) if r.scan_report else 0,
                    "test_cases_run": r.scan_report.total_cases if r.scan_report else 0,
                    "raw_findings": len(r.triaged),
                    "triage": {
                        t: sum(1 for f in r.triaged if f.triage == t)
                        for t in ("confirmed", "suspected", "likely_false_positive")
                    },
                    "findings": [f.__dict__ for f in r.triaged],
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_case_study_markdown(self) -> str:
        triage = self.triage_counts()
        lines = [
            f"# MCP Fleet Security Audit — {self.org_name}",
            "",
            f"**Period**: {self.started_at[:19]} → {self.finished_at[:19]}",
            "",
            "## Executive summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Targets in scope | {len(self.results)} |",
            f"| Successfully scanned | {self.targets_scanned()} |",
            f"| Auth blocked (OAuth / 401) | {len(self.targets_auth_blocked())} |",
            f"| Scan errors | {len(self.targets_failed())} |",
            f"| Raw fuzzer hits | {self.total_raw_findings()} |",
            f"| Confirmed (review priority) | {triage.get('confirmed', 0)} |",
            f"| Suspected | {triage.get('suspected', 0)} |",
            f"| Likely false positive (admin tools) | {triage.get('likely_false_positive', 0)} |",
            "",
            "## Per-target results",
            "",
        ]
        for r in self.results:
            status = "OK" if r.success and r.scan_report else (
                "AUTH_BLOCKED" if r.auth_blocked else "FAILED"
            )
            tools = len(r.scan_report.tools) if r.scan_report else 0
            cases = r.scan_report.total_cases if r.scan_report else 0
            lines.append(f"### {r.name} ({status})")
            lines.append(f"- URL: `{r.url}`")
            if r.scan_report:
                lines.append(f"- Tools: {tools} · Test cases: {cases} · Findings (triaged): {len(r.triaged)}")
            if r.error:
                lines.append(f"- Error: {r.error[:200]}")
            lines.append("")

        lines.append("## Findings requiring review (confirmed + suspected)")
        lines.append("")
        for r in self.results:
            priority = [f for f in r.triaged if f.triage in ("confirmed", "suspected")]
            if not priority:
                continue
            lines.append(f"### {r.name}")
            lines.append("| Tool | Argument | Category | Triage | Reason |")
            lines.append("|------|----------|----------|--------|--------|")
            for f in priority[:25]:
                lines.append(
                    f"| {f.tool_name} | {f.argument} | {f.category} | {f.triage} | {f.reason[:60]} |"
                )
            if len(priority) > 25:
                lines.append(f"_… and {len(priority) - 25} more_")
            lines.append("")

        lines.append("---")
        lines.append("_Generated by Hemlock MCP Fleet Audit (v9.2)_")
        return "\n".join(lines)

    def save(self, directory: str) -> dict[str, str]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / "mcp_fleet_audit.json"
        md_path = out / "mcp_fleet_case_study.md"
        json_path.write_text(self.to_json(), encoding="utf-8")
        md_path.write_text(self.to_case_study_markdown(), encoding="utf-8")
        for r in self.results:
            if r.scan_report:
                safe = r.name.replace("/", "_").replace(" ", "_")
                (out / f"{safe}.json").write_text(r.scan_report.to_json(), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path)}


def triage_vulnerability(
    target_name: str,
    vuln: McpVulnerability,
) -> TriagedFinding:
    tool_lower = vuln.tool_name.lower()
    reason = "Standard fuzzer hit"
    triage = "suspected"

    if vuln.category == "chained_tool_call":
        triage = "confirmed"
        reason = "Chained tool invocation detected by interceptor"
    elif any(p in tool_lower for p in _DESTRUCTIVE_TOOL_PATTERNS):
        triage = "likely_false_positive"
        reason = "Administrative/destructive tool — manual review recommended"
    elif vuln.category in ("prompt_injection", "path_traversal", "ssrf", "sql_injection"):
        triage = "confirmed"
        reason = f"High-risk category: {vuln.category}"
    elif len(vuln.response) < 20 and vuln.indicator == "echo":
        triage = "likely_false_positive"
        reason = "Short echo response — likely payload reflection only"

    return TriagedFinding(
        target_name=target_name,
        tool_name=vuln.tool_name,
        argument=vuln.argument,
        category=vuln.category,
        severity=vuln.severity,
        triage=triage,
        reason=reason,
        indicator=vuln.indicator,
        discovery_method=vuln.discovery_method,
    )


def load_fleet_config(path: str) -> tuple[str, list[McpFleetTarget]]:
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if path.endswith(".json"):
        data = json.loads(raw)
    else:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML required for YAML fleet configs. "
                "Install with pip install pyyaml or use a .json config."
            ) from exc
        data = yaml.safe_load(raw) or {}
    org = str(data.get("org", data.get("org_name", "Organization")))
    targets: list[McpFleetTarget] = []
    for item in data.get("targets", []):
        token = item.get("auth_token")
        env_key = item.get("auth_token_env")
        if not token and env_key:
            token = os.environ.get(env_key) or None
        targets.append(
            McpFleetTarget(
                name=str(item["name"]),
                url=str(item["url"]),
                auth_token=token,
                auth_token_env=env_key,
                expect_auth_failure=bool(item.get("expect_auth_failure", False)),
                skip=bool(item.get("skip", False)),
                notes=str(item.get("notes", "")),
            )
        )
    return org, targets


class McpFleetAuditor:
    def __init__(
        self,
        org_name: str,
        targets: list[McpFleetTarget],
        max_workers: int = 4,
        verbose: bool = False,
    ) -> None:
        self.org_name = org_name
        self.targets = targets
        self.max_workers = max(1, max_workers)
        self.verbose = verbose

    @classmethod
    def from_yaml(cls, path: str, **kwargs: Any) -> "McpFleetAuditor":
        org, targets = load_fleet_config(path)
        return cls(org_name=org, targets=targets, **kwargs)

    def _scan_one(self, target: McpFleetTarget) -> McpTargetAuditResult:
        if target.skip:
            return McpTargetAuditResult(
                name=target.name,
                url=target.url,
                success=False,
                error="skipped by config",
            )
        try:
            scanner = McpScanner(
                target.url,
                auth_token=target.auth_token,
                verbose=self.verbose,
            )
            report = scanner.scan()
            triaged = [triage_vulnerability(target.name, v) for v in report.vulnerabilities]
            return McpTargetAuditResult(
                name=target.name,
                url=target.url,
                success=True,
                scan_report=report,
                triaged=triaged,
            )
        except Exception as exc:
            msg = str(exc)
            auth_blocked = (
                target.expect_auth_failure
                or "401" in msg
                or "Unauthorized" in msg
                or "403" in msg
            )
            return McpTargetAuditResult(
                name=target.name,
                url=target.url,
                success=False,
                error=msg[:500],
                auth_blocked=auth_blocked,
            )

    def run(self) -> McpFleetAuditReport:
        started = datetime.now(timezone.utc).isoformat()
        results: list[McpTargetAuditResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_one, t): t for t in self.targets}
            for fut in as_completed(futures):
                results.append(fut.result())

        # Stable order by config
        order = {t.name: i for i, t in enumerate(self.targets)}
        results.sort(key=lambda r: order.get(r.name, 999))

        finished = datetime.now(timezone.utc).isoformat()
        return McpFleetAuditReport(
            org_name=self.org_name,
            started_at=started,
            finished_at=finished,
            results=results,
        )

    def exit_code(self, report: McpFleetAuditReport, fail_on_confirmed: bool = True) -> int:
        triage = report.triage_counts()
        if fail_on_confirmed and triage.get("confirmed", 0) > 0:
            return 2
        if report.targets_failed():
            return 1
        return 0
