"""Tests for hemlock.mcp_fleet_audit (v9.2)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from hemlock.mcp_fleet_audit import (
    McpFleetAuditor,
    McpFleetTarget,
    McpScanReport,
    McpVulnerability,
    load_fleet_config,
    triage_vulnerability,
)
from hemlock.mcp_payloads import McpToolSchema


def test_triage_destructive_tool():
    v = McpVulnerability(
        tool_name="reiniciar_mcp",
        argument="name",
        category="prompt_injection",
        payload="test",
        severity="medium",
        indicator="echo",
        response="ok",
    )
    t = triage_vulnerability("admin", v)
    assert t.triage == "likely_false_positive"


def test_triage_chained_call():
    v = McpVulnerability(
        tool_name="foo",
        argument="x",
        category="chained_tool_call",
        payload="",
        severity="high",
        indicator="chain",
        response="",
    )
    t = triage_vulnerability("router", v)
    assert t.triage == "confirmed"


def test_triage_injection_category():
    v = McpVulnerability(
        tool_name="read_file",
        argument="path",
        category="path_traversal",
        payload="../../etc/passwd",
        severity="high",
        indicator="marker",
        response="root:x:0:0",
    )
    t = triage_vulnerability("svc", v)
    assert t.triage == "confirmed"


def test_load_fleet_config(tmp_path):
    cfg = tmp_path / "fleet.yaml"
    cfg.write_text(
        "org: TestOrg\n"
        "targets:\n"
        "  - name: a\n"
        "    url: http://localhost:3005/mcp\n",
        encoding="utf-8",
    )
    org, targets = load_fleet_config(str(cfg))
    assert org == "TestOrg"
    assert len(targets) == 1
    assert targets[0].name == "a"


def _fake_report(vuln_count: int = 1) -> McpScanReport:
    vulns = [
        McpVulnerability(
            tool_name="tool",
            argument="arg",
            category="prompt_injection",
            payload="p",
            severity="high",
            indicator="i",
            response="r",
        )
    ] * vuln_count
    return McpScanReport(
        target="http://test/mcp",
        transport="streamable_http",
        tools=[McpToolSchema(name="tool", description="", input_schema={})],
        vulnerabilities=vulns,
        total_cases=10,
    )


def test_fleet_auditor_run_mocked():
    from hemlock.mcp_fleet_audit import McpTargetAuditResult

    auditor = McpFleetAuditor(
        org_name="Lab",
        targets=[
            McpFleetTarget(name="a", url="http://a/mcp"),
            McpFleetTarget(name="b", url="http://b/mcp", skip=True),
        ],
        verbose=False,
    )

    def fake_scan(target: McpFleetTarget) -> McpTargetAuditResult:
        if target.skip:
            return McpTargetAuditResult(
                name=target.name, url=target.url, success=False, error="skipped by config",
            )
        rep = _fake_report()
        return McpTargetAuditResult(
            name=target.name,
            url=target.url,
            success=True,
            scan_report=rep,
            triaged=[triage_vulnerability(target.name, rep.vulnerabilities[0])],
        )

    with patch.object(McpFleetAuditor, "_scan_one", side_effect=fake_scan):
        report = auditor.run()
    assert report.org_name == "Lab"
    assert report.targets_scanned() == 1


def test_case_study_markdown_contains_summary():
    from hemlock.mcp_fleet_audit import McpFleetAuditReport, McpTargetAuditResult

    report = McpFleetAuditReport(
        org_name="Multipli",
        started_at="2026-07-31T12:00:00+00:00",
        finished_at="2026-07-31T12:05:00+00:00",
        results=[
            McpTargetAuditResult(
                name="admin",
                url="http://x/mcp",
                success=True,
                scan_report=_fake_report(2),
                triaged=[
                    triage_vulnerability("admin", _fake_report().vulnerabilities[0]),
                ],
            ),
        ],
    )
    md = report.to_case_study_markdown()
    assert "Executive summary" in md
    assert "Multipli" in md


def test_save_writes_files(tmp_path):
    from hemlock.mcp_fleet_audit import McpFleetAuditReport, McpTargetAuditResult

    report = McpFleetAuditReport(
        org_name="X",
        started_at="t0",
        finished_at="t1",
        results=[
            McpTargetAuditResult(
                name="svc",
                url="http://x/mcp",
                success=True,
                scan_report=_fake_report(),
                triaged=[],
            ),
        ],
    )
    paths = report.save(str(tmp_path))
    assert paths["json"].endswith("mcp_fleet_audit.json")
    data = json.loads((tmp_path / "mcp_fleet_audit.json").read_text(encoding="utf-8"))
    assert data["org_name"] == "X"
