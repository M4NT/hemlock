"""SARIF 2.1.0 exporter for HemReport and EvalReport (v4.7).

SARIF (Static Analysis Results Interchange Format) is the standard format
accepted by GitHub Advanced Security, VS Code, and most SAST tooling.

References:
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json
from typing import Any

_TOOL_NAME = "Hemlock"
_TOOL_URI = "https://github.com/M4NT/hemlock"

# Map hemlock severity → SARIF level
_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule(rule_id: str, name: str, short_desc: str, full_desc: str, severity: str) -> dict:
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": full_desc},
        "defaultConfiguration": {"level": _SEVERITY_MAP.get(severity, "warning")},
        "properties": {"severity": severity},
    }


def _result(rule_id: str, message: str, level: str, uri: str = "hemlock://pipeline") -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }
        ],
    }


def hem_report_to_sarif(report: Any, tool_version: str = "4.7.0") -> dict:
    """Convert a HemReport to a SARIF 2.1.0 document."""
    from hemlock import __version__

    version = tool_version or __version__

    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for r in report.results:
        rule_id = f"HEM-{r.channel.upper().replace('_', '-')}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(_rule(
                rule_id=rule_id,
                name=f"{r.channel.replace('_', ' ').title()} Attack",
                short_desc=f"Attack channel: {r.channel}",
                full_desc=r.detail or f"Hemlock detected a vulnerability in the {r.channel} channel.",
                severity=r.severity,
            ))
        if r.succeeded:
            results.append(_result(
                rule_id=rule_id,
                message=f"[{r.channel}] {r.variant} attack succeeded — {r.detail}",
                level=_SEVERITY_MAP.get(r.severity, "warning"),
                uri=f"hemlock://{report.target}/{r.channel}",
            ))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": version,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "riskScore": report.risk_score(),
                    "channelsAtRisk": report.channels_at_risk(),
                },
            }
        ],
    }


def eval_report_to_sarif(report: Any, tool_version: str = "4.7.0") -> dict:
    """Convert an EvalReport to a SARIF 2.1.0 document."""
    from hemlock import __version__

    version = tool_version or __version__

    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for s in report.scenarios:
        rule_id = f"EVAL-{s.attack_name.upper().replace('_', '-').replace(' ', '-')}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(_rule(
                rule_id=rule_id,
                name=s.attack_name.replace("_", " ").title(),
                short_desc=f"Eval: {s.attack_name} ({s.category})",
                full_desc=f"EvalBenchmark scenario for {s.attack_name}, category {s.category}.",
                severity="high" if s.succeeded else "info",
            ))
        if s.succeeded:
            results.append(_result(
                rule_id=rule_id,
                message=f"[{s.category}] {s.attack_name} / {s.variant} succeeded. Notes: {s.notes}",
                level="error",
                uri=f"hemlock://eval/{s.category}/{s.attack_name}",
            ))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": version,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "modelName": report.model_name,
                    "overallScore": report.overall_score(),
                    "attackSuccessRate": report.attack_success_rate(),
                },
            }
        ],
    }


def to_sarif_json(sarif_doc: dict, indent: int = 2) -> str:
    return json.dumps(sarif_doc, indent=indent)


def mcp_fleet_audit_to_sarif(report: Any, tool_version: str | None = None) -> dict:
    """Convert an McpFleetAuditReport to SARIF 2.1.0 (v9.3)."""
    from hemlock import __version__

    version = tool_version or __version__
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()

    for target in report.results:
        for finding in target.triaged:
            if finding.triage not in ("confirmed", "suspected"):
                continue
            rule_id = f"MCP-{finding.category.upper().replace('_', '-')}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append(
                    _rule(
                        rule_id=rule_id,
                        name=f"MCP {finding.category.replace('_', ' ')}",
                        short_desc=f"MCP fuzzer: {finding.category}",
                        full_desc=finding.reason,
                        severity=finding.severity,
                    )
                )
            level = _SEVERITY_MAP.get(finding.severity, "warning")
            if finding.triage == "suspected":
                level = "note"
            msg = (
                f"[{finding.target_name}] {finding.tool_name}.{finding.argument} "
                f"({finding.triage}) — {finding.reason}"
            )
            results.append(
                _result(
                    rule_id=rule_id,
                    message=msg,
                    level=level,
                    uri=f"mcp://{finding.target_name}/{finding.tool_name}",
                )
            )

    triage = report.triage_counts()
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": version,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "orgName": report.org_name,
                    "targetsScanned": report.targets_scanned(),
                    "targetsAuthBlocked": report.targets_auth_blocked(),
                    "triage": triage,
                },
            }
        ],
    }
