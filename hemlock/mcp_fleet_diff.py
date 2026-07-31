"""MCP fleet audit diff — compare baseline vs current runs (v9.5)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


FindingKey = tuple[str, str, str, str]  # target, tool, argument, category


def _finding_key(row: dict[str, Any]) -> FindingKey:
    return (
        str(row.get("target_name", row.get("target", ""))),
        str(row.get("tool_name", row.get("tool", ""))),
        str(row.get("argument", "")),
        str(row.get("category", "")),
    )


def _load_findings(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = []
    for result in data.get("results", []):
        target = str(result.get("name", ""))
        for f in result.get("findings", []):
            if not isinstance(f, dict):
                continue
            row = dict(f)
            row.setdefault("target_name", target)
            findings.append(row)
    return findings


def _confirmed_keys(findings: list[dict[str, Any]]) -> set[FindingKey]:
    keys: set[FindingKey] = set()
    for f in findings:
        if f.get("triage") == "confirmed":
            keys.add(_finding_key(f))
    return keys


@dataclass
class McpFleetAuditDiff:
    baseline_path: str
    current_path: str
    baseline_confirmed: int = 0
    current_confirmed: int = 0
    new_confirmed: list[dict[str, Any]] = field(default_factory=list)
    resolved_confirmed: list[FindingKey] = field(default_factory=list)
    still_confirmed: list[FindingKey] = field(default_factory=list)

    def delta_confirmed(self) -> int:
        return self.current_confirmed - self.baseline_confirmed

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_path": self.baseline_path,
            "current_path": self.current_path,
            "baseline_confirmed": self.baseline_confirmed,
            "current_confirmed": self.current_confirmed,
            "delta_confirmed": self.delta_confirmed(),
            "new_confirmed": self.new_confirmed,
            "resolved_confirmed": [
                {"target": t, "tool": tl, "argument": a, "category": c}
                for t, tl, a, c in self.resolved_confirmed
            ],
            "still_confirmed": [
                {"target": t, "tool": tl, "argument": a, "category": c}
                for t, tl, a, c in self.still_confirmed
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            "# MCP Fleet Audit Diff",
            "",
            f"- Baseline: `{self.baseline_path}` ({self.baseline_confirmed} confirmed)",
            f"- Current: `{self.current_path}` ({self.current_confirmed} confirmed)",
            f"- Delta: **{self.delta_confirmed():+d}** confirmed",
            "",
            "## New confirmed",
            "",
        ]
        if not self.new_confirmed:
            lines.append("_None_")
        else:
            lines.append("| Target | Tool | Argument | Category |")
            lines.append("|--------|------|----------|----------|")
            for f in self.new_confirmed[:30]:
                lines.append(
                    f"| {f.get('target_name', '')} | {f.get('tool_name', f.get('tool', ''))} "
                    f"| {f.get('argument', '')} | {f.get('category', '')} |"
                )
        lines.extend(["", "## Resolved (no longer confirmed)", ""])
        if not self.resolved_confirmed:
            lines.append("_None_")
        else:
            for t, tl, a, c in self.resolved_confirmed[:30]:
                lines.append(f"- `{t}` · {tl}.{a} ({c})")
        return "\n".join(lines)


def diff_fleet_audits(baseline_path: str, current_path: str) -> McpFleetAuditDiff:
    baseline_findings = _load_findings(baseline_path)
    current_findings = _load_findings(current_path)

    base_keys = _confirmed_keys(baseline_findings)
    curr_keys = _confirmed_keys(current_findings)

    new_keys = curr_keys - base_keys
    resolved = base_keys - curr_keys
    still = base_keys & curr_keys

    new_rows = [f for f in current_findings if _finding_key(f) in new_keys and f.get("triage") == "confirmed"]

    return McpFleetAuditDiff(
        baseline_path=baseline_path,
        current_path=current_path,
        baseline_confirmed=len(base_keys),
        current_confirmed=len(curr_keys),
        new_confirmed=new_rows,
        resolved_confirmed=sorted(resolved),
        still_confirmed=sorted(still),
    )
