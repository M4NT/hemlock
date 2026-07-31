"""Tests for hemlock.mcp_fleet_diff (v9.5)."""

from __future__ import annotations

import json

from hemlock.mcp_fleet_diff import diff_fleet_audits


def _write_audit(path, findings):
    data = {
        "org_name": "Test",
        "started_at": "t0",
        "finished_at": "t1",
        "summary": {},
        "results": [
            {
                "name": "admin",
                "findings": findings,
            },
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_diff_new_and_resolved(tmp_path):
    base = tmp_path / "base.json"
    curr = tmp_path / "curr.json"
    _write_audit(
        base,
        [
            {"target_name": "admin", "tool_name": "a", "argument": "x", "category": "ssrf", "triage": "confirmed"},
            {"target_name": "admin", "tool_name": "b", "argument": "y", "category": "path_traversal", "triage": "confirmed"},
        ],
    )
    _write_audit(
        curr,
        [
            {"target_name": "admin", "tool_name": "b", "argument": "y", "category": "path_traversal", "triage": "suspected"},
            {"target_name": "admin", "tool_name": "c", "argument": "z", "category": "chained_tool_call", "triage": "confirmed"},
        ],
    )
    diff = diff_fleet_audits(str(base), str(curr))
    assert diff.baseline_confirmed == 2
    assert diff.current_confirmed == 1
    assert diff.delta_confirmed() == -1
    assert len(diff.new_confirmed) == 1
    assert diff.new_confirmed[0]["tool_name"] == "c"
    assert len(diff.resolved_confirmed) == 2
