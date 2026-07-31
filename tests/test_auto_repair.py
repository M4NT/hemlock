from __future__ import annotations

import pytest

from hemlock.auto_repair import HemRepairer, RepairProposal, RepairReport
from hemlock.hem_session import ChannelResult, HemReport
from hemlock.mock import MockRepairerLLM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(channels_succeeded: list[tuple[str, str, str]] | None = None) -> HemReport:
    """Build a HemReport from (channel, variant, severity) tuples."""
    if channels_succeeded is None:
        channels_succeeded = [("rag", "v1", "high")]
    results = [
        ChannelResult(channel=ch, variant=var, succeeded=True, severity=sev, detail="test")
        for ch, var, sev in channels_succeeded
    ]
    return HemReport(target="test", results=results)


def _make_empty_report() -> HemReport:
    """Report with no results → no at-risk channels."""
    return HemReport(target="test", results=[])


# ---------------------------------------------------------------------------
# 1. RepairProposal dataclass fields
# ---------------------------------------------------------------------------

def test_repair_proposal_fields():
    p = RepairProposal(channel="rag", file_path="app.py", description="fix it", patch="diff", confidence=0.9)
    assert p.channel == "rag"
    assert p.file_path == "app.py"
    assert p.description == "fix it"
    assert p.patch == "diff"
    assert p.confidence == 0.9


# ---------------------------------------------------------------------------
# 2. RepairReport dataclass fields
# ---------------------------------------------------------------------------

def test_repair_report_fields():
    p = RepairProposal(channel="rag", file_path=None, description="d", patch="", confidence=0.5)
    rr = RepairReport(proposals=[p], applied=["d"], skipped=[])
    assert len(rr.proposals) == 1
    assert rr.applied == ["d"]
    assert rr.skipped == []


# ---------------------------------------------------------------------------
# 3. to_markdown returns string with table headers
# ---------------------------------------------------------------------------

def test_repair_report_to_markdown_headers():
    p = RepairProposal(channel="rag", file_path=None, description="fix rag", patch="", confidence=0.85)
    rr = RepairReport(proposals=[p])
    md = rr.to_markdown()
    assert isinstance(md, str)
    assert "| Channel |" in md
    assert "| Confidence |" in md
    assert "| Description |" in md


# ---------------------------------------------------------------------------
# 4. to_dict has required keys
# ---------------------------------------------------------------------------

def test_repair_report_to_dict_keys():
    rr = RepairReport(proposals=[], applied=[], skipped=[])
    d = rr.to_dict()
    assert "proposals" in d
    assert "applied" in d
    assert "skipped" in d


# ---------------------------------------------------------------------------
# 5. MockRepairerLLM.propose_repair returns correct dict keys
# ---------------------------------------------------------------------------

def test_mock_repairer_llm_returns_dict():
    llm = MockRepairerLLM()
    result = llm.propose_repair("rag", "Use input validation")
    assert "description" in result
    assert "patch" in result
    assert "confidence" in result


# ---------------------------------------------------------------------------
# 6. MockRepairerLLM records calls
# ---------------------------------------------------------------------------

def test_mock_repairer_llm_records_calls():
    llm = MockRepairerLLM()
    llm.propose_repair("rag", "hint one")
    llm.propose_repair("memory", "hint two")
    assert len(llm.calls) == 2
    assert llm.calls[0] == ("rag", "hint one")
    assert llm.calls[1] == ("memory", "hint two")


# ---------------------------------------------------------------------------
# 7. HemRepairer.propose() returns list of RepairProposals
# ---------------------------------------------------------------------------

def test_repairer_propose_returns_list():
    report = _make_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm)
    proposals = repairer.propose()
    assert isinstance(proposals, list)
    assert all(isinstance(p, RepairProposal) for p in proposals)


# ---------------------------------------------------------------------------
# 8. HemRepairer.propose() returns one proposal per (channel, hint)
# ---------------------------------------------------------------------------

def test_repairer_propose_one_per_hint():
    report = _make_report([("rag", "v1", "high")])
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm)
    proposals = repairer.propose()
    hints = report.remediation_hints()
    expected_count = sum(len(h) for h in hints.values())
    assert len(proposals) == expected_count


# ---------------------------------------------------------------------------
# 9. apply() with dry_run=True puts all proposals in skipped
# ---------------------------------------------------------------------------

def test_repairer_apply_dry_run_all_skipped():
    report = _make_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm, dry_run=True)
    rr = repairer.apply()
    assert len(rr.skipped) == len(rr.proposals)


# ---------------------------------------------------------------------------
# 10. apply() with dry_run=True returns no applied entries
# ---------------------------------------------------------------------------

def test_repairer_apply_dry_run_no_applied():
    report = _make_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm, dry_run=True)
    rr = repairer.apply()
    assert rr.applied == []


# ---------------------------------------------------------------------------
# 11. apply() returns RepairReport type
# ---------------------------------------------------------------------------

def test_repairer_apply_returns_repair_report():
    report = _make_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm)
    rr = repairer.apply()
    assert isinstance(rr, RepairReport)


# ---------------------------------------------------------------------------
# 12. to_markdown includes channel names
# ---------------------------------------------------------------------------

def test_repair_report_to_markdown_includes_channels():
    p = RepairProposal(channel="memory", file_path=None, description="fix memory", patch="", confidence=0.9)
    rr = RepairReport(proposals=[p])
    md = rr.to_markdown()
    assert "memory" in md


# ---------------------------------------------------------------------------
# 13. to_dict proposals list has correct structure
# ---------------------------------------------------------------------------

def test_repair_report_to_dict_proposals_structure():
    p = RepairProposal(channel="rag", file_path="f.py", description="d", patch="diff", confidence=0.7)
    rr = RepairReport(proposals=[p])
    d = rr.to_dict()
    assert len(d["proposals"]) == 1
    entry = d["proposals"][0]
    assert entry["channel"] == "rag"
    assert entry["file_path"] == "f.py"
    assert entry["description"] == "d"
    assert entry["patch"] == "diff"
    assert entry["confidence"] == 0.7


# ---------------------------------------------------------------------------
# 14. Report with no at-risk channels → empty proposals
# ---------------------------------------------------------------------------

def test_repairer_no_at_risk_channels_empty_proposals():
    report = _make_empty_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm)
    proposals = repairer.propose()
    assert proposals == []


# ---------------------------------------------------------------------------
# 15. apply() with dry_run=False and no codebase_path still skips all
# ---------------------------------------------------------------------------

def test_repairer_apply_no_codebase_path_skips_all():
    report = _make_report()
    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm, codebase_path=None, dry_run=False)
    rr = repairer.apply()
    assert rr.applied == []
    assert len(rr.skipped) == len(rr.proposals)


# ---------------------------------------------------------------------------
# 16. MockRepairerLLM confidence value is correct
# ---------------------------------------------------------------------------

def test_mock_repairer_llm_confidence():
    llm = MockRepairerLLM()
    result = llm.propose_repair("tool_output", "Sanitize tool output")
    assert result["confidence"] == 0.85


# ---------------------------------------------------------------------------
# 17. RepairReport.to_markdown with no proposals skips table
# ---------------------------------------------------------------------------

def test_repair_report_to_markdown_no_proposals():
    rr = RepairReport(proposals=[])
    md = rr.to_markdown()
    assert "# Auto-repair Report" in md
    assert "**Proposals:** 0" in md
    assert "| Channel |" not in md
