from __future__ import annotations

import pytest

from hemlock.compliance import ComplianceEntry, ComplianceMapper, FRAMEWORKS
from hemlock.hem_session import ChannelResult, HemReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_report(channel: str = "rag", severity: str = "high", succeeded: bool = True, variant: str = "v1") -> HemReport:
    return HemReport(
        target="test",
        results=[ChannelResult(channel=channel, variant=variant, succeeded=succeeded, severity=severity, detail="test")],
    )


def make_multi_report(entries: list[tuple[str, str, str]]) -> HemReport:
    """entries: list of (channel, severity, variant)"""
    results = [
        ChannelResult(channel=ch, variant=var, succeeded=(sev != "none"), severity=sev, detail="test")
        for ch, sev, var in entries
    ]
    return HemReport(target="test", results=results)


MAPPER = ComplianceMapper()


# ---------------------------------------------------------------------------
# 1. map() with owasp-llm returns ComplianceEntry list
# ---------------------------------------------------------------------------

def test_map_owasp_returns_list():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "owasp-llm")
    assert isinstance(entries, list)
    assert all(isinstance(e, ComplianceEntry) for e in entries)


# ---------------------------------------------------------------------------
# 2. OWASP LLM01 triggered by rag channel at risk
# ---------------------------------------------------------------------------

def test_owasp_llm01_rag():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "owasp-llm")
    llm01 = [e for e in entries if e.control_id == "LLM01" and e.channel == "rag"]
    assert len(llm01) == 1
    assert llm01[0].severity == "high"


# ---------------------------------------------------------------------------
# 3. OWASP LLM01 triggered by cross_agent channel at risk
# ---------------------------------------------------------------------------

def test_owasp_llm01_cross_agent():
    report = make_report("cross_agent", "critical")
    entries = MAPPER.map(report, "owasp-llm")
    llm01 = [e for e in entries if e.control_id == "LLM01" and e.channel == "cross_agent"]
    assert len(llm01) == 1
    assert llm01[0].severity == "critical"


# ---------------------------------------------------------------------------
# 4. OWASP LLM02 triggered by tool_output channel at risk
# ---------------------------------------------------------------------------

def test_owasp_llm02_tool_output():
    report = make_report("tool_output", "high")
    entries = MAPPER.map(report, "owasp-llm")
    llm02 = [e for e in entries if e.control_id == "LLM02" and e.channel == "tool_output"]
    assert len(llm02) == 1


# ---------------------------------------------------------------------------
# 5. OWASP LLM08 triggered by graph channel at risk
# ---------------------------------------------------------------------------

def test_owasp_llm08_graph():
    report = make_report("graph", "high")
    entries = MAPPER.map(report, "owasp-llm")
    llm08 = [e for e in entries if e.control_id == "LLM08" and e.channel == "graph"]
    assert len(llm08) == 1


# ---------------------------------------------------------------------------
# 6. OWASP mappings: no entries when no channels at risk
# ---------------------------------------------------------------------------

def test_owasp_no_entries_when_no_risk():
    report = make_report("rag", "none", succeeded=False)
    entries = MAPPER.map(report, "owasp-llm")
    assert entries == []


# ---------------------------------------------------------------------------
# 7. map() with mitre-atlas returns correct entries
# ---------------------------------------------------------------------------

def test_map_mitre_returns_list():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "mitre-atlas")
    assert isinstance(entries, list)
    assert all(e.framework == "mitre-atlas" for e in entries)


# ---------------------------------------------------------------------------
# 8. MITRE AML.T0051 triggered by rag channel
# ---------------------------------------------------------------------------

def test_mitre_t0051_rag():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "mitre-atlas")
    t0051 = [e for e in entries if e.control_id == "AML.T0051" and e.channel == "rag"]
    assert len(t0051) == 1


# ---------------------------------------------------------------------------
# 9. MITRE AML.T0051 triggered by cross_agent channel
# ---------------------------------------------------------------------------

def test_mitre_t0051_cross_agent():
    report = make_report("cross_agent", "critical")
    entries = MAPPER.map(report, "mitre-atlas")
    t0051 = [e for e in entries if e.control_id == "AML.T0051" and e.channel == "cross_agent"]
    assert len(t0051) == 1


# ---------------------------------------------------------------------------
# 10. map() with nist-ai-rmf returns entries
# ---------------------------------------------------------------------------

def test_map_nist_returns_entries():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "nist-ai-rmf")
    assert isinstance(entries, list)
    assert len(entries) > 0
    assert all(e.framework == "nist-ai-rmf" for e in entries)


# ---------------------------------------------------------------------------
# 11. NIST GOVERN 1.1 triggered by any at-risk channel
# ---------------------------------------------------------------------------

def test_nist_govern_11_any_at_risk_channel():
    report = make_report("mcp", "high")
    entries = MAPPER.map(report, "nist-ai-rmf")
    govern = [e for e in entries if e.control_id == "GOVERN 1.1" and e.channel == "mcp"]
    assert len(govern) == 1


# ---------------------------------------------------------------------------
# 12. map_all returns dict with all 3 frameworks as keys
# ---------------------------------------------------------------------------

def test_map_all_returns_all_frameworks():
    report = make_report("rag", "high")
    result = MAPPER.map_all(report)
    assert set(result.keys()) == set(FRAMEWORKS)
    for fw, entries in result.items():
        assert isinstance(entries, list)


# ---------------------------------------------------------------------------
# 13. to_markdown returns string with markdown table headers
# ---------------------------------------------------------------------------

def test_to_markdown_has_table_headers():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "owasp-llm")
    md = MAPPER.to_markdown(entries)
    assert isinstance(md, str)
    assert "| Framework |" in md
    assert "| Control ID |" in md


# ---------------------------------------------------------------------------
# 14. to_dict returns list of dicts with correct keys
# ---------------------------------------------------------------------------

def test_to_dict_has_correct_keys():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "owasp-llm")
    dicts = MAPPER.to_dict(entries)
    assert isinstance(dicts, list)
    assert len(dicts) > 0
    expected_keys = {"framework", "control_id", "control_name", "description", "severity", "channel"}
    for d in dicts:
        assert set(d.keys()) == expected_keys


# ---------------------------------------------------------------------------
# 15. HemReport.to_compliance method exists and returns list
# ---------------------------------------------------------------------------

def test_hem_report_to_compliance():
    report = make_report("rag", "high")
    result = report.to_compliance("owasp-llm")
    assert isinstance(result, list)
    assert all(isinstance(e, ComplianceEntry) for e in result)


# ---------------------------------------------------------------------------
# 16. severity is propagated to entries
# ---------------------------------------------------------------------------

def test_severity_propagated_to_entries():
    report = make_report("rag", "critical")
    entries = MAPPER.map(report, "owasp-llm")
    rag_entries = [e for e in entries if e.channel == "rag"]
    assert all(e.severity == "critical" for e in rag_entries)


# ---------------------------------------------------------------------------
# 17. framework "invalid" raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_framework_raises():
    report = make_report("rag", "high")
    with pytest.raises(ValueError):
        MAPPER.map(report, "invalid-framework")


# ---------------------------------------------------------------------------
# 18. LLM03 triggered by variant containing "poisoning"
# ---------------------------------------------------------------------------

def test_owasp_llm03_poisoning_variant():
    report = HemReport(
        target="test",
        results=[ChannelResult(channel="rag", variant="data_poisoning", succeeded=True, severity="high", detail="test")],
    )
    entries = MAPPER.map(report, "owasp-llm")
    llm03 = [e for e in entries if e.control_id == "LLM03"]
    assert len(llm03) >= 1
    assert any(e.channel == "rag" for e in llm03)


# ---------------------------------------------------------------------------
# 19. NIST MAP 1.5 triggered by cross_agent
# ---------------------------------------------------------------------------

def test_nist_map_15_cross_agent():
    report = make_report("cross_agent", "critical")
    entries = MAPPER.map(report, "nist-ai-rmf")
    map15 = [e for e in entries if e.control_id == "MAP 1.5" and e.channel == "cross_agent"]
    assert len(map15) == 1


# ---------------------------------------------------------------------------
# 20. NIST MANAGE 2.2 triggered by mcp channel
# ---------------------------------------------------------------------------

def test_nist_manage_22_mcp():
    report = make_report("mcp", "high")
    entries = MAPPER.map(report, "nist-ai-rmf")
    manage = [e for e in entries if e.control_id == "MANAGE 2.2" and e.channel == "mcp"]
    assert len(manage) == 1


# ---------------------------------------------------------------------------
# 21. MITRE AML.T0054 triggered by variant containing "override"
# ---------------------------------------------------------------------------

def test_mitre_t0054_override_variant():
    report = HemReport(
        target="test",
        results=[ChannelResult(channel="rag", variant="system_override", succeeded=True, severity="high", detail="test")],
    )
    entries = MAPPER.map(report, "mitre-atlas")
    t0054 = [e for e in entries if e.control_id == "AML.T0054"]
    assert len(t0054) >= 1


# ---------------------------------------------------------------------------
# 22. MITRE AML.T0048 triggered by memory channel
# ---------------------------------------------------------------------------

def test_mitre_t0048_memory():
    report = make_report("memory", "critical")
    entries = MAPPER.map(report, "mitre-atlas")
    t0048 = [e for e in entries if e.control_id == "AML.T0048" and e.channel == "memory"]
    assert len(t0048) == 1


# ---------------------------------------------------------------------------
# 23. to_markdown rows contain entry data
# ---------------------------------------------------------------------------

def test_to_markdown_contains_entry_data():
    report = make_report("rag", "high")
    entries = MAPPER.map(report, "owasp-llm")
    md = MAPPER.to_markdown(entries)
    assert "owasp-llm" in md
    assert "rag" in md


# ---------------------------------------------------------------------------
# 24. multi-channel report populates multiple entries
# ---------------------------------------------------------------------------

def test_multi_channel_report_multiple_entries():
    report = make_multi_report([
        ("rag", "high", "v1"),
        ("cross_agent", "critical", "v2"),
        ("graph", "high", "n_hop_propagation"),
    ])
    entries = MAPPER.map(report, "owasp-llm")
    channels_hit = {e.channel for e in entries}
    assert "rag" in channels_hit
    assert "cross_agent" in channels_hit
    assert "graph" in channels_hit


# ---------------------------------------------------------------------------
# 25. HemReport.to_compliance with default framework
# ---------------------------------------------------------------------------

def test_hem_report_to_compliance_default_framework():
    report = make_report("tool_output", "high")
    result = report.to_compliance()  # default: owasp-llm
    assert any(e.framework == "owasp-llm" for e in result)
