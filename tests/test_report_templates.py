"""Tests for report_templates — executive/technical templates and remediation_hints."""

from __future__ import annotations

import pytest

from hemlock.hem_session import ChannelResult, HemReport
from hemlock.report_templates import remediation_hints, render


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _report(results: list[ChannelResult], target: str = "test-app") -> HemReport:
    return HemReport(target=target, results=results)


def _cr(channel, severity, succeeded=True, variant="v1", detail="test"):
    return ChannelResult(
        channel=channel, variant=variant, succeeded=succeeded,
        severity=severity, detail=detail,
    )


CLEAN_REPORT = _report([])
HIGH_RAG     = _report([_cr("rag", "high")])
CRITICAL_MEM = _report([_cr("memory", "critical")])
MULTI_RISK   = _report([
    _cr("rag",         "high"),
    _cr("cross_agent", "critical"),
    _cr("memory",      "critical"),
    _cr("tool_output", "high"),
    _cr("graph",       "none", succeeded=False),
])


# ---------------------------------------------------------------------------
# TestRemediationHints
# ---------------------------------------------------------------------------

class TestRemediationHints:
    def test_clean_report_empty_hints(self):
        assert remediation_hints(CLEAN_REPORT) == {}

    def test_high_rag_returns_rag_hints(self):
        hints = remediation_hints(HIGH_RAG)
        assert "rag" in hints
        assert isinstance(hints["rag"], list)
        assert len(hints["rag"]) > 0

    def test_critical_memory_returns_memory_hints(self):
        hints = remediation_hints(CRITICAL_MEM)
        assert "memory" in hints

    def test_multi_channel_returns_all_at_risk(self):
        hints = remediation_hints(MULTI_RISK)
        # graph is "none" → not at risk; others are high/critical
        assert "rag"         in hints
        assert "cross_agent" in hints
        assert "memory"      in hints
        assert "tool_output" in hints
        assert "graph"       not in hints

    def test_hint_text_not_empty(self):
        hints = remediation_hints(HIGH_RAG)
        for tip in hints["rag"]:
            assert len(tip) > 10

    def test_all_known_channels_have_hints(self):
        from hemlock.report_templates import _HINTS
        for ch in ["rag", "cross_agent", "memory", "tool_output", "graph", "mcp"]:
            assert ch in _HINTS
            assert _HINTS[ch]


# ---------------------------------------------------------------------------
# TestRenderTechnical
# ---------------------------------------------------------------------------

class TestRenderTechnical:
    def test_renders_string(self):
        md = render(CLEAN_REPORT, template="technical")
        assert isinstance(md, str)
        assert len(md) > 100

    def test_contains_target(self):
        md = render(HIGH_RAG, template="technical")
        assert "test-app" in md

    def test_contains_channel_header(self):
        md = render(MULTI_RISK, template="technical")
        assert "Rag" in md or "rag" in md.lower()
        assert "Cross Agent" in md or "cross_agent" in md.lower()

    def test_remediation_section_present_when_at_risk(self):
        md = render(HIGH_RAG, template="technical")
        assert "Remediation" in md

    def test_remediation_section_absent_when_clean(self):
        md = render(CLEAN_REPORT, template="technical")
        assert "Remediation" not in md

    def test_code_snippet_present_for_rag(self):
        md = render(HIGH_RAG, template="technical")
        assert "```" in md

    def test_succeeded_variants_in_table(self):
        md = render(HIGH_RAG, template="technical")
        assert "v1" in md

    def test_risk_score_present(self):
        md = render(HIGH_RAG, template="technical")
        assert "Risk Score" in md or "risk_score" in md.lower()

    def test_default_template_is_technical(self):
        md_default   = render(HIGH_RAG)
        md_technical = render(HIGH_RAG, template="technical")
        assert md_default == md_technical


# ---------------------------------------------------------------------------
# TestRenderExecutive
# ---------------------------------------------------------------------------

class TestRenderExecutive:
    def test_renders_string(self):
        md = render(HIGH_RAG, template="executive")
        assert isinstance(md, str)
        assert len(md) > 100

    def test_contains_target(self):
        md = render(HIGH_RAG, template="executive")
        assert "test-app" in md

    def test_risk_label_present(self):
        md = render(HIGH_RAG, template="executive")
        assert any(label in md for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_no_code_fences(self):
        # Executive template has no code snippets
        md = render(CLEAN_REPORT, template="executive")
        assert "```" not in md

    def test_clean_report_no_findings_text(self):
        md = render(CLEAN_REPORT, template="executive")
        assert "No high or critical" in md or "no" in md.lower()

    def test_at_risk_channels_listed(self):
        md = render(MULTI_RISK, template="executive")
        assert "Rag" in md or "rag" in md.lower()
        assert "Memory" in md or "memory" in md.lower()

    def test_top_remediation_actions_section(self):
        md = render(HIGH_RAG, template="executive")
        assert "Remediation" in md

    def test_next_steps_present_when_at_risk(self):
        md = render(HIGH_RAG, template="executive")
        assert "Next Steps" in md

    def test_critical_label_for_high_score(self):
        # risk score for cross_agent critical is high — check label
        report = _report([_cr("cross_agent", "critical")] * 3)
        md = render(report, template="executive")
        assert "CRITICAL" in md or "HIGH" in md


# ---------------------------------------------------------------------------
# TestRenderErrors
# ---------------------------------------------------------------------------

class TestRenderErrors:
    def test_unknown_template_raises(self):
        with pytest.raises(ValueError, match="Unknown template"):
            render(CLEAN_REPORT, template="unknown")


# ---------------------------------------------------------------------------
# TestHemReportRenderMethod
# ---------------------------------------------------------------------------

class TestHemReportRenderMethod:
    def test_report_render_returns_markdown(self):
        md = HIGH_RAG.render(template="executive")
        assert "# Security Assessment" in md

    def test_report_render_technical(self):
        md = HIGH_RAG.render(template="technical")
        assert "# Security Assessment" in md

    def test_report_remediation_hints_delegates(self):
        hints = HIGH_RAG.remediation_hints()
        assert "rag" in hints
