"""Tests for HemSession and HemReport — unified threat assessment (v3.0)."""

from __future__ import annotations

import json

import pytest

from hemlock.hem_session import (
    ChannelResult,
    HemReport,
    HemSession,
    _SEVERITY_ORDER,
    _SEVERITY_WEIGHT,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _result(channel="rag", variant="v1", succeeded=True, severity="high", detail="ok"):
    return ChannelResult(
        channel=channel, variant=variant,
        succeeded=succeeded, severity=severity, detail=detail,
    )


def _mock_session(channels=None):
    return HemSession.mock(target="test-target", channels=channels)


# ---------------------------------------------------------------------------
# TestChannelResult
# ---------------------------------------------------------------------------

class TestChannelResult:
    def test_weight_maps_correctly(self):
        assert ChannelResult("c", "v", True, "critical", "").weight() == 100
        assert ChannelResult("c", "v", True, "high",     "").weight() == 70
        assert ChannelResult("c", "v", True, "medium",   "").weight() == 40
        assert ChannelResult("c", "v", True, "low",      "").weight() == 10
        assert ChannelResult("c", "v", False, "none",    "").weight() == 0

    def test_fields_accessible(self):
        r = _result(channel="mcp", variant="static_scan", succeeded=True, severity="critical")
        assert r.channel == "mcp"
        assert r.variant == "static_scan"
        assert r.succeeded is True
        assert r.severity == "critical"


# ---------------------------------------------------------------------------
# TestHemReport
# ---------------------------------------------------------------------------

class TestHemReport:
    def test_risk_score_empty(self):
        report = HemReport("t", [])
        assert report.risk_score() == 0.0

    def test_risk_score_all_none(self):
        results = [_result(severity="none", succeeded=False) for _ in range(3)]
        report  = HemReport("t", results)
        assert report.risk_score() == 0.0

    def test_risk_score_all_critical(self):
        results = [_result(severity="critical") for _ in range(3)]
        report  = HemReport("t", results)
        assert report.risk_score() == 100.0

    def test_risk_score_mixed(self):
        results = [
            _result(severity="critical"),
            _result(severity="none", succeeded=False),
        ]
        report = HemReport("t", results)
        score  = report.risk_score()
        assert 0 < score < 100

    def test_channels_at_risk_empty(self):
        report = HemReport("t", [_result(severity="none", succeeded=False)])
        assert report.channels_at_risk() == []

    def test_channels_at_risk_includes_high_and_critical(self):
        results = [
            _result(channel="rag",  severity="high"),
            _result(channel="mem",  severity="critical"),
            _result(channel="tool", severity="none", succeeded=False),
        ]
        report = HemReport("t", results)
        at_risk = report.channels_at_risk()
        assert "rag" in at_risk
        assert "mem" in at_risk
        assert "tool" not in at_risk

    def test_succeeded_attacks(self):
        results = [
            _result(channel="rag",  variant="title",    succeeded=True),
            _result(channel="mem",  variant="direct",   succeeded=False),
            _result(channel="graph",variant="nhop",     succeeded=True),
        ]
        report = HemReport("t", results)
        s = report.succeeded_attacks()
        assert "rag/title" in s
        assert "graph/nhop" in s
        assert "mem/direct" not in s

    def test_channel_summary_worst_severity(self):
        results = [
            _result(channel="rag", severity="high"),
            _result(channel="rag", severity="critical"),
            _result(channel="rag", severity="none", succeeded=False),
        ]
        report   = HemReport("t", results)
        summary  = report.channel_summary()
        assert summary["rag"] == "critical"

    def test_to_dict_keys(self):
        report = HemReport("tgt", [_result()])
        d = report.to_dict()
        assert "target"            in d
        assert "risk_score"        in d
        assert "channels_at_risk"  in d
        assert "succeeded_attacks" in d
        assert "results"           in d

    def test_to_dict_result_fields(self):
        report = HemReport("t", [_result()])
        r = report.to_dict()["results"][0]
        assert "channel"   in r
        assert "variant"   in r
        assert "succeeded" in r
        assert "severity"  in r
        assert "detail"    in r

    def test_to_json_valid(self):
        report = HemReport("t", [_result()])
        parsed = json.loads(report.to_json())
        assert parsed["target"] == "t"

    def test_to_markdown_contains_header(self):
        report = HemReport("t", [_result()])
        md = report.to_markdown()
        assert "# Hemlock Threat Model Report" in md

    def test_to_markdown_contains_score(self):
        report = HemReport("t", [_result(severity="high")])
        md = report.to_markdown()
        assert "Risk score" in md

    def test_to_markdown_contains_channel_summary(self):
        report = HemReport("t", [_result(channel="rag", severity="high")])
        md = report.to_markdown()
        assert "Channel Summary" in md
        assert "rag" in md


# ---------------------------------------------------------------------------
# TestHemSessionMock — construction
# ---------------------------------------------------------------------------

class TestHemSessionMock:
    def test_mock_builds_without_error(self):
        session = _mock_session()
        assert session is not None

    def test_mock_default_channels_exclude_mcp(self):
        session = _mock_session()
        assert "mcp" not in session._channels

    def test_mock_with_mcp_transport_includes_mcp(self):
        from hemlock.mock import MockMcpTransport
        from hemlock.mcp_payloads import McpToolSchema
        tools = [McpToolSchema(name="noop", description="no-op", input_schema={})]
        transport = MockMcpTransport(tools=tools)
        session = HemSession.mock(mcp_transport=transport)
        assert "mcp" in session._channels

    def test_mock_channel_filter(self):
        session = _mock_session(channels=["rag", "graph"])
        assert session._channels == ["rag", "graph"]

    def test_mock_pipelines_populated(self):
        session = _mock_session()
        assert session._rag_pipeline         is not None
        assert session._cross_agent_pipeline is not None
        assert session._memory_pipeline      is not None
        assert session._tool_output_pipeline is not None

    def test_mock_graph_tools_populated(self):
        session = _mock_session()
        assert len(session._graph_tools)     > 0
        assert len(session._graph_prop_tools) > len(session._graph_tools)

    def test_target_name_passed(self):
        session = HemSession.mock(target="my-pipeline")
        assert session.target == "my-pipeline"


# ---------------------------------------------------------------------------
# TestHemSessionRun — single channel isolation
# ---------------------------------------------------------------------------

class TestHemSessionRun:
    def test_run_rag_returns_results(self):
        from attacks.indirect_injection import IndirectInjection
        session = _mock_session(channels=["rag"])
        report  = session.run()
        assert len(report.results) == len(IndirectInjection.VARIANTS)
        assert all(r.channel == "rag" for r in report.results)

    def test_run_memory_returns_results(self):
        from attacks.memory_poisoning import MemoryPoisoning
        session = _mock_session(channels=["memory"])
        report  = session.run()
        assert len(report.results) == len(MemoryPoisoning.VARIANTS)
        assert all(r.channel == "memory" for r in report.results)

    def test_run_cross_agent_returns_results(self):
        from attacks.cross_agent_poisoning import CrossAgentPoisoning
        session = _mock_session(channels=["cross_agent"])
        report  = session.run()
        assert len(report.results) == len(CrossAgentPoisoning.VARIANTS)
        assert all(r.channel == "cross_agent" for r in report.results)

    def test_run_tool_output_returns_results(self):
        from attacks.tool_output_poisoning import ToolOutputPoisoning
        session = _mock_session(channels=["tool_output"])
        report  = session.run()
        assert len(report.results) == len(ToolOutputPoisoning.VARIANTS)
        assert all(r.channel == "tool_output" for r in report.results)

    def test_run_graph_returns_one_result(self):
        session = _mock_session(channels=["graph"])
        report  = session.run()
        assert len(report.results) == 1
        assert report.results[0].channel == "graph"

    def test_run_mcp_not_run_without_transport(self):
        session = _mock_session(channels=["rag", "mcp"])
        # mcp is in channels but no transport → _run_mcp returns None
        report = session.run()
        assert all(r.channel != "mcp" for r in report.results)

    def test_run_mcp_with_transport(self):
        from hemlock.mock import MockMcpTransport
        from hemlock.mcp_payloads import McpToolSchema
        tools     = [McpToolSchema(name="noop", description="no-op", input_schema={})]
        transport = MockMcpTransport(tools=tools)
        session   = HemSession.mock(channels=["mcp"], mcp_transport=transport)
        report    = session.run()
        mcp_results = [r for r in report.results if r.channel == "mcp"]
        assert len(mcp_results) == 1

    def test_run_empty_channels(self):
        session = _mock_session(channels=[])
        report  = session.run()
        assert report.results == []
        assert report.risk_score() == 0.0


# ---------------------------------------------------------------------------
# TestHemSessionRunFull — full mock run (slowest)
# ---------------------------------------------------------------------------

class TestHemSessionRunFull:
    @pytest.mark.slow
    def test_full_mock_run_produces_report(self):
        session = _mock_session()
        report  = session.run()
        assert len(report.results) > 0
        assert 0 <= report.risk_score() <= 100

    @pytest.mark.slow
    def test_full_report_has_all_active_channels(self):
        session  = _mock_session()
        report   = session.run()
        channels_in_results = {r.channel for r in report.results}
        for ch in session._channels:
            assert ch in channels_in_results

    @pytest.mark.slow
    def test_full_report_severity_values_valid(self):
        session = _mock_session()
        report  = session.run()
        valid   = set(_SEVERITY_ORDER)
        for r in report.results:
            assert r.severity in valid, f"Invalid severity '{r.severity}' in {r}"

    @pytest.mark.slow
    def test_full_report_to_json_roundtrip(self):
        session = _mock_session()
        report  = session.run()
        d       = json.loads(report.to_json())
        assert d["target"] == "test-target"
        assert isinstance(d["risk_score"], float)
        assert isinstance(d["results"], list)
