"""Tests for UnifiedAgentScorer — coverage across all 4 agentic attack surfaces."""

from __future__ import annotations

import tempfile

import pytest
from langchain_core.tools import tool

from hemlock.mock import MockEmbeddings, MockLLM
from hemlock.pipeline import Pipeline
from hemlock.unified_agent_scorer import (
    UnifiedAgentScorer,
    UnifiedAgentScorerReport,
    UnifiedScenarioResult,
    print_unified_report,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}"


@tool
def get_order_status(order_id: str) -> str:
    """Get order status."""
    return f"Order {order_id}: processing"


TOOLS = [send_email, get_order_status]


@pytest.fixture(scope="module")
def unified_report():
    """Run the unified scorer once and reuse for all tests."""
    scorer = UnifiedAgentScorer.from_tools(TOOLS, model_name="test-unified")
    return scorer.run(verbose=False)


# ---------------------------------------------------------------------------
# UnifiedAgentScorer
# ---------------------------------------------------------------------------

class TestUnifiedAgentScorer:
    def test_from_tools_builds_scorer(self):
        scorer = UnifiedAgentScorer.from_tools(TOOLS)
        assert len(scorer.surface_configs) == 4

    def test_all_four_surfaces_present(self, unified_report):
        surfaces = {s.attack_surface for s in unified_report.scenarios}
        assert surfaces == {"rag_agent", "cross_agent", "memory", "tool_output"}

    def test_no_defense_baseline_all_succeed(self, unified_report):
        no_defense = [
            s for s in unified_report.scenarios
            if s.validator_config == "none"
        ]
        assert all(s.attack_succeeded for s in no_defense), (
            f"All 'none' configs should succeed. Failed: "
            f"{[s for s in no_defense if not s.attack_succeeded]}"
        )

    def test_guarded_blocks_cross_agent(self, unified_report):
        guarded_cross = [
            s for s in unified_report.scenarios
            if s.attack_surface == "cross_agent" and s.validator_config == "guarded"
        ]
        assert all(not s.attack_succeeded for s in guarded_cross)

    def test_guarded_blocks_memory(self, unified_report):
        guarded_mem = [
            s for s in unified_report.scenarios
            if s.attack_surface == "memory" and s.validator_config == "guarded"
        ]
        assert all(not s.attack_succeeded for s in guarded_mem)

    def test_guarded_blocks_tool_output(self, unified_report):
        guarded_top = [
            s for s in unified_report.scenarios
            if s.attack_surface == "tool_output" and s.validator_config == "guarded"
        ]
        assert all(not s.attack_succeeded for s in guarded_top)

    def test_allowlist_blocks_rag_agent(self, unified_report):
        allowlist = [
            s for s in unified_report.scenarios
            if s.attack_surface == "rag_agent" and s.validator_config == "allowlist"
        ]
        assert all(not s.attack_succeeded for s in allowlist)


# ---------------------------------------------------------------------------
# UnifiedAgentScorerReport
# ---------------------------------------------------------------------------

class TestUnifiedAgentScorerReport:
    def test_success_rate_range(self, unified_report):
        rate = unified_report.success_rate()
        assert 0.0 <= rate <= 1.0

    def test_rate_by_surface_keys(self, unified_report):
        rates = unified_report.rate_by_surface()
        assert set(rates.keys()) == {"rag_agent", "cross_agent", "memory", "tool_output"}

    def test_to_json_contains_surface_rates(self, unified_report):
        import json
        data = json.loads(unified_report.to_json())
        assert "rates_by_surface" in data
        assert "tool_hijack_rate" in data["rates_by_surface"]
        assert "cross_infection_rate" in data["rates_by_surface"]
        assert "memory_persistence_rate" in data["rates_by_surface"]
        assert "tool_output_injection_rate" in data["rates_by_surface"]

    def test_to_markdown_contains_all_surfaces(self, unified_report):
        md = unified_report.to_markdown()
        assert "Tool Hijack Rate" in md
        assert "Cross-Infection Rate" in md
        assert "Memory Persistence Rate" in md
        assert "Tool Output Injection Rate" in md

    def test_print_unified_report_does_not_raise(self, unified_report):
        # Just ensure it renders without error
        print_unified_report(unified_report)

    def test_scenario_count_matches_expected(self, unified_report):
        from attacks.agent_tool_hijack import AgentToolHijack
        from attacks.cross_agent_poisoning import CrossAgentPoisoning
        from attacks.memory_poisoning import MemoryPoisoning
        from attacks.tool_output_poisoning import ToolOutputPoisoning

        expected = (
            len(AgentToolHijack.VARIANTS) * 3 +         # none, domain_blocklist, allowlist
            len(CrossAgentPoisoning.VARIANTS) * 2 +     # none, guarded
            len(MemoryPoisoning.VARIANTS) * 2 +         # none, guarded
            len(ToolOutputPoisoning.VARIANTS) * 2       # none, guarded
        )
        assert len(unified_report.scenarios) == expected
