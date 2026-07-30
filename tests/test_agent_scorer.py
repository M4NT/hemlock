"""Tests for AgentScorer."""

from __future__ import annotations

import tempfile

import pytest
from langchain_core.tools import tool

from attacks.agent_tool_hijack import AgentToolHijack
from defenses.tool_call_validator import ToolCallValidator
from hemlock.agent_pipeline import AgentPipeline, MockAgentExecutor
from hemlock.agent_scorer import AgentScorer, AgentScorerReport, VALIDATOR_CONFIGS
from hemlock.pipeline import Pipeline
from tests.conftest import MockLLM


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}"


@tool
def get_order_status(order_id: str) -> str:
    """Get order status."""
    return f"Order {order_id}: processing"


TOOLS = [send_email, get_order_status]


def make_agent_pipeline():
    tmp      = tempfile.mkdtemp()
    inner    = Pipeline(llm=MockLLM("ok"), persist_dir=tmp, collection=f"scorer_test_{id(tmp)}")
    executor = MockAgentExecutor(tools=TOOLS)
    return AgentPipeline(pipeline=inner, executor=executor, tools=TOOLS)


class TestAgentScorer:
    def test_runs_all_variants_x_configs(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        expected = len(AgentToolHijack.VARIANTS) * len(VALIDATOR_CONFIGS)
        assert len(report.scenarios) == expected

    def test_none_config_all_succeed(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"none": None},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        assert all(s.attack_succeeded for s in report.scenarios)

    def test_domain_blocklist_blocks_all_variants(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"domain_blocklist": ToolCallValidator()},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        assert all(not s.attack_succeeded for s in report.scenarios)
        assert all(s.blocked_at == "tool_call" for s in report.scenarios)

    def test_allowlist_config_blocks_all_variants(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"allowlist": ToolCallValidator(allowed_tools=["get_order_status"])},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        assert all(not s.attack_succeeded for s in report.scenarios)

    def test_success_rate_with_no_defense_is_100(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"none": None},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        assert report.success_rate() == 1.0

    def test_success_rate_with_full_defense_is_0(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"domain_blocklist": ToolCallValidator()},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        assert report.success_rate() == 0.0

    def test_report_to_json_roundtrip(self):
        import json
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"none": None},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        data   = json.loads(report.to_json())
        assert data["model"] == "mock"
        assert data["total_scenarios"] == len(AgentToolHijack.VARIANTS)

    def test_report_to_markdown_contains_attack_name(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            validator_configs={"none": None},
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        md     = report.to_markdown()
        assert "Agent Tool Hijack" in md
        assert "SUCCEEDED" in md

    def test_by_config_groups_correctly(self):
        scorer = AgentScorer(
            agent_pipeline_factory=make_agent_pipeline,
            attacks=[AgentToolHijack],
            model_name="mock",
        )
        report = scorer.run(verbose=False)
        by_cfg = report.by_config()
        for cfg_name in VALIDATOR_CONFIGS:
            assert cfg_name in by_cfg
            assert len(by_cfg[cfg_name]) == len(AgentToolHijack.VARIANTS)
