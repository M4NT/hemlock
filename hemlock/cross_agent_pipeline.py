"""Cross-agent pipeline — two AgentPipelines connected through a trust boundary.

This module models the attack surface unique to multi-agent architectures:
Agent B does not re-run the retrieval defense layers on Agent A's output
because A's output arrives through the agent-to-agent channel, which is
implicitly trusted. An attacker who poisons A's RAG store can propagate
injected instructions to B without ever touching B's vector store.

Key distinction from multi_hop_poisoning:
    multi_hop_poisoning  — within one pipeline; retriever follows document
                           references; all defense layers still apply.
    CrossAgentPoisoning  — across two pipelines; A's output bypasses B's
                           ingest/retrieval defenses because it is treated
                           as pre-validated peer input.

Reference:
    Greshake et al. (2023) — "Not What You've Signed Up For" — arxiv:2302.12173
    Debenedetti et al. (2024) — "AgentDojo" — arxiv:2406.13352
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from hemlock.agent_pipeline import AgentAttackResult, AgentPipeline, AgentTrace


# ---------------------------------------------------------------------------
# CrossAgentMockExecutor
# ---------------------------------------------------------------------------

from hemlock.agent_pipeline import MockAgentExecutor


class CrossAgentMockExecutor(MockAgentExecutor):
    """MockAgentExecutor that re-emits executed tool calls in parseable form.

    Models the realistic behavior of a vulnerable agent: after executing a
    tool call, it includes the call instruction in its output so that a
    downstream agent receives it as "trusted guidance" and re-executes it.

    This is the mechanism behind tool_call_injection and instruction_laundering:
    the injected instruction propagates hop-by-hop through the pipeline.
    """

    def invoke(self, inputs: dict[str, Any]) -> dict[str, Any]:
        result = super().invoke(inputs)

        if self.last_calls:
            relay_lines = []
            for call in self.last_calls:
                args_str = ", ".join(f"{k}={v}" for k, v in call.args.items())
                relay_lines.append(f"call {call.tool_name} with {args_str}")

            result["output"] = (
                result["output"]
                + "\n\nRelay for downstream pipeline:\n"
                + "\n".join(relay_lines)
            )

        return result


# ---------------------------------------------------------------------------
# CrossAgentTrace
# ---------------------------------------------------------------------------

@dataclass
class CrossAgentTrace:
    """Full provenance trace for a cross-agent attack: both A and B hops."""

    agent_a_trace: AgentTrace
    agent_b_trace: AgentTrace
    propagation_path: str = "a_response → b_context"
    boundary_guarded: bool = False
    boundary_report: Any | None = None  # DefenseReport if guard applied

    # Convenience accessors for scorers
    @property
    def query(self) -> str:
        return self.agent_a_trace.query

    @property
    def tool_calls(self):
        """B's tool calls — the ones that matter for scoring."""
        return self.agent_b_trace.tool_calls

    @property
    def response(self) -> str:
        return self.agent_b_trace.response


@dataclass
class CrossAgentAttackResult:
    attack_name: str
    reference: str
    succeeded: bool
    trace: CrossAgentTrace
    notes: str = ""

    def __str__(self) -> str:
        status   = "SUCCEEDED" if self.succeeded else "FAILED"
        b_calls  = ", ".join(
            f"{c.tool_name}({c.args})" for c in self.trace.agent_b_trace.tool_calls
        ) or "none"
        return (
            f"[{status}] {self.attack_name}\n"
            f"  ref:        {self.reference}\n"
            f"  query:      {self.trace.query}\n"
            f"  agent_b_calls: {b_calls}\n"
            f"  guarded:    {self.trace.boundary_guarded}\n"
            f"  notes:      {self.notes}"
        )


# ---------------------------------------------------------------------------
# CrossAgentPipeline
# ---------------------------------------------------------------------------

class CrossAgentPipeline:
    """Two AgentPipelines connected through an explicit trust boundary.

    Agent A retrieves from its own RAG store (which may be poisoned).
    A's output is passed to B as trusted context — bypassing B's
    ingest and retrieval defenses, because B assumes A already validated it.

    The CrossAgentBoundaryGuard sits at the A→B handoff point and can
    sanitize A's output before B receives it.
    """

    def __init__(
        self,
        agent_a: AgentPipeline,
        agent_b: AgentPipeline,
        boundary_guard=None,
    ) -> None:
        self.agent_a        = agent_a
        self.agent_b        = agent_b
        self.boundary_guard = boundary_guard

    def query(self, question: str) -> CrossAgentTrace:
        # Hop 1: A processes the query (retrieves from possibly-poisoned store)
        trace_a = self.agent_a.query(question)

        a_output      = trace_a.response
        guarded       = False
        boundary_report = None

        # Trust boundary: optionally sanitize A's output before passing to B
        if self.boundary_guard:
            sanitized, boundary_report = self.boundary_guard.sanitize(a_output)
            if boundary_report.triggered:
                a_output = sanitized
            guarded = True

        # Hop 2: B receives A's output as trusted context (bypasses B's retrieval defenses)
        trace_b = self.agent_b.query(question, injected_context=a_output)

        return CrossAgentTrace(
            agent_a_trace   = trace_a,
            agent_b_trace   = trace_b,
            boundary_guarded= guarded,
            boundary_report = boundary_report,
        )

    def reset(self) -> None:
        self.agent_a.reset()
        self.agent_b.reset()


# ---------------------------------------------------------------------------
# CrossAgentAttack base
# ---------------------------------------------------------------------------

class CrossAgentAttack(ABC):
    """Base for attacks that propagate across an agent-to-agent trust boundary."""

    name: str      = ""
    reference: str = ""
    VARIANTS: list = []

    def __init__(self, pipeline: CrossAgentPipeline) -> None:
        self.pipeline = pipeline

    @abstractmethod
    def setup(self) -> None:
        """Inject malicious documents into Agent A's pipeline."""

    @abstractmethod
    def run(self) -> CrossAgentAttackResult:
        """Execute the attack and return a scored result."""

    @abstractmethod
    def _score(self, trace: CrossAgentTrace) -> bool:
        """Return True if the attack propagated through to Agent B's tool calls."""
