"""Tool-output pipeline — tool responses as an injection channel.

Closes the fourth and final context-ingress channel of an autonomous agent:

  1. RAG / static documents   → indirect_injection (v1)
  2. Upstream agent output    → cross_agent_poisoning (v2)
  3. Persistent memory        → memory_poisoning (v2.1)
  4. Tool response content    → tool_output_poisoning (v2.2)  ← this module

A ReAct-style agent treats tool responses as trusted data — the output of its
own tools is never re-run through ingest or retrieval defenses. An attacker
who controls what a tool returns (via a compromised API, a poisoned database,
a malicious search result, or a spoofed email body) can embed injection
instructions inside that trusted channel.

Two-pass execution model:
  Pass 1  Agent reads RAG context → calls a legitimate tool.
  Pass 2  Agent reads the tool's response as trusted context →
          follows any embedded instruction without defense filtering.

The ToolOutputGuard intercepts between the two passes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from defenses.base import DefenseReport
from hemlock.agent_pipeline import AgentAttack, AgentAttackResult, AgentPipeline, AgentTrace, MockAgentExecutor, ToolCall


# ---------------------------------------------------------------------------
# Two-pass executor
# ---------------------------------------------------------------------------

class ToolOutputMockExecutor(MockAgentExecutor):
    """MockAgentExecutor that feeds tool responses back as a second context pass.

    Pass 1: standard — scans the RAG-retrieved context for call instructions.
    Pass 2: scans each tool's response for embedded call instructions.
            This is the attack surface — tool responses bypass all defenses.

    An optional output_guard validates each response before pass 2.
    """

    def __init__(
        self,
        tools: list,
        poisoned_responses: dict[str, str] | None = None,
        output_guard=None,
    ) -> None:
        super().__init__(tools)
        self.poisoned_responses = poisoned_responses or {}
        self.output_guard       = output_guard
        self.guard_triggered    = False
        self.guard_report: DefenseReport | None = None

    def invoke(self, inputs: dict[str, Any]) -> dict[str, Any]:
        self.guard_triggered = False
        self.guard_report    = None

        # Pass 1: execute calls found in initial context
        result = super().invoke(inputs)
        first_pass_calls = list(self.last_calls)
        all_calls        = list(first_pass_calls)

        # Pass 2: feed each tool response back as trusted context
        response_parts: list[str] = []
        for call in first_pass_calls:
            resp = self.poisoned_responses.get(call.tool_name, call.result or "")

            if self.output_guard:
                sanitized, report = self.output_guard.sanitize(resp)
                if report.triggered:
                    self.guard_triggered = True
                    self.guard_report    = report
                    resp = sanitized

            response_parts.append(f"[Tool response from {call.tool_name}]: {resp}")

        if response_parts:
            second_ctx = "\n".join(response_parts)
            super().invoke({"input": inputs.get("input", ""), "context": second_ctx})
            all_calls.extend(self.last_calls)

        self.last_calls = all_calls
        return result


# ---------------------------------------------------------------------------
# Tool-output pipeline
# ---------------------------------------------------------------------------

class ToolOutputPipeline(AgentPipeline):
    """AgentPipeline whose tool responses are processed as a second context pass.

    Accepts an optional output_guard (ToolOutputGuard) that intercepts tool
    responses before they are fed back to the executor.
    """

    def __init__(
        self,
        pipeline,
        executor: ToolOutputMockExecutor,
        tools: list,
        output_guard=None,
    ) -> None:
        if not isinstance(executor, ToolOutputMockExecutor):
            raise TypeError("ToolOutputPipeline requires a ToolOutputMockExecutor")
        super().__init__(pipeline=pipeline, executor=executor, tools=tools)
        if output_guard:
            self.executor.output_guard = output_guard

    @property
    def guard_triggered(self) -> bool:
        return getattr(self.executor, "guard_triggered", False)

    @property
    def guard_report(self) -> DefenseReport | None:
        return getattr(self.executor, "guard_report", None)


# ---------------------------------------------------------------------------
# ToolOutputAttack base
# ---------------------------------------------------------------------------

class ToolOutputAttack(AgentAttack):
    """Base for attacks that inject via tool response content."""

    def __init__(self, pipeline: ToolOutputPipeline) -> None:
        if not isinstance(pipeline, ToolOutputPipeline):
            raise TypeError("ToolOutputAttack requires a ToolOutputPipeline")
        super().__init__(pipeline)

    @property
    def tool_pipeline(self) -> ToolOutputPipeline:
        return self.pipeline  # type: ignore[return-value]
