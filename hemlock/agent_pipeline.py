"""Agent pipeline — RAG + tool-use layer with full tool call interception.

v2 extension: where v1 tests whether the model *believes* an injected payload,
v2 tests whether the agent *acts* on it — specifically, whether tool calls are
hijacked to use attacker-controlled parameters.

The AgentPipeline wraps an inner Pipeline (for RAG retrieval) and an executor
(MockAgentExecutor for zero-API-key tests, or a real LangChain AgentExecutor).
Every tool call is intercepted and recorded in the AgentTrace.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from hemlock.pipeline import Pipeline


# ---------------------------------------------------------------------------
# Data primitives
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    tool_name: str
    args: dict[str, Any]
    result: str | None = None
    blocked: bool = False


@dataclass
class AgentTrace:
    """Like RetrievalTrace but includes intercepted tool calls."""
    query: str
    retrieved_chunks: list
    full_prompt: str
    response: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    injected: bool = False
    injection_source: str | None = None


@dataclass
class AgentAttackResult:
    attack_name: str
    reference: str
    succeeded: bool
    trace: AgentTrace
    notes: str = ""

    def __str__(self) -> str:
        status = "SUCCEEDED" if self.succeeded else "FAILED"
        calls = ", ".join(
            f"{c.tool_name}({c.args})" for c in self.trace.tool_calls
        ) or "none"
        return (
            f"[{status}] {self.attack_name}\n"
            f"  ref: {self.reference}\n"
            f"  query: {self.trace.query}\n"
            f"  tool_calls: {calls}\n"
            f"  notes: {self.notes}"
        )


# ---------------------------------------------------------------------------
# Mock executor (zero API key)
# ---------------------------------------------------------------------------

class MockAgentExecutor:
    """Deterministic agent that follows tool call instructions found in context.

    Scans retrieved context for lines of the form:
        call TOOLNAME with key=value, key2=value2

    This mirrors what a real LLM would do when it reads injected instructions —
    allowing tests to verify defense layers without a live model.
    """

    _CALL_PATTERN = re.compile(
        r"call\s+(\w+)\s+with\s+([^\n]+)",
        re.I,
    )

    def __init__(self, tools: list) -> None:
        self.tools = {t.name: t for t in tools}
        self.last_calls: list[ToolCall] = []

    def invoke(self, inputs: dict[str, Any]) -> dict[str, Any]:
        self.last_calls.clear()
        context = inputs.get("context", "")
        query   = inputs.get("input", "")

        for match in self._CALL_PATTERN.finditer(context):
            tool_name = match.group(1).lower()
            args      = self._parse_args(match.group(2))

            if tool_name not in self.tools:
                continue

            try:
                result = self.tools[tool_name].run(args)
            except Exception as exc:
                result = f"[error: {exc}]"

            self.last_calls.append(ToolCall(tool_name=tool_name, args=args, result=result))

        if self.last_calls:
            output = "; ".join(
                f"Called {c.tool_name}({c.args}): {c.result}" for c in self.last_calls
            )
        else:
            output = f"Processed: {query}"

        return {"output": output}

    @staticmethod
    def _parse_args(args_str: str) -> dict[str, str]:
        result = {}
        for part in args_str.split(","):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                result[k.strip()] = v.strip().strip("\"'")
        return result or {"input": args_str.strip()}


# ---------------------------------------------------------------------------
# Agent pipeline
# ---------------------------------------------------------------------------

class AgentPipeline:
    """Wraps an inner Pipeline (RAG) and a tool-using executor.

    Exposes the same ingest/query/reset interface as Pipeline so attack
    classes can use either interchangeably.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        executor: MockAgentExecutor | Any,
        tools: list,
    ) -> None:
        self.pipeline = pipeline
        self.executor = executor
        self.tools    = tools

    def ingest_text(self, text: str, metadata: dict | None = None) -> int:
        return self.pipeline.ingest_text(text, metadata)

    def query(
        self,
        question: str,
        system_prompt: str | None = None,
        injected_context: str | None = None,
    ) -> AgentTrace:
        store  = self.pipeline._get_store()
        chunks = store.as_retriever(
            search_kwargs={"k": self.pipeline.top_k}
        ).invoke(question)
        rag_context = "\n\n---\n\n".join(c.page_content for c in chunks)

        # injected_context arrives through the agent-to-agent channel —
        # it bypasses retrieval defenses because the receiving agent treats
        # output from a peer as implicitly trusted (the exploited assumption).
        if injected_context:
            context = (
                f"[Trusted context from upstream agent]\n{injected_context}"
                f"\n\n---\n\n[Retrieved context]\n{rag_context}"
            )
        else:
            context = rag_context

        result     = self.executor.invoke({"input": question, "context": context})
        tool_calls = list(getattr(self.executor, "last_calls", []))

        injected, source = self.pipeline._detect_injection(chunks)

        return AgentTrace(
            query=question,
            retrieved_chunks=chunks,
            full_prompt=context,
            response=result.get("output", ""),
            tool_calls=tool_calls,
            injected=injected,
            injection_source=source,
        )

    def reset(self) -> None:
        self.pipeline.reset()
        if hasattr(self.executor, "last_calls"):
            self.executor.last_calls.clear()


# ---------------------------------------------------------------------------
# AgentAttack base
# ---------------------------------------------------------------------------

class AgentAttack(ABC):
    """Base for attacks that target tool-using agents.

    Separate from Attack (which targets plain RAG pipelines) because the
    success criterion shifts from text markers to tool call parameters.
    """

    name: str      = ""
    reference: str = ""
    VARIANTS: list = []

    def __init__(self, pipeline: AgentPipeline) -> None:
        self.pipeline = pipeline

    @abstractmethod
    def setup(self) -> None:
        """Inject malicious documents into the pipeline."""

    @abstractmethod
    def run(self) -> AgentAttackResult:
        """Execute the attack and return a scored result."""

    @abstractmethod
    def _score(self, trace: AgentTrace) -> bool:
        """Return True if a tool call was successfully hijacked."""
