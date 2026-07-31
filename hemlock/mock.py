"""Mock primitives for zero-API-key testing and CLI demo mode."""

from __future__ import annotations

import hashlib
import random
from typing import TYPE_CHECKING

from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage

if TYPE_CHECKING:
    from hemlock.mcp_payloads import McpToolSchema


class MockEmbeddings(Embeddings):
    """Deterministic 384-dim embeddings — no PyTorch, no model download.

    Uses a seeded PRNG (sha256 of text) to produce a unit vector per text.
    Retrieval order is pseudo-random but stable across runs, which is fine
    for tests that only need "document exists in store" semantics.
    """

    DIM = 384

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)

    @classmethod
    def _embed(cls, text: str) -> list[float]:
        seed = int(hashlib.sha256(text.encode()).hexdigest()[:16], 16)
        rng = random.Random(seed)
        vec = [rng.gauss(0, 1) for _ in range(cls.DIM)]
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        return [x / norm for x in vec]


class MockLLM:
    """Minimal LLM stub that returns a configurable response.

    Supports the pipe operator (llm | parser) used by LangChain chains.
    """

    def __init__(self, response: str = "This is a safe answer.") -> None:
        self.response = response

    def invoke(self, *args, **kwargs) -> AIMessage:
        return AIMessage(content=self.response)

    def __or__(self, other):
        class _Piped:
            def __init__(self, llm, next_):
                self._llm  = llm
                self._next = next_

            def invoke(self, *args, **kwargs):
                result = self._llm.invoke(*args, **kwargs)
                return self._next.invoke(result)

        return _Piped(self, other)


class MockJudgeLLM:
    """Deterministic LLM stub for HemJudge tests.

    Returns a fixed JSON verdict without any LLM call.
    """

    def __init__(self, verdict: bool, confidence: float = 0.9, reasoning: str = "mock verdict") -> None:
        self._verdict    = verdict
        self._confidence = confidence
        self._reasoning  = reasoning

    def invoke(self, messages, **kwargs) -> AIMessage:
        content = (
            f'{{"succeeded": {"true" if self._verdict else "false"}, '
            f'"confidence": {self._confidence}, '
            f'"reasoning": "{self._reasoning}"}}'
        )
        return AIMessage(content=content)


class MockMcpTransport:
    """In-memory MCP transport for tests — no subprocess, no network.

    Args:
        tools:     List of McpToolSchema to expose via list_tools().
        responses: Dict mapping tool_name → response string. Tools not in the
                   dict return "ok: <tool_name>".
    """

    def __init__(
        self,
        tools: list[McpToolSchema],
        responses: dict[str, str] | None = None,
    ) -> None:
        self._tools     = tools
        self._responses = responses or {}
        self.calls: list[tuple[str, dict]] = []

    async def list_tools(self) -> list[McpToolSchema]:
        return list(self._tools)

    async def call_tool(self, name: str, args: dict) -> str:
        self.calls.append((name, args))
        return self._responses.get(name, f"ok: {name}")

    async def close(self) -> None:
        pass


class MockRepairerLLM:
    """Deterministic LLM stub for HemRepairer tests.

    Returns a fixed repair proposal without real LLM calls.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []  # (channel, hint) pairs

    def propose_repair(self, channel: str, hint: str) -> dict:
        """Return a deterministic repair proposal for a channel+hint."""
        self.calls.append((channel, hint))
        return {
            "description": f"Fix {channel}: {hint[:40]}",
            "patch": f"--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-# vulnerable\n+# fixed: {channel}",
            "confidence": 0.85,
        }
