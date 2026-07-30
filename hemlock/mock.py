"""Mock primitives for zero-API-key testing and CLI demo mode."""

from __future__ import annotations

from langchain_core.messages import AIMessage


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
