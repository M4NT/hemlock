"""Tests for hemlock.framework_adapters (v7.9) — no real LangChain/LlamaIndex deps."""

from __future__ import annotations

import pytest
from langchain_core.documents import Document

from hemlock.framework_adapters import (
    HemGuard,
    LangChainAdapter,
    LlamaIndexAdapter,
    hem_guard,
)
from hemlock.pipeline import RetrievalTrace


class _MockRunnable:
    def __init__(self, response: str = "Paris is the capital of France.") -> None:
        self.response = response
        self.last_input = None

    def invoke(self, input_data):
        self.last_input = input_data
        return self.response


class _MockMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _MockQueryEngine:
    def __init__(self, text: str = "LlamaIndex answer") -> None:
        self._text = text

    def query(self, q: str):
        class R:
            response = self._text

        return R()


class _MockRetriever:
    def retrieve(self, q: str):
        return ["node1", "node2"]


class _MockSynthesizer:
    def synthesize(self, query, nodes):
        return f"synth:{query}:{len(nodes)}"


class _MockPipeline:
    def __init__(self) -> None:
        self.ingested = []
        self.reset_called = False

    def ingest_text(self, text: str, metadata=None) -> int:
        self.ingested.append((text, metadata))
        return 1

    def query(self, question: str, system_prompt: str | None = None) -> RetrievalTrace:
        return RetrievalTrace(
            query=question,
            retrieved_chunks=[Document(page_content="ctx")],
            full_prompt="prompt",
            response="safe response",
        )

    def reset(self) -> None:
        self.reset_called = True


class _BlockIngest:
    name = "BlockIngest"

    def inspect(self, doc):
        from defenses.base import DefenseReport

        if "MALICIOUS" in doc.page_content:
            return None, DefenseReport(defense_name=self.name, triggered=True, detail="blocked")
        return doc, DefenseReport(defense_name=self.name, triggered=False, detail="ok")


class _BlockOutput:
    name = "BlockOutput"

    def validate(self, response: str):
        from defenses.base import DefenseReport

        triggered = "SECRET" in response
        return DefenseReport(
            defense_name=self.name,
            triggered=triggered,
            detail="secret found" if triggered else "ok",
        )


class TestLangChainAdapter:
    def test_from_runnable_string_response(self):
        runnable = _MockRunnable("hello world")
        pipeline = LangChainAdapter.from_runnable(runnable)
        trace = pipeline.query("What is France?")
        assert trace.response == "hello world"

    def test_from_runnable_dict_input(self):
        runnable = _MockRunnable("dict path")
        pipeline = LangChainAdapter.from_runnable(runnable, input_key="question")
        pipeline.query("test")
        assert runnable.last_input == {"question": "test"}

    def test_from_runnable_message_content(self):
        class MsgRunnable:
            def invoke(self, q):
                return _MockMessage("from message")

        pipeline = LangChainAdapter.from_runnable(MsgRunnable())
        trace = pipeline.query("q")
        assert trace.response == "from message"

    def test_from_invoke(self):
        pipeline = LangChainAdapter.from_invoke(lambda q: {"response": f"echo:{q}"})
        trace = pipeline.query("ping")
        assert trace.response == "echo:ping"

    def test_returns_retrieval_trace_directly(self):
        rt = RetrievalTrace(
            query="q",
            retrieved_chunks=[],
            full_prompt="",
            response="direct",
        )
        pipeline = LangChainAdapter.from_invoke(lambda q: rt)
        result = pipeline.query("q")
        assert result.response == "direct"


class TestLlamaIndexAdapter:
    def test_from_query_engine(self):
        pipeline = LlamaIndexAdapter.from_query_engine(_MockQueryEngine("idx answer"))
        trace = pipeline.query("question")
        assert trace.response == "idx answer"

    def test_from_retriever_and_synthesizer(self):
        pipeline = LlamaIndexAdapter.from_retriever_and_synthesizer(
            _MockRetriever(),
            _MockSynthesizer(),
        )
        trace = pipeline.query("hello")
        assert trace.response == "synth:hello:2"

    def test_from_retrieve_and_synthesize_fn(self):
        pipeline = LlamaIndexAdapter.from_retrieve_and_synthesize_fn(
            lambda q: [q],
            lambda q, nodes: f"{q}-{nodes[0]}",
        )
        trace = pipeline.query("x")
        assert trace.response == "x-x"


class TestHemGuard:
    def test_ingest_blocked(self):
        inner = _MockPipeline()
        guard = HemGuard(inner, ingest_defenses=[_BlockIngest()])
        n = guard.ingest_text("MALICIOUS payload")
        assert n == 0
        assert len(inner.ingested) == 0
        assert guard.blocked_count() == 1

    def test_ingest_allowed(self):
        inner = _MockPipeline()
        guard = HemGuard(inner, ingest_defenses=[_BlockIngest()])
        n = guard.ingest_text("clean doc")
        assert n == 1
        assert len(inner.ingested) == 1

    def test_output_blocked(self):
        inner = _MockPipeline()
        guard = HemGuard(inner, output_defenses=[_BlockOutput()])

        class LeakyPipeline(_MockPipeline):
            def query(self, question, system_prompt=None):
                return RetrievalTrace(
                    query=question,
                    retrieved_chunks=[],
                    full_prompt="",
                    response="SECRET key leaked",
                )

        guard.pipeline = LeakyPipeline()
        trace = guard.query("q")
        assert trace.response == "[BLOCKED BY HEMLOCK]"
        assert guard.blocked_count() == 1

    def test_context_manager(self):
        inner = _MockPipeline()
        with hem_guard(inner) as guard:
            trace = guard.query("q")
            assert trace.response == "safe response"
        assert guard.defense_reports() == []

    def test_reset_clears_reports(self):
        inner = _MockPipeline()
        guard = HemGuard(inner, ingest_defenses=[_BlockIngest()])
        guard.ingest_text("MALICIOUS")
        guard.reset()
        assert guard.defense_reports() == []
        assert inner.reset_called
