"""Framework Integration Adapters — v7.9.

Zero-friction wrappers for LangChain LCEL chains and LlamaIndex query engines,
plus HemGuard for scoped defense application around any pipeline.

Usage:
    from hemlock.framework_adapters import LangChainAdapter, LlamaIndexAdapter, HemGuard

    pipeline = LangChainAdapter.from_runnable(my_chain)
    attack = DirectInjection(pipeline)

    with HemGuard(inner_pipeline, ingest_defenses=[...]) as guard:
        trace = guard.query("What is our refund policy?")
        print(guard.defense_reports())
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from hemlock.external_pipeline import CallablePipeline
from hemlock.pipeline import RetrievalTrace


class LangChainAdapter:
    """Wrap LangChain runnables as Hemlock-compatible pipelines."""

    @staticmethod
    def from_runnable(runnable: Any, input_key: str = "question") -> CallablePipeline:
        def fn(query: str) -> str | RetrievalTrace:
            try:
                result = runnable.invoke({input_key: query})
            except (TypeError, ValueError):
                result = runnable.invoke(query)
            return LangChainAdapter._coerce_response(result)

        return CallablePipeline(fn)

    @staticmethod
    def from_invoke(invoke_fn: Callable[[str], Any]) -> CallablePipeline:
        def fn(query: str) -> str | RetrievalTrace:
            return LangChainAdapter._coerce_response(invoke_fn(query))

        return CallablePipeline(fn)

    @staticmethod
    def _coerce_response(result: Any) -> str | RetrievalTrace:
        if isinstance(result, RetrievalTrace):
            return result
        if hasattr(result, "content"):
            return str(result.content)
        if isinstance(result, dict):
            if "response" in result:
                return str(result["response"])
            if "answer" in result:
                return str(result["answer"])
        return str(result)


class LlamaIndexAdapter:
    """Wrap LlamaIndex query engines and retriever+synthesizer pairs."""

    @staticmethod
    def from_query_engine(query_engine: Any) -> CallablePipeline:
        def fn(query: str) -> str:
            response = query_engine.query(query)
            if hasattr(response, "response"):
                return str(response.response)
            return str(response)

        return CallablePipeline(fn)

    @staticmethod
    def from_retriever_and_synthesizer(
        retriever: Any,
        response_synthesizer: Any,
    ) -> CallablePipeline:
        def fn(query: str) -> str:
            nodes = retriever.retrieve(query)
            response = response_synthesizer.synthesize(query, nodes)
            return str(response)

        return CallablePipeline(fn)

    @staticmethod
    def from_retrieve_and_synthesize_fn(
        retrieve_fn: Callable[[str], Any],
        synthesize_fn: Callable[[str, Any], Any],
    ) -> CallablePipeline:
        def fn(query: str) -> str:
            nodes = retrieve_fn(query)
            response = synthesize_fn(query, nodes)
            return str(response)

        return CallablePipeline(fn)


class HemGuard:
    """Context manager that applies Hemlock defense layers around a pipeline."""

    def __init__(
        self,
        pipeline: Any,
        ingest_defenses: list | None = None,
        retrieval_defenses: list | None = None,
        output_defenses: list | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.ingest_defenses = ingest_defenses or []
        self.retrieval_defenses = retrieval_defenses or []
        self.output_defenses = output_defenses or []
        self._reports: list[Any] = []

    def ingest_text(self, text: str, metadata: dict | None = None) -> int:
        from langchain_core.documents import Document

        doc = Document(page_content=text, metadata=metadata or {})
        for defense in self.ingest_defenses:
            sanitized, report = defense.inspect(doc)
            self._reports.append(report)
            if sanitized is None:
                return 0
            doc = sanitized
        return self.pipeline.ingest_text(doc.page_content, doc.metadata)

    def query(self, question: str, system_prompt: str | None = None) -> RetrievalTrace:
        if system_prompt is not None:
            trace = self.pipeline.query(question, system_prompt)
        else:
            trace = self.pipeline.query(question)

        chunks = list(trace.retrieved_chunks)
        for defense in self.retrieval_defenses:
            chunks, reports = defense.filter(chunks)
            self._reports.extend(reports)

        response = trace.response
        for defense in self.output_defenses:
            report = defense.validate(response)
            self._reports.append(report)
            if report.triggered:
                response = "[BLOCKED BY HEMLOCK]"

        if response != trace.response or chunks != trace.retrieved_chunks:
            return RetrievalTrace(
                query=trace.query,
                retrieved_chunks=chunks,
                full_prompt=trace.full_prompt,
                response=response,
                injected=trace.injected,
                injection_source=trace.injection_source,
            )
        return trace

    def reset(self) -> None:
        self.pipeline.reset()
        self._reports.clear()

    def defense_reports(self) -> list[Any]:
        return list(self._reports)

    def blocked_count(self) -> int:
        return sum(1 for r in self._reports if getattr(r, "triggered", False))

    def __enter__(self) -> "HemGuard":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


@contextmanager
def hem_guard(
    pipeline: Any,
    ingest_defenses: list | None = None,
    retrieval_defenses: list | None = None,
    output_defenses: list | None = None,
) -> Iterator[HemGuard]:
    guard = HemGuard(
        pipeline,
        ingest_defenses=ingest_defenses,
        retrieval_defenses=retrieval_defenses,
        output_defenses=output_defenses,
    )
    yield guard
