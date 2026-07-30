"""Mock primitives for zero-API-key testing and CLI demo mode."""

from __future__ import annotations

import hashlib
import random

from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage


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
