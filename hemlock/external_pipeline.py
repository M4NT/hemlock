"""External Pipeline adapter — run attacks against an already-deployed RAG endpoint.

Use case:
    Your team has a production RAG at https://rag.internal/query.
    You want to test it with Hemlock without rebuilding it locally.

    ExternalPipeline wraps the endpoint and exposes the same interface as
    Pipeline, so all attack modules work transparently.

Endpoint contract:
    POST /query
    Request:  {"query": str, "hardening_level": str}
    Response: {"response": str, "retrieved_chunks": [...], "full_prompt": str}

    The response schema is flexible — missing fields are filled with defaults.
    If your endpoint returns only {"response": str}, that works too.

Ingest behavior:
    ExternalPipeline cannot control what documents are in the remote index.
    setup() and ingest_text() are no-ops by default. You can override
    ingest_endpoint to point at a POST /ingest route if your RAG exposes one.

    For attacks that require index control (direct_injection, context_override),
    use the attack's setup() only when ingest_endpoint is set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from langchain_core.documents import Document

from hemlock.pipeline import RetrievalTrace


@dataclass
class ExternalPipeline:
    """Thin adapter that routes Pipeline calls to an HTTP endpoint."""

    query_endpoint: str
    ingest_endpoint: str | None = None
    reset_endpoint: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 30

    # Mirrors Pipeline interface
    top_k: int = 4

    def query(self, query: str, hardening_level: str = "baseline") -> RetrievalTrace:
        payload = {"query": query, "hardening_level": hardening_level}
        data = self._post(self.query_endpoint, payload)

        chunks = [
            Document(page_content=c["content"], metadata=c.get("metadata", {}))
            for c in data.get("retrieved_chunks", [])
        ]

        return RetrievalTrace(
            query=query,
            retrieved_chunks=chunks,
            full_prompt=data.get("full_prompt", ""),
            response=data.get("response", ""),
            injected=data.get("injected", False),
            injection_source=data.get("injection_source"),
        )

    def ingest_text(self, text: str, metadata: dict[str, Any] | None = None) -> int:
        if not self.ingest_endpoint:
            return 0
        payload = {"text": text, "metadata": metadata or {}}
        data = self._post(self.ingest_endpoint, payload)
        return int(data.get("chunks_added", 0))

    def reset(self) -> None:
        if not self.reset_endpoint:
            return
        self._post(self.reset_endpoint, {})

    def _post(self, url: str, payload: dict) -> dict:
        import urllib.request
        import urllib.error

        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", **self.headers}

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(
                f"ExternalPipeline HTTP {e.code} from {url}: {body}"
            ) from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"ExternalPipeline connection error ({url}): {e.reason}"
            ) from e


class CallablePipeline:
    """Wraps a plain Python callable instead of an HTTP endpoint.

    Useful for testing against a local RAG without spinning up a server:

        def my_rag(query: str) -> str:
            return my_chain.invoke(query)

        pipeline = CallablePipeline(my_rag)
        attack = DirectInjection(pipeline)
    """

    def __init__(self, fn, top_k: int = 4) -> None:
        self._fn = fn
        self.top_k = top_k

    def query(self, query: str, hardening_level: str = "baseline") -> RetrievalTrace:
        response = self._fn(query)
        if isinstance(response, RetrievalTrace):
            return response
        return RetrievalTrace(
            query=query,
            retrieved_chunks=[],
            full_prompt="",
            response=str(response),
        )

    def ingest_text(self, text: str, metadata: dict | None = None) -> int:
        return 0

    def reset(self) -> None:
        pass
