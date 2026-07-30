"""Tests for ExternalPipeline and CallablePipeline adapters."""

import json
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from hemlock.external_pipeline import ExternalPipeline, CallablePipeline
from hemlock.pipeline import RetrievalTrace


def _mock_urlopen(response_data: dict):
    """Context manager mock for urllib.request.urlopen."""
    import io
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestExternalPipeline:
    def test_query_returns_retrieval_trace(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        response = {
            "response": "Paris is the capital.",
            "full_prompt": "prompt here",
            "retrieved_chunks": [{"content": "France info", "metadata": {}}],
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            trace = pipeline.query("What is the capital of France?")

        assert isinstance(trace, RetrievalTrace)
        assert trace.response == "Paris is the capital."
        assert trace.full_prompt == "prompt here"
        assert len(trace.retrieved_chunks) == 1
        assert trace.retrieved_chunks[0].page_content == "France info"

    def test_query_handles_minimal_response(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        response = {"response": "simple answer"}
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            trace = pipeline.query("test query")

        assert trace.response == "simple answer"
        assert trace.retrieved_chunks == []
        assert trace.full_prompt == ""

    def test_query_preserves_injected_flag(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        response = {
            "response": "injected",
            "injected": True,
            "injection_source": "malicious/doc.md",
            "retrieved_chunks": [],
            "full_prompt": "",
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            trace = pipeline.query("q")

        assert trace.injected is True
        assert trace.injection_source == "malicious/doc.md"

    def test_ingest_text_noop_without_endpoint(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        result = pipeline.ingest_text("text", {"source": "test"})
        assert result == 0

    def test_ingest_text_calls_endpoint_when_set(self):
        pipeline = ExternalPipeline(
            query_endpoint="http://test/query",
            ingest_endpoint="http://test/ingest",
        )
        response = {"chunks_added": 3}
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(response)):
            result = pipeline.ingest_text("some text")

        assert result == 3

    def test_reset_noop_without_endpoint(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        pipeline.reset()  # should not raise

    def test_reset_calls_endpoint_when_set(self):
        pipeline = ExternalPipeline(
            query_endpoint="http://test/query",
            reset_endpoint="http://test/reset",
        )
        with patch("urllib.request.urlopen", return_value=_mock_urlopen({})):
            pipeline.reset()  # should not raise

    def test_http_error_raises_runtime_error(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        err = HTTPError("http://test/query", 500, "Internal Error", {}, None)
        err.read = lambda: b"server error"
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError, match="HTTP 500"):
                pipeline.query("q")

    def test_url_error_raises_runtime_error(self):
        pipeline = ExternalPipeline(query_endpoint="http://test/query")
        with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
            with pytest.raises(RuntimeError, match="connection error"):
                pipeline.query("q")

    def test_custom_headers_are_sent(self):
        pipeline = ExternalPipeline(
            query_endpoint="http://test/query",
            headers={"Authorization": "Bearer token123"},
        )
        captured_headers = []

        def capture_request(req, timeout=None):
            captured_headers.append(dict(req.headers))
            return _mock_urlopen({"response": "ok"})

        with patch("urllib.request.urlopen", side_effect=capture_request):
            pipeline.query("q")

        assert any("Authorization" in h for h in captured_headers)


class TestCallablePipeline:
    def test_wraps_plain_callable(self):
        def my_rag(query: str) -> str:
            return f"answer to: {query}"

        pipeline = CallablePipeline(my_rag)
        trace = pipeline.query("test question")

        assert isinstance(trace, RetrievalTrace)
        assert "answer to: test question" in trace.response

    def test_passthrough_when_callable_returns_trace(self):
        expected_trace = RetrievalTrace(
            query="q",
            retrieved_chunks=[],
            full_prompt="prompt",
            response="direct",
        )

        pipeline = CallablePipeline(lambda q: expected_trace)
        trace = pipeline.query("q")
        assert trace is expected_trace

    def test_ingest_is_noop(self):
        pipeline = CallablePipeline(lambda q: "answer")
        assert pipeline.ingest_text("text") == 0

    def test_reset_is_noop(self):
        pipeline = CallablePipeline(lambda q: "answer")
        pipeline.reset()  # should not raise

    def test_query_includes_original_query_in_trace(self):
        pipeline = CallablePipeline(lambda q: "ok")
        trace = pipeline.query("my question")
        assert trace.query == "my question"
