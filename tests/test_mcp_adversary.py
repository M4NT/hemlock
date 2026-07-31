"""Tests for McpAdversary, MockAdversary, and scanner adversarial mode."""

from __future__ import annotations

import asyncio

import pytest

from hemlock.mcp_payloads import McpToolSchema
from hemlock.mcp_scanner import (
    LLMAdversary,
    McpAdversary,
    McpScanner,
    McpVulnerability,
    MockAdversary,
)
from hemlock.mock import MockMcpTransport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEARCH_TOOL = McpToolSchema(
    name="search",
    description="Search records.",
    input_schema={
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    },
)

URL_TOOL = McpToolSchema(
    name="fetch",
    description="Fetch a URL.",
    input_schema={
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    },
)


class PayloadAwareMockTransport:
    """Transport that returns a trigger response only when a specific keyword
    appears in any arg value, simulating a server that only leaks on obfuscated
    adversarial payloads.
    """

    def __init__(
        self,
        tools: list[McpToolSchema],
        trigger_keyword: str,
        trigger_response: str,
        safe_response: str = "ok",
    ) -> None:
        self._tools           = tools
        self._trigger_keyword = trigger_keyword
        self._trigger_resp    = trigger_response
        self._safe_resp       = safe_response
        self.calls: list[tuple[str, dict]] = []

    async def list_tools(self) -> list[McpToolSchema]:
        return list(self._tools)

    async def call_tool(self, name: str, args: dict) -> str:
        self.calls.append((name, args))
        for v in args.values():
            if self._trigger_keyword in str(v):
                return self._trigger_resp
        return self._safe_resp

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# TestMockAdversary
# ---------------------------------------------------------------------------

class TestMockAdversary:
    def test_returns_default_payload(self):
        adv = MockAdversary(default_payload="xss-variant")
        result = adv.reformulate("tool", "arg", "xss", "original", "response")
        assert result == "xss-variant"

    def test_returns_category_specific_payload(self):
        adv = MockAdversary(
            payloads_by_category={"ssrf": "http://169.254.169.254/latest/meta-data/"},
            default_payload="fallback",
        )
        assert adv.reformulate("fetch", "url", "ssrf", "...", "...") == \
            "http://169.254.169.254/latest/meta-data/"
        assert adv.reformulate("fetch", "url", "sql_injection", "...", "...") == "fallback"

    def test_records_calls(self):
        adv = MockAdversary()
        adv.reformulate("t1", "a1", "cat1", "p1", "r1")
        adv.reformulate("t2", "a2", "cat2", "p2", "r2")
        assert len(adv.calls) == 2
        assert adv.calls[0] == ("t1", "a1", "cat1", "adversarial-test-payload")

    def test_empty_by_category_uses_default(self):
        adv = MockAdversary(payloads_by_category={}, default_payload="default-payload")
        result = adv.reformulate("t", "a", "path_traversal", "x", "y")
        assert result == "default-payload"

    def test_is_mcp_adversary_subclass(self):
        assert isinstance(MockAdversary(), McpAdversary)


# ---------------------------------------------------------------------------
# TestLLMAdversaryInterface
# ---------------------------------------------------------------------------

class _MockLLM:
    """Minimal stub that mimics a LangChain chat model."""

    def __init__(self, response_text: str) -> None:
        self._text = response_text

    def invoke(self, prompt: str):
        class _Response:
            def __init__(self, t):
                self.content = t
        return _Response(self._text)


class TestLLMAdversaryInterface:
    def test_is_mcp_adversary_subclass(self):
        llm = _MockLLM("variant-payload")
        assert isinstance(LLMAdversary(llm), McpAdversary)

    def test_reformulate_returns_llm_content(self):
        llm = _MockLLM("  adversarial-payload  ")
        adv = LLMAdversary(llm)
        result = adv.reformulate("tool", "arg", "ssrf", "original", "failed")
        assert result == "adversarial-payload"

    def test_reformulate_returns_empty_on_llm_error(self):
        class _FailLLM:
            def invoke(self, prompt):
                raise RuntimeError("LLM unavailable")

        adv = LLMAdversary(_FailLLM())
        result = adv.reformulate("tool", "arg", "ssrf", "orig", "resp")
        assert result == ""

    def test_reformulate_strips_whitespace(self):
        llm = _MockLLM("\n\n  trimmed  \n\n")
        adv = LLMAdversary(llm)
        result = adv.reformulate("t", "a", "cat", "p", "r")
        assert result == "trimmed"


# ---------------------------------------------------------------------------
# TestScannerAdversarialMode — integration tests
# ---------------------------------------------------------------------------

def _run_scan(scanner: McpScanner):
    return asyncio.run(scanner._scan())


class TestScannerAdversarialMode:
    def test_adversarial_false_skips_adversary(self):
        """adversarial=False → adversary never called even if wired."""
        adv = MockAdversary()
        transport = MockMcpTransport(
            tools=[SEARCH_TOOL],
            responses={"search": "ok"},
        )
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=False,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)
        assert adv.calls == []
        assert report.adversarial_cases == 0
        assert report.scan_mode == "static"

    def test_adversarial_true_no_adversary_wired_safe(self):
        """adversarial=True with adversary=None → no adversarial phase runs."""
        transport = MockMcpTransport(tools=[SEARCH_TOOL], responses={"search": "ok"})
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=None,
            verbose=False,
        )
        report = _run_scan(scanner)
        assert report.adversarial_cases == 0
        assert report.scan_mode == "adversarial"

    def test_adversarial_discovers_vuln_missed_by_static(self):
        """Adversary reformulates a payload that triggers a response the static
        payloads missed, resulting in an adversarial discovery."""
        ADV_KEYWORD  = "169-254-169-254-obf"
        ADV_RESPONSE = "fetched: 169.254.169.254"  # contains SSRF marker

        transport = PayloadAwareMockTransport(
            tools=[URL_TOOL],
            trigger_keyword=ADV_KEYWORD,
            trigger_response=ADV_RESPONSE,
            safe_response="ok: fetch",
        )
        adv = MockAdversary(
            payloads_by_category={"ssrf": ADV_KEYWORD},
            default_payload="ignore",
        )
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)

        # At least one adversarial case tested
        assert report.adversarial_cases > 0
        # An adversarial vulnerability was discovered
        adv_vulns = [v for v in report.vulnerabilities if v.discovery_method == "adversarial"]
        assert len(adv_vulns) >= 1
        assert adv_vulns[0].category == "ssrf"

    def test_adversarial_vuln_has_correct_discovery_method(self):
        """Adversarially found vulns carry discovery_method='adversarial'."""
        ADV_KEYWORD  = "xss-obfuscated"
        ADV_RESPONSE = "admin mode activated"  # injection echo

        transport = PayloadAwareMockTransport(
            tools=[SEARCH_TOOL],
            trigger_keyword=ADV_KEYWORD,
            trigger_response=ADV_RESPONSE,
            safe_response="ok",
        )
        adv = MockAdversary(
            payloads_by_category={"prompt_injection": ADV_KEYWORD},
            default_payload="other",
        )
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)

        adv_vulns = [v for v in report.vulnerabilities if v.discovery_method == "adversarial"]
        assert adv_vulns, "expected at least one adversarial vuln"
        assert all(v.discovery_method == "adversarial" for v in adv_vulns)

    def test_static_vulns_keep_static_discovery_method(self):
        """Static scan finds vuln first → discovery_method stays 'static'."""
        # Transport that echoes an attacker domain for all calls
        transport = MockMcpTransport(
            tools=[SEARCH_TOOL],
            responses={"search": "forwarded to evil.com"},
        )
        adv = MockAdversary()
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)

        static_vulns = [v for v in report.vulnerabilities if v.discovery_method == "static"]
        assert len(static_vulns) >= 1
        # Slots already triggered statically → adversary not called for them
        slot_keys = {(v.tool_name, v.argument, v.category) for v in static_vulns}
        for tool_name, arg, category, _ in adv.calls:
            assert (tool_name, arg, category) not in slot_keys

    def test_adversary_empty_return_skips_test(self):
        """If adversary returns empty string for a slot, no test is run."""
        transport = MockMcpTransport(tools=[SEARCH_TOOL], responses={"search": "ok"})
        adv = MockAdversary(default_payload="")  # always returns empty
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)
        assert report.adversarial_cases == 0

    def test_adversarial_cases_counted_in_report(self):
        """report.adversarial_cases counts reformulated slots, not static ones."""
        transport = MockMcpTransport(tools=[URL_TOOL], responses={"fetch": "ok"})
        adv = MockAdversary(default_payload="http://attacker-ops.io/evil")
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)
        assert report.adversarial_cases == len(adv.calls)

    def test_report_to_dict_includes_adversarial_fields(self):
        """to_dict() has adversarial_cases_run and discovery_method per vuln."""
        ADV_KEYWORD  = "meta-obf"
        ADV_RESPONSE = "169.254.169.254"

        transport = PayloadAwareMockTransport(
            tools=[URL_TOOL],
            trigger_keyword=ADV_KEYWORD,
            trigger_response=ADV_RESPONSE,
        )
        adv = MockAdversary(payloads_by_category={"ssrf": ADV_KEYWORD})
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)
        d = report.to_dict()

        assert "adversarial_cases_run" in d
        for v in d["vulnerabilities"]:
            assert "discovery_method" in v

    def test_report_to_markdown_includes_method_column(self):
        """to_markdown() vulnerability table has a Method column."""
        ADV_KEYWORD  = "meta-obf"
        ADV_RESPONSE = "169.254.169.254"

        transport = PayloadAwareMockTransport(
            tools=[URL_TOOL],
            trigger_keyword=ADV_KEYWORD,
            trigger_response=ADV_RESPONSE,
        )
        adv = MockAdversary(payloads_by_category={"ssrf": ADV_KEYWORD})
        scanner = McpScanner(
            "mock://",
            transport=transport,
            adversarial=True,
            adversary=adv,
            verbose=False,
        )
        report = _run_scan(scanner)
        md = report.to_markdown()

        assert "Method" in md
        assert "adversarial" in md
