"""MCP Server Fuzzer — transport-agnostic security scanner for MCP servers.

Usage:
    from hemlock.mcp_scanner import McpScanner
    report = McpScanner("npx -y @modelcontextprotocol/server-everything").scan()
    print(report.to_markdown())

Transport is auto-detected from the target string:
  - Starts with http:// or https:// → HttpSseMcpTransport
  - Otherwise → StdioMcpTransport (target treated as a shell command)
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from hemlock.mcp_payloads import (
    McpTestCase,
    McpToolSchema,
    detect_success,
    generate_test_cases,
)


# ---------------------------------------------------------------------------
# Adversary interface
# ---------------------------------------------------------------------------

_ADVERSARIAL_MCP_PROMPT = """\
You are a security researcher testing an MCP (Model Context Protocol) server for injection \
vulnerabilities. A previous payload for a specific tool argument did NOT trigger a \
vulnerability response.

Tool: {tool_name}
Argument: {arg_name}
Category: {category}

Previous payload (did not trigger):
{original_payload}

Server response to previous payload:
{failed_response}

Generate ONE new payload targeting the same vulnerability category using a different \
approach: different encoding, framing, obfuscation, or syntax variation. Avoid the exact \
same characters or patterns as the previous payload.

Rules:
1. Stay within the {category} category — do not change the attack goal.
2. Use a different technique than the previous payload.
3. Keep the payload under 120 characters if possible.
4. Output ONLY the payload text. No explanation, no quotes.

NEW PAYLOAD:"""


class McpAdversary(ABC):
    """Interface for LLM-based adversarial payload reformulation.

    Implementors receive a failed static payload and produce a semantic variant
    that may bypass server-side defenses undetected by static patterns.
    """

    @abstractmethod
    def reformulate(
        self,
        tool_name: str,
        arg_name: str,
        category: str,
        original_payload: str,
        failed_response: str,
    ) -> str:
        """Return a new payload targeting the same category.

        An empty string or None signals that no further variant can be produced.
        """


class LLMAdversary(McpAdversary):
    """Adversary backed by any LangChain-compatible LLM.

    Usage::

        from langchain_openai import ChatOpenAI
        adversary = LLMAdversary(ChatOpenAI(model="gpt-4o-mini"))
        scanner   = McpScanner(target, adversary=adversary)
    """

    def __init__(self, llm: Any) -> None:
        self._llm = llm

    def reformulate(
        self,
        tool_name: str,
        arg_name: str,
        category: str,
        original_payload: str,
        failed_response: str,
    ) -> str:
        prompt = _ADVERSARIAL_MCP_PROMPT.format(
            tool_name=tool_name,
            arg_name=arg_name,
            category=category,
            original_payload=original_payload,
            failed_response=failed_response[:200],
        )
        try:
            response = self._llm.invoke(prompt)
            text = response.content if hasattr(response, "content") else str(response)
            return text.strip()
        except Exception:
            return ""


class MockAdversary(McpAdversary):
    """Deterministic adversary for tests — returns a fixed payload per category.

    If ``payloads_by_category`` is provided, the mock returns the matching
    entry; otherwise it falls back to ``default_payload``.

    Each (tool_name, arg_name, category) slot is served from a cycle so tests
    can verify multi-round behaviour.
    """

    def __init__(
        self,
        payloads_by_category: dict[str, str] | None = None,
        default_payload: str = "adversarial-test-payload",
    ) -> None:
        self._by_category = payloads_by_category or {}
        self._default     = default_payload
        self.calls: list[tuple[str, str, str, str]] = []  # (tool, arg, category, returned)

    def reformulate(
        self,
        tool_name: str,
        arg_name: str,
        category: str,
        original_payload: str,
        failed_response: str,
    ) -> str:
        result = self._by_category.get(category, self._default)
        self.calls.append((tool_name, arg_name, category, result))
        return result


# ---------------------------------------------------------------------------
# Vulnerability + chained call events
# ---------------------------------------------------------------------------

@dataclass
class ChainedCallEvent:
    """A secondary tool invocation detected in a tool's response."""
    triggered_by_tool: str
    triggered_by_payload: str
    chained_tool: str
    evidence: str
    confidence: str  # "high" | "medium"


@dataclass
class InterceptedCall:
    """Record of one tool call and any chained calls detected in its response."""
    tool_name: str
    args: dict
    response: str
    chained_events: list[ChainedCallEvent] = field(default_factory=list)


@dataclass
class McpVulnerability:
    tool_name: str
    argument: str
    category: str
    payload: str
    severity: str  # "high" | "medium" | "low"
    indicator: str
    response: str
    discovery_method: str = "static"  # "static" | "adversarial"


@dataclass
class McpScanReport:
    target: str
    transport: str
    tools: list[McpToolSchema]
    vulnerabilities: list[McpVulnerability]
    scan_mode: str = "static"
    total_cases: int = 0
    adversarial_cases: int = 0

    # ------------------------------------------------------------------

    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    def chained_call_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.category == "chained_tool_call")

    def tools_affected(self) -> set[str]:
        return {v.tool_name for v in self.vulnerabilities}

    def to_dict(self) -> dict[str, Any]:
        chained = [v for v in self.vulnerabilities if v.category == "chained_tool_call"]
        direct  = [v for v in self.vulnerabilities if v.category != "chained_tool_call"]
        return {
            "target":                  self.target,
            "transport":               self.transport,
            "scan_mode":               self.scan_mode,
            "tools_found":             len(self.tools),
            "test_cases_run":          self.total_cases,
            "adversarial_cases_run":   self.adversarial_cases,
            "vulnerabilities_found":   self.vuln_count(),
            "chained_calls_detected":  len(chained),
            "tools_affected":          sorted(self.tools_affected()),
            "tools": [
                {"name": t.name, "description": t.description}
                for t in self.tools
            ],
            "vulnerabilities": [
                {
                    "tool":             v.tool_name,
                    "argument":         v.argument,
                    "category":         v.category,
                    "severity":         v.severity,
                    "indicator":        v.indicator,
                    "payload":          v.payload[:80],
                    "response":         v.response[:120],
                    "discovery_method": v.discovery_method,
                }
                for v in self.vulnerabilities
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        chained = [v for v in self.vulnerabilities if v.category == "chained_tool_call"]
        direct  = [v for v in self.vulnerabilities if v.category != "chained_tool_call"]

        adv_line = (
            f"**Adversarial cases run**: {self.adversarial_cases}  \n"
            if self.adversarial_cases > 0
            else ""
        )
        lines = [
            f"# Hemlock MCP Scan Report",
            f"",
            f"**Target**: `{self.target}`  ",
            f"**Transport**: {self.transport}  ",
            f"**Mode**: {self.scan_mode}  ",
            f"**Tools discovered**: {len(self.tools)}  ",
            f"**Test cases run**: {self.total_cases}  ",
            adv_line + f"**Vulnerabilities found**: {len(direct)}  ",
            f"**Chained calls detected**: {len(chained)}",
            f"",
        ]

        if not self.tools:
            lines.append("_No tools discovered._")
            return "\n".join(lines)

        lines += ["## Tools", ""]
        for t in self.tools:
            lines.append(f"- **{t.name}** — {t.description}")
        lines.append("")

        if direct:
            lines += ["## Vulnerabilities", ""]
            lines += [
                "| Tool | Argument | Category | Severity | Method | Indicator |",
                "|------|----------|----------|----------|--------|-----------|",
            ]
            for v in direct:
                lines.append(
                    f"| {v.tool_name} | {v.argument} | {v.category} | "
                    f"{v.severity} | {v.discovery_method} | {v.indicator[:60]} |"
                )
            lines.append("")

        if chained:
            lines += ["## Chained Call Detections", ""]
            lines += [
                "| Triggered By | Chained Tool | Confidence | Evidence |",
                "|-------------|-------------|------------|---------|",
            ]
            for v in chained:
                lines.append(
                    f"| {v.tool_name} | {v.response[:30]} | {v.severity} | {v.indicator[:60]} |"
                )
            lines.append("")

        if not self.vulnerabilities:
            lines.append("## Result\n\n_No vulnerabilities detected._")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chained call detector
# ---------------------------------------------------------------------------

# JSON keys that, if present and matching a known tool, indicate a chained call
_CHAIN_JSON_KEYS = ("tool_name", "function", "name", "tool", "function_name", "action")

# Verb patterns indicating an explicit tool invocation in text
_CALL_VERBS = r"(?:calling|called|executing|executed|invoking|invoked|running|ran|dispatching|dispatched)"


def _find_json_objects(text: str) -> list[dict]:
    """Extract all valid top-level JSON objects from a string (including nested)."""
    objects = []
    for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", text):
        try:
            objects.append(json.loads(match.group()))
        except json.JSONDecodeError:
            pass
    return objects


def _detect_chained_calls(
    response: str,
    known_tools: set[str],
    triggered_by_tool: str,
    triggered_by_payload: str,
) -> list[ChainedCallEvent]:
    """Detect secondary tool invocations embedded in a tool response.

    Three detection strategies:
    1. High confidence — JSON object with a tool-name key matching a known tool.
    2. Medium confidence — verb + tool name in text (called send_email ...).
    3. Medium confidence — call syntax: send_email(...) in text.

    Results are deduplicated by (triggered_by_tool, chained_tool).
    """
    seen: set[tuple[str, str]] = set()
    events: list[ChainedCallEvent] = []

    def _record(chained_tool: str, evidence: str, confidence: str) -> None:
        key = (triggered_by_tool, chained_tool)
        if key in seen:
            return
        seen.add(key)
        events.append(ChainedCallEvent(
            triggered_by_tool=triggered_by_tool,
            triggered_by_payload=triggered_by_payload[:80],
            chained_tool=chained_tool,
            evidence=evidence[:120],
            confidence=confidence,
        ))

    # 1 — JSON pattern (high confidence)
    for obj in _find_json_objects(response):
        for key in _CHAIN_JSON_KEYS:
            value = obj.get(key)
            if isinstance(value, str) and value in known_tools and value != triggered_by_tool:
                _record(value, json.dumps(obj)[:120], "high")

    # 2 — Verb + tool name (medium confidence)
    for tool in known_tools:
        if tool == triggered_by_tool:
            continue
        pattern = rf"{_CALL_VERBS}\s+['\"`]?{re.escape(tool)}['\"`]?"
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            _record(tool, m.group(), "medium")

    # 3 — Call syntax: tool_name(...) (medium confidence)
    for tool in known_tools:
        if tool == triggered_by_tool:
            continue
        pattern = rf"\b{re.escape(tool)}\s*\([^)]*\)"
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            _record(tool, m.group(), "medium")

    return events


# ---------------------------------------------------------------------------
# Transport abstraction
# ---------------------------------------------------------------------------

class McpTransport(ABC):
    """Protocol-agnostic interface over an MCP server connection."""

    @abstractmethod
    async def list_tools(self) -> list[McpToolSchema]: ...

    @abstractmethod
    async def call_tool(self, name: str, args: dict) -> str: ...

    @abstractmethod
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Intercepting transport (chained call detection layer)
# ---------------------------------------------------------------------------

class McpInterceptingTransport(McpTransport):
    """Wraps any McpTransport and inspects every response for chained calls.

    Always active — the scanner wraps the real/mock transport in this layer
    automatically. Tests can also instantiate it directly.
    """

    def __init__(self, inner: McpTransport) -> None:
        self._inner       = inner
        self._known_tools: set[str] = set()
        self.intercepted: list[InterceptedCall] = []

    async def list_tools(self) -> list[McpToolSchema]:
        tools = await self._inner.list_tools()
        self._known_tools = {t.name for t in tools}
        return tools

    async def call_tool(self, name: str, args: dict) -> str:
        response = await self._inner.call_tool(name, args)

        # Extract the payload (first non-empty string argument value)
        payload = next((v for v in args.values() if isinstance(v, str) and v), "")

        chained = _detect_chained_calls(response, self._known_tools, name, payload)
        self.intercepted.append(InterceptedCall(
            tool_name=name,
            args=args,
            response=response,
            chained_events=chained,
        ))
        return response

    async def close(self) -> None:
        await self._inner.close()

    def all_chained_events(self) -> list[ChainedCallEvent]:
        return [e for call in self.intercepted for e in call.chained_events]


# ---------------------------------------------------------------------------
# Real transports (require `mcp` package)
# ---------------------------------------------------------------------------

class StdioMcpTransport(McpTransport):
    """Spawns an MCP server subprocess and communicates via stdio."""

    def __init__(self, command: str):
        parts = shlex.split(command)
        self._cmd  = parts[0]
        self._args = parts[1:]
        self._session = None
        self._cm      = None

    async def _connect(self):
        if self._session is not None:
            return
        try:
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client
        except ImportError as exc:
            raise ImportError(
                "The 'mcp' package is required for stdio transport.\n"
                "Install: pip install 'hemlock-rag[mcp]'"
            ) from exc

        params = StdioServerParameters(command=self._cmd, args=self._args)
        self._cm = stdio_client(params)
        read, write = await self._cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()

    async def list_tools(self) -> list[McpToolSchema]:
        await self._connect()
        result = await self._session.list_tools()
        return [
            McpToolSchema(
                name=t.name,
                description=t.description or "",
                input_schema=t.inputSchema or {},
            )
            for t in result.tools
        ]

    async def call_tool(self, name: str, args: dict) -> str:
        await self._connect()
        result = await self._session.call_tool(name, args)
        parts = []
        for item in (result.content or []):
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n".join(parts)

    async def close(self) -> None:
        if self._session is not None:
            await self._session_cm.__aexit__(None, None, None)
            await self._cm.__aexit__(None, None, None)
            self._session = None


class HttpSseMcpTransport(McpTransport):
    """Connects to a remote MCP server over HTTP/SSE."""

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self._url     = url
        self._headers = headers or {}
        self._session = None
        self._cm      = None

    async def _connect(self):
        if self._session is not None:
            return
        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError as exc:
            raise ImportError(
                "The 'mcp' package is required for HTTP/SSE transport.\n"
                "Install: pip install 'hemlock-rag[mcp]'"
            ) from exc

        self._cm = sse_client(self._url, headers=self._headers or None)
        read, write = await self._cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()

    async def list_tools(self) -> list[McpToolSchema]:
        await self._connect()
        result = await self._session.list_tools()
        return [
            McpToolSchema(
                name=t.name,
                description=t.description or "",
                input_schema=t.inputSchema or {},
            )
            for t in result.tools
        ]

    async def call_tool(self, name: str, args: dict) -> str:
        await self._connect()
        result = await self._session.call_tool(name, args)
        parts = []
        for item in (result.content or []):
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n".join(parts)

    async def close(self) -> None:
        if self._session is not None:
            await self._session_cm.__aexit__(None, None, None)
            await self._cm.__aexit__(None, None, None)
            self._session = None


class StreamableHttpMcpTransport(McpTransport):
    """Connects to a remote MCP server over Streamable HTTP (MCP spec /mcp endpoints)."""

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self._url = url
        self._headers = headers or {}
        self._session = None
        self._cm = None
        self._http_client = None

    async def _connect(self):
        if self._session is not None:
            return
        try:
            import httpx
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except ImportError as exc:
            raise ImportError(
                "The 'mcp' package is required for HTTP transport.\n"
                "Install: pip install 'hemlock-rag[mcp]'"
            ) from exc

        self._http_client = httpx.AsyncClient(headers=self._headers, timeout=30.0)
        self._cm = streamable_http_client(self._url, http_client=self._http_client)
        read, write, _ = await self._cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()

    async def list_tools(self) -> list[McpToolSchema]:
        await self._connect()
        result = await self._session.list_tools()
        return [
            McpToolSchema(
                name=t.name,
                description=t.description or "",
                input_schema=t.inputSchema or {},
            )
            for t in result.tools
        ]

    async def call_tool(self, name: str, args: dict) -> str:
        await self._connect()
        result = await self._session.call_tool(name, args)
        parts = []
        for item in (result.content or []):
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n".join(parts)

    async def close(self) -> None:
        if self._session is not None:
            await self._session_cm.__aexit__(None, None, None)
            await self._cm.__aexit__(None, None, None)
            self._session = None
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


# ---------------------------------------------------------------------------
# Transport factory
# ---------------------------------------------------------------------------

def _make_transport(
    target: str,
    headers: dict[str, str] | None = None,
) -> tuple[McpTransport, str]:
    """Return (transport, transport_name) for a given target string."""
    if target.startswith(("http://", "https://")):
        path = target.split("?", 1)[0].lower()
        if path.endswith("/sse") or "/sse/" in path:
            return HttpSseMcpTransport(target, headers=headers), "http_sse"
        return StreamableHttpMcpTransport(target, headers=headers), "streamable_http"
    return StdioMcpTransport(target), "stdio"


# ---------------------------------------------------------------------------
# Severity heuristic
# ---------------------------------------------------------------------------

_HIGH_CATEGORIES = {"path_traversal", "ssrf", "chained_tool_call"}


def _severity(category: str) -> str:
    if category in _HIGH_CATEGORIES:
        return "high"
    if category == "prompt_injection":
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class McpScanner:
    """Security fuzzer for MCP servers.

    Args:
        target:      MCP server target — a shell command (stdio) or URL (HTTP/SSE).
        transport:   Inject a custom McpTransport (overrides auto-detection; used in tests).
        adversarial: If True, uses an LLM adversary to generate semantic payloads (NYI).
        verbose:     Print progress to stdout.
    """

    def __init__(
        self,
        target: str,
        *,
        transport: McpTransport | None = None,
        adversarial: bool = False,
        adversary: "McpAdversary | None" = None,
        verbose: bool = True,
        auth_token: str | None = None,
        http_headers: dict[str, str] | None = None,
    ):
        self.target      = target
        self._transport  = transport
        self.adversarial = adversarial
        self._adversary  = adversary
        self.verbose     = verbose
        headers = dict(http_headers or {})
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        self._http_headers = headers or None

    # ------------------------------------------------------------------

    def scan(self) -> McpScanReport:
        """Synchronous entry point — wraps the async scan."""
        return asyncio.run(self._scan())

    async def _scan(self) -> McpScanReport:
        if self._transport is not None:
            raw_transport  = self._transport
            transport_name = "mock"
        else:
            raw_transport, transport_name = _make_transport(self.target, headers=self._http_headers)

        # Always wrap in the intercepting layer for chained call detection
        interceptor = McpInterceptingTransport(raw_transport)

        try:
            return await self._run(interceptor, transport_name)
        finally:
            await interceptor.close()

    async def _run(self, interceptor: McpInterceptingTransport, transport_name: str) -> McpScanReport:
        if self.verbose:
            print(f"[hemlock scan-mcp] Discovering tools from {self.target!r} ({transport_name})")

        tools = await interceptor.list_tools()

        if self.verbose:
            print(f"[hemlock scan-mcp] {len(tools)} tool(s) found: {[t.name for t in tools]}")

        all_cases: list[McpTestCase] = []
        for tool in tools:
            all_cases.extend(generate_test_cases(tool))

        if self.verbose:
            print(f"[hemlock scan-mcp] Running {len(all_cases)} test case(s)...")

        tool_index = {t.name: t for t in tools}
        vulnerabilities: list[McpVulnerability] = []
        # Maps (tool_name, argument, category) → (payload, response) for non-triggering cases
        failed_slots: dict[tuple[str, str, str], tuple[str, str]] = {}
        static_hits: set[tuple[str, str, str]] = set()

        for case in all_cases:
            tool_schema = tool_index[case.tool_name]
            args = case.filled_args(tool_schema)
            try:
                response = await interceptor.call_tool(case.tool_name, args)
            except Exception as exc:
                response = str(exc)

            succeeded, indicator = detect_success(response, case.category, case.payload)
            slot_key = (case.tool_name, case.argument, case.category)
            if succeeded:
                static_hits.add(slot_key)
                vulnerabilities.append(McpVulnerability(
                    tool_name=case.tool_name,
                    argument=case.argument,
                    category=case.category,
                    payload=case.payload,
                    severity=_severity(case.category),
                    indicator=indicator,
                    response=response[:200],
                ))
            elif slot_key not in static_hits:
                # Keep only the last failed case per slot (sufficient for adversary)
                failed_slots[slot_key] = (case.payload, response)

        # Collect chained call events from interceptor
        for event in interceptor.all_chained_events():
            vulnerabilities.append(McpVulnerability(
                tool_name=event.triggered_by_tool,
                argument="(chained call)",
                category="chained_tool_call",
                payload=event.triggered_by_payload,
                severity="high",
                indicator=(
                    f"chained call to '{event.chained_tool}' "
                    f"(confidence: {event.confidence}): {event.evidence[:60]}"
                ),
                response=event.evidence,
            ))

        # Deduplicate chained call vulns by (tool_name, chained_tool indicator)
        seen_chains: set[str] = set()
        deduped: list[McpVulnerability] = []
        for v in vulnerabilities:
            key = f"{v.tool_name}|{v.category}|{v.indicator[:40]}"
            if key not in seen_chains:
                seen_chains.add(key)
                deduped.append(v)

        # ------------------------------------------------------------------
        # Adversarial phase — only runs when adversarial=True and an adversary
        # is wired up; tests one reformulated payload per non-triggering slot.
        # ------------------------------------------------------------------
        adversarial_cases = 0
        if self.adversarial and self._adversary is not None:
            non_triggering = {
                k: v for k, v in failed_slots.items()
                if k not in static_hits
            }
            if self.verbose and non_triggering:
                print(
                    f"[hemlock scan-mcp] Adversarial phase: reformulating "
                    f"{len(non_triggering)} non-triggering slot(s)..."
                )
            for (tool_name, arg, category), (orig_payload, failed_resp) in non_triggering.items():
                new_payload = self._adversary.reformulate(
                    tool_name, arg, category, orig_payload, failed_resp
                )
                if not new_payload:
                    continue
                tool_schema = tool_index[tool_name]
                adv_case = McpTestCase(
                    tool_name=tool_name,
                    argument=arg,
                    category=category,
                    payload=new_payload,
                )
                adv_args = adv_case.filled_args(tool_schema)
                adversarial_cases += 1
                try:
                    adv_resp = await interceptor.call_tool(tool_name, adv_args)
                except Exception as exc:
                    adv_resp = str(exc)
                adv_ok, adv_indicator = detect_success(adv_resp, category, new_payload)
                if adv_ok:
                    deduped.append(McpVulnerability(
                        tool_name=tool_name,
                        argument=arg,
                        category=category,
                        payload=new_payload,
                        severity=_severity(category),
                        indicator=adv_indicator,
                        response=adv_resp[:200],
                        discovery_method="adversarial",
                    ))

        if self.verbose:
            vuln_count  = len(deduped)
            chain_count = sum(1 for v in deduped if v.category == "chained_tool_call")
            color = "\033[91m" if vuln_count else "\033[92m"
            reset = "\033[0m"
            parts = [f"{vuln_count - chain_count} direct vulnerabilit{'y' if (vuln_count - chain_count) == 1 else 'ies'}"]
            if chain_count:
                parts.append(f"{chain_count} chained call{'s' if chain_count > 1 else ''}")
            print(f"{color}[hemlock scan-mcp] {', '.join(parts)} detected across {len(tools)} tool(s).{reset}")

        return McpScanReport(
            target=self.target,
            transport=transport_name,
            tools=tools,
            vulnerabilities=deduped,
            scan_mode="adversarial" if self.adversarial else "static",
            total_cases=len(all_cases),
            adversarial_cases=adversarial_cases,
        )
