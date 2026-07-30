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


@dataclass
class McpScanReport:
    target: str
    transport: str
    tools: list[McpToolSchema]
    vulnerabilities: list[McpVulnerability]
    scan_mode: str = "static"
    total_cases: int = 0

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
            "vulnerabilities_found":   self.vuln_count(),
            "chained_calls_detected":  len(chained),
            "tools_affected":          sorted(self.tools_affected()),
            "tools": [
                {"name": t.name, "description": t.description}
                for t in self.tools
            ],
            "vulnerabilities": [
                {
                    "tool":      v.tool_name,
                    "argument":  v.argument,
                    "category":  v.category,
                    "severity":  v.severity,
                    "indicator": v.indicator,
                    "payload":   v.payload[:80],
                    "response":  v.response[:120],
                }
                for v in self.vulnerabilities
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        chained = [v for v in self.vulnerabilities if v.category == "chained_tool_call"]
        direct  = [v for v in self.vulnerabilities if v.category != "chained_tool_call"]

        lines = [
            f"# Hemlock MCP Scan Report",
            f"",
            f"**Target**: `{self.target}`  ",
            f"**Transport**: {self.transport}  ",
            f"**Mode**: {self.scan_mode}  ",
            f"**Tools discovered**: {len(self.tools)}  ",
            f"**Test cases run**: {self.total_cases}  ",
            f"**Vulnerabilities found**: {len(direct)}  ",
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
                "| Tool | Argument | Category | Severity | Indicator |",
                "|------|----------|----------|----------|-----------|",
            ]
            for v in direct:
                lines.append(
                    f"| {v.tool_name} | {v.argument} | {v.category} | "
                    f"{v.severity} | {v.indicator[:60]} |"
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

    def __init__(self, url: str):
        self._url     = url
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

        self._cm = sse_client(self._url)
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


# ---------------------------------------------------------------------------
# Transport factory
# ---------------------------------------------------------------------------

def _make_transport(target: str) -> tuple[McpTransport, str]:
    """Return (transport, transport_name) for a given target string."""
    if target.startswith(("http://", "https://")):
        return HttpSseMcpTransport(target), "http_sse"
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
        verbose: bool = True,
    ):
        self.target      = target
        self._transport  = transport
        self.adversarial = adversarial
        self.verbose     = verbose

    # ------------------------------------------------------------------

    def scan(self) -> McpScanReport:
        """Synchronous entry point — wraps the async scan."""
        return asyncio.run(self._scan())

    async def _scan(self) -> McpScanReport:
        if self._transport is not None:
            raw_transport  = self._transport
            transport_name = "mock"
        else:
            raw_transport, transport_name = _make_transport(self.target)

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

        for case in all_cases:
            tool_schema = tool_index[case.tool_name]
            args = case.filled_args(tool_schema)
            try:
                response = await interceptor.call_tool(case.tool_name, args)
            except Exception as exc:
                response = str(exc)

            succeeded, indicator = detect_success(response, case.category, case.payload)
            if succeeded:
                vulnerabilities.append(McpVulnerability(
                    tool_name=case.tool_name,
                    argument=case.argument,
                    category=case.category,
                    payload=case.payload,
                    severity=_severity(case.category),
                    indicator=indicator,
                    response=response[:200],
                ))

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
        )
