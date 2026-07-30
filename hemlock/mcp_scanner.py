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
# Vulnerability + report
# ---------------------------------------------------------------------------

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

    def tools_affected(self) -> set[str]:
        return {v.tool_name for v in self.vulnerabilities}

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":         self.target,
            "transport":      self.transport,
            "scan_mode":      self.scan_mode,
            "tools_found":    len(self.tools),
            "test_cases_run": self.total_cases,
            "vulnerabilities_found": self.vuln_count(),
            "tools_affected": sorted(self.tools_affected()),
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
        lines = [
            f"# Hemlock MCP Scan Report",
            f"",
            f"**Target**: `{self.target}`  ",
            f"**Transport**: {self.transport}  ",
            f"**Mode**: {self.scan_mode}  ",
            f"**Tools discovered**: {len(self.tools)}  ",
            f"**Test cases run**: {self.total_cases}  ",
            f"**Vulnerabilities found**: {self.vuln_count()}",
            f"",
        ]

        if not self.tools:
            lines.append("_No tools discovered._")
            return "\n".join(lines)

        lines += ["## Tools", ""]
        for t in self.tools:
            lines.append(f"- **{t.name}** — {t.description}")
        lines.append("")

        if not self.vulnerabilities:
            lines.append("## Vulnerabilities\n\n_None detected._")
            return "\n".join(lines)

        lines += ["## Vulnerabilities", ""]
        lines += [
            "| Tool | Argument | Category | Severity | Indicator |",
            "|------|----------|----------|----------|-----------|",
        ]
        for v in self.vulnerabilities:
            lines.append(
                f"| {v.tool_name} | {v.argument} | {v.category} | "
                f"{v.severity} | {v.indicator[:60]} |"
            )

        return "\n".join(lines)


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

_HIGH_CATEGORIES = {"path_traversal", "ssrf"}


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
            transport      = self._transport
            transport_name = "mock"
        else:
            transport, transport_name = _make_transport(self.target)

        try:
            return await self._run(transport, transport_name)
        finally:
            await transport.close()

    async def _run(self, transport: McpTransport, transport_name: str) -> McpScanReport:
        if self.verbose:
            print(f"[hemlock scan-mcp] Discovering tools from {self.target!r} ({transport_name})")

        tools = await transport.list_tools()

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
                response = await transport.call_tool(case.tool_name, args)
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

        if self.verbose:
            vuln_count = len(vulnerabilities)
            color = "\033[91m" if vuln_count else "\033[92m"
            reset = "\033[0m"
            print(
                f"{color}[hemlock scan-mcp] "
                f"{vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'} detected "
                f"across {len(tools)} tool(s).{reset}"
            )

        return McpScanReport(
            target=self.target,
            transport=transport_name,
            tools=tools,
            vulnerabilities=vulnerabilities,
            scan_mode="adversarial" if self.adversarial else "static",
            total_cases=len(all_cases),
        )
