"""DefenseSynthesizer — auto-build defenses for at-risk channels (v3.8).

Reads a HemReport and, per at-risk channel, selects the appropriate defense
classes from the ``defenses`` package and instantiates a ready-to-use chain.

Only defenses that actually exist in ``defenses.__init__`` are used. The
channel→defense map below was validated against the exported names.

Usage:
    session = HemSession.mock()
    report  = session.run()
    synth   = DefenseSynthesizer(report)
    for result in synth.synthesize():
        print(result.channel, result.defenses)
    chain = synth.build_chain("rag")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from defenses import (
    CrossAgentBoundaryGuard,
    ExfiltrationGuard,
    GraphBoundaryGuard,
    InjectionSuccessGuard,
    MemoryBoundaryGuard,
    OutputDefense,
    OutputDefenseChain,
    ToolOutputGuard,
)

if TYPE_CHECKING:
    from hemlock.hem_session import HemReport


# channel → (defense classes, reasoning). PromptLeakageGuard from the original
# design does not exist; ExfiltrationGuard covers prompt/context leakage on rag.
_CHANNEL_DEFENSES: dict[str, tuple[list[type], str]] = {
    "rag": (
        [InjectionSuccessGuard, ExfiltrationGuard],
        "RAG output can carry injected directives and leaked context; guard the "
        "generation output for injection success markers and exfiltration signals.",
    ),
    "cross_agent": (
        [CrossAgentBoundaryGuard],
        "Agent-to-agent messages can relay poisoned directives; validate every "
        "boundary crossing.",
    ),
    "memory": (
        [MemoryBoundaryGuard],
        "Persistent memory writes can encode relay/override payloads; validate "
        "writes at the memory boundary.",
    ),
    "tool_output": (
        [ToolOutputGuard],
        "Tool responses are untrusted input; sanitize them before they re-enter "
        "the prompt.",
    ),
    "graph": (
        [GraphBoundaryGuard],
        "N-hop propagation spreads payloads across nodes; guard each traversal "
        "output.",
    ),
    "mcp": (
        [InjectionSuccessGuard, ToolOutputGuard],
        "MCP tool descriptions and outputs are untrusted; guard for injection "
        "markers and sanitize tool output.",
    ),
}


@dataclass
class SynthesisResult:
    channel: str
    defenses: list[str] = field(default_factory=list)
    defense_objects: list = field(default_factory=list)
    reasoning: str = ""


class DefenseSynthesizer:
    def __init__(self, report: "HemReport") -> None:
        self.report = report

    def synthesize(self) -> list[SynthesisResult]:
        results: list[SynthesisResult] = []
        for channel in self.report.channels_at_risk():
            mapping = _CHANNEL_DEFENSES.get(channel)
            if mapping is None:
                continue
            classes, reasoning = mapping
            objects = [cls() for cls in classes]
            results.append(SynthesisResult(
                channel=channel,
                defenses=[cls.__name__ for cls in classes],
                defense_objects=objects,
                reasoning=reasoning,
            ))
        return results

    def build_chain(self, channel: str) -> OutputDefenseChain:
        mapping = _CHANNEL_DEFENSES.get(channel)
        if mapping is None:
            return OutputDefenseChain([])
        classes, _ = mapping
        # Only OutputDefense instances belong in an output chain. MemoryBoundaryGuard
        # is an IngestDefense (validate_write), so it is excluded here.
        objects = [cls() for cls in classes]
        output_defenses: list[OutputDefense] = [
            o for o in objects if isinstance(o, OutputDefense)
        ]
        return OutputDefenseChain(output_defenses)

    def summary(self) -> str:
        results = self.synthesize()
        lines = [
            "# Hemlock Defense Synthesis",
            "",
            f"**Target**: {self.report.target}  ",
            f"**At-risk channels**: {len(results)}",
            "",
        ]
        if not results:
            lines.append("No at-risk channels — no defenses synthesized.")
            return "\n".join(lines)

        lines += [
            "| Channel | Defenses | Reasoning |",
            "|---------|----------|-----------|",
        ]
        for r in results:
            lines.append(f"| {r.channel} | {', '.join(r.defenses)} | {r.reasoning} |")
        return "\n".join(lines)
