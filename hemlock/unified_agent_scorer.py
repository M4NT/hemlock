"""UnifiedAgentScorer — coverage matrix across all 4 agentic attack surfaces.

Extends AgentScorer to cover:
  Surface 1  rag_agent      AgentToolHijack — RAG context → tool call hijack
  Surface 2  cross_agent    CrossAgentPoisoning — A→B channel trust abuse
  Surface 3  memory         MemoryPoisoning — persistent memory injection
  Surface 4  tool_output    ToolOutputPoisoning — tool response injection

Each surface has its own pipeline type and its own defense mechanism:
  rag_agent    → ToolCallValidator (post-hoc, applied to tool call list)
  cross_agent  → CrossAgentBoundaryGuard (built into CrossAgentPipeline)
  memory       → MemoryIsolationGuard (built into MemoryAgentPipeline)
  tool_output  → ToolOutputGuard (built into ToolOutputMockExecutor)

Defense configs per surface:
  rag_agent    none | domain_blocklist | allowlist
  cross_agent  none | guarded
  memory       none | guarded
  tool_output  none | guarded

Metrics reported:
  Tool Hijack Rate        rag_agent scenarios succeeded / total
  Cross-Infection Rate    cross_agent scenarios succeeded / total
  Memory Persistence Rate memory scenarios succeeded / total
  Tool Output Injection Rate tool_output scenarios succeeded / total
  Overall Attack Rate     all surfaces combined
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from defenses.tool_call_validator import ToolCallValidator
from hemlock.agent_scorer import AgentScenarioResult, AgentScorer, VALIDATOR_CONFIGS

console = Console()

SURFACE_LABELS = {
    "rag_agent":    "RAG Agent",
    "cross_agent":  "Cross-Agent",
    "memory":       "Memory",
    "tool_output":  "Tool Output",
}


# ---------------------------------------------------------------------------
# Extended scenario result
# ---------------------------------------------------------------------------

@dataclass
class UnifiedScenarioResult(AgentScenarioResult):
    attack_surface: str = "unknown"


# ---------------------------------------------------------------------------
# Unified report
# ---------------------------------------------------------------------------

@dataclass
class UnifiedAgentScorerReport:
    model: str
    scenarios: list[UnifiedScenarioResult] = field(default_factory=list)

    def success_rate(self) -> float:
        if not self.scenarios:
            return 0.0
        return sum(1 for s in self.scenarios if s.attack_succeeded) / len(self.scenarios)

    def rate_by_surface(self) -> dict[str, float]:
        by_surface: dict[str, list[UnifiedScenarioResult]] = {}
        for s in self.scenarios:
            by_surface.setdefault(s.attack_surface, []).append(s)
        return {
            surface: sum(1 for s in scenarios if s.attack_succeeded) / len(scenarios)
            for surface, scenarios in by_surface.items()
        }

    def to_dict(self) -> dict[str, Any]:
        rates = self.rate_by_surface()
        return {
            "model": self.model,
            "success_rate": self.success_rate(),
            "total_scenarios": len(self.scenarios),
            "rates_by_surface": {
                "tool_hijack_rate":         rates.get("rag_agent", 0.0),
                "cross_infection_rate":     rates.get("cross_agent", 0.0),
                "memory_persistence_rate":  rates.get("memory", 0.0),
                "tool_output_injection_rate": rates.get("tool_output", 0.0),
            },
            "scenarios": [
                {
                    "attack":           s.attack_name,
                    "variant":          s.variant,
                    "validator_config": s.validator_config,
                    "attack_surface":   s.attack_surface,
                    "attack_succeeded": s.attack_succeeded,
                    "blocked_at":       s.blocked_at,
                    "blocked_calls":    s.blocked_calls,
                    "total_calls":      s.total_calls,
                }
                for s in self.scenarios
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        rates = self.rate_by_surface()
        lines = [
            "# Hemlock — Unified Agent Vulnerability Report",
            "",
            f"**Model:** `{self.model}`  ",
            f"**Overall attack success rate:** {self.success_rate():.0%}  ",
            f"**Total scenarios:** {len(self.scenarios)}",
            "",
            "## Rates by Attack Surface",
            "",
            "| Surface | Metric | Rate |",
            "|---------|--------|------|",
            f"| RAG Agent | Tool Hijack Rate | {rates.get('rag_agent', 0):.0%} |",
            f"| Cross-Agent | Cross-Infection Rate | {rates.get('cross_agent', 0):.0%} |",
            f"| Memory | Memory Persistence Rate | {rates.get('memory', 0):.0%} |",
            f"| Tool Output | Tool Output Injection Rate | {rates.get('tool_output', 0):.0%} |",
            "",
            "## Full Coverage Matrix",
            "",
            "| Surface | Attack | Variant | Defense Config | Blocked at | Result |",
            "|---------|--------|---------|----------------|------------|--------|",
        ]
        for s in self.scenarios:
            status  = "SUCCEEDED" if s.attack_succeeded else "blocked"
            blocked = s.blocked_at or "—"
            variant = s.variant or "—"
            surface = SURFACE_LABELS.get(s.attack_surface, s.attack_surface)
            lines.append(
                f"| {surface} | {s.attack_name} | `{variant}` | `{s.validator_config}` "
                f"| {blocked} | **{status}** |"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unified scorer
# ---------------------------------------------------------------------------

class UnifiedAgentScorer:
    """Runs all 4 agentic attack surfaces in a single pass.

    Usage:
        scorer = UnifiedAgentScorer.from_tools(tools, model_name="mock")
        report = scorer.run()
        print_unified_report(report)
    """

    def __init__(
        self,
        surface_configs: list[dict],
        model_name: str = "mock",
    ) -> None:
        """
        surface_configs: list of dicts, each with keys:
            attack_class     type
            pipeline_factory callable  → pipeline instance (no args)
            defense_configs  dict[str, callable]  config_name → pipeline_factory_with_defense
            post_hoc_validators  dict[str, ToolCallValidator | None]  (optional)
            attack_surface   str
        """
        self.surface_configs = surface_configs
        self.model_name      = model_name

    @classmethod
    def from_tools(cls, tools: list, model_name: str = "mock") -> "UnifiedAgentScorer":
        """Build the standard unified scorer using MockLLM + MockEmbeddings."""
        import tempfile

        from attacks.agent_tool_hijack import AgentToolHijack
        from attacks.cross_agent_poisoning import CrossAgentPoisoning
        from attacks.memory_poisoning import MemoryPoisoning
        from attacks.tool_output_poisoning import ToolOutputPoisoning
        from defenses.cross_agent_boundary_guard import CrossAgentBoundaryGuard
        from defenses.memory_isolation_guard import MemoryIsolationGuard
        from defenses.tool_call_validator import ToolCallValidator
        from defenses.tool_output_guard import ToolOutputGuard
        from hemlock.agent_pipeline import AgentPipeline, MockAgentExecutor
        from hemlock.cross_agent_pipeline import CrossAgentMockExecutor, CrossAgentPipeline
        from hemlock.memory_agent_pipeline import MemoryAgentPipeline
        from hemlock.mock import MockEmbeddings, MockLLM
        from hemlock.pipeline import Pipeline
        from hemlock.tool_output_pipeline import ToolOutputMockExecutor, ToolOutputPipeline

        def _inner():
            tmp = tempfile.mkdtemp()
            return Pipeline(
                llm=MockLLM("ok"),
                persist_dir=tmp,
                collection=f"unified_{id(tmp)}",
                embeddings=MockEmbeddings(),
            )

        def make_agent():
            return AgentPipeline(pipeline=_inner(), executor=MockAgentExecutor(tools=tools), tools=tools)

        def make_cross(guard=None):
            from hemlock.cross_agent_pipeline import CrossAgentMockExecutor
            a = AgentPipeline(pipeline=_inner(), executor=CrossAgentMockExecutor(tools=tools), tools=tools)
            b = AgentPipeline(pipeline=_inner(), executor=MockAgentExecutor(tools=tools), tools=tools)
            return CrossAgentPipeline(agent_a=a, agent_b=b, boundary_guard=guard)

        def make_memory(guard=None):
            return MemoryAgentPipeline(
                pipeline=_inner(),
                executor=MockAgentExecutor(tools=tools),
                tools=tools,
                memory_guard=guard,
            )

        def make_tool_output(guard=None):
            return ToolOutputPipeline(
                pipeline=_inner(),
                executor=ToolOutputMockExecutor(tools=tools),
                tools=tools,
                output_guard=guard,
            )

        return cls(
            model_name=model_name,
            surface_configs=[
                {
                    "attack_class":   AgentToolHijack,
                    "attack_surface": "rag_agent",
                    "pipeline_factories": {
                        "none":             make_agent,
                        "domain_blocklist": make_agent,
                        "allowlist":        make_agent,
                    },
                    "post_hoc_validators": VALIDATOR_CONFIGS,
                },
                {
                    "attack_class":   CrossAgentPoisoning,
                    "attack_surface": "cross_agent",
                    "pipeline_factories": {
                        "none":    make_cross,
                        "guarded": lambda: make_cross(guard=CrossAgentBoundaryGuard()),
                    },
                },
                {
                    "attack_class":   MemoryPoisoning,
                    "attack_surface": "memory",
                    "pipeline_factories": {
                        "none":    make_memory,
                        "guarded": lambda: make_memory(guard=MemoryIsolationGuard()),
                    },
                },
                {
                    "attack_class":   ToolOutputPoisoning,
                    "attack_surface": "tool_output",
                    "pipeline_factories": {
                        "none":    make_tool_output,
                        "guarded": lambda: make_tool_output(guard=ToolOutputGuard()),
                    },
                },
            ],
        )

    def run(self, verbose: bool = True) -> UnifiedAgentScorerReport:
        report = UnifiedAgentScorerReport(model=self.model_name)

        total = sum(
            len(getattr(cfg["attack_class"], "VARIANTS", []) or [None])
            * len(cfg["pipeline_factories"])
            for cfg in self.surface_configs
        )
        i = 0

        for cfg in self.surface_configs:
            attack_cls   = cfg["attack_class"]
            surface      = cfg["attack_surface"]
            factories    = cfg["pipeline_factories"]
            post_hoc     = cfg.get("post_hoc_validators", {})
            variants     = getattr(attack_cls, "VARIANTS", []) or [None]

            for variant in variants:
                for cfg_name, factory in factories.items():
                    i += 1
                    pipeline   = factory()
                    validator  = post_hoc.get(cfg_name)

                    attack = (
                        attack_cls(pipeline, variant=variant)
                        if variant is not None
                        else attack_cls(pipeline)
                    )

                    label = (
                        f"[{i}/{total}] [{surface}] {attack.name}"
                        f"{f' [{variant}]' if variant else ''} × {cfg_name}"
                    )
                    if verbose:
                        console.print(f"  [dim]{label}[/dim]")

                    result = self._run_scenario(attack, validator, cfg_name, surface)
                    report.scenarios.append(result)

        return report

    def _run_scenario(
        self,
        attack,
        validator,
        cfg_name: str,
        surface: str,
    ) -> UnifiedScenarioResult:
        attack_result = attack.run()
        tool_calls    = list(attack_result.trace.tool_calls)

        blocked_calls = 0
        blocked_at    = None

        # Post-hoc validator (rag_agent surface only)
        if validator and tool_calls:
            _, reports    = validator.filter_calls(tool_calls)
            blocked_calls = sum(1 for r in reports if r.triggered)
            if blocked_calls:
                blocked_at = "tool_call"

        # Built-in guard (cross_agent, memory, tool_output)
        if blocked_at is None and cfg_name == "guarded":
            from hemlock.cross_agent_pipeline import CrossAgentPipeline
            from hemlock.memory_agent_pipeline import MemoryAgentPipeline
            from hemlock.tool_output_pipeline import ToolOutputPipeline

            p = attack.pipeline
            if isinstance(p, CrossAgentPipeline):
                br = getattr(p, "last_boundary_report", None)
                if br and br.triggered:
                    blocked_at    = "boundary_guard"
                    blocked_calls = 1
            elif isinstance(p, MemoryAgentPipeline):
                # guard blocked entries before query — attack cannot succeed
                if not attack_result.succeeded:
                    blocked_at    = "memory_guard"
                    blocked_calls = 1
            elif isinstance(p, ToolOutputPipeline):
                if p.guard_triggered:
                    blocked_at    = "tool_output_guard"
                    blocked_calls = 1

        attack_succeeded = attack_result.succeeded and blocked_at is None

        return UnifiedScenarioResult(
            attack_name      = attack_result.attack_name,
            variant          = getattr(attack, "variant", None),
            validator_config = cfg_name,
            attack_succeeded = attack_succeeded,
            blocked_calls    = blocked_calls,
            total_calls      = len(tool_calls),
            blocked_at       = blocked_at,
            attack_result    = attack_result,
            attack_surface   = surface,
        )


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------

def print_unified_report(report: UnifiedAgentScorerReport) -> None:
    table = Table(
        title=f"Hemlock — Unified Agent Report ({report.model})",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Surface",   style="blue",    no_wrap=True)
    table.add_column("Attack",    style="cyan",    no_wrap=True)
    table.add_column("Variant",   style="magenta")
    table.add_column("Defense",   style="yellow",  justify="center")
    table.add_column("Blocked at",                 justify="center")
    table.add_column("Result",                     justify="center")

    for s in report.scenarios:
        result_str  = "[red]SUCCEEDED[/red]" if s.attack_succeeded else "[green]blocked[/green]"
        blocked_str = s.blocked_at or "[dim]—[/dim]"
        variant_str = s.variant    or "[dim]—[/dim]"
        surface_str = SURFACE_LABELS.get(s.attack_surface, s.attack_surface)
        table.add_row(surface_str, s.attack_name, variant_str, s.validator_config, blocked_str, result_str)

    console.print(table)

    # Per-surface summary
    rates = report.rate_by_surface()
    metrics = {
        "rag_agent":    ("Tool Hijack Rate",          "red" if rates.get("rag_agent", 0) > 0 else "green"),
        "cross_agent":  ("Cross-Infection Rate",      "red" if rates.get("cross_agent", 0) > 0 else "green"),
        "memory":       ("Memory Persistence Rate",   "red" if rates.get("memory", 0) > 0 else "green"),
        "tool_output":  ("Tool Output Injection Rate","red" if rates.get("tool_output", 0) > 0 else "green"),
    }

    summary = Table(title="Impact Metrics", box=box.SIMPLE)
    summary.add_column("Surface",  style="blue")
    summary.add_column("Metric",   style="cyan")
    summary.add_column("Rate",     justify="right")

    for surface, (metric, color) in metrics.items():
        rate = rates.get(surface, 0.0)
        summary.add_row(
            SURFACE_LABELS.get(surface, surface),
            metric,
            f"[{color}]{rate:.0%}[/{color}]",
        )

    console.print(summary)

    overall = report.success_rate()
    color   = "red" if overall > 0 else "green"
    console.print(
        f"\n[bold]Overall: [{color}]{overall:.0%}[/{color}]"
        f" ({sum(1 for s in report.scenarios if s.attack_succeeded)}"
        f"/{len(report.scenarios)} scenarios)[/bold]"
    )
