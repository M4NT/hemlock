"""Automatic vulnerability scorer.

Runs every attack against every defense configuration and produces a
coverage matrix: which attacks succeed, which defenses block them, and
at what hardening level.

Output formats: rich terminal table, JSON, Markdown.

Reference:
    Inspired by the evaluation methodology in:
    Yi et al. (2023) — "Benchmarking and Defending Against Indirect Prompt
    Injection Attacks on Large Language Models" — arxiv:2312.14197
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from attacks.base import Attack, AttackResult
from defenses.base import IngestDefense, RetrievalDefense, OutputDefense
from defenses.prompt_hardening import get_prompt, LEVELS
from hemlock.pipeline import Pipeline, RetrievalTrace

console = Console()

HARDENING_LEVELS = list(LEVELS.keys())  # baseline, l1, l2, l3, l4


@dataclass
class ScenarioResult:
    attack_name: str
    hardening_level: str
    ingest_defenses: list[str]
    retrieval_defenses: list[str]
    output_defenses: list[str]
    attack_succeeded: bool
    blocked_at: str | None  # "ingest" | "retrieval" | "output" | None
    attack_result: AttackResult | None = None


@dataclass
class ScorerReport:
    model: str
    scenarios: list[ScenarioResult] = field(default_factory=list)

    def success_rate(self) -> float:
        if not self.scenarios:
            return 0.0
        return sum(1 for s in self.scenarios if s.attack_succeeded) / len(self.scenarios)

    def by_attack(self) -> dict[str, list[ScenarioResult]]:
        result: dict[str, list[ScenarioResult]] = {}
        for s in self.scenarios:
            result.setdefault(s.attack_name, []).append(s)
        return result

    def by_hardening(self) -> dict[str, list[ScenarioResult]]:
        result: dict[str, list[ScenarioResult]] = {}
        for s in self.scenarios:
            result.setdefault(s.hardening_level, []).append(s)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "success_rate": self.success_rate(),
            "total_scenarios": len(self.scenarios),
            "scenarios": [
                {
                    "attack": s.attack_name,
                    "hardening": s.hardening_level,
                    "ingest_defenses": s.ingest_defenses,
                    "retrieval_defenses": s.retrieval_defenses,
                    "output_defenses": s.output_defenses,
                    "attack_succeeded": s.attack_succeeded,
                    "blocked_at": s.blocked_at,
                }
                for s in self.scenarios
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            f"# Hemlock Vulnerability Report",
            f"",
            f"**Model:** `{self.model}`  ",
            f"**Overall attack success rate:** {self.success_rate():.0%}  ",
            f"**Total scenarios:** {len(self.scenarios)}",
            f"",
            f"## Coverage Matrix",
            f"",
            f"| Attack | Hardening | Blocked at | Result |",
            f"|--------|-----------|------------|--------|",
        ]
        for s in self.scenarios:
            status = "SUCCEEDED" if s.attack_succeeded else "blocked"
            blocked = s.blocked_at or "—"
            lines.append(
                f"| {s.attack_name} | `{s.hardening_level}` | {blocked} | **{status}** |"
            )

        lines += [
            f"",
            f"## By Hardening Level",
            f"",
        ]
        for level, scenarios in self.by_hardening().items():
            succeeded = sum(1 for s in scenarios if s.attack_succeeded)
            lines.append(f"- **`{level}`**: {succeeded}/{len(scenarios)} attacks succeeded")

        return "\n".join(lines)


class Scorer:
    """Orchestrates attack × defense scenarios and produces a ScorerReport."""

    def __init__(
        self,
        pipeline: Pipeline,
        attacks: list[type[Attack]],
        ingest_defenses: list[IngestDefense] | None = None,
        retrieval_defenses: list[RetrievalDefense] | None = None,
        output_defenses: list[OutputDefense] | None = None,
        hardening_levels: list[str] | None = None,
        model_name: str = "unknown",
    ) -> None:
        self.pipeline = pipeline
        self.attack_classes = attacks
        self.ingest_defenses = ingest_defenses or []
        self.retrieval_defenses = retrieval_defenses or []
        self.output_defenses = output_defenses or []
        self.hardening_levels = hardening_levels or HARDENING_LEVELS
        self.model_name = model_name

    def run(self, verbose: bool = True) -> ScorerReport:
        report = ScorerReport(model=self.model_name)

        total = len(self.attack_classes) * len(self.hardening_levels)
        done = 0

        for attack_cls in self.attack_classes:
            for level in self.hardening_levels:
                done += 1
                attack = attack_cls(self.pipeline)
                label = f"[{done}/{total}] {attack.name} × {level}"

                if verbose:
                    console.print(f"  [dim]{label}[/dim]")

                scenario = self._run_scenario(attack, level)
                report.scenarios.append(scenario)

        return report

    def _run_scenario(self, attack: Attack, hardening_level: str) -> ScenarioResult:
        # 1. Setup — ingest documents (legitimate + malicious)
        attack.setup()

        # 2. Apply ingest defenses to the malicious chunks already in the store
        #    (in a real system, these run BEFORE ingest; here we simulate post-hoc
        #    by checking if the malicious doc would have been caught)
        blocked_at = None
        ingest_blocked = self._simulate_ingest_defense(attack)
        if ingest_blocked:
            blocked_at = "ingest"

        # 3. Retrieve chunks
        store = self.pipeline._get_store()
        from langchain_core.documents import Document
        chunks = store.similarity_search(attack.__class__.__dict__.get(
            "TRIGGER_QUERY",
            getattr(
                __import__(attack.__module__, fromlist=[""]),
                "TRIGGER_QUERY",
                "query",
            ),
        ), k=self.pipeline.top_k)

        # 4. Apply retrieval defenses
        retrieval_blocked = False
        if self.retrieval_defenses and not blocked_at:
            for defense in self.retrieval_defenses:
                chunks, reports = defense.filter(chunks)
            if not chunks:
                retrieval_blocked = True
                blocked_at = "retrieval"

        # 5. Run attack (full pipeline query)
        system_prompt = get_prompt(hardening_level)
        attack_result = self._run_attack_with_prompt(attack, system_prompt)

        # 6. Apply output defenses
        output_blocked = False
        if self.output_defenses and not blocked_at:
            for defense in self.output_defenses:
                out_report = defense.validate(attack_result.trace.response)
                if out_report.triggered:
                    output_blocked = True
                    blocked_at = "output"
                    break

        # 7. Final verdict
        #    Attack succeeded if: not blocked at any layer AND attack scored True
        attack_succeeded = (
            not ingest_blocked
            and not retrieval_blocked
            and not output_blocked
            and attack_result.succeeded
        )

        return ScenarioResult(
            attack_name=attack_result.attack_name,
            hardening_level=hardening_level,
            ingest_defenses=[d.name for d in self.ingest_defenses],
            retrieval_defenses=[d.name for d in self.retrieval_defenses],
            output_defenses=[d.name for d in self.output_defenses],
            attack_succeeded=attack_succeeded,
            blocked_at=blocked_at,
            attack_result=attack_result,
        )

    def _simulate_ingest_defense(self, attack: Attack) -> bool:
        """Check if any ingest defense would have blocked the malicious document."""
        if not self.ingest_defenses:
            return False

        mod = __import__(attack.__module__, fromlist=[""])
        # Collect all MALICIOUS_DOC / *_INJECTED_DOC / *_DOC constants
        candidates = [
            v for k, v in vars(mod).items()
            if isinstance(v, str) and (
                "MALICIOUS" in k or "INJECTED" in k or k.endswith("_DOC")
            ) and k not in ("TRIGGER_QUERY",)
        ]

        from langchain_core.documents import Document
        for content in candidates:
            doc = Document(page_content=content, metadata={"source": "malicious"})
            for defense in self.ingest_defenses:
                result, report = defense.inspect(doc)
                if report.triggered:
                    return True
        return False

    def _run_attack_with_prompt(self, attack: Attack, system_prompt: str) -> AttackResult:
        mod = __import__(attack.__module__, fromlist=[""])
        trigger = getattr(mod, "TRIGGER_QUERY", "test query")
        trace = self.pipeline.query(trigger, system_prompt=system_prompt)

        # Re-score with the attack's own scorer
        succeeded = attack._score(trace)
        from attacks.base import AttackResult
        return AttackResult(
            attack_name=attack.name,
            reference=attack.reference,
            succeeded=succeeded,
            trace=trace,
        )


def print_report(report: ScorerReport) -> None:
    """Render the report as a rich terminal table."""
    table = Table(
        title=f"Hemlock — Vulnerability Report ({report.model})",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Attack", style="cyan", no_wrap=True)
    table.add_column("Hardening", style="yellow", justify="center")
    table.add_column("Blocked at", justify="center")
    table.add_column("Result", justify="center")

    for s in report.scenarios:
        result_str = "[red]SUCCEEDED[/red]" if s.attack_succeeded else "[green]blocked[/green]"
        blocked_str = s.blocked_at or "[dim]—[/dim]"
        table.add_row(s.attack_name, s.hardening_level, blocked_str, result_str)

    console.print(table)

    by_level = report.by_hardening()
    summary = Table(title="By Hardening Level", box=box.SIMPLE)
    summary.add_column("Level", style="yellow")
    summary.add_column("Attacks succeeded", justify="right")
    summary.add_column("Attacks blocked", justify="right")

    for level in HARDENING_LEVELS:
        scenarios = by_level.get(level, [])
        succeeded = sum(1 for s in scenarios if s.attack_succeeded)
        blocked = len(scenarios) - succeeded
        summary.add_row(level, str(succeeded), str(blocked))

    console.print(summary)
    console.print(
        f"\n[bold]Overall attack success rate: "
        f"[{'red' if report.success_rate() > 0 else 'green'}]"
        f"{report.success_rate():.0%}[/]"
        f" ({sum(1 for s in report.scenarios if s.attack_succeeded)}"
        f"/{len(report.scenarios)} scenarios)[/bold]"
    )
