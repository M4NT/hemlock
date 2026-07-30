"""Automatic vulnerability scorer.

Runs every attack × variant × defense configuration and produces a
coverage matrix: which attacks succeed, which defenses block them, and
at what hardening level.

Output formats: rich terminal table, JSON, Markdown, HTML.

Reference:
    Inspired by the evaluation methodology in:
    Yi et al. (2023) — "Benchmarking and Defending Against Indirect Prompt
    Injection Attacks on Large Language Models" — arxiv:2312.14197
"""

from __future__ import annotations

import copy
import json
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from attacks.base import Attack, AttackResult
from defenses.base import IngestDefense, OutputDefense, RetrievalDefense
from defenses.prompt_hardening import LEVELS, get_prompt
from hemlock.pipeline import Pipeline

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
    blocked_at: str | None = None  # "ingest" | "retrieval" | "output" | None
    variant: str | None = None
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
                    "variant": s.variant,
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
            "# Hemlock Vulnerability Report",
            "",
            f"**Model:** `{self.model}`  ",
            f"**Overall attack success rate:** {self.success_rate():.0%}  ",
            f"**Total scenarios:** {len(self.scenarios)}",
            "",
            "## Coverage Matrix",
            "",
            "| Attack | Variant | Hardening | Blocked at | Result |",
            "|--------|---------|-----------|------------|--------|",
        ]
        for s in self.scenarios:
            status = "SUCCEEDED" if s.attack_succeeded else "blocked"
            blocked = s.blocked_at or "—"
            variant = s.variant or "—"
            lines.append(
                f"| {s.attack_name} | `{variant}` | `{s.hardening_level}` | {blocked} | **{status}** |"
            )

        lines += ["", "## By Hardening Level", ""]
        for level, scenarios in self.by_hardening().items():
            succeeded = sum(1 for s in scenarios if s.attack_succeeded)
            lines.append(f"- **`{level}`**: {succeeded}/{len(scenarios)} attacks succeeded")

        return "\n".join(lines)

    def to_html(self) -> str:
        rate = self.success_rate()
        rate_color = "#e74c3c" if rate > 0 else "#27ae60"

        rows = ""
        for s in self.scenarios:
            result_class = "succeeded" if s.attack_succeeded else "blocked"
            result_label = "SUCCEEDED" if s.attack_succeeded else "blocked"
            variant = s.variant or "—"
            blocked = s.blocked_at or "—"
            rows += (
                f"<tr>"
                f"<td>{s.attack_name}</td>"
                f"<td><code>{variant}</code></td>"
                f"<td><code>{s.hardening_level}</code></td>"
                f"<td>{blocked}</td>"
                f'<td class="{result_class}">{result_label}</td>'
                f"</tr>\n"
            )

        level_rows = ""
        for level, scenarios in self.by_hardening().items():
            succeeded = sum(1 for sc in scenarios if sc.attack_succeeded)
            blocked = len(scenarios) - succeeded
            level_rows += (
                f"<tr><td><code>{level}</code></td><td>{succeeded}</td><td>{blocked}</td></tr>\n"
            )

        return textwrap.dedent(f"""\
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <title>Hemlock — Vulnerability Report</title>
              <style>
                body {{ font-family: sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
                h1 {{ color: #2c3e50; }}
                .summary {{ background: #f8f9fa; border-radius: 6px; padding: 1rem 1.5rem; margin: 1rem 0; }}
                .rate {{ font-size: 2rem; font-weight: bold; color: {rate_color}; }}
                table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
                th {{ background: #2c3e50; color: white; padding: .6rem 1rem; text-align: left; }}
                td {{ padding: .5rem 1rem; border-bottom: 1px solid #ddd; }}
                tr:nth-child(even) {{ background: #f8f9fa; }}
                .succeeded {{ color: #e74c3c; font-weight: bold; }}
                .blocked {{ color: #27ae60; }}
                code {{ background: #eee; padding: 1px 4px; border-radius: 3px; }}
              </style>
            </head>
            <body>
              <h1>Hemlock — Vulnerability Report</h1>
              <div class="summary">
                <div class="rate">{rate:.0%}</div>
                <p>Overall attack success rate &mdash; <strong>{self.model}</strong></p>
                <p>{len(self.scenarios)} total scenarios</p>
              </div>

              <h2>Coverage Matrix</h2>
              <table>
                <thead>
                  <tr><th>Attack</th><th>Variant</th><th>Hardening</th><th>Blocked at</th><th>Result</th></tr>
                </thead>
                <tbody>
            {rows}
                </tbody>
              </table>

              <h2>By Hardening Level</h2>
              <table>
                <thead>
                  <tr><th>Level</th><th>Succeeded</th><th>Blocked</th></tr>
                </thead>
                <tbody>
            {level_rows}
                </tbody>
              </table>
            </body>
            </html>
        """)


class Scorer:
    """Orchestrates attack × variant × defense scenarios and produces a ScorerReport."""

    def __init__(
        self,
        pipeline: Pipeline,
        attacks: list[type[Attack]],
        ingest_defenses: list[IngestDefense] | None = None,
        retrieval_defenses: list[RetrievalDefense] | None = None,
        output_defenses: list[OutputDefense] | None = None,
        hardening_levels: list[str] | None = None,
        model_name: str = "unknown",
        max_workers: int = 1,
    ) -> None:
        self.pipeline = pipeline
        self.attack_classes = attacks
        self.ingest_defenses = ingest_defenses or []
        self.retrieval_defenses = retrieval_defenses or []
        self.output_defenses = output_defenses or []
        self.hardening_levels = hardening_levels or HARDENING_LEVELS
        self.model_name = model_name
        self.max_workers = max_workers

    def _build_scenarios(self) -> list[tuple[type[Attack], str | None, str]]:
        """Return (attack_cls, variant_or_None, level) for every scenario."""
        scenarios = []
        for attack_cls in self.attack_classes:
            variants = getattr(attack_cls, "VARIANTS", []) or [None]
            for variant in variants:
                for level in self.hardening_levels:
                    scenarios.append((attack_cls, variant, level))
        return scenarios

    def run(self, verbose: bool = True) -> ScorerReport:
        report = ScorerReport(model=self.model_name)
        scenarios = self._build_scenarios()
        total = len(scenarios)

        if self.max_workers == 1:
            for i, (attack_cls, variant, level) in enumerate(scenarios, 1):
                attack = self._make_attack(attack_cls, variant)
                label = f"[{i}/{total}] {attack.name}{f' [{variant}]' if variant else ''} × {level}"
                if verbose:
                    console.print(f"  [dim]{label}[/dim]")
                result = self._run_scenario(attack, level)
                result.variant = variant
                report.scenarios.append(result)
        else:
            results: list[tuple[int, ScenarioResult]] = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_idx = {}
                for i, (attack_cls, variant, level) in enumerate(scenarios):
                    fresh = self._fresh_pipeline(i)
                    attack = self._make_attack(attack_cls, variant, pipeline=fresh)
                    future = executor.submit(self._run_scenario_safe, attack, level, fresh)
                    future_to_idx[future] = (i, variant)

                done = 0
                for future in as_completed(future_to_idx):
                    idx, variant = future_to_idx[future]
                    done += 1
                    result = future.result()
                    result.variant = variant
                    if verbose:
                        attack_cls, v, level = scenarios[idx]
                        console.print(
                            f"  [dim][{done}/{total}] {attack_cls.name}"
                            f"{f' [{v}]' if v else ''} × {level}[/dim]"
                        )
                    results.append((idx, result))

            for _, result in sorted(results, key=lambda x: x[0]):
                report.scenarios.append(result)

        return report

    def _make_attack(self, attack_cls, variant, pipeline=None):
        p = pipeline or self.pipeline
        if variant is None:
            return attack_cls(p)
        return attack_cls(p, variant=variant)

    def _fresh_pipeline(self, idx: int) -> Pipeline:
        fresh = copy.copy(self.pipeline)
        fresh.collection = f"hemlock_score_{idx}"
        return fresh

    def _run_scenario_safe(self, attack: Attack, level: str, pipeline: Pipeline) -> ScenarioResult:
        try:
            return self._run_scenario(attack, level)
        finally:
            try:
                pipeline.reset()
            except Exception:
                pass

    def _run_scenario(self, attack: Attack, hardening_level: str) -> ScenarioResult:
        # 1. Setup — ingest documents (legitimate + malicious)
        attack.setup()

        # 2. Simulate ingest defense
        blocked_at = None
        if self._simulate_ingest_defense(attack):
            blocked_at = "ingest"

        # 3. Retrieve chunks for retrieval defense check
        trigger = self._get_trigger(attack)
        store = self.pipeline._get_store()
        chunks = store.similarity_search(trigger, k=self.pipeline.top_k)

        # 4. Apply retrieval defenses
        retrieval_blocked = False
        if self.retrieval_defenses and not blocked_at:
            for defense in self.retrieval_defenses:
                chunks, _ = defense.filter(chunks)
            if not chunks:
                retrieval_blocked = True
                blocked_at = "retrieval"

        # 5. Run attack with the given hardening level
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
        attack_succeeded = (
            not (blocked_at == "ingest")
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

    def _get_trigger(self, attack: Attack) -> str:
        """Get the trigger query for this attack instance (handles per-variant triggers)."""
        instance_trigger = getattr(attack, "_trigger_query", None)
        if instance_trigger:
            return instance_trigger
        mod = __import__(attack.__module__, fromlist=[""])
        return getattr(mod, "TRIGGER_QUERY", "test query")

    def _simulate_ingest_defense(self, attack: Attack) -> bool:
        """Check whether any ingest defense would have blocked the malicious document."""
        if not self.ingest_defenses:
            return False

        # Prefer the instance-level malicious doc (variant attacks store it here)
        if hasattr(attack, "_malicious_doc"):
            candidates = [attack._malicious_doc]
        else:
            mod = __import__(attack.__module__, fromlist=[""])
            candidates = [
                v for k, v in vars(mod).items()
                if isinstance(v, str)
                and ("MALICIOUS" in k or "INJECTED" in k or k.endswith("_DOC"))
                and k != "TRIGGER_QUERY"
            ]

        from langchain_core.documents import Document

        for content in candidates:
            doc = Document(page_content=content, metadata={"source": "malicious"})
            for defense in self.ingest_defenses:
                _, report = defense.inspect(doc)
                if report.triggered:
                    return True
        return False

    def _run_attack_with_prompt(self, attack: Attack, system_prompt: str) -> AttackResult:
        trigger = self._get_trigger(attack)
        trace = self.pipeline.query(trigger, system_prompt=system_prompt)
        succeeded = attack._score(trace)
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
    table.add_column("Variant", style="magenta")
    table.add_column("Hardening", style="yellow", justify="center")
    table.add_column("Blocked at", justify="center")
    table.add_column("Result", justify="center")

    for s in report.scenarios:
        result_str = "[red]SUCCEEDED[/red]" if s.attack_succeeded else "[green]blocked[/green]"
        blocked_str = s.blocked_at or "[dim]—[/dim]"
        variant_str = s.variant or "[dim]—[/dim]"
        table.add_row(s.attack_name, variant_str, s.hardening_level, blocked_str, result_str)

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
