"""Hemlock CLI — run attack labs from the terminal."""

from __future__ import annotations

import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(name="hemlock", help="RAG security lab — test your pipeline against known attacks.")
console = Console()


def _get_pipeline(model: str, persist_dir: str):
    from hemlock.pipeline import Pipeline

    if model.startswith("claude"):
        from langchain_anthropic import ChatAnthropic
        llm = ChatAnthropic(model=model, api_key=os.environ["ANTHROPIC_API_KEY"])
    elif model.startswith("gpt"):
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model=model, api_key=os.environ["OPENAI_API_KEY"])
    else:
        from langchain_ollama import ChatOllama
        llm = ChatOllama(model=model)

    return Pipeline(llm=llm, persist_dir=persist_dir)


def _default_defenses(no_ingest: bool, no_retrieval: bool, no_output: bool):
    from defenses.chunk_filter import InjectionChunkFilter
    from defenses.input_sanitizer import (
        InjectionPatternFilter,
        MarkdownHeaderSanitizer,
        UnicodeNormalizer,
    )
    from defenses.output_validator import ExfiltrationGuard, InjectionSuccessGuard
    return (
        [] if no_ingest else [InjectionPatternFilter(), UnicodeNormalizer(), MarkdownHeaderSanitizer()],
        [] if no_retrieval else [InjectionChunkFilter()],
        [] if no_output else [ExfiltrationGuard(), InjectionSuccessGuard()],
    )


@app.command()
def list_attacks() -> None:
    """List all discovered attack modules."""
    from attacks.registry import ATTACK_REGISTRY
    table = Table(title="Hemlock — Discovered Attacks")
    table.add_column("Name", style="cyan")
    table.add_column("Class")
    table.add_column("Reference")
    for name, cls in sorted(ATTACK_REGISTRY.items()):
        table.add_row(name, cls.__name__, getattr(cls, "reference", "—")[:80])
    console.print(table)
    console.print(f"\n[dim]{len(ATTACK_REGISTRY)} attacks discovered.[/dim]")


@app.command()
def score(
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write output to file"),
    no_ingest: bool = typer.Option(False, "--no-ingest", help="Skip ingest defenses"),
    no_retrieval: bool = typer.Option(False, "--no-retrieval", help="Skip retrieval defenses"),
    no_output: bool = typer.Option(False, "--no-output", help="Skip output defenses"),
    endpoint: str = typer.Option(None, "--endpoint", help="External RAG endpoint URL"),
    attack: list[str] = typer.Option(None, "--attack", "-a", help="Run only these attacks (repeatable)"),
) -> None:
    """Run all attacks against all defense configurations and print a vulnerability report."""
    from attacks.registry import ATTACK_REGISTRY
    from hemlock.scorer import Scorer, print_report

    ingest_d, retrieval_d, output_d = _default_defenses(no_ingest, no_retrieval, no_output)

    if endpoint:
        from hemlock.external_pipeline import ExternalPipeline
        pipeline = ExternalPipeline(query_endpoint=endpoint)
    else:
        pipeline = _get_pipeline(model, persist_dir)

    selected = _select_attacks(ATTACK_REGISTRY, attack)

    scorer = Scorer(
        pipeline=pipeline,
        attacks=list(selected.values()),
        ingest_defenses=ingest_d,
        retrieval_defenses=retrieval_d,
        output_defenses=output_d,
        model_name=model,
    )

    console.print(f"\n[bold]Running Hemlock scorer — {model}[/bold]")
    console.print(
        f"Attacks: {len(selected)} | "
        f"Defenses: ingest={'on' if not no_ingest else 'off'} | "
        f"retrieval={'on' if not no_retrieval else 'off'} | "
        f"output={'on' if not no_output else 'off'}\n"
    )

    report = scorer.run(verbose=True)

    if output == "terminal":
        print_report(report)
    elif output in ("json", "markdown"):
        content = report.to_json() if output == "json" else report.to_markdown()
        if not out_file:
            console.print(content)

    if out_file:
        content = report.to_json() if output == "json" else report.to_markdown()
        with open(out_file, "w") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")


@app.command()
def gate(
    baseline: str = typer.Option(..., "--baseline", "-b", help="Path to baseline JSON report"),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    save: str = typer.Option(None, "--save", help="Save new report to this path"),
    fail_on_regression: bool = typer.Option(True, "--fail-on-regression/--no-fail"),
    threshold: float = typer.Option(0.05, "--threshold", help="Max allowed success rate increase"),
) -> None:
    """Compare current attack success rate against a saved baseline. Exits 1 on regression.

    Use in CI/CD:

    \\b
        hemlock score --output json --out baseline.json
        hemlock gate --baseline baseline.json --save latest.json
    """
    import json

    from attacks.registry import ATTACK_REGISTRY
    from hemlock.scorer import Scorer

    if not os.path.exists(baseline):
        console.print(f"[red]Baseline not found:[/red] {baseline}")
        raise typer.Exit(1)

    with open(baseline) as f:
        baseline_data = json.load(f)
    baseline_rate = float(baseline_data.get("success_rate", 0.0))

    console.print(f"\n[bold]Hemlock gate — baseline success rate: {baseline_rate:.0%}[/bold]")

    ingest_d, retrieval_d, output_d = _default_defenses(False, False, False)
    pipeline = _get_pipeline(model, persist_dir)

    scorer = Scorer(
        pipeline=pipeline,
        attacks=list(ATTACK_REGISTRY.values()),
        ingest_defenses=ingest_d,
        retrieval_defenses=retrieval_d,
        output_defenses=output_d,
        model_name=model,
    )

    report = scorer.run(verbose=True)
    current_rate = report.success_rate()
    delta = current_rate - baseline_rate
    regressed = delta > threshold

    console.print(f"\n[bold]Current success rate:[/bold] {current_rate:.0%}")
    console.print(f"[bold]Delta vs baseline:[/bold] {delta:+.0%} (threshold: {threshold:.0%})")

    if save:
        _write_report(report, save)
        console.print(f"[dim]Report saved to {save}[/dim]")

    if regressed and fail_on_regression:
        console.print(
            f"\n[red bold]REGRESSION DETECTED[/red bold] — "
            f"attack success rate increased by {delta:.0%}. Blocking."
        )
        raise typer.Exit(1)
    elif regressed:
        console.print("\n[yellow]Regression detected[/yellow] but --no-fail is set.")
    else:
        console.print("\n[green bold]Gate passed[/green bold] — no regression.")


@app.command()
def run(
    attack: str = typer.Argument("all", help="Attack name or 'all'"),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
) -> None:
    """Run one or all attack labs against the configured pipeline."""
    from attacks.registry import ATTACK_REGISTRY

    pipeline = _get_pipeline(model, persist_dir)

    if attack == "all":
        targets = ATTACK_REGISTRY
    elif attack in ATTACK_REGISTRY:
        targets = {attack: ATTACK_REGISTRY[attack]}
    else:
        available = ", ".join(sorted(ATTACK_REGISTRY))
        console.print(f"[red]Unknown attack:[/red] '{attack}'\nAvailable: {available}")
        raise typer.Exit(1)

    results = []
    for name, cls in targets.items():
        console.print(f"\n[bold yellow]Running:[/bold yellow] {name}")
        instance = cls(pipeline)
        result = instance.run()
        results.append(result)
        _print_result(result)

    _print_summary(results)


def _select_attacks(
    registry: dict, names: list[str] | None
) -> dict:
    if not names:
        return registry
    selected = {}
    for name in names:
        if name not in registry:
            available = ", ".join(sorted(registry))
            console.print(f"[red]Unknown attack:[/red] '{name}'\nAvailable: {available}")
            raise typer.Exit(1)
        selected[name] = registry[name]
    return selected


def _write_report(report, path: str) -> None:
    with open(path, "w") as f:
        f.write(report.to_json())


def _print_result(result) -> None:
    color = "red" if result.succeeded else "green"
    status = "SUCCEEDED" if result.succeeded else "FAILED"
    panel = Panel(
        f"[bold]Reference:[/bold] {result.reference}\n"
        f"[bold]Query:[/bold] {result.trace.query}\n"
        f"[bold]Response:[/bold] {result.trace.response[:300]}\n"
        f"[bold]Injection detected:[/bold] {result.trace.injected}\n"
        f"[bold]Notes:[/bold] {result.notes}",
        title=f"[{color}]{status}[/{color}] — {result.attack_name}",
        border_style=color,
    )
    console.print(panel)


def _print_summary(results: list) -> None:
    table = Table(title="Hemlock — Attack Summary")
    table.add_column("Attack", style="cyan")
    table.add_column("Result", style="bold")
    table.add_column("Reference")

    for r in results:
        status = "[red]SUCCEEDED[/red]" if r.succeeded else "[green]FAILED[/green]"
        table.add_row(r.attack_name, status, r.reference)

    console.print(table)
    total = len(results)
    compromised = sum(1 for r in results if r.succeeded)
    console.print(f"\n[bold]{compromised}/{total} attacks succeeded against this pipeline.[/bold]")
