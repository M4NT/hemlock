"""Hemlock CLI — run attack labs from the terminal."""

from __future__ import annotations

import os
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

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


@app.command()
def run(
    attack: str = typer.Argument(
        "all", help="Attack to run: direct_injection | context_override | poisoning | all"
    ),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
) -> None:
    """Run one or all attack labs against the configured pipeline."""
    from attacks.direct_injection import DirectInjection
    from attacks.context_override import ContextOverride
    from attacks.poisoning import KnowledgePoisoning

    attack_map = {
        "direct_injection": DirectInjection,
        "context_override": ContextOverride,
        "poisoning": KnowledgePoisoning,
    }

    pipeline = _get_pipeline(model, persist_dir)
    targets = attack_map if attack == "all" else {attack: attack_map[attack]}

    results = []
    for name, cls in targets.items():
        console.print(f"\n[bold yellow]Running:[/bold yellow] {name}")
        instance = cls(pipeline)
        result = instance.run()
        results.append(result)
        _print_result(result)

    _print_summary(results)


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
