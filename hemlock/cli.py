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
def score(
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write output to file"),
    no_ingest: bool = typer.Option(False, "--no-ingest", help="Skip ingest defenses"),
    no_retrieval: bool = typer.Option(False, "--no-retrieval", help="Skip retrieval defenses"),
    no_output: bool = typer.Option(False, "--no-output", help="Skip output defenses"),
) -> None:
    """Run all attacks against all defense configurations and print a vulnerability report."""
    import os
    from attacks.direct_injection import DirectInjection
    from attacks.context_override import ContextOverride
    from attacks.poisoning import KnowledgePoisoning
    from attacks.indirect_injection import IndirectInjection
    from attacks.exfiltration import Exfiltration
    from defenses.input_sanitizer import InjectionPatternFilter, UnicodeNormalizer, MarkdownHeaderSanitizer
    from defenses.chunk_filter import InjectionChunkFilter
    from defenses.output_validator import ExfiltrationGuard, InjectionSuccessGuard
    from hemlock.scorer import Scorer, print_report

    pipeline = _get_pipeline(model, persist_dir)

    scorer = Scorer(
        pipeline=pipeline,
        attacks=[DirectInjection, ContextOverride, KnowledgePoisoning, IndirectInjection, Exfiltration],
        ingest_defenses=[] if no_ingest else [
            InjectionPatternFilter(),
            UnicodeNormalizer(),
            MarkdownHeaderSanitizer(),
        ],
        retrieval_defenses=[] if no_retrieval else [InjectionChunkFilter()],
        output_defenses=[] if no_output else [ExfiltrationGuard(), InjectionSuccessGuard()],
        model_name=model,
    )

    console.print(f"\n[bold]Running Hemlock scorer — {model}[/bold]")
    console.print(f"Defenses: ingest={'on' if not no_ingest else 'off'} | "
                  f"retrieval={'on' if not no_retrieval else 'off'} | "
                  f"output={'on' if not no_output else 'off'}\n")

    report = scorer.run(verbose=True)

    if output == "terminal":
        print_report(report)
    elif output == "json":
        content = report.to_json()
        console.print(content) if not out_file else None
    elif output == "markdown":
        content = report.to_markdown()
        console.print(content) if not out_file else None

    if out_file:
        content = report.to_json() if output == "json" else report.to_markdown()
        with open(out_file, "w") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")


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
    from attacks.indirect_injection import IndirectInjection
    from attacks.exfiltration import Exfiltration

    attack_map = {
        "direct_injection": DirectInjection,
        "context_override": ContextOverride,
        "poisoning": KnowledgePoisoning,
        "indirect_injection": IndirectInjection,
        "exfiltration": Exfiltration,
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
