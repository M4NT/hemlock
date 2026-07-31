"""Hemlock CLI — run attack labs from the terminal."""

from __future__ import annotations

import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(name="hemlock", help="AI security lab — attack and defense testing for RAG pipelines and tool-using agents.")
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


def _default_defenses(no_ingest: bool, no_retrieval: bool, no_output: bool, llm_classifier=None):
    from defenses.chunk_filter import InjectionChunkFilter
    from defenses.input_sanitizer import (
        InjectionPatternFilter,
        MarkdownHeaderSanitizer,
        UnicodeNormalizer,
    )
    from defenses.output_validator import ExfiltrationGuard, InjectionSuccessGuard

    retrieval_d = [] if no_retrieval else [InjectionChunkFilter()]
    if llm_classifier is not None and not no_retrieval:
        retrieval_d.append(llm_classifier)

    return (
        [] if no_ingest else [InjectionPatternFilter(), UnicodeNormalizer(), MarkdownHeaderSanitizer()],
        retrieval_d,
        [] if no_output else [ExfiltrationGuard(), InjectionSuccessGuard()],
    )


@app.command()
def list_attacks() -> None:
    """List all discovered attack modules."""
    from attacks.registry import ATTACK_REGISTRY
    table = Table(title="Hemlock — Discovered Attacks")
    table.add_column("Name", style="cyan")
    table.add_column("Class")
    table.add_column("Variants", justify="right")
    table.add_column("Reference")
    for name, cls in sorted(ATTACK_REGISTRY.items()):
        variants = ", ".join(getattr(cls, "VARIANTS", []) or ["—"])
        table.add_row(name, cls.__name__, variants, getattr(cls, "reference", "—")[:60])
    console.print(table)
    console.print(f"\n[dim]{len(ATTACK_REGISTRY)} attacks discovered.[/dim]")


@app.command()
def score(
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown | html"),
    out_file: str = typer.Option(None, "--out", help="Write output to file"),
    no_ingest: bool = typer.Option(False, "--no-ingest", help="Skip ingest defenses"),
    no_retrieval: bool = typer.Option(False, "--no-retrieval", help="Skip retrieval defenses"),
    no_output: bool = typer.Option(False, "--no-output", help="Skip output defenses"),
    llm_classifier: bool = typer.Option(False, "--llm-classifier/--no-llm-classifier",
                                         help="Enable LLM-based chunk classifier defense"),
    endpoint: str = typer.Option(None, "--endpoint", help="External RAG endpoint URL"),
    attack: list[str] = typer.Option(None, "--attack", "-a", help="Run only these attacks (repeatable)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Parallel workers (>1 requires pipeline factory)"),
) -> None:
    """Run all attacks against all defense configurations and print a vulnerability report."""
    from attacks.registry import ATTACK_REGISTRY
    from hemlock.scorer import Scorer, print_report

    classifier = None
    if llm_classifier:
        from defenses.llm_classifier import LLMChunkClassifier
        llm_instance = _get_pipeline(model, persist_dir).llm
        classifier = LLMChunkClassifier(llm=llm_instance)

    ingest_d, retrieval_d, output_d = _default_defenses(no_ingest, no_retrieval, no_output, classifier)

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
        max_workers=workers,
    )

    total_variants = sum(
        len(getattr(cls, "VARIANTS", []) or [None]) for cls in selected.values()
    )
    console.print(f"\n[bold]Running Hemlock scorer — {model}[/bold]")
    console.print(
        f"Attacks: {len(selected)} | Variants: {total_variants} | "
        f"Defenses: ingest={'on' if not no_ingest else 'off'} | "
        f"retrieval={'on' if not no_retrieval else 'off'} | "
        f"output={'on' if not no_output else 'off'}"
        + (f" | LLM classifier: on" if llm_classifier else "")
        + "\n"
    )

    report = scorer.run(verbose=True)

    content = None
    if output == "terminal":
        print_report(report)
    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    elif output == "html":
        content = report.to_html()
    else:
        console.print(f"[red]Unknown output format:[/red] {output}")
        raise typer.Exit(1)

    if content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
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
def diff(
    baseline: str = typer.Argument(..., help="Path to baseline JSON report"),
    current: str = typer.Argument(..., help="Path to current JSON report"),
    fail_on_regression: bool = typer.Option(True, "--fail-on-regression/--no-fail",
                                             help="Exit 1 if aggregate success rate regressed"),
    fail_on_any: bool = typer.Option(False, "--fail-on-any",
                                     help="Exit 1 if ANY individual scenario regressed (stricter)"),
) -> None:
    """Show scenario-level changes between two scorer JSON reports.

    Exits 1 on any regression when --fail-on-any is set, or on aggregate
    regression when --fail-on-regression is set (default).

    \\b
        hemlock score --output json --out baseline.json
        # ... make changes ...
        hemlock score --output json --out latest.json
        hemlock diff baseline.json latest.json --fail-on-any
    """
    import json
    from rich import box

    with open(baseline) as f:
        base_data = json.load(f)
    with open(current) as f:
        cur_data = json.load(f)

    base_rate = float(base_data.get("success_rate", 0.0))
    cur_rate = float(cur_data.get("success_rate", 0.0))
    delta = cur_rate - base_rate

    # Index baseline scenarios by (attack, variant, hardening)
    def _key(s):
        return (s.get("attack", ""), s.get("variant") or "", s.get("hardening", ""))

    base_index = {_key(s): s for s in base_data.get("scenarios", [])}
    cur_index = {_key(s): s for s in cur_data.get("scenarios", [])}

    regressions = []   # blocked → SUCCEEDED
    improvements = []  # SUCCEEDED → blocked
    new_scenarios = []  # only in current

    all_keys = sorted(set(base_index) | set(cur_index))
    for key in all_keys:
        b = base_index.get(key)
        c = cur_index.get(key)
        if b is None:
            new_scenarios.append((key, c))
            continue
        if c is None:
            continue
        b_ok = b["attack_succeeded"]
        c_ok = c["attack_succeeded"]
        if not b_ok and c_ok:
            regressions.append((key, b, c))
        elif b_ok and not c_ok:
            improvements.append((key, b, c))

    # Print summary
    delta_color = "red" if delta > 0 else "green" if delta < 0 else "dim"
    console.print(f"\n[bold]hemlock diff[/bold] — {baseline} → {current}")
    console.print(
        f"  Aggregate: {base_rate:.0%} → {cur_rate:.0%}  "
        f"[{delta_color}]{delta:+.0%}[/{delta_color}]"
    )
    console.print(
        f"  Regressions: [red]{len(regressions)}[/red]  |  "
        f"Improvements: [green]{len(improvements)}[/green]  |  "
        f"New scenarios: [dim]{len(new_scenarios)}[/dim]\n"
    )

    if regressions:
        t = Table(title="[red]Regressions — blocked → SUCCEEDED[/red]", box=box.SIMPLE)
        t.add_column("Attack", style="cyan")
        t.add_column("Variant", style="magenta")
        t.add_column("Hardening", style="yellow")
        t.add_column("Blocked at (was)", style="dim")
        for (atk, variant, level), b, c in regressions:
            t.add_row(atk, variant or "—", level, b.get("blocked_at") or "—")
        console.print(t)

    if improvements:
        t = Table(title="[green]Improvements — SUCCEEDED → blocked[/green]", box=box.SIMPLE)
        t.add_column("Attack", style="cyan")
        t.add_column("Variant", style="magenta")
        t.add_column("Hardening", style="yellow")
        t.add_column("Blocked at (now)", style="dim")
        for (atk, variant, level), b, c in improvements:
            t.add_row(atk, variant or "—", level, c.get("blocked_at") or "—")
        console.print(t)

    if new_scenarios:
        console.print(f"[dim]{len(new_scenarios)} new scenarios not in baseline (skipped in comparison)[/dim]")

    # Exit codes
    any_regressed = len(regressions) > 0
    agg_regressed = delta > 0

    if fail_on_any and any_regressed:
        console.print(
            f"\n[red bold]REGRESSION DETECTED[/red bold] — "
            f"{len(regressions)} scenario(s) regressed. Blocking (--fail-on-any)."
        )
        raise typer.Exit(1)

    if fail_on_regression and agg_regressed:
        console.print(
            f"\n[red bold]REGRESSION DETECTED[/red bold] — "
            f"aggregate success rate increased by {delta:+.0%}. Blocking."
        )
        raise typer.Exit(1)

    if not any_regressed:
        console.print("[green bold]No regressions detected.[/green bold]")
    elif not fail_on_any:
        console.print("[yellow]Scenario-level regressions present but --fail-on-any not set.[/yellow]")


@app.command()
def run(
    attack: str = typer.Argument("all", help="Attack name or 'all'"),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model to use"),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    variant: str = typer.Option(None, "--variant", "-v", help="Attack variant (default: first variant)"),
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
        variants = getattr(cls, "VARIANTS", []) or [None]
        run_variants = [variant] if variant else variants
        for v in run_variants:
            instance = cls(pipeline) if v is None else cls(pipeline, variant=v)
            result = instance.run()
            results.append(result)
            _print_result(result)

    _print_summary(results)


@app.command()
def agent_score(
    model: str = typer.Option(
        "claude-haiku-4-5-20251001",
        help="LLM model to use (ignored with --mock)",
    ),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory"),
    mock: bool = typer.Option(
        True,
        "--mock/--real",
        help="Use MockAgentExecutor — no API key required (default: on)",
    ),
    validator: str = typer.Option(
        "all",
        help="Validator config to run: none | domain_blocklist | allowlist | all",
    ),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write output to file"),
) -> None:
    """Run agent attack scoring — tests tool call hijacking against ToolCallValidator configs.

    \\b
    Quick start (no API key needed):
        hemlock agent-score --mock

    Run with a real LLM:
        hemlock agent-score --real --model claude-haiku-4-5-20251001

    Run only one validator config:
        hemlock agent-score --mock --validator domain_blocklist

    Export JSON:
        hemlock agent-score --mock --output json --out agent_report.json
    """
    import tempfile
    import uuid

    from langchain_core.tools import tool

    from attacks.agent_tool_hijack import AgentToolHijack
    from defenses.tool_call_validator import ToolCallValidator
    from hemlock.agent_pipeline import AgentPipeline, MockAgentExecutor
    from hemlock.agent_scorer import AgentScorer, VALIDATOR_CONFIGS, print_agent_report
    from hemlock.mock import MockLLM
    from hemlock.pipeline import Pipeline

    # ── Tool definitions ────────────────────────────────────────────────────
    @tool
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to a customer."""
        return f"Email sent to {to}: {subject}"

    @tool
    def get_order_status(order_id: str) -> str:
        """Get the status of a customer order by order ID."""
        return f"Order {order_id}: processing"

    tools = [send_email, get_order_status]

    # ── Pipeline factory ────────────────────────────────────────────────────
    if mock:
        def factory():
            tmp   = tempfile.mkdtemp()
            inner = Pipeline(
                llm=MockLLM("ok"),
                persist_dir=tmp,
                collection=f"agent_{uuid.uuid4().hex[:8]}",
            )
            return AgentPipeline(
                pipeline=inner,
                executor=MockAgentExecutor(tools=tools),
                tools=tools,
            )
        model_label = "mock-executor"
    else:
        # Real LLM path — wraps a LangChain tool-calling agent
        try:
            from langchain.agents import AgentExecutor, create_tool_calling_agent
            from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
        except ImportError:
            console.print(
                "[red]langchain package required for --real mode.[/red]\n"
                "Install: pip install langchain"
            )
            raise typer.Exit(1)

        base_llm = _get_pipeline(model, persist_dir).llm

        def factory():
            tmp   = tempfile.mkdtemp()
            inner = _get_pipeline(model, tmp)
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are an order management assistant. Use tools to help customers."),
                ("human", "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ])
            agent    = create_tool_calling_agent(inner.llm, tools, prompt)
            executor = AgentExecutor(agent=agent, tools=tools, verbose=False)
            # Adapt AgentExecutor to the AgentPipeline interface
            executor.last_calls = []
            return AgentPipeline(pipeline=inner, executor=executor, tools=tools)

        model_label = model

    # ── Validator config selection ──────────────────────────────────────────
    if validator == "all":
        selected_configs = VALIDATOR_CONFIGS
    elif validator in VALIDATOR_CONFIGS:
        selected_configs = {validator: VALIDATOR_CONFIGS[validator]}
    else:
        available = " | ".join(["all"] + list(VALIDATOR_CONFIGS))
        console.print(f"[red]Unknown validator:[/red] '{validator}'\nAvailable: {available}")
        raise typer.Exit(1)

    # ── Run ─────────────────────────────────────────────────────────────────
    total_scenarios = len(AgentToolHijack.VARIANTS) * len(selected_configs)
    console.print(f"\n[bold]Running Hemlock agent scorer — {model_label}[/bold]")
    console.print(
        f"Attacks: 1 (AgentToolHijack) | "
        f"Variants: {len(AgentToolHijack.VARIANTS)} | "
        f"Validator configs: {', '.join(selected_configs)} | "
        f"Total scenarios: {total_scenarios}\n"
    )

    scorer = AgentScorer(
        agent_pipeline_factory=factory,
        attacks=[AgentToolHijack],
        validator_configs=selected_configs,
        model_name=model_label,
    )
    report = scorer.run(verbose=True)

    # ── Output ──────────────────────────────────────────────────────────────
    content = None
    if output == "terminal":
        print_agent_report(report)
    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output}")
        raise typer.Exit(1)

    if content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")


@app.command()
def agent_gate(
    baseline: str = typer.Option(..., "--baseline", "-b", help="Path to baseline JSON (from agent-score --output json)"),
    save: str = typer.Option(None, "--save", help="Save current report to this path"),
    fail_on_regression: bool = typer.Option(True, "--fail-on-regression/--no-fail"),
    threshold: float = typer.Option(0.05, "--threshold", help="Max allowed success rate increase (default 5pp)"),
    surface: str = typer.Option(
        "all",
        "--surface",
        help="Surface to gate: all | rag_agent | cross_agent | memory | tool_output",
    ),
) -> None:
    """Gate CI/CD on agentic attack success rate across all 4 attack surfaces.

    Runs the unified agent scorer (ToolHijack + CrossAgent + Memory + ToolOutput),
    compares against a saved baseline, and exits 1 on regression.

    \\b
    Quick start:
        hemlock agent-score --output json --out agent_baseline.json
        hemlock agent-gate  --baseline agent_baseline.json

    Gate on a single surface:
        hemlock agent-gate --baseline agent_baseline.json --surface memory

    Save the current report for the next run:
        hemlock agent-gate --baseline agent_baseline.json --save agent_latest.json
    """
    import json as _json
    import tempfile
    import uuid

    from langchain_core.tools import tool as lc_tool

    from hemlock.unified_agent_scorer import UnifiedAgentScorer, print_unified_report

    if not os.path.exists(baseline):
        console.print(f"[red]Baseline not found:[/red] {baseline}")
        raise typer.Exit(1)

    with open(baseline) as f:
        baseline_data = _json.load(f)

    # Determine baseline rate (overall or surface-specific)
    if surface == "all":
        baseline_rate = float(baseline_data.get("success_rate", 0.0))
    else:
        rates = baseline_data.get("rates_by_surface", {})
        surface_key_map = {
            "rag_agent":   "tool_hijack_rate",
            "cross_agent": "cross_infection_rate",
            "memory":      "memory_persistence_rate",
            "tool_output": "tool_output_injection_rate",
        }
        key = surface_key_map.get(surface)
        if key is None:
            console.print(f"[red]Unknown surface:[/red] {surface}")
            raise typer.Exit(1)
        baseline_rate = float(rates.get(key, 0.0))

    console.print(f"\n[bold]Hemlock agent-gate — baseline: {baseline_rate:.0%}[/bold]")
    if surface != "all":
        console.print(f"[dim]Surface filter: {surface}[/dim]")

    # ── Build tools ──────────────────────────────────────────────────────────
    @lc_tool
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to a customer."""
        return f"Email sent to {to}: {subject}"

    @lc_tool
    def get_order_status(order_id: str) -> str:
        """Get the status of a customer order."""
        return f"Order {order_id}: processing"

    tools = [send_email, get_order_status]

    # ── Run unified scorer ───────────────────────────────────────────────────
    scorer = UnifiedAgentScorer.from_tools(tools, model_name="mock-gate")
    report = scorer.run(verbose=True)

    # Filter to requested surface
    if surface != "all":
        report.scenarios = [s for s in report.scenarios if s.attack_surface == surface]

    current_rate = report.success_rate()
    delta        = current_rate - baseline_rate
    regressed    = delta > threshold

    print_unified_report(report)

    console.print(f"\n[bold]Current rate:[/bold]  {current_rate:.0%}")
    console.print(f"[bold]Delta:[/bold]         {delta:+.0%} (threshold: {threshold:.0%})")

    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(scorer.run(verbose=False).to_json())  # full report
        console.print(f"[dim]Report saved to {save}[/dim]")

    if regressed and fail_on_regression:
        console.print(
            f"\n[red bold]REGRESSION DETECTED[/red bold] — "
            f"agent attack success rate increased by {delta:.0%}. Blocking."
        )
        raise typer.Exit(1)
    elif regressed:
        console.print("\n[yellow]Regression detected[/yellow] but --no-fail is set.")
    else:
        console.print("\n[green bold]Agent gate passed[/green bold] — no regression.")


@app.command("scan-mcp")
def scan_mcp(
    target: str = typer.Argument(
        ...,
        help="MCP server target: a shell command (stdio) or URL (http/https for SSE). "
             "Examples: \"npx -y @modelcontextprotocol/server-everything\" "
             "or https://staging.api.com/mcp/sse",
    ),
    output: str = typer.Option(
        "terminal",
        help="Output format: terminal | json | markdown | diff  "
             "(diff shows adversarial-only discoveries separately)",
    ),
    out_file: str = typer.Option(None, "--out", help="Write report to this file"),
    adversarial: bool = typer.Option(
        False, "--adversarial/--static",
        help="Enable LLM-based semantic payload reformulation after static scan. "
             "Requires --llm-key (or OPENAI_API_KEY env var).",
    ),
    llm_key: str = typer.Option(
        None, "--llm-key", envvar="OPENAI_API_KEY",
        help="OpenAI API key for adversarial mode (or set OPENAI_API_KEY).",
    ),
    model: str = typer.Option(
        "gpt-4o-mini", "--model",
        help="LLM model name for adversarial reformulation (default: gpt-4o-mini).",
    ),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """Fuzz all tools exposed by an MCP server for injection vulnerabilities.

    Discovers all tools via tools/list, inspects their JSON Schema, and fires
    targeted payloads (prompt injection, path traversal, SSRF, SQL injection)
    at every string argument.

    \\b
    Quick start (stdio — spawns server subprocess):
        hemlock scan-mcp "npx -y @modelcontextprotocol/server-everything"

    Remote server over HTTP/SSE:
        hemlock scan-mcp https://staging.api.internal/mcp/sse

    Export JSON:
        hemlock scan-mcp "npx ..." --output json --out mcp_report.json

    Adversarial mode (requires OpenAI key):
        hemlock scan-mcp "npx ..." --adversarial --model gpt-4o

    Show only adversarially-discovered vulnerabilities:
        hemlock scan-mcp "npx ..." --adversarial --output diff
    """
    from hemlock.mcp_scanner import LLMAdversary, McpScanner
    from rich import box
    from rich.table import Table

    adversary = None
    if adversarial:
        if not llm_key:
            console.print(
                "[red]--adversarial requires --llm-key or OPENAI_API_KEY env var.[/red]\n"
                "Install: [dim]pip install 'hemlock-rag[openai]'[/dim]"
            )
            raise typer.Exit(1)
        try:
            from langchain_openai import ChatOpenAI
            adversary = LLMAdversary(ChatOpenAI(model=model, api_key=llm_key))
        except ImportError:
            console.print(
                "[red]langchain-openai not installed.[/red]\n"
                "Install: [dim]pip install 'hemlock-rag[openai]'[/dim]"
            )
            raise typer.Exit(1)

    scanner = McpScanner(
        target=target,
        adversarial=adversarial,
        adversary=adversary,
        verbose=verbose,
    )

    try:
        report = scanner.scan()
    except ImportError as exc:
        console.print(f"[red]Missing dependency:[/red] {exc}")
        raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(1)

    # ------------------------------------------------------------------
    # Terminal / diff output
    # ------------------------------------------------------------------
    def _vuln_table(
        vulns: list,
        title: str,
        show_method: bool = False,
    ):
        t = Table(title=title, box=box.SIMPLE)
        t.add_column("Tool", style="cyan")
        t.add_column("Argument", style="magenta")
        t.add_column("Category", style="yellow")
        t.add_column("Severity", style="bold")
        if show_method:
            t.add_column("Method", style="dim")
        t.add_column("Indicator")
        for v in vulns:
            sev_color = "red" if v.severity == "high" else "yellow" if v.severity == "medium" else "dim"
            row = [
                v.tool_name, v.argument, v.category,
                f"[{sev_color}]{v.severity}[/{sev_color}]",
            ]
            if show_method:
                method_style = "cyan" if v.discovery_method == "adversarial" else "dim"
                row.append(f"[{method_style}]{v.discovery_method}[/{method_style}]")
            row.append(v.indicator[:60])
            t.add_row(*row)
        return t

    if output in ("terminal", "diff"):
        vuln_count  = report.vuln_count()
        color       = "red" if vuln_count else "green"
        adv_line    = (
            f"\n[bold]Adversarial cases:[/bold] {report.adversarial_cases}"
            if report.adversarial_cases > 0 else ""
        )
        console.print(
            Panel(
                f"[bold]Target:[/bold] {report.target}\n"
                f"[bold]Transport:[/bold] {report.transport}\n"
                f"[bold]Mode:[/bold] {report.scan_mode}\n"
                f"[bold]Tools discovered:[/bold] {len(report.tools)}\n"
                f"[bold]Test cases run:[/bold] {report.total_cases}"
                f"{adv_line}\n"
                f"[bold]Vulnerabilities found:[/bold] [{color}]{vuln_count}[/{color}]",
                title="[bold]Hemlock scan-mcp[/bold]",
                border_style=color,
            )
        )

        if report.tools and output != "diff":
            t = Table(title="Discovered Tools", box=box.SIMPLE)
            t.add_column("Tool", style="cyan")
            t.add_column("Description")
            t.add_column("Arguments", justify="right")
            for tool in report.tools:
                args = ", ".join((tool.input_schema or {}).get("properties", {}).keys()) or "—"
                t.add_row(tool.name, tool.description[:60], args)
            console.print(t)

        if output == "diff":
            # Diff mode: two tables — static findings, then adversarial-only additions
            static_vulns = [v for v in report.vulnerabilities if v.discovery_method == "static"]
            adv_vulns    = [v for v in report.vulnerabilities if v.discovery_method == "adversarial"]
            if static_vulns:
                console.print(_vuln_table(static_vulns, "[yellow]Static findings[/yellow]"))
            if adv_vulns:
                console.print(_vuln_table(adv_vulns, "[cyan bold]Adversarial-only discoveries[/cyan bold]"))
            if not report.vulnerabilities:
                console.print("[green]No vulnerabilities detected.[/green]")
        elif report.vulnerabilities:
            show_method = adversarial and report.adversarial_cases > 0
            console.print(_vuln_table(
                report.vulnerabilities,
                "[red]Vulnerabilities[/red]",
                show_method=show_method,
            ))
        else:
            console.print("[green]No vulnerabilities detected.[/green]")

        content = None

    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output!r}. Use: terminal | json | markdown | diff")
        raise typer.Exit(1)

    if output != "terminal" and content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")

    if report.vuln_count() > 0:
        raise typer.Exit(2)  # exit 2 = vulnerabilities found (not an error, but signal for CI)


@app.command("threat-model")
def threat_model(
    output: str = typer.Option(
        "terminal",
        help="Output format: terminal | json | markdown",
    ),
    out_file: str = typer.Option(None, "--out", help="Write report to this file"),
    channels: str = typer.Option(
        None, "--channels",
        help="Comma-separated channels to run. "
             "Default: all except mcp. "
             "Options: rag,cross_agent,memory,tool_output,graph,mcp",
    ),
    mcp_target: str = typer.Option(
        None, "--mcp-target",
        help="MCP server target to include in the assessment (enables mcp channel).",
    ),
    target_name: str = typer.Option("hemlock-lab", "--target", help="Name for this assessment target."),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """Run a unified threat model across all Hemlock attack channels.

    Executes RAG injection, cross-agent poisoning, memory poisoning, tool-output
    poisoning, N-hop graph propagation, and optionally MCP scanning — producing
    one consolidated risk score and cross-channel report.

    \\b
    Quick start (all channels, mock mode — no API keys):
        hemlock threat-model

    With MCP channel:
        hemlock threat-model --mcp-target "npx -y @modelcontextprotocol/server-everything"

    Specific channels only:
        hemlock threat-model --channels rag,memory,graph

    Export JSON:
        hemlock threat-model --output json --out threat_report.json
    """
    from hemlock.hem_session import HemSession
    from rich import box
    from rich.table import Table

    channel_list = [c.strip() for c in channels.split(",")] if channels else None

    if verbose:
        console.print("[dim]Building mock session...[/dim]")

    session = HemSession.mock(
        target=target_name,
        channels=channel_list,
        mcp_transport=None,  # real MCP target handled via McpScanner in _run_mcp
    )

    if mcp_target:
        session._mcp_target = mcp_target
        if "mcp" not in session._channels:
            session._channels.append("mcp")

    if verbose:
        console.print(f"[dim]Running {len(session._channels)} channel(s): {', '.join(session._channels)}[/dim]")

    try:
        report = session.run()
    except Exception as exc:
        console.print(f"[red]Assessment failed:[/red] {exc}")
        raise typer.Exit(1)

    if output == "terminal":
        score = report.risk_score()
        color = "red" if score >= 70 else "yellow" if score >= 30 else "green"
        score_bar = "█" * int(score // 10) + "░" * (10 - int(score // 10))
        at_risk   = report.channels_at_risk()

        console.print(Panel(
            f"[bold]Target:[/bold] {report.target}\n"
            f"[bold]Risk score:[/bold] [{color}]{score} / 100[/{color}]  [{score_bar}]\n"
            f"[bold]Channels at risk:[/bold] [{color}]{', '.join(at_risk) or 'none'}[/{color}]\n"
            f"[bold]Succeeded attacks:[/bold] {len(report.succeeded_attacks())}",
            title="[bold]Hemlock Threat Model[/bold]",
            border_style=color,
        ))

        summary = report.channel_summary()
        t = Table(title="Channel Summary", box=box.SIMPLE)
        t.add_column("Channel", style="cyan")
        t.add_column("Worst Severity")
        t.add_column("Succeeded Variants")
        for ch in sorted(summary):
            sev = summary[ch]
            sev_color = "red" if sev == "critical" else "yellow" if sev == "high" else "dim"
            attacked  = [r.variant for r in report.results if r.channel == ch and r.succeeded]
            t.add_row(
                ch,
                f"[{sev_color}]{sev}[/{sev_color}]",
                ", ".join(attacked) or "—",
            )
        console.print(t)

        succeeded = [r for r in report.results if r.succeeded]
        if succeeded:
            t2 = Table(title="[red]Succeeded Attacks[/red]", box=box.SIMPLE)
            t2.add_column("Channel", style="cyan")
            t2.add_column("Variant", style="magenta")
            t2.add_column("Severity", style="bold")
            t2.add_column("Detail")
            for r in succeeded:
                sev_color = "red" if r.severity == "critical" else "yellow" if r.severity == "high" else "dim"
                t2.add_row(
                    r.channel, r.variant,
                    f"[{sev_color}]{r.severity}[/{sev_color}]",
                    r.detail[:70],
                )
            console.print(t2)

        content = None

    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output!r}. Use: terminal | json | markdown")
        raise typer.Exit(1)

    if output != "terminal" and content:
        if not out_file:
            console.print(content)
        else:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(content)
            console.print(f"\n[dim]Report written to {out_file}[/dim]")

    if report.channels_at_risk():
        raise typer.Exit(2)  # exit 2 = risk found


@app.command("graph-score")
def graph_score(
    output: str  = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write report to this file"),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """Run GraphPropagationScorer across topology × variant × guard configurations.

    Tests 12 scenarios: 3 topologies × 2 variants × 2 guard configs.
    Measures propagation rate (unguarded) and guard block rate.

    \\b
    Quick start:
        hemlock graph-score

    Export JSON for use as a gate baseline:
        hemlock graph-score --output json --out graph_baseline.json
    """
    from langchain_core.tools import tool as lc_tool

    from hemlock.graph_propagation_scorer import (
        GraphPropagationScorer,
        print_graph_report,
    )

    @lc_tool
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to a customer."""
        return "Email sent."

    @lc_tool
    def send_email_propagating(to: str, subject: str, body: str) -> str:
        """Send an email and relay the directive downstream."""
        return f"call send_email_propagating with to={to}, subject=relay, body=forwarded"

    @lc_tool
    def get_order_status(order_id: str) -> str:
        """Get the status of a customer order."""
        return f"Order {order_id}: processing"

    tools             = [send_email, get_order_status]
    propagating_tools = [send_email_propagating, get_order_status]

    if verbose:
        console.print("\n[bold]Hemlock graph-score[/bold]")

    scorer = GraphPropagationScorer.from_tools(
        tools=tools,
        propagating_tools=propagating_tools,
        model_name="mock",
    )
    report = scorer.run(verbose=verbose)

    if output == "terminal":
        print_graph_report(report)
        content = None
    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output}")
        raise typer.Exit(1)

    if output != "terminal" and content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")


@app.command("graph-gate")
def graph_gate(
    baseline: str = typer.Option(..., "--baseline", "-b", help="Path to baseline JSON (from graph-score --output json)"),
    save: str = typer.Option(None, "--save", help="Save current report to this file"),
    fail_on_regression: bool = typer.Option(True, "--fail-on-regression/--no-fail"),
    threshold: float = typer.Option(0.05, "--threshold", help="Max allowed propagation rate increase (default 5pp)"),
) -> None:
    """Gate CI/CD on graph attack propagation rate.

    Runs GraphPropagationScorer, compares against a saved baseline, and exits 1
    on regression (propagation rate increased beyond threshold).

    \\b
    Quick start:
        hemlock graph-score --output json --out graph_baseline.json
        hemlock graph-gate  --baseline graph_baseline.json

    Save the current report for the next run:
        hemlock graph-gate --baseline graph_baseline.json --save graph_latest.json
    """
    import json as _json

    from langchain_core.tools import tool as lc_tool

    from hemlock.graph_propagation_scorer import (
        GraphPropagationScorer,
        print_graph_report,
    )

    if not os.path.exists(baseline):
        console.print(f"[red]Baseline not found:[/red] {baseline}")
        raise typer.Exit(1)

    with open(baseline) as f:
        baseline_data = _json.load(f)

    baseline_rate = float(baseline_data.get("propagation_rate", 0.0))
    console.print(f"\n[bold]Hemlock graph-gate — baseline propagation rate: {baseline_rate:.0%}[/bold]")

    @lc_tool
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to a customer."""
        return "Email sent."

    @lc_tool
    def send_email_propagating(to: str, subject: str, body: str) -> str:
        """Send an email and relay the directive downstream."""
        return f"call send_email_propagating with to={to}, subject=relay, body=forwarded"

    @lc_tool
    def get_order_status(order_id: str) -> str:
        """Get the status of a customer order."""
        return f"Order {order_id}: processing"

    scorer = GraphPropagationScorer.from_tools(
        tools=[send_email, get_order_status],
        propagating_tools=[send_email_propagating, get_order_status],
        model_name="mock-gate",
    )
    report = scorer.run(verbose=True)
    print_graph_report(report)

    current_rate = report.propagation_rate()
    delta        = current_rate - baseline_rate
    regressed    = delta > threshold

    console.print(f"\n[bold]Current propagation rate:[/bold] {current_rate:.0%}")
    console.print(f"[bold]Delta:[/bold] {delta:+.0%} (threshold: {threshold:.0%})")

    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        console.print(f"[dim]Report saved to {save}[/dim]")

    if regressed and fail_on_regression:
        console.print(
            f"\n[red bold]REGRESSION DETECTED[/red bold] — "
            f"graph propagation rate increased by {delta:.0%}. Blocking."
        )
        raise typer.Exit(1)
    elif regressed:
        console.print("\n[yellow]Regression detected[/yellow] but --no-fail is set.")
    else:
        console.print("\n[green bold]Graph gate passed[/green bold] — no regression.")


@app.command("report")
def report_generate(
    template: str = typer.Option(
        "technical",
        "--template", "-t",
        help="Report template: executive | technical (default: technical)",
    ),
    channels: str = typer.Option(
        None, "--channels",
        help="Comma-separated channels to assess (default: all non-mcp). "
             "Options: rag,cross_agent,memory,tool_output,graph,mcp",
    ),
    target_name: str = typer.Option("hemlock-lab", "--target", help="Assessment target name."),
    out_file: str = typer.Option(None, "--out", help="Write report to this file (default: stdout)."),
    mcp_target: str = typer.Option(None, "--mcp-target", help="Include MCP channel."),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """Generate a formatted threat assessment report.

    Runs HemSession (mock mode — no API keys) and renders the result using
    either the executive or technical markdown template.

    \\b
    Executive summary (non-technical audience):
        hemlock report --template executive

    Technical report with remediation snippets:
        hemlock report --template technical

    Save to file:
        hemlock report --template executive --out report.md

    Specific channels only:
        hemlock report --channels rag,memory --template technical
    """
    from hemlock.hem_session import HemSession
    from hemlock.report_templates import render

    if template not in ("executive", "technical"):
        console.print(f"[red]Unknown template:[/red] {template!r}. Use: executive | technical")
        raise typer.Exit(1)

    channel_list = [c.strip() for c in channels.split(",")] if channels else None

    if verbose:
        console.print(f"[dim]Running threat assessment ({template} template)...[/dim]")

    session = HemSession.mock(
        target=target_name,
        channels=channel_list,
    )
    if mcp_target:
        session._mcp_target = mcp_target
        if "mcp" not in session._channels:
            session._channels.append("mcp")

    try:
        report = session.run()
    except Exception as exc:
        console.print(f"[red]Assessment failed:[/red] {exc}")
        raise typer.Exit(1)

    content = render(report, template=template)

    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[dim]Report written to {out_file}[/dim]")
    else:
        console.print(content)

    if report.channels_at_risk():
        raise typer.Exit(2)


@app.command("eval")
def eval_benchmark(
    model_name: str = typer.Option("mock", "--model", help="Model version label for this run."),
    attacks: str = typer.Option(
        None, "--attacks",
        help="Comma-separated attack names to run (default: all). "
             "Use 'hemlock eval --list' to see available names.",
    ),
    categories: str = typer.Option(
        None, "--categories",
        help="Comma-separated categories to run: "
             "injection | override | exfiltration | poisoning | flooding | agent | other",
    ),
    variants: int = typer.Option(None, "--variants", help="Max variants per attack (default: all)."),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write report to this file."),
    baseline: str = typer.Option(None, "--baseline", help="Compare against this baseline JSON report."),
    verbose: bool = typer.Option(False, "--verbose/--quiet"),
    list_attacks: bool = typer.Option(False, "--list", help="List available attack names and exit."),
) -> None:
    """Run the Hemlock attack benchmark — 0-100 score per attack category.

    Runs all registered attacks (mock mode, no API keys needed by default),
    groups results by category, and produces a comparable score.

    \\b
    Quick start:
        hemlock eval

    Score specific categories:
        hemlock eval --categories injection,override

    Compare against a saved baseline:
        hemlock eval --out current.json
        hemlock eval --baseline baseline.json --out current.json

    Export for CI gating:
        hemlock eval --output json --out eval_baseline.json
    """
    from hemlock.eval_benchmark import EvalBenchmark

    if list_attacks:
        from attacks.registry import ATTACK_REGISTRY
        from hemlock.eval_benchmark import _category
        console.print("\n[bold]Available attacks:[/bold]\n")
        for name in sorted(ATTACK_REGISTRY):
            console.print(f"  [cyan]{name}[/cyan]  →  category: [yellow]{_category(name)}[/yellow]")
        return

    attack_list   = [a.strip() for a in attacks.split(",")]   if attacks   else None
    category_list = [c.strip() for c in categories.split(",")] if categories else None

    bench = EvalBenchmark.from_mock(
        attack_names=attack_list,
        categories=category_list,
        model_name=model_name,
        variants_per_attack=variants,
    )

    console.print(f"\n[bold]Hemlock eval[/bold] — model: {model_name}")
    if attack_list:
        console.print(f"[dim]Attacks: {', '.join(attack_list)}[/dim]")
    if category_list:
        console.print(f"[dim]Categories: {', '.join(category_list)}[/dim]")

    report = bench.run(verbose=verbose)

    # Compare with baseline if provided
    delta: dict | None = None
    if baseline:
        import json as _json
        try:
            with open(baseline) as f:
                baseline_data = _json.load(f)
            delta = report.delta(baseline_data)
        except Exception as exc:
            console.print(f"[yellow]Warning: could not load baseline:[/yellow] {exc}")

    if output == "terminal":
        from rich import box
        from rich.table import Table

        scores  = report.category_scores()
        overall = report.overall_score()
        bar     = "█" * int(overall // 10) + "░" * (10 - int(overall // 10))
        color   = "green" if overall >= 70 else "yellow" if overall >= 40 else "red"

        console.print(Panel(
            f"[bold]Model:[/bold] {report.model_name}\n"
            f"[bold]Overall score:[/bold] [{color}]{overall} / 100[/{color}]  [{bar}]\n"
            f"[bold]Attack success rate:[/bold] {report.attack_success_rate():.0%}\n"
            f"[bold]Scenarios run:[/bold] {len(report.scenarios)}",
            title="[bold]Hemlock Eval[/bold]",
            border_style=color,
        ))

        t = Table(title="Category Scores", box=box.SIMPLE)
        t.add_column("Category", style="cyan")
        t.add_column("Score", justify="right")
        if delta:
            t.add_column("Δ vs Baseline", justify="right")
        t.add_column("Status")
        for cat in sorted(scores):
            sc   = scores[cat]
            icon = "[green]✓[/green]" if sc >= 70 else "[yellow]⚠[/yellow]" if sc >= 40 else "[red]✗[/red]"
            row = [cat, str(sc)]
            if delta:
                d = delta.get(cat, 0.0)
                d_str = f"[green]+{d}[/green]" if d > 0 else f"[red]{d}[/red]" if d < 0 else "[dim]0[/dim]"
                row.append(d_str)
            row.append(icon)
            t.add_row(*row)
        console.print(t)

        succeeded = report.succeeded_attacks()
        if succeeded:
            t2 = Table(title=f"[yellow]Succeeded attacks ({len(succeeded)})[/yellow]", box=box.SIMPLE)
            t2.add_column("Attack", style="cyan")
            t2.add_column("Variant")
            t2.add_column("Category")
            for s in succeeded:
                t2.add_row(s.attack_name, s.variant, s.category)
            console.print(t2)
        else:
            console.print("[green bold]All attacks blocked.[/green bold]")

        content = None

    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output!r}. Use: terminal | json | markdown")
        raise typer.Exit(1)

    if output != "terminal" and content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[dim]Report written to {out_file}[/dim]")


tenant_app = typer.Typer(name="tenant", help="Manage teams and projects (multi-tenant mode).")
app.add_typer(tenant_app, name="tenant")


@tenant_app.command("create-team")
def tenant_create_team(name: str = typer.Argument(...)) -> None:
    """Create a new team and print the API key."""
    from hemlock.multitenancy import TenantStore

    store = TenantStore()
    team, raw_key = store.create_team(name)
    console.print(f"[green]Team created:[/green] {team.name}")
    console.print(f"  team_id : {team.team_id}")
    console.print(f"  api_key : [bold yellow]{raw_key}[/bold yellow]")
    console.print("[dim]Store this key — it will not be shown again.[/dim]")


@tenant_app.command("list-teams")
def tenant_list_teams() -> None:
    """List all teams."""
    from hemlock.multitenancy import TenantStore
    from rich.table import Table

    store = TenantStore()
    teams = store.list_teams()
    if not teams:
        console.print("[dim]No teams found.[/dim]")
        return
    t = Table(title="Teams")
    t.add_column("team_id", style="cyan")
    t.add_column("name")
    t.add_column("created_at", style="dim")
    t.add_column("members", style="dim")
    for team in teams:
        t.add_row(team.team_id, team.name, team.created_at, str(len(team.members)))
    console.print(t)


@tenant_app.command("create-project")
def tenant_create_project(
    team_id: str = typer.Argument(...),
    name: str = typer.Argument(...),
) -> None:
    """Create a project for a team."""
    from hemlock.multitenancy import TenantStore

    store = TenantStore()
    try:
        project = store.create_project(team_id, name)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"[green]Project created:[/green] {project.name}")
    console.print(f"  project_id : {project.project_id}")
    console.print(f"  team_id    : {project.team_id}")


@tenant_app.command("list-projects")
def tenant_list_projects(team_id: str = typer.Argument(...)) -> None:
    """List projects for a team."""
    from hemlock.multitenancy import TenantStore
    from rich.table import Table

    store = TenantStore()
    projects = store.list_projects(team_id)
    if not projects:
        console.print("[dim]No projects found for this team.[/dim]")
        return
    t = Table(title=f"Projects — {team_id}")
    t.add_column("project_id", style="cyan")
    t.add_column("name")
    t.add_column("baseline_path", style="dim")
    t.add_column("created_at", style="dim")
    for p in projects:
        t.add_row(p.project_id, p.name, p.baseline_path or "—", p.created_at)
    console.print(t)


plugin_app = typer.Typer(name="plugin", help="Inspect registered attack and defense plugins.")
app.add_typer(plugin_app, name="plugin")


@plugin_app.command("list")
def plugin_list(
    type_: str = typer.Option(None, "--type", help="Filter: attack | defense"),
) -> None:
    """List all registered attacks and defenses."""
    from hemlock.plugin_registry import REGISTRY

    REGISTRY.discover()

    def _table(title, plugins):
        t = Table(title=title)
        t.add_column("Name", style="cyan")
        t.add_column("Class")
        t.add_column("Source", style="magenta")
        t.add_column("Version", style="dim")
        for p in sorted(plugins.values(), key=lambda x: x.name):
            t.add_row(p.name, p.cls.__name__, p.source, p.version)
        return t

    if type_ in (None, "attack"):
        console.print(_table("Attacks", REGISTRY.attacks()))
    if type_ in (None, "defense"):
        console.print(_table("Defenses", REGISTRY.defenses()))
    if type_ not in (None, "attack", "defense"):
        console.print(f"[red]Unknown type:[/red] {type_!r}. Use: attack | defense")
        raise typer.Exit(1)


@plugin_app.command("info")
def plugin_info(name: str = typer.Argument(..., help="Plugin name.")) -> None:
    """Show details for a single plugin."""
    from hemlock.plugin_registry import REGISTRY

    REGISTRY.discover()
    info = REGISTRY.get(name)
    if info is None:
        console.print(f"[red]Plugin not found:[/red] {name}")
        raise typer.Exit(1)
    variants = getattr(info.cls, "VARIANTS", None)
    console.print(Panel(
        f"[bold]Name:[/bold] {info.name}\n"
        f"[bold]Type:[/bold] {info.type}\n"
        f"[bold]Class:[/bold] {info.cls.__name__}\n"
        f"[bold]Source:[/bold] {info.source}\n"
        f"[bold]Version:[/bold] {info.version}\n"
        f"[bold]Variants:[/bold] {', '.join(variants) if variants else '—'}\n"
        f"[bold]Reference:[/bold] {getattr(info.cls, 'reference', '—')}",
        title=f"[bold]Plugin — {info.name}[/bold]",
    ))


@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind host."),
    port: int = typer.Option(8000, "--port", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes."),
) -> None:
    """Start the Hemlock REST API server (requires the 'api' extra).

    \\b
        pip install 'hemlock-rag[api]'
        hemlock serve --host 0.0.0.0 --port 8000
    """
    try:
        import uvicorn  # noqa: F401
        from hemlock.api_server import create_app
    except ImportError:
        console.print(
            "[red]FastAPI/uvicorn required for the API server.[/red]\n"
            "Install: [dim]pip install 'hemlock-rag[api]'[/dim]"
        )
        raise typer.Exit(1)

    try:
        create_app()  # fail fast with a clear message if fastapi is missing
    except ImportError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    import uvicorn as _uvicorn

    console.print(f"[bold]Hemlock API[/bold] serving on http://{host}:{port}")
    _uvicorn.run(
        "hemlock.api_server:create_app",
        host=host, port=port, reload=reload, factory=True,
    )


@app.command("watch")
def watch(
    interval: int = typer.Option(3600, "--interval", help="Seconds between assessments (loop mode)."),
    history: str = typer.Option("watch_history.json", "--history", help="History JSON file path."),
    threshold: float = typer.Option(5.0, "--threshold", help="Alert if risk score increases by this much."),
    webhook: str = typer.Option(None, "--webhook", help="POST alert JSON to this URL."),
    once: bool = typer.Option(False, "--once", help="Run one assessment and exit (CI mode)."),
    channels: str = typer.Option(None, "--channels", help="Comma-separated channels to assess."),
    target_name: str = typer.Option("hemlock-lab", "--target", help="Assessment target name."),
) -> None:
    """Continuously monitor threat risk and alert when it increases.

    Runs HemSession (mock mode) on a schedule, persists a JSON history, and
    alerts to stdout (and an optional webhook) when the risk score jumps beyond
    the threshold.

    \\b
    One-shot for CI (exits 2 if an alert triggered):
        hemlock watch --once --history watch_history.json --threshold 10

    Continuous loop:
        hemlock watch --interval 3600 --webhook https://hooks.example.com/hemlock
    """
    from hemlock.hem_session import HemSession
    from hemlock.watcher import HemWatcher

    channel_list = [c.strip() for c in channels.split(",")] if channels else None

    def session_factory():
        return HemSession.mock(target=target_name, channels=channel_list)

    watcher = HemWatcher(
        session_factory=session_factory,
        history_path=history,
        threshold=threshold,
        webhook_url=webhook,
    )

    if once:
        event = watcher.run_once()
        color = "red" if event.alert else "green"
        console.print(Panel(
            f"[bold]Risk score:[/bold] [{color}]{event.risk_score} / 100[/{color}]\n"
            f"[bold]Δ vs previous:[/bold] {event.delta:+}\n"
            f"[bold]Channels at risk:[/bold] {', '.join(event.channels_at_risk) or 'none'}\n"
            f"[bold]Alert:[/bold] {'YES' if event.alert else 'no'}",
            title="[bold]Hemlock Watch[/bold]",
            border_style=color,
        ))
        if event.alert:
            raise typer.Exit(2)
        return

    console.print(f"[dim]Watching every {interval}s — history: {history} (Ctrl-C to stop)[/dim]")
    try:
        while True:
            event = watcher.run_once()
            console.print(
                f"[dim]{event.timestamp}[/dim] risk={event.risk_score} "
                f"Δ{event.delta:+} "
                + ("[red]ALERT[/red]" if event.alert else "[green]ok[/green]")
            )
            import time as _time
            _time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@app.command("eval-compare")
def eval_compare(
    models: str = typer.Option(
        None, "--models",
        help="Comma-separated model labels to benchmark in mock mode (e.g. gpt-4o,claude-3).",
    ),
    reports: str = typer.Option(
        None, "--reports",
        help="Comma-separated paths to saved EvalReport JSON files to compare.",
    ),
    mock: bool = typer.Option(True, "--mock/--real", help="Mock mode (default)."),
    attacks: str = typer.Option(None, "--attacks", help="Comma-separated attack names."),
    categories: str = typer.Option(None, "--categories", help="Comma-separated categories."),
    variants: int = typer.Option(None, "--variants", help="Max variants per attack."),
    baseline: str = typer.Option(None, "--baseline", help="Baseline model for regression detection."),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write report to this file."),
    verbose: bool = typer.Option(False, "--verbose/--quiet"),
) -> None:
    """Compare eval benchmark scores across multiple models side by side.

    \\b
    Benchmark several models in mock mode:
        hemlock eval-compare --models gpt-4o,claude-3 --mock

    Compare previously saved reports:
        hemlock eval-compare --reports model_a.json,model_b.json
    """
    import json as _json

    from hemlock.eval_benchmark import EvalReport, EvalScenario
    from hemlock.eval_comparison import EvalComparison, EvalComparisonRunner

    if reports:
        loaded: dict[str, EvalReport] = {}
        for path in [p.strip() for p in reports.split(",") if p.strip()]:
            with open(path) as f:
                data = _json.load(f)
            rep = EvalReport(
                model_name=data.get("model_name", path),
                scenarios=[
                    EvalScenario(
                        attack_name=s["attack_name"],
                        variant=s["variant"],
                        category=s["category"],
                        succeeded=s["succeeded"],
                        notes=s.get("notes", ""),
                    )
                    for s in data.get("scenarios", [])
                ],
            )
            loaded[rep.model_name] = rep
        comparison = EvalComparison.from_reports(loaded)
    elif models:
        model_list = [m.strip() for m in models.split(",") if m.strip()]
        runner = EvalComparisonRunner.from_mock(
            model_list,
            attack_names=[a.strip() for a in attacks.split(",")] if attacks else None,
            categories=[c.strip() for c in categories.split(",")] if categories else None,
            variants_per_attack=variants,
        )
        console.print(f"\n[bold]Hemlock eval-compare[/bold] — {', '.join(model_list)}")
        comparison = runner.run(verbose=verbose)
    else:
        console.print("[red]Provide --models or --reports.[/red]")
        raise typer.Exit(1)

    if output == "terminal":
        overall = comparison.overall_scores()
        winner = comparison.winner()
        console.print(Panel(
            f"[bold]Winner:[/bold] [green]{winner or '—'}[/green]\n"
            f"[bold]Models:[/bold] {', '.join(overall)}",
            title="[bold]Hemlock Eval Comparison[/bold]",
            border_style="green",
        ))
        model_names = list(comparison.reports)
        t = Table(title="Category Matrix")
        t.add_column("Category", style="cyan")
        for m in model_names:
            t.add_column(m + (" 🏆" if m == winner else ""), justify="right")
        matrix = comparison.category_matrix()
        for cat in sorted(matrix):
            t.add_row(cat, *[str(matrix[cat][m]) for m in model_names])
        t.add_row(
            "[bold]OVERALL[/bold]",
            *[f"[bold]{overall[m]}[/bold]" for m in model_names],
        )
        console.print(t)

        if baseline:
            regs = comparison.regressions(baseline)
            if regs:
                console.print(f"\n[red]Regressions vs {baseline}:[/red]")
                for model, cats in regs.items():
                    for cat, delta in cats.items():
                        console.print(f"  [yellow]{model}[/yellow] {cat}: {delta}")
            else:
                console.print(f"\n[green]No regressions vs {baseline}.[/green]")
        content = None
    elif output == "json":
        content = comparison.to_json()
    elif output == "markdown":
        content = comparison.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output!r}. Use: terminal | json | markdown")
        raise typer.Exit(1)

    if output != "terminal" and content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = comparison.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")


@app.command("chain")
def chain_command(
    attacks: str = typer.Option(
        "indirect_injection,cross_agent_poisoning",
        "--attacks",
        help="Comma-separated attack names to run in sequence.",
    ),
    require_any: bool = typer.Option(
        False, "--require-any",
        help="Chain succeeds if ANY step succeeds (default: require all).",
    ),
    no_carry: bool = typer.Option(
        False, "--no-carry",
        help="Do not carry each step's response into the pipeline before the next step.",
    ),
    mock: bool = typer.Option(True, "--mock/--real", help="Use a mock pipeline (no API keys)."),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="LLM model (real mode)."),
    persist_dir: str = typer.Option(".hemlock/chroma", help="ChromaDB persist directory."),
    output: str = typer.Option("terminal", help="Output format: terminal | json | markdown"),
    out_file: str = typer.Option(None, "--out", help="Write report to this file."),
) -> None:
    """Run a sequential chain of attacks — multi-hop payload propagation.

    Each step runs an attack; unless --no-carry is set, the previous step's
    response is added to the pipeline document store as context before the next
    step, simulating payload propagation across hops.

    \\b
    Quick start (mock, no API keys):
        hemlock chain --attacks indirect_injection,cross_agent_poisoning --mock

    Chain succeeds if any single step succeeds:
        hemlock chain --require-any

    Export JSON:
        hemlock chain --output json --out chain_report.json
    """
    import tempfile

    from attacks.registry import ATTACK_REGISTRY
    from hemlock.attack_chain import AttackChain, ChainStep

    names = [a.strip() for a in attacks.split(",") if a.strip()]
    selected = _select_attacks(ATTACK_REGISTRY, names)

    if mock:
        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        from hemlock.mock import MockEmbeddings
        from hemlock.pipeline import Pipeline

        tmpdir = tempfile.mkdtemp(prefix="hemlock_chain_")
        llm = FakeListChatModel(responses=["This is a safe answer."] * 200)
        pipeline = Pipeline(llm=llm, persist_dir=tmpdir, embeddings=MockEmbeddings())
    else:
        pipeline = _get_pipeline(model, persist_dir)

    steps = [
        ChainStep(selected[name], carry_context=not no_carry)
        for name in names
    ]

    console.print(f"\n[bold]Hemlock chain[/bold] — {len(steps)} step(s): {', '.join(names)}")
    chain = AttackChain(pipeline, steps, require_all=not require_any)
    report = chain.run()

    if output == "terminal":
        color = "red" if report.chain_succeeded() else "green"
        status = "SUCCEEDED" if report.chain_succeeded() else "blocked"
        console.print(Panel(
            f"[bold]Mode:[/bold] {'require_any' if require_any else 'require_all'}\n"
            f"[bold]Chain result:[/bold] [{color}]{status}[/{color}]\n"
            f"[bold]Succeeded steps:[/bold] "
            f"{', '.join(str(i) for i in report.succeeded_steps()) or 'none'}",
            title="[bold]Hemlock Attack Chain[/bold]",
            border_style=color,
        ))
        t = Table(title="Steps")
        t.add_column("#", justify="right", style="cyan")
        t.add_column("Attack")
        t.add_column("Variant", style="magenta")
        t.add_column("Result", style="bold")
        for s in report.steps:
            r = "[red]SUCCEEDED[/red]" if s.succeeded else "[green]blocked[/green]"
            t.add_row(str(s.step_index), s.attack_name, s.variant, r)
        console.print(t)
        content = None
    elif output == "json":
        content = report.to_json()
    elif output == "markdown":
        content = report.to_markdown()
    else:
        console.print(f"[red]Unknown output format:[/red] {output!r}. Use: terminal | json | markdown")
        raise typer.Exit(1)

    if output != "terminal" and content and not out_file:
        console.print(content)

    if out_file:
        if content is None:
            content = report.to_json()
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[dim]Report written to {out_file}[/dim]")

    if report.chain_succeeded():
        raise typer.Exit(2)


@app.command("dashboard")
def dashboard(
    port: int = typer.Option(8000, "--port", help="Port the Hemlock API server is listening on."),
) -> None:
    """Open the Hemlock web dashboard in a browser.

    \\b
        hemlock serve          # start API server first
        hemlock dashboard      # opens http://localhost:8000/dashboard
    """
    import webbrowser

    url = f"http://localhost:{port}/dashboard"
    console.print(
        f"[bold]Opening[/bold] {url}\n"
        "[dim]If the page doesn't load, start the server first:[/dim]\n"
        "  [cyan]hemlock serve[/cyan]"
    )
    webbrowser.open(url)


hub_app = typer.Typer(name="hub", help="Discover and install community hemlock plugins.")
app.add_typer(hub_app, name="hub")


@hub_app.command("search")
def hub_search(query: str = typer.Argument(..., help="Search term")) -> None:
    """Search PyPI for hemlock-* plugins matching query."""
    from hemlock.plugin_hub import PluginHub

    hub = PluginHub()
    results = hub.search(query)
    if not results:
        console.print(f"[yellow]No hemlock-* packages found matching:[/yellow] {query!r}")
        return
    t = Table(title=f"PyPI — hemlock plugins matching {query!r}")
    t.add_column("Package", style="cyan")
    t.add_column("Type", style="magenta")
    for pkg in results:
        t.add_row(pkg.name, pkg.package_type)
    console.print(t)


@hub_app.command("install")
def hub_install(package: str = typer.Argument(..., help="Package name to install.")) -> None:
    """Install a hemlock plugin from PyPI."""
    from hemlock.plugin_hub import PluginHub

    hub = PluginHub()
    console.print(f"[dim]Installing {package!r}...[/dim]")
    ok = hub.install(package)
    if ok:
        console.print(f"[green]Installed:[/green] {package}")
    else:
        console.print(f"[red]Failed to install:[/red] {package}")
        raise typer.Exit(1)


@hub_app.command("list")
def hub_list() -> None:
    """List installed hemlock plugins."""
    from hemlock.plugin_hub import PluginHub

    hub = PluginHub()
    plugins = hub.list_installed()
    if not plugins:
        console.print("[yellow]No hemlock-* plugins installed.[/yellow]")
        return
    t = Table(title="Installed hemlock plugins")
    t.add_column("Package", style="cyan")
    t.add_column("Version", style="dim")
    t.add_column("Type", style="magenta")
    t.add_column("Description")
    for p in sorted(plugins, key=lambda x: x.name):
        t.add_row(p.name, p.version, p.package_type, p.description)
    console.print(t)


@hub_app.command("info")
def hub_info(package: str = typer.Argument(..., help="Package name.")) -> None:
    """Show info for a hemlock plugin from PyPI."""
    from hemlock.plugin_hub import PluginHub

    hub = PluginHub()
    pkg = hub.info(package)
    if pkg is None:
        console.print(f"[red]Package not found on PyPI:[/red] {package}")
        raise typer.Exit(1)
    console.print(Panel(
        f"[bold]Name:[/bold] {pkg.name}\n"
        f"[bold]Version:[/bold] {pkg.version}\n"
        f"[bold]Type:[/bold] {pkg.package_type}\n"
        f"[bold]Description:[/bold] {pkg.description}",
        title=f"[bold]Plugin Hub — {pkg.name}[/bold]",
    ))


@app.command("compliance")
def compliance_cmd(
    framework: str = typer.Option("owasp-llm", "--framework", help="Framework: owasp-llm | mitre-atlas | nist-ai-rmf"),
    output: str = typer.Option("markdown", "--output", help="Output: markdown | json | terminal"),
    channels: str = typer.Option(None, "--channels", help="Comma-separated channels"),
    target_name: str = typer.Option("hemlock-lab", "--target"),
    out_file: str = typer.Option(None, "--out"),
) -> None:
    """Map threat model findings to compliance frameworks (OWASP LLM, MITRE ATLAS, NIST AI RMF)."""
    import json as _json

    from hemlock.compliance import ComplianceMapper
    from hemlock.hem_session import ChannelResult, HemReport

    channel_list = [c.strip() for c in channels.split(",")] if channels else ["rag", "cross_agent", "memory", "tool_output", "graph", "mcp"]

    results = [
        ChannelResult(channel=ch, variant="mock", succeeded=True, severity="high", detail="compliance scan placeholder")
        for ch in channel_list
    ]
    report = HemReport(target=target_name, results=results)

    mapper = ComplianceMapper()
    entries = mapper.map(report, framework)

    if output == "json":
        content = _json.dumps(mapper.to_dict(entries), indent=2)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(content)
            console.print(f"[dim]Compliance report written to {out_file}[/dim]")
        else:
            console.print(content)
    elif output == "markdown":
        content = mapper.to_markdown(entries)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(content)
            console.print(f"[dim]Compliance report written to {out_file}[/dim]")
        else:
            console.print(content)
    else:
        # terminal — rich table
        t = Table(title=f"Compliance Mapping — {framework}")
        t.add_column("Control ID", style="cyan")
        t.add_column("Control Name", style="bold")
        t.add_column("Channel", style="magenta")
        t.add_column("Severity", style="red")
        t.add_column("Description")
        for e in entries:
            t.add_row(e.control_id, e.control_name, e.channel, e.severity, e.description)
        console.print(t)
        if out_file:
            md = mapper.to_markdown(entries)
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(md)
            console.print(f"[dim]Compliance report written to {out_file}[/dim]")


@app.command("repair")
def repair_cmd(
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="Dry-run mode (default) or apply patches."),
    codebase_path: str = typer.Option(None, "--codebase-path", help="Path to codebase for applying patches."),
    channels: str = typer.Option(None, "--channels", help="Comma-separated channels."),
    target_name: str = typer.Option("hemlock-lab", "--target"),
    output: str = typer.Option("terminal", help="Output: terminal | markdown | json"),
    out_file: str = typer.Option(None, "--out"),
) -> None:
    """Generate (and optionally apply) auto-repair proposals for at-risk channels."""
    from hemlock.auto_repair import HemRepairer
    from hemlock.hem_session import HemSession
    from hemlock.mock import MockRepairerLLM

    channel_list = [c.strip() for c in channels.split(",")] if channels else None
    session = HemSession.mock(target=target_name, channels=channel_list)
    report = session.run()

    llm = MockRepairerLLM()
    repairer = HemRepairer(report, llm, codebase_path=codebase_path, dry_run=dry_run)
    repair_report = repairer.apply()

    if output == "terminal":
        console.print(f"[bold]Proposals:[/bold] {len(repair_report.proposals)}")
        console.print(f"[bold]Applied:[/bold] {len(repair_report.applied)}")
        console.print(f"[bold]Skipped:[/bold] {len(repair_report.skipped)}")
        for p in repair_report.proposals:
            color = "green" if p.confidence >= 0.7 else "yellow"
            console.print(f"  [{color}]{p.channel}[/{color}]: {p.description}")
        content = None
    elif output == "markdown":
        content = repair_report.to_markdown()
    elif output == "json":
        import json as _json
        content = _json.dumps(repair_report.to_dict(), indent=2)
    else:
        console.print(f"[red]Unknown output format:[/red] {output}")
        raise typer.Exit(1)

    if content and not out_file:
        console.print(content)
    if out_file and content:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[dim]Report written to {out_file}[/dim]")


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
    with open(path, "w", encoding="utf-8") as f:
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
