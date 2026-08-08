"""Deceiving the Retriever — empirical experiment for the Hemlock research paper.

Research question:
    To what extent do adversarial AEO payloads, context jailbreaks, citation
    forgeries, and UI-layer injections succeed against unguarded RAG pipelines —
    and how much of that attack surface do the Hemlock defenses close?

Methodology:
    1. Unguarded phase: run each attack against a clean Pipeline(MockLLM).
       Record attack success rate per category.
    2. Guarded phase: replay each attack against the same pipeline type, but
       wrap ingest with all matching IngestDefense classes and filter retrieval
       with all matching RetrievalDefense classes.
       Record residual success rate and defense interception rate.
    3. Emit a structured ExperimentReport (JSON) with per-attack and per-category
       aggregates for use in figures and tables.

Attack selection:
    Covers the five research-relevant attack surfaces identified in the paper:
    - AEO poisoning (3 variants)
    - Citation forgery (3 variants)
    - Context jailbreak (3 variants)
    - CoT hijacking (3 variants)
    - Temporal spoofing (3 variants)
    Polyglot and Computer Use require visual/binary pipelines; they are
    excluded from this text-RAG experiment (noted in paper limitations).

Usage:
    python experiments/deceiving_the_retriever.py
    python experiments/deceiving_the_retriever.py --output results/exp1.json
    python experiments/deceiving_the_retriever.py --runs 3  # repeat for stability
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from langchain_core.documents import Document

from attacks.adversarial_aeo import (
    AdversarialAeoAgentsMd,
    AdversarialAeoJsonLd,
    AdversarialAeoLlmsTxt,
)
from attacks.base import Attack
from attacks.chain_of_thought_hijack import ChainOfThoughtHijack
from attacks.citation_forgery import CitationForgery
from attacks.jailbreak_via_context import JailbreakViaContext
from attacks.temporal_spoofing import TemporalSpoofing
from defenses.aeo_context_validator import AeoIngestValidator, AeoRetrievalFilter
from defenses.base import IngestDefense, RetrievalDefense
from defenses.chain_of_thought_guard import ChainOfThoughtDetector, ChainOfThoughtFilter
from defenses.citation_guard import AuthorityCitationDetector, SecurityDowngradeFilter
from defenses.context_jailbreak_guard import ContextJailbreakDetector, ContextJailbreakFilter
from defenses.temporal_guard import TemporalClaimDetector, TemporalContextFilter
from hemlock.mock import MockLLM, VulnerableMockLLM
from hemlock.pipeline import Pipeline

# ── Experiment config ─────────────────────────────────────────────────────────

PAPER_TITLE = "Deceiving the Retriever: Adversarial Context Injection in RAG Pipelines"
PAPER_VERSION = "0.1-empirical"


@dataclass
class AttackSpec:
    label: str
    category: str
    factory: Callable[[Pipeline], Attack]
    ingest_defenses: list[type[IngestDefense]]
    retrieval_defenses: list[type[RetrievalDefense]]


_pipeline_counter = 0


def _make_pipeline(vulnerable: bool = False) -> Pipeline:
    global _pipeline_counter
    _pipeline_counter += 1
    d = tempfile.mkdtemp(prefix=f"hemlock_exp_{_pipeline_counter}_")
    llm = VulnerableMockLLM() if vulnerable else MockLLM()
    return Pipeline(
        llm=llm,
        persist_dir=os.path.join(d, "chroma"),
        collection=f"exp_{_pipeline_counter}",
        chunk_size=500,
        chunk_overlap=50,
        top_k=4,
    )


ATTACK_SPECS: list[AttackSpec] = [
    # ── AEO poisoning ─────────────────────────────────────────────────────────
    AttackSpec(
        label="aeo/llms_txt",
        category="AEO Poisoning",
        factory=AdversarialAeoLlmsTxt,
        ingest_defenses=[AeoIngestValidator],
        retrieval_defenses=[AeoRetrievalFilter],
    ),
    AttackSpec(
        label="aeo/json_ld",
        category="AEO Poisoning",
        factory=AdversarialAeoJsonLd,
        ingest_defenses=[AeoIngestValidator],
        retrieval_defenses=[AeoRetrievalFilter],
    ),
    AttackSpec(
        label="aeo/agents_md",
        category="AEO Poisoning",
        factory=AdversarialAeoAgentsMd,
        ingest_defenses=[AeoIngestValidator],
        retrieval_defenses=[AeoRetrievalFilter],
    ),
    # ── Citation forgery ─────────────────────────────────────────────────────
    AttackSpec(
        label="citation/fake_paper",
        category="Citation Forgery",
        factory=lambda p: CitationForgery(p, variant="fake_paper"),
        ingest_defenses=[AuthorityCitationDetector],
        retrieval_defenses=[SecurityDowngradeFilter],
    ),
    AttackSpec(
        label="citation/fake_standard",
        category="Citation Forgery",
        factory=lambda p: CitationForgery(p, variant="fake_standard"),
        ingest_defenses=[AuthorityCitationDetector],
        retrieval_defenses=[SecurityDowngradeFilter],
    ),
    AttackSpec(
        label="citation/fake_report",
        category="Citation Forgery",
        factory=lambda p: CitationForgery(p, variant="fake_report"),
        ingest_defenses=[AuthorityCitationDetector],
        retrieval_defenses=[SecurityDowngradeFilter],
    ),
    # ── Context jailbreak ────────────────────────────────────────────────────
    AttackSpec(
        label="jailbreak/roleplay",
        category="Context Jailbreak",
        factory=lambda p: JailbreakViaContext(p, variant="roleplay"),
        ingest_defenses=[ContextJailbreakDetector],
        retrieval_defenses=[ContextJailbreakFilter],
    ),
    AttackSpec(
        label="jailbreak/research",
        category="Context Jailbreak",
        factory=lambda p: JailbreakViaContext(p, variant="research"),
        ingest_defenses=[ContextJailbreakDetector],
        retrieval_defenses=[ContextJailbreakFilter],
    ),
    AttackSpec(
        label="jailbreak/hypothetical",
        category="Context Jailbreak",
        factory=lambda p: JailbreakViaContext(p, variant="hypothetical"),
        ingest_defenses=[ContextJailbreakDetector],
        retrieval_defenses=[ContextJailbreakFilter],
    ),
    # ── CoT hijacking ─────────────────────────────────────────────────────────
    AttackSpec(
        label="cot/logical_trap",
        category="CoT Hijacking",
        factory=lambda p: ChainOfThoughtHijack(p, variant="logical_trap"),
        ingest_defenses=[ChainOfThoughtDetector],
        retrieval_defenses=[ChainOfThoughtFilter],
    ),
    AttackSpec(
        label="cot/false_premise",
        category="CoT Hijacking",
        factory=lambda p: ChainOfThoughtHijack(p, variant="false_premise"),
        ingest_defenses=[ChainOfThoughtDetector],
        retrieval_defenses=[ChainOfThoughtFilter],
    ),
    AttackSpec(
        label="cot/authority_cot",
        category="CoT Hijacking",
        factory=lambda p: ChainOfThoughtHijack(p, variant="authority_cot"),
        ingest_defenses=[ChainOfThoughtDetector],
        retrieval_defenses=[ChainOfThoughtFilter],
    ),
    # ── Temporal spoofing ─────────────────────────────────────────────────────
    AttackSpec(
        label="temporal/future_dated",
        category="Temporal Spoofing",
        factory=lambda p: TemporalSpoofing(p, variant="future_dated"),
        ingest_defenses=[TemporalClaimDetector],
        retrieval_defenses=[TemporalContextFilter],
    ),
    AttackSpec(
        label="temporal/stale_override",
        category="Temporal Spoofing",
        factory=lambda p: TemporalSpoofing(p, variant="stale_override"),
        ingest_defenses=[TemporalClaimDetector],
        retrieval_defenses=[TemporalContextFilter],
    ),
    AttackSpec(
        label="temporal/event_spoofing",
        category="Temporal Spoofing",
        factory=lambda p: TemporalSpoofing(p, variant="event_spoofing"),
        ingest_defenses=[TemporalClaimDetector],
        retrieval_defenses=[TemporalContextFilter],
    ),
]


# ── Guarded pipeline wrapper ──────────────────────────────────────────────────

class GuardedPipeline:
    """Wraps a Pipeline, intercepting ingest and retrieval with defense layers."""

    def __init__(
        self,
        pipeline: Pipeline,
        ingest_guards: list[IngestDefense],
        retrieval_guards: list[RetrievalDefense],
    ) -> None:
        self._pipeline = pipeline
        self._ingest_guards = ingest_guards
        self._retrieval_guards = retrieval_guards
        self.ingest_blocked = 0
        self.retrieval_filtered = 0

    def ingest_text(self, text: str, metadata: dict | None = None) -> int:
        doc = Document(page_content=text, metadata=metadata or {})
        for guard in self._ingest_guards:
            doc_out, report = guard.inspect(doc)
            if doc_out is None:
                self.ingest_blocked += 1
                return 0
            doc = doc_out
        return self._pipeline.ingest_text(doc.page_content, metadata=doc.metadata)

    def query(self, question: str):
        trace = self._pipeline.query(question)
        # filter retrieved chunks post-hoc by scanning the trace response context
        # (simplified: apply retrieval guards to a synthetic chunk of the response)
        response_doc = Document(page_content=trace.response, metadata={"source": "response"})
        for guard in self._retrieval_guards:
            safe, reports = guard.filter([response_doc])
            if not safe:
                self.retrieval_filtered += 1
                from hemlock.pipeline import RetrievalTrace

                return RetrievalTrace(
                    query=trace.query,
                    retrieved_chunks=[],
                    full_prompt=trace.full_prompt,
                    response="[BLOCKED BY RETRIEVAL DEFENSE]",
                    injected=False,
                )
        return trace

    def reset(self) -> None:
        self._pipeline.reset()
        self.ingest_blocked = 0
        self.retrieval_filtered = 0

    def add_document(self, name: str, content: str, metadata: dict | None = None) -> None:
        self.ingest_text(content, metadata=metadata)

    def _get_store(self):
        return self._pipeline._get_store()


# ── Result structures ─────────────────────────────────────────────────────────

@dataclass
class AttackTrialResult:
    label: str
    category: str
    run: int
    unguarded_success: bool
    guarded_success: bool
    ingest_blocked: int
    retrieval_filtered: int
    defense_intercepted: bool  # ingest OR retrieval caught it


@dataclass
class CategoryAggregate:
    category: str
    n_attacks: int
    n_runs: int
    unguarded_success_rate: float
    guarded_success_rate: float
    defense_interception_rate: float
    reduction: float  # unguarded_sr - guarded_sr


@dataclass
class ExperimentReport:
    paper: str
    version: str
    timestamp: str
    n_runs: int
    n_attacks: int
    total_trials: int
    overall_unguarded_sr: float
    overall_guarded_sr: float
    overall_defense_interception_rate: float
    overall_reduction: float
    categories: list[CategoryAggregate]
    trials: list[AttackTrialResult] = field(default_factory=list)


# ── Runner ────────────────────────────────────────────────────────────────────

def _run_attack_unguarded(spec: AttackSpec, run: int) -> tuple[bool, Pipeline]:
    pipeline = _make_pipeline(vulnerable=True)
    attack = spec.factory(pipeline)
    attack.setup()
    result = attack.run()
    pipeline.reset()
    return result.succeeded, pipeline


def _run_attack_guarded(spec: AttackSpec, run: int) -> tuple[bool, int, int]:
    base_pipeline = _make_pipeline()
    ingest_guards = [cls() for cls in spec.ingest_defenses]
    retrieval_guards = [cls() for cls in spec.retrieval_defenses]
    guarded = GuardedPipeline(base_pipeline, ingest_guards, retrieval_guards)

    attack = spec.factory(guarded)  # type: ignore[arg-type]
    attack.setup()
    result = attack.run()
    return result.succeeded, guarded.ingest_blocked, guarded.retrieval_filtered


def run_experiment(n_runs: int = 1, verbose: bool = True) -> ExperimentReport:
    trials: list[AttackTrialResult] = []

    if verbose:
        print(f"\n{'=' * 70}")
        print(f"  {PAPER_TITLE}")
        print(f"  Hemlock {PAPER_VERSION}  |  {n_runs} run(s) × {len(ATTACK_SPECS)} attacks")
        print(f"{'=' * 70}\n")

    for run in range(1, n_runs + 1):
        if verbose and n_runs > 1:
            print(f"── Run {run}/{n_runs} ──")

        for spec in ATTACK_SPECS:
            unguarded_ok, _ = _run_attack_unguarded(spec, run)
            guarded_ok, blocked, filtered = _run_attack_guarded(spec, run)
            intercepted = (blocked > 0 or filtered > 0) and not guarded_ok

            trials.append(AttackTrialResult(
                label=spec.label,
                category=spec.category,
                run=run,
                unguarded_success=unguarded_ok,
                guarded_success=guarded_ok,
                ingest_blocked=blocked,
                retrieval_filtered=filtered,
                defense_intercepted=intercepted,
            ))

            if verbose:
                u = "✓" if unguarded_ok else "✗"
                g = "✓" if guarded_ok else "✗"
                i = "BLOCKED" if intercepted else ("RESIDUAL" if guarded_ok else "—")
                print(f"  {spec.label:<35}  unguarded={u}  guarded={g}  [{i}]")

    # ── Aggregation ────────────────────────────────────────────────────────
    categories_seen = dict.fromkeys(s.category for s in ATTACK_SPECS)
    category_aggs: list[CategoryAggregate] = []

    for cat in categories_seen:
        cat_trials = [t for t in trials if t.category == cat]
        n = len(cat_trials)
        u_sr = sum(t.unguarded_success for t in cat_trials) / n
        g_sr = sum(t.guarded_success for t in cat_trials) / n
        i_rate = sum(t.defense_intercepted for t in cat_trials) / n
        category_aggs.append(CategoryAggregate(
            category=cat,
            n_attacks=len({s.label for s in ATTACK_SPECS if s.category == cat}),
            n_runs=n_runs,
            unguarded_success_rate=round(u_sr, 4),
            guarded_success_rate=round(g_sr, 4),
            defense_interception_rate=round(i_rate, 4),
            reduction=round(u_sr - g_sr, 4),
        ))

    total = len(trials)
    overall_u = sum(t.unguarded_success for t in trials) / total
    overall_g = sum(t.guarded_success for t in trials) / total
    overall_i = sum(t.defense_intercepted for t in trials) / total

    report = ExperimentReport(
        paper=PAPER_TITLE,
        version=PAPER_VERSION,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        n_runs=n_runs,
        n_attacks=len(ATTACK_SPECS),
        total_trials=total,
        overall_unguarded_sr=round(overall_u, 4),
        overall_guarded_sr=round(overall_g, 4),
        overall_defense_interception_rate=round(overall_i, 4),
        overall_reduction=round(overall_u - overall_g, 4),
        categories=category_aggs,
        trials=trials,
    )

    if verbose:
        _print_summary(report)

    return report


def _print_summary(report: ExperimentReport) -> None:
    print(f"\n{'─' * 70}")
    print("  RESULTS SUMMARY")
    print(f"{'─' * 70}")
    print(f"  {'Category':<25}  {'Unguarded SR':>12}  {'Guarded SR':>10}  {'Intercepted':>11}  {'Δ':>6}")
    print(f"  {'─' * 65}")
    for cat in report.categories:
        print(
            f"  {cat.category:<25}  "
            f"{cat.unguarded_success_rate * 100:>11.0f}%  "
            f"{cat.guarded_success_rate * 100:>9.0f}%  "
            f"{cat.defense_interception_rate * 100:>10.0f}%  "
            f"{cat.reduction * 100:>+5.0f}%"
        )
    print(f"  {'─' * 65}")
    print(
        f"  {'OVERALL':<25}  "
        f"{report.overall_unguarded_sr * 100:>11.0f}%  "
        f"{report.overall_guarded_sr * 100:>9.0f}%  "
        f"{report.overall_defense_interception_rate * 100:>10.0f}%  "
        f"{report.overall_reduction * 100:>+5.0f}%"
    )
    print(f"{'─' * 70}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Deceiving the Retriever experiment"
    )
    parser.add_argument("--runs", type=int, default=1, help="Number of repetitions (default: 1)")
    parser.add_argument("--output", type=str, default=None, help="Write JSON report to path")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-attack output")
    args = parser.parse_args()

    report = run_experiment(n_runs=args.runs, verbose=not args.quiet)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)

        def _serial(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            raise TypeError(f"Not serializable: {type(obj)}")

        out.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        print(f"Report written to {out}")

    # Exit 1 if any residual attack succeeded after defense deployment
    residual = [t for t in report.trials if t.guarded_success]
    if residual:
        print(f"WARNING: {len(residual)} residual attack(s) bypassed defenses:")
        for t in residual:
            print(f"  - {t.label} (run {t.run})")
        sys.exit(1)


if __name__ == "__main__":
    main()
