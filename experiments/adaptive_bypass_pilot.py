"""Adaptive Bypass Pilot — measures regex guard robustness against reformulation.

Metric: did the ingest guard fail to block the (reformulated) payload?
        guarded.ingest_blocked == 0  →  bypass

This is distinct from end-to-end attack success. The VulnerableMockLLM is NOT
used here — we measure the defense layer only, not LLM behavior after bypass.

Loop per trial:
    payload = original _malicious_doc
    for i in 0..budget:
        attack._malicious_doc = payload
        attack.setup()          # calls guarded.reset() then ingests all docs
        if guarded.ingest_blocked == 0:
            bypassed = True; break
        blocked_by = triggered report details
        payload = adversary_llm.reformulate(payload, blocked_by)
    else:
        bypassed = False

Usage:
    python experiments/adaptive_bypass_pilot.py
    python experiments/adaptive_bypass_pilot.py --budget 10 --reps 5
    python experiments/adaptive_bypass_pilot.py --resume --output results/pilot.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

# Load .env if present
_env_path = Path(__file__).parent.parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

from langchain_groq import ChatGroq

from attacks.citation_forgery import CitationForgery
from attacks.cross_tenant_poisoning import CrossTenantPoisoning
from attacks.fuzzer import _REFORMULATION_PROMPT
from attacks.jailbreak_via_context import JailbreakViaContext
from attacks.semantic_backdoor import SemanticBackdoor
from attacks.temporal_spoofing import TemporalSpoofing
from defenses.citation_guard import AuthorityCitationDetector, SecurityDowngradeFilter
from defenses.context_jailbreak_guard import ContextJailbreakDetector, ContextJailbreakFilter
from defenses.cross_tenant_guard import CrossTenantIsolationFilter, CrossTenantMetadataDetector
from defenses.semantic_backdoor_guard import SemanticBackdoorDetector, SemanticBackdoorFilter
from defenses.semantic_intent_guard import SemanticIntentGuard, build_full_library
from defenses.temporal_guard import TemporalClaimDetector, TemporalContextFilter
from experiments.deceiving_the_retriever import GuardedPipeline
from experiments.fuzz_trial import FuzzTrial, append_trial, load_trials
from hemlock.mock import MockLLM
from hemlock.pipeline import Pipeline

# ── Pipeline factory ───────────────────────────────────────────────────────────

_counter = 0


def _make_guarded(ingest_guards, retrieval_guards) -> GuardedPipeline:
    global _counter
    _counter += 1
    d = tempfile.mkdtemp(prefix=f"pilot_{_counter}_")
    base = Pipeline(
        llm=MockLLM(),
        persist_dir=os.path.join(d, "chroma"),
        collection=f"pilot_{_counter}",
        chunk_size=500,
        chunk_overlap=50,
        top_k=4,
    )
    return GuardedPipeline(base, ingest_guards=ingest_guards, retrieval_guards=retrieval_guards)


# ── Reformulation ──────────────────────────────────────────────────────────────

def _reformulate(adversary_llm, payload: str, blocked_by: list[str]) -> str:
    reason = "; ".join(blocked_by) if blocked_by else "unknown"
    prompt = _REFORMULATION_PROMPT.format(payload=payload, reason=reason)
    try:
        response = adversary_llm.invoke(prompt)
        return response.content if hasattr(response, "content") else str(response)
    except Exception:
        return ""


# ── Single trial ───────────────────────────────────────────────────────────────

def _run_trial(
    *,
    category: str,
    variant: str,
    attack_cls,
    variant_arg: str,
    ingest_guards,
    retrieval_guards,
    run_id: int,
    budget: int,
    adversary_llm,
    llm_model: str,
    store_payloads: bool,
) -> FuzzTrial:
    guarded = _make_guarded(ingest_guards, retrieval_guards)
    attack = attack_cls(guarded, variant_arg)

    if not hasattr(attack, "_malicious_doc"):
        raise ValueError(f"{attack_cls.__name__} has no _malicious_doc attribute")

    original_payload = attack._malicious_doc
    payload = original_payload
    bypassed = False
    variants_used = 0
    blocked_by: list[str] = []
    winning_payload: str | None = None

    for i in range(budget + 1):
        attack._malicious_doc = payload
        attack.setup()  # calls guarded.reset() + ingests all docs

        triggered = [r for r in guarded._ingest_reports if r.triggered]

        if guarded.ingest_blocked == 0:
            bypassed = True
            variants_used = i + 1
            winning_payload = payload
            break

        blocked_by = [r.detail for r in triggered]

        if i < budget:
            new_payload = _reformulate(adversary_llm, payload, blocked_by)
            if not new_payload:
                break
            payload = new_payload

    if not bypassed:
        variants_used = budget + 1

    sha = (
        hashlib.sha256(winning_payload.encode()).hexdigest()
        if winning_payload
        else None
    )

    return FuzzTrial(
        run_id=run_id,
        attack_category=category,
        attack_variant=variant,
        defense_type="regex_baseline",
        budget=budget,
        original_succeeded=(bypassed and variants_used == 1),
        bypassed=bypassed,
        variants_used=variants_used,
        blocked_by=blocked_by,
        winning_payload_sha256=sha,
        winning_payload_text=winning_payload if store_payloads else None,
        llm_model=llm_model,
    )


# ── Pilot specs ────────────────────────────────────────────────────────────────
# Each entry: (category, variant, attack_cls, variant_arg, regex_ingest_guards, regex_retrieval_guards)
# Semantic defense replaces guards entirely; regex guards used only in --defense regex|both.

SPECS = [
    # citation_forgery
    ("citation_forgery", "fake_paper",    CitationForgery,     "fake_paper",
     [AuthorityCitationDetector()], [SecurityDowngradeFilter()]),
    ("citation_forgery", "fake_standard", CitationForgery,     "fake_standard",
     [AuthorityCitationDetector()], [SecurityDowngradeFilter()]),

    # jailbreak_via_context
    ("jailbreak_via_context", "roleplay",  JailbreakViaContext, "roleplay",
     [ContextJailbreakDetector()], [ContextJailbreakFilter()]),
    ("jailbreak_via_context", "research",  JailbreakViaContext, "research",
     [ContextJailbreakDetector()], [ContextJailbreakFilter()]),

    # temporal_spoofing
    ("temporal_spoofing", "stale_override", TemporalSpoofing, "stale_override",
     [TemporalClaimDetector()], [TemporalContextFilter()]),
    ("temporal_spoofing", "future_dated",   TemporalSpoofing, "future_dated",
     [TemporalClaimDetector()], [TemporalContextFilter()]),

    # cross_tenant_poisoning (Plan B)
    ("cross_tenant_poisoning", "namespace_bleed", CrossTenantPoisoning, "namespace_bleed",
     [CrossTenantMetadataDetector()], [CrossTenantIsolationFilter()]),
    ("cross_tenant_poisoning", "filter_bypass",   CrossTenantPoisoning, "filter_bypass",
     [CrossTenantMetadataDetector()], [CrossTenantIsolationFilter()]),

    # semantic_backdoor (Plan B)
    ("semantic_backdoor", "keyword_trigger", SemanticBackdoor, "keyword_trigger",
     [SemanticBackdoorDetector()], [SemanticBackdoorFilter()]),
    ("semantic_backdoor", "phrase_trigger",  SemanticBackdoor, "phrase_trigger",
     [SemanticBackdoorDetector()], [SemanticBackdoorFilter()]),
]

_SEMANTIC_GUARD: SemanticIntentGuard | None = None


def _get_semantic_guard() -> SemanticIntentGuard:
    global _SEMANTIC_GUARD
    if _SEMANTIC_GUARD is None:
        templates, labels = build_full_library()
        _SEMANTIC_GUARD = SemanticIntentGuard(templates, labels=labels, threshold=0.55)
    return _SEMANTIC_GUARD


# ── Main ──────────────────────────────────────────────────────────────────────

def run_pilot(
    output: str,
    budget: int,
    reps: int,
    model: str,
    store_payloads: bool,
    resume: bool,
    defense: str = "regex",
) -> None:
    """Run the adaptive bypass pilot.

    defense: "regex"    — use per-category regex guards (original baseline)
             "semantic" — use SemanticIntentGuard(threshold=0.55) for all categories
             "both"     — run regex first, then semantic (appends to same file with different defense_type)
    """
    if defense not in ("regex", "semantic", "both"):
        print(f"ERROR: --defense must be regex|semantic|both, got '{defense}'", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        print("ERROR: GROQ_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    adversary_llm = ChatGroq(model=model, api_key=api_key)

    runs = []
    if defense in ("regex", "both"):
        runs.append("regex")
    if defense in ("semantic", "both"):
        runs.append("semantic")

    for defense_mode in runs:
        completed: set[tuple] = set()
        if resume:
            for t in load_trials(output):
                if t.defense_type == (defense_mode + "_baseline" if defense_mode == "regex" else "semantic_proposed"):
                    completed.add((t.attack_category, t.attack_variant, t.run_id))

        defense_label = "regex_baseline" if defense_mode == "regex" else "semantic_proposed"
        total = len(SPECS) * reps
        done = 0

        print(f"\n{'='*60}")
        print(f"Defense: {defense_label}")
        print(f"Pilot: {len(SPECS)} variants × {reps} reps × budget {budget} = {total} runs")
        print(f"Model: {model}  |  Output: {output}")
        print(f"Metric: ingest guard bypass (ingest_blocked == 0)")
        if completed:
            print(f"Resuming — {len(completed)} trials already done")
        print()

        if defense_mode == "semantic":
            _get_semantic_guard()  # pre-load model once

        for category, variant, attack_cls, variant_arg, ingest_gs, retrieval_gs in SPECS:
            for run_id in range(reps):
                if (category, variant, run_id) in completed:
                    done += 1
                    continue

                if defense_mode == "semantic":
                    active_ingest = [_get_semantic_guard()]
                    active_retrieval = []
                else:
                    active_ingest = [g.__class__() for g in ingest_gs]
                    active_retrieval = [g.__class__() for g in retrieval_gs]

                trial = _run_trial(
                    category=category,
                    variant=variant,
                    attack_cls=attack_cls,
                    variant_arg=variant_arg,
                    ingest_guards=active_ingest,
                    retrieval_guards=active_retrieval,
                    run_id=run_id,
                    budget=budget,
                    adversary_llm=adversary_llm,
                    llm_model=model,
                    store_payloads=store_payloads,
                )
                # Override defense_type to reflect actual defense used
                from dataclasses import replace
                trial = replace(trial, defense_type=defense_label)
                append_trial(output, trial)
                done += 1

                status = "BYPASSED" if trial.bypassed else "resisted"
                print(
                    f"[{done:>3}/{total}] {category}/{variant} run={run_id} "
                    f"{status} variants_used={trial.variants_used}"
                )

    print(f"\nDone. Results: {output}")
    _print_summary(output)


def _print_summary(path: str) -> None:
    trials = load_trials(path)
    if not trials:
        return

    from collections import defaultdict
    by_defense_cat: dict[tuple, list] = defaultdict(list)
    for t in trials:
        by_defense_cat[(t.defense_type, t.attack_category)].append(t)

    defenses = sorted({t.defense_type for t in trials})
    for defense_type in defenses:
        print(f"\n── Summary [{defense_type}] ────────────────────────────────────")
        print(f"{'Category':<30} {'Bypass%':>8} {'Avg variants':>13} {'Original%':>10}")
        print("-" * 65)
        cats = sorted({cat for (dt, cat) in by_defense_cat if dt == defense_type})
        for cat in cats:
            ts = by_defense_cat[(defense_type, cat)]
            bypass_rate  = sum(t.bypassed for t in ts) / len(ts)
            avg_variants = sum(t.variants_used for t in ts) / len(ts)
            orig_rate    = sum(t.original_succeeded for t in ts) / len(ts)
            print(f"{cat:<30} {bypass_rate*100:>7.0f}% {avg_variants:>13.1f} {orig_rate*100:>9.0f}%")


def main() -> None:
    p = argparse.ArgumentParser(description="Adaptive bypass pilot — guard-level metric")
    p.add_argument("--output",   default="results/pilot.jsonl")
    p.add_argument("--budget",   type=int, default=10)
    p.add_argument("--reps",     type=int, default=5)
    p.add_argument("--model",    default="llama-3.1-8b-instant")
    p.add_argument("--defense",  default="regex", choices=["regex", "semantic", "both"],
                   help="regex: per-category regex guards; semantic: SemanticIntentGuard; both: run both")
    p.add_argument("--store-payloads", action="store_true")
    p.add_argument("--resume",         action="store_true")
    args = p.parse_args()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    run_pilot(
        output=args.output,
        budget=args.budget,
        reps=args.reps,
        model=args.model,
        store_payloads=args.store_payloads,
        resume=args.resume,
        defense=args.defense,
    )


if __name__ == "__main__":
    main()
