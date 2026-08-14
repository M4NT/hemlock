"""Side-by-side comparison of regex vs. semantic defense results.

Reads a single JSONL file (or two separate files) and prints a
structured table: bypass rate per attack category, per defense type.

Usage:
    python experiments/compare_pilots.py                          # default: results/pilot.jsonl
    python experiments/compare_pilots.py --input results/pilot_full.jsonl
    python experiments/compare_pilots.py --regex results/pilot.jsonl --semantic results/pilot_semantic.jsonl
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from experiments.fuzz_trial import FuzzTrial, load_trials


def _summarise(trials: list[FuzzTrial]) -> dict[tuple[str, str], dict]:
    """Return {(defense_type, category): {bypass%, avg_variants, n}} dict."""
    groups: dict[tuple[str, str], list[FuzzTrial]] = defaultdict(list)
    for t in trials:
        groups[(t.defense_type, t.attack_category)].append(t)

    out = {}
    for key, ts in groups.items():
        out[key] = {
            "bypass_pct":    round(100 * sum(t.bypassed for t in ts) / len(ts), 1),
            "avg_variants":  round(sum(t.variants_used for t in ts) / len(ts), 1),
            "orig_pct":      round(100 * sum(t.original_succeeded for t in ts) / len(ts), 1),
            "n":             len(ts),
        }
    return out


def _render_table(data: dict[tuple[str, str], dict]) -> None:
    categories = sorted({cat for (_, cat) in data})
    defenses   = sorted({dt  for (dt, _)  in data})

    REGEX_LABEL    = "regex_baseline"
    SEMANTIC_LABEL = "semantic_proposed"

    has_regex    = REGEX_LABEL    in defenses
    has_semantic = SEMANTIC_LABEL in defenses

    col_w = 30

    header = f"{'Attack category':<{col_w}}"
    if has_regex:
        header += f"  {'Regex bypass%':>14}  {'Avg vars':>8}"
    if has_semantic:
        header += f"  {'Semantic bypass%':>16}  {'Avg vars':>8}"
    if has_regex and has_semantic:
        header += f"  {'Delta':>8}"

    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    for cat in categories:
        row = f"{cat:<{col_w}}"
        regex_bp    = data.get((REGEX_LABEL,    cat), {}).get("bypass_pct")
        semantic_bp = data.get((SEMANTIC_LABEL, cat), {}).get("bypass_pct")
        regex_av    = data.get((REGEX_LABEL,    cat), {}).get("avg_variants", "—")
        semantic_av = data.get((SEMANTIC_LABEL, cat), {}).get("avg_variants", "—")

        if has_regex:
            bp_s = f"{regex_bp:.1f}%" if regex_bp is not None else "—"
            row += f"  {bp_s:>14}  {str(regex_av):>8}"
        if has_semantic:
            bp_s = f"{semantic_bp:.1f}%" if semantic_bp is not None else "—"
            row += f"  {bp_s:>16}  {str(semantic_av):>8}"
        if has_regex and has_semantic and regex_bp is not None and semantic_bp is not None:
            delta = semantic_bp - regex_bp
            sign  = "+" if delta > 0 else ""
            row  += f"  {sign}{delta:.1f}pp"

        print(row)

    print("-" * len(header))

    # Overall averages
    row = f"{'OVERALL':<{col_w}}"
    for label, flag in [(REGEX_LABEL, has_regex), (SEMANTIC_LABEL, has_semantic)]:
        if flag:
            all_bp = [v["bypass_pct"] for (dt, _), v in data.items() if dt == label]
            all_av = [v["avg_variants"] for (dt, _), v in data.items() if dt == label]
            avg_bp = round(sum(all_bp) / len(all_bp), 1) if all_bp else 0
            avg_av = round(sum(all_av) / len(all_av), 1) if all_av else 0
            if label == REGEX_LABEL:
                row += f"  {f'{avg_bp:.1f}%':>14}  {str(avg_av):>8}"
            else:
                row += f"  {f'{avg_bp:.1f}%':>16}  {str(avg_av):>8}"

    if has_regex and has_semantic:
        r_all = [v["bypass_pct"] for (dt, _), v in data.items() if dt == REGEX_LABEL]
        s_all = [v["bypass_pct"] for (dt, _), v in data.items() if dt == SEMANTIC_LABEL]
        if r_all and s_all:
            delta = round(sum(s_all)/len(s_all) - sum(r_all)/len(r_all), 1)
            sign  = "+" if delta > 0 else ""
            row  += f"  {sign}{delta:.1f}pp"

    print(row)
    print("=" * len(header))


def main() -> None:
    p = argparse.ArgumentParser(description="Compare regex vs. semantic pilot results")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--input",    default="results/pilot.jsonl",
                   help="Single JSONL with both defense types (default)")
    p.add_argument("--regex",    default=None,
                   help="Separate JSONL for regex baseline")
    p.add_argument("--semantic", default=None,
                   help="Separate JSONL for semantic defense")
    args = p.parse_args()

    trials: list[FuzzTrial] = []

    if args.regex or args.semantic:
        if args.regex:
            trials += load_trials(args.regex)
        if args.semantic:
            trials += load_trials(args.semantic)
    else:
        trials = load_trials(args.input)

    if not trials:
        print("No trials found.")
        return

    defenses = {t.defense_type for t in trials}
    n_total  = len(trials)
    print(f"Loaded {n_total} trials | defense types: {sorted(defenses)}")

    data = _summarise(trials)
    _render_table(data)


if __name__ == "__main__":
    main()
