"""Figure generator for Hemlock research paper.

Two modes:

  Experiment report mode (--input *.json):
    Reads an ExperimentReport JSON (output of deceiving_the_retriever.py).
    Table 1  — per-category attack success rates
    Figure 1 — grouped bar: Unguarded vs Guarded SR per category
    Figure 2 — defense interception rate per category (horizontal bar)

  Pilot comparison mode (--pilot *.jsonl):
    Reads FuzzTrial JSONL (output of adaptive_bypass_pilot.py --defense both|composite).
    Figure 3 — grouped bar: bypass% per category × defense type
    Table 2  — bypass rate comparison across defense types

Usage:
    python experiments/figures.py --input results/exp_10runs.json
    python experiments/figures.py --input results/exp_10runs.json --output results/figures/
    python experiments/figures.py --pilot results/pilot_full.jsonl --output results/figures/
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


# ── SVG helpers ───────────────────────────────────────────────────────────────

_WIDTH = 700
_HEIGHT = 340
_PAD_LEFT = 170
_PAD_RIGHT = 30
_PAD_TOP = 40
_PAD_BOTTOM = 55

_BLUE = "#3b82f6"
_RED = "#ef4444"
_GREEN = "#22c55e"
_GRAY_AXIS = "#d1d5db"
_GRAY_TEXT = "#374151"
_GRAY_LIGHT = "#f3f4f6"


def _bar_chart_grouped(
    categories: list[str],
    series_a: list[float],  # unguarded SR
    series_b: list[float],  # guarded SR
    title: str,
) -> str:
    n = len(categories)
    chart_w = _WIDTH - _PAD_LEFT - _PAD_RIGHT
    chart_h = _HEIGHT - _PAD_TOP - _PAD_BOTTOM
    group_w = chart_w / n
    bar_w = group_w * 0.32
    gap = group_w * 0.04

    lines: list[str] = []
    lines.append(f'<svg viewBox="0 0 {_WIDTH} {_HEIGHT}" xmlns="http://www.w3.org/2000/svg" '
                 f'font-family="ui-monospace,monospace" font-size="11">')

    # background
    lines.append(f'<rect width="{_WIDTH}" height="{_HEIGHT}" fill="white"/>')

    # title
    lines.append(f'<text x="{_WIDTH // 2}" y="22" text-anchor="middle" '
                 f'font-size="13" font-weight="bold" fill="{_GRAY_TEXT}">{title}</text>')

    # y-axis labels + grid lines (0%, 25%, 50%, 75%, 100%)
    for pct in (0, 25, 50, 75, 100):
        y = _PAD_TOP + chart_h - (pct / 100) * chart_h
        lines.append(f'<line x1="{_PAD_LEFT}" y1="{y:.1f}" x2="{_WIDTH - _PAD_RIGHT}" '
                     f'y2="{y:.1f}" stroke="{_GRAY_AXIS}" stroke-width="1"/>')
        lines.append(f'<text x="{_PAD_LEFT - 6}" y="{y + 4:.1f}" text-anchor="end" '
                     f'fill="{_GRAY_TEXT}">{pct}%</text>')

    # bars
    for i, (cat, a, b) in enumerate(zip(categories, series_a, series_b)):
        cx = _PAD_LEFT + i * group_w + group_w / 2
        x_a = cx - bar_w - gap / 2
        x_b = cx + gap / 2
        h_a = (a * chart_h)
        h_b = (b * chart_h)
        y_a = _PAD_TOP + chart_h - h_a
        y_b = _PAD_TOP + chart_h - h_b

        lines.append(f'<rect x="{x_a:.1f}" y="{y_a:.1f}" width="{bar_w:.1f}" '
                     f'height="{h_a:.1f}" fill="{_RED}" rx="2"/>')
        lines.append(f'<rect x="{x_b:.1f}" y="{y_b:.1f}" width="{bar_w:.1f}" '
                     f'height="{h_b:.1f}" fill="{_BLUE}" rx="2"/>')

        # value labels above bars
        if a > 0.04:
            lines.append(f'<text x="{x_a + bar_w / 2:.1f}" y="{y_a - 3:.1f}" '
                         f'text-anchor="middle" fill="{_RED}" font-size="10">'
                         f'{a * 100:.0f}%</text>')
        if b > 0.04:
            lines.append(f'<text x="{x_b + bar_w / 2:.1f}" y="{y_b - 3:.1f}" '
                         f'text-anchor="middle" fill="{_BLUE}" font-size="10">'
                         f'{b * 100:.0f}%</text>')
        else:
            lines.append(f'<text x="{x_b + bar_w / 2:.1f}" y="{_PAD_TOP + chart_h - 3:.1f}" '
                         f'text-anchor="middle" fill="{_BLUE}" font-size="10">0%</text>')

        # x-axis label (wrapped at slash)
        short = cat.replace(" ", "\n")
        words = cat.split()
        lx = cx
        ly = _PAD_TOP + chart_h + 14
        if len(words) == 2:
            lines.append(f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{words[0]}</text>')
            lines.append(f'<text x="{lx:.1f}" y="{ly + 13:.1f}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{words[1]}</text>')
        else:
            lines.append(f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{cat}</text>')

    # x-axis line
    lines.append(f'<line x1="{_PAD_LEFT}" y1="{_PAD_TOP + chart_h}" '
                 f'x2="{_WIDTH - _PAD_RIGHT}" y2="{_PAD_TOP + chart_h}" '
                 f'stroke="{_GRAY_TEXT}" stroke-width="1.5"/>')

    # legend
    lx = _PAD_LEFT
    ly = _HEIGHT - 12
    lines.append(f'<rect x="{lx}" y="{ly - 8}" width="12" height="10" fill="{_RED}" rx="2"/>')
    lines.append(f'<text x="{lx + 15}" y="{ly}" fill="{_GRAY_TEXT}">Unguarded</text>')
    lx2 = lx + 105
    lines.append(f'<rect x="{lx2}" y="{ly - 8}" width="12" height="10" fill="{_BLUE}" rx="2"/>')
    lines.append(f'<text x="{lx2 + 15}" y="{ly}" fill="{_GRAY_TEXT}">Guarded</text>')

    lines.append("</svg>")
    return "\n".join(lines)


def _bar_chart_horizontal(
    categories: list[str],
    values: list[float],
    title: str,
    color: str = _GREEN,
) -> str:
    n = len(categories)
    h = max(260, n * 48 + 60)
    w = 600
    pad_left = 160
    pad_right = 60
    pad_top = 40
    pad_bottom = 30
    chart_w = w - pad_left - pad_right
    bar_h = 28
    row_h = (h - pad_top - pad_bottom) / n

    lines: list[str] = []
    lines.append(f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" '
                 f'font-family="ui-monospace,monospace" font-size="11">')
    lines.append(f'<rect width="{w}" height="{h}" fill="white"/>')
    lines.append(f'<text x="{w // 2}" y="22" text-anchor="middle" '
                 f'font-size="13" font-weight="bold" fill="{_GRAY_TEXT}">{title}</text>')

    # x-axis grid
    for pct in (0, 25, 50, 75, 100):
        x = pad_left + (pct / 100) * chart_w
        lines.append(f'<line x1="{x:.1f}" y1="{pad_top}" x2="{x:.1f}" '
                     f'y2="{h - pad_bottom}" stroke="{_GRAY_AXIS}" stroke-width="1"/>')
        lines.append(f'<text x="{x:.1f}" y="{h - pad_bottom + 14}" text-anchor="middle" '
                     f'fill="{_GRAY_TEXT}">{pct}%</text>')

    for i, (cat, v) in enumerate(zip(categories, values)):
        cy = pad_top + i * row_h + row_h / 2
        bw = v * chart_w
        by = cy - bar_h / 2
        lines.append(f'<rect x="{pad_left}" y="{by:.1f}" width="{bw:.1f}" '
                     f'height="{bar_h}" fill="{color}" rx="3"/>')
        lines.append(f'<text x="{pad_left - 6}" y="{cy + 4:.1f}" text-anchor="end" '
                     f'fill="{_GRAY_TEXT}">{cat}</text>')
        lines.append(f'<text x="{pad_left + bw + 5:.1f}" y="{cy + 4:.1f}" '
                     f'fill="{_GRAY_TEXT}">{v * 100:.0f}%</text>')

    lines.append(f'<line x1="{pad_left}" y1="{pad_top}" x2="{pad_left}" '
                 f'y2="{h - pad_bottom}" stroke="{_GRAY_TEXT}" stroke-width="1.5"/>')
    lines.append("</svg>")
    return "\n".join(lines)


# ── Table 1 ───────────────────────────────────────────────────────────────────

def _table1_markdown(report: dict) -> str:
    cats = report["categories"]
    overall = {
        "category": "**OVERALL**",
        "unguarded_success_rate": report["overall_unguarded_sr"],
        "guarded_success_rate": report["overall_guarded_sr"],
        "defense_interception_rate": report["overall_defense_interception_rate"],
        "reduction": report["overall_reduction"],
    }

    rows = cats + [overall]
    col_w = [25, 14, 12, 13, 7]
    header = (
        f"| {'Category':<{col_w[0]}} | {'Unguarded SR':>{col_w[1]}} "
        f"| {'Guarded SR':>{col_w[2]}} | {'Intercepted':>{col_w[3]}} "
        f"| {'Δ':>{col_w[4]}} |"
    )
    sep = f"|{'-' * (col_w[0] + 2)}|{'-' * (col_w[1] + 2)}|{'-' * (col_w[2] + 2)}|{'-' * (col_w[3] + 2)}|{'-' * (col_w[4] + 2)}|"

    lines = [
        f"**Table 1.** Attack success rate before and after defense deployment "
        f"({report['n_runs']} runs × {report['n_attacks']} attacks = "
        f"{report['total_trials']} trials).",
        "",
        header,
        sep,
    ]
    for r in rows:
        cat = r["category"]
        u = f"{r['unguarded_success_rate'] * 100:.0f}%"
        g = f"{r['guarded_success_rate'] * 100:.0f}%"
        i = f"{r['defense_interception_rate'] * 100:.0f}%"
        d = f"{r['reduction'] * 100:+.0f}%"
        lines.append(
            f"| {cat:<{col_w[0]}} | {u:>{col_w[1]}} "
            f"| {g:>{col_w[2]}} | {i:>{col_w[3]}} "
            f"| {d:>{col_w[4]}} |"
        )
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def generate_figures(input_path: str, output_dir: str, table_only: bool = False) -> None:
    with open(input_path, encoding="utf-8") as f:
        report = json.load(f)

    os.makedirs(output_dir, exist_ok=True)

    # Table 1
    table_md = _table1_markdown(report)
    table_path = os.path.join(output_dir, "table1.md")
    Path(table_path).write_text(table_md, encoding="utf-8")
    print(f"[table1]  {table_path}")
    print()
    print(table_md)

    if table_only:
        return

    cats = report["categories"]
    labels = [c["category"] for c in cats]
    u_sr = [c["unguarded_success_rate"] for c in cats]
    g_sr = [c["guarded_success_rate"] for c in cats]
    i_rate = [c["defense_interception_rate"] for c in cats]

    # Figure 1 — grouped bar: unguarded vs guarded
    fig1 = _bar_chart_grouped(
        labels, u_sr, g_sr,
        title="Figure 1 — Attack Success Rate: Unguarded vs. Guarded",
    )
    fig1_path = os.path.join(output_dir, "figure1_sr_comparison.svg")
    Path(fig1_path).write_text(fig1, encoding="utf-8")
    print(f"[figure1] {fig1_path}")

    # Figure 2 — horizontal bar: interception rate
    fig2 = _bar_chart_horizontal(
        labels, i_rate,
        title="Figure 2 — Defense Interception Rate by Category",
        color=_GREEN,
    )
    fig2_path = os.path.join(output_dir, "figure2_interception.svg")
    Path(fig2_path).write_text(fig2, encoding="utf-8")
    print(f"[figure2] {fig2_path}")


# ── Pilot comparison figures ──────────────────────────────────────────────────

_ORANGE = "#f97316"
_PURPLE = "#8b5cf6"

_DEFENSE_COLORS = {
    "regex_baseline":     _RED,
    "semantic_proposed":  _ORANGE,
    "composite_proposed": _GREEN,
}

_DEFENSE_LABELS = {
    "regex_baseline":     "Regex",
    "semantic_proposed":  "Semantic",
    "composite_proposed": "Composite",
}


def _load_pilot_jsonl(path: str) -> list[dict]:
    import json
    trials = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                trials.append(json.loads(line))
    return trials


def _pilot_bypass_table(trials: list[dict]) -> tuple[list[str], list[str], dict]:
    """Return (categories, defenses, data[defense][category] = bypass_pct)."""
    from collections import defaultdict
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for t in trials:
        groups[(t["defense_type"], t["attack_category"])].append(t["bypassed"])

    categories = sorted({t["attack_category"] for t in trials})
    defenses   = sorted({t["defense_type"]    for t in trials})

    data: dict[str, dict[str, float]] = {}
    for dt in defenses:
        data[dt] = {}
        for cat in categories:
            vals = groups.get((dt, cat), [])
            data[dt][cat] = (sum(vals) / len(vals)) if vals else 0.0

    return categories, defenses, data


def _bar_chart_pilot(
    categories: list[str],
    defenses: list[str],
    data: dict[str, dict[str, float]],
    title: str,
) -> str:
    n = len(categories)
    nd = len(defenses)
    w = max(700, n * 120 + 200)
    h = 360
    pad_left = 50
    pad_right = 30
    pad_top = 50
    pad_bottom = 80
    chart_w = w - pad_left - pad_right
    chart_h = h - pad_top - pad_bottom
    group_w = chart_w / n
    bar_w = (group_w * 0.8) / nd
    gap = group_w * 0.1

    lines: list[str] = []
    lines.append(f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" '
                 f'font-family="ui-monospace,monospace" font-size="11">')
    lines.append(f'<rect width="{w}" height="{h}" fill="white"/>')
    lines.append(f'<text x="{w // 2}" y="26" text-anchor="middle" '
                 f'font-size="13" font-weight="bold" fill="{_GRAY_TEXT}">{title}</text>')

    for pct in (0, 25, 50, 75, 100):
        y = pad_top + chart_h - (pct / 100) * chart_h
        lines.append(f'<line x1="{pad_left}" y1="{y:.1f}" x2="{w - pad_right}" '
                     f'y2="{y:.1f}" stroke="{_GRAY_AXIS}" stroke-width="1"/>')
        lines.append(f'<text x="{pad_left - 4}" y="{y + 4:.1f}" text-anchor="end" '
                     f'fill="{_GRAY_TEXT}">{pct}%</text>')

    for i, cat in enumerate(categories):
        group_x = pad_left + i * group_w + gap
        for j, dt in enumerate(defenses):
            v = data[dt].get(cat, 0.0)
            color = _DEFENSE_COLORS.get(dt, _BLUE)
            bx = group_x + j * bar_w
            bh = v * chart_h
            by = pad_top + chart_h - bh
            lines.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w - 2:.1f}" '
                         f'height="{bh:.1f}" fill="{color}" rx="2"/>')
            label = f"{v * 100:.0f}%"
            if bh > 14:
                lines.append(f'<text x="{bx + (bar_w - 2) / 2:.1f}" y="{by - 3:.1f}" '
                             f'text-anchor="middle" fill="{color}" font-size="9">{label}</text>')

        # x label
        short_cat = cat.replace("_", " ")
        cx = pad_left + i * group_w + group_w / 2
        words = short_cat.split()
        ly = pad_top + chart_h + 16
        if len(words) >= 2:
            mid = len(words) // 2
            lines.append(f'<text x="{cx:.1f}" y="{ly}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{" ".join(words[:mid])}</text>')
            lines.append(f'<text x="{cx:.1f}" y="{ly + 13}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{" ".join(words[mid:])}</text>')
        else:
            lines.append(f'<text x="{cx:.1f}" y="{ly}" text-anchor="middle" '
                         f'fill="{_GRAY_TEXT}">{short_cat}</text>')

    lines.append(f'<line x1="{pad_left}" y1="{pad_top + chart_h}" '
                 f'x2="{w - pad_right}" y2="{pad_top + chart_h}" '
                 f'stroke="{_GRAY_TEXT}" stroke-width="1.5"/>')

    # legend
    lx = pad_left
    ly = h - 14
    for dt in defenses:
        color = _DEFENSE_COLORS.get(dt, _BLUE)
        label = _DEFENSE_LABELS.get(dt, dt)
        lines.append(f'<rect x="{lx}" y="{ly - 9}" width="12" height="10" fill="{color}" rx="2"/>')
        lines.append(f'<text x="{lx + 15}" y="{ly}" fill="{_GRAY_TEXT}">{label}</text>')
        lx += len(label) * 7 + 30

    lines.append("</svg>")
    return "\n".join(lines)


def _table2_markdown(categories: list[str], defenses: list[str], data: dict) -> str:
    col_w = 28
    def_labels = [_DEFENSE_LABELS.get(d, d) for d in defenses]
    header = f"| {'Attack category':<{col_w}} |" + "".join(f" {l:>12} |" for l in def_labels)
    sep    = f"|{'-' * (col_w + 2)}|" + "".join(f"{'-' * 14}|" for _ in defenses)
    lines  = [
        "**Table 2.** Bypass rate per category per defense type (ingest-guard metric).",
        "",
        header,
        sep,
    ]
    for cat in categories:
        row = f"| {cat:<{col_w}} |"
        for dt in defenses:
            pct = data[dt].get(cat, 0.0) * 100
            row += f" {pct:>11.0f}% |"
        lines.append(row)

    # overall row
    row = f"| {'**OVERALL**':<{col_w}} |"
    for dt in defenses:
        vals = list(data[dt].values())
        avg  = sum(vals) / len(vals) * 100 if vals else 0
        row += f" {avg:>11.0f}% |"
    lines.append(row)
    return "\n".join(lines)


def generate_pilot_figures(pilot_path: str, output_dir: str) -> None:
    trials = _load_pilot_jsonl(pilot_path)
    if not trials:
        print("No trials found in", pilot_path)
        return

    os.makedirs(output_dir, exist_ok=True)
    categories, defenses, data = _pilot_bypass_table(trials)

    # Table 2
    table_md = _table2_markdown(categories, defenses, data)
    table_path = os.path.join(output_dir, "table2_pilot_comparison.md")
    Path(table_path).write_text(table_md, encoding="utf-8")
    print(f"[table2]  {table_path}")
    print()
    print(table_md)

    # Figure 3
    fig = _bar_chart_pilot(
        categories, defenses, data,
        title="Figure 3 — Bypass Rate by Attack Category and Defense Type",
    )
    fig_path = os.path.join(output_dir, "figure3_pilot_comparison.svg")
    Path(fig_path).write_text(fig, encoding="utf-8")
    print(f"\n[figure3] {fig_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate paper figures from experiment results")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--input",  help="ExperimentReport JSON (deceiving_the_retriever output)")
    grp.add_argument("--pilot",  help="FuzzTrial JSONL (adaptive_bypass_pilot output)")
    parser.add_argument("--output", default="results/figures", help="Output directory")
    parser.add_argument("--table-only", action="store_true", help="Only generate tables (no SVGs)")
    args = parser.parse_args()

    if args.input:
        generate_figures(args.input, args.output, table_only=args.table_only)
    else:
        generate_pilot_figures(args.pilot, args.output)


if __name__ == "__main__":
    main()
