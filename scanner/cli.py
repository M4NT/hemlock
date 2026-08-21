"""hemlock scan — CLI entry point.

Usage:
    python -m scanner scan ./docs/
    python -m scanner scan policy.md
    python -m scanner scan --text "paste document text here"
    python -m scanner scan --json ./docs/
    python -m scanner scan --threshold 0.75 ./docs/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.scan import Scanner, ScanResult


# ── ANSI colours (disabled on Windows without color support) ──────────────────

def _supports_color() -> bool:
    import os
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.name != "nt" or \
           "ANSICON" in __import__("os").environ or \
           "WT_SESSION" in __import__("os").environ  # Windows Terminal


_COLOR = _supports_color()

_RED    = "\033[91m" if _COLOR else ""
_YELLOW = "\033[93m" if _COLOR else ""
_CYAN   = "\033[96m" if _COLOR else ""
_GREEN  = "\033[92m" if _COLOR else ""
_BOLD   = "\033[1m"  if _COLOR else ""
_RESET  = "\033[0m"  if _COLOR else ""


def _colorize(verdict: str, text: str) -> str:
    colors = {
        "dangerous":  _RED + _BOLD,
        "suspicious": _YELLOW,
        "low":        _CYAN,
        "safe":       _GREEN,
    }
    return colors.get(verdict, "") + text + _RESET


# ── Formatting ────────────────────────────────────────────────────────────────

def _format_result(result: ScanResult) -> str:
    icon = "✗" if result.findings else "✓"
    verdict_padded = result.verdict.upper().ljust(12)  # pad before colorizing to keep column width
    verdict_str = _colorize(result.verdict, verdict_padded)
    source = Path(result.source).name if result.source != "<input>" else "<input>"
    cats = ", ".join(sorted({f.category for f in result.findings}))
    cat_str = f"  [{cats}]" if cats else ""

    line = f"{icon} {verdict_str} {source:<36} score:{result.score:>3}{cat_str}"

    if result.findings:
        snippet = result.findings[0].snippet[:110].replace("\n", " ").strip()
        line += f'\n    "{snippet}..."'

    return line


def _summary(results: list[ScanResult]) -> str:
    counts = {"dangerous": 0, "suspicious": 0, "low": 0, "safe": 0}
    for r in results:
        counts[r.verdict] += 1
    total = len(results)
    parts = [f"{total} file{'s' if total != 1 else ''} scanned"]
    for verdict, count in counts.items():
        if count:
            parts.append(_colorize(verdict, f"{count} {verdict}"))
    return " · ".join(parts)


# ── JSON output ───────────────────────────────────────────────────────────────

def _to_json(results: list[ScanResult]) -> str:
    def _finding_dict(f):
        return {
            "category": f.category,
            "mechanism": f.mechanism,
            "score": f.score,
            "snippet": f.snippet[:200],
        }

    output = [
        {
            "source": r.source,
            "score": r.score,
            "verdict": r.verdict,
            "clean": r.clean,
            "findings": [_finding_dict(f) for f in r.findings],
        }
        for r in results
    ]
    return json.dumps(output, indent=2)


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    scanner = Scanner(threshold=args.threshold)

    results: list[ScanResult] = []

    if args.text:
        results.append(scanner.scan_text(args.text))
    else:
        target = Path(args.target)
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 1

        if target.is_file():
            results.append(scanner.scan_file(target))
        else:
            globs = args.glob or ["**/*.md"]
            files = sorted({f for pattern in globs for f in target.glob(pattern) if f.is_file()})
            if not files:
                print(f"no files matching {globs} in {target}", file=sys.stderr)
                return 0
            print(f"scanning {len(files)} file{'s' if len(files) != 1 else ''}...\n", file=sys.stderr)
            for f in files:
                r = scanner.scan_file(f)
                results.append(r)

    if args.json:
        print(_to_json(results))
        return _exit_code(results)

    for r in results:
        print(_format_result(r))

    if len(results) > 1:
        print(f"\n{_summary(results)}")

    return _exit_code(results)


def _exit_code(results: list[ScanResult]) -> int:
    """Mirror ScanRepo: 0 safe, 1 suspicious, 2 dangerous."""
    verdicts = {r.verdict for r in results}
    if "dangerous" in verdicts:
        return 2
    if "suspicious" in verdicts:
        return 1
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hemlock-scan",
        description="Scan documents for RAG attack patterns before ingesting.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a file, directory, or text snippet.")
    scan_p.add_argument("target", nargs="?", default=".", help="File or directory path (default: .)")
    scan_p.add_argument("--text", help="Scan a raw text string instead of a file.")
    scan_p.add_argument("--threshold", type=float, default=0.55,
                        help="Semantic similarity cutoff (default: 0.55, pilot-aligned).")
    scan_p.add_argument("--glob", action="append", default=None, metavar="PATTERN",
                        help="Glob pattern when scanning a directory. "
                             "Can be repeated: --glob '**/*.md' --glob '**/*.txt'. "
                             "Default: **/*.md")
    scan_p.add_argument("--json", action="store_true", help="Output results as JSON.")

    args = parser.parse_args()
    if args.command == "scan":
        sys.exit(cmd_scan(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
