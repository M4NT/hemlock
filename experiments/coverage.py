"""Defense coverage matrix — maps each attack category to its defenses and empirical status.

Shows:
  - Which defenses cover each attack
  - Whether the attack/defense pair has been tested empirically in a pilot
  - Bypass rate from pilot_full.jsonl (if available)

Usage:
    python experiments/coverage.py
    python experiments/coverage.py --pilot results/pilot_full.jsonl
    python experiments/coverage.py --format markdown
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

# ── Coverage registry ─────────────────────────────────────────────────────────
# Each entry: (attack_category, [defense_names], notes)
# "empirical": whether this pair was measured in adaptive_bypass_pilot.py

COVERAGE: list[dict] = [
    {
        "attack": "citation_forgery",
        "defenses": ["AuthorityCitationDetector", "SecurityDowngradeFilter", "SemanticIntentGuard"],
        "empirical": True,
        "notes": "Pilot: regex 100% bypass; semantic 0% bypass",
    },
    {
        "attack": "jailbreak_via_context",
        "defenses": ["ContextJailbreakDetector", "ContextJailbreakFilter", "SemanticIntentGuard"],
        "empirical": True,
        "notes": "Pilot: regex 83% bypass; semantic 0% bypass",
    },
    {
        "attack": "temporal_spoofing",
        "defenses": ["TemporalClaimDetector", "TemporalContextFilter", "SemanticIntentGuard"],
        "empirical": True,
        "notes": "Pilot: regex 100% bypass; semantic 0% bypass",
    },
    {
        "attack": "cross_tenant_poisoning",
        "defenses": ["CrossTenantMetadataDetector", "CrossTenantIsolationFilter", "SemanticIntentGuard"],
        "empirical": True,
        "notes": "Pilot: regex 100% bypass; semantic 0% bypass",
    },
    {
        "attack": "semantic_backdoor",
        "defenses": ["SemanticBackdoorDetector", "SemanticBackdoorFilter",
                     "ConditionalTriggerGuard", "ConditionalTriggerFilter"],
        "empirical": True,
        "notes": "100% bypass across all 3 defenses; adversary evades structural patterns via reformulation",
    },
    {
        "attack": "direct_injection",
        "defenses": ["InjectionPatternFilter", "InjectionChunkFilter"],
        "empirical": False,
        "notes": "Regex-based; no adaptive bypass pilot run",
    },
    {
        "attack": "indirect_injection",
        "defenses": ["InjectionPatternFilter", "InjectionChunkFilter", "ProvenanceFilter"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "context_override",
        "defenses": ["InjectionPatternFilter", "InjectionChunkFilter"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "poisoning (knowledge)",
        "defenses": ["InjectionChunkFilter", "ProvenanceFilter"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "exfiltration",
        "defenses": ["ExfiltrationGuard", "OutputDefenseChain"],
        "empirical": False,
        "notes": "Output-layer defense",
    },
    {
        "attack": "invisible_markup",
        "defenses": ["InvisibleMarkupDetector", "HtmlMarkupSanitizer", "UnicodeNormalizer"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "authority_spoofing",
        "defenses": ["AuthorityCitationDetector"],
        "empirical": False,
        "notes": "Partial overlap with citation_forgery defenses",
    },
    {
        "attack": "chain_of_thought_hijack",
        "defenses": ["ChainOfThoughtDetector", "ChainOfThoughtFilter"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "multi_hop_poisoning",
        "defenses": ["MultiHopPoisonDetector", "MultiHopPoisonFilter"],
        "empirical": False,
        "notes": "No _malicious_doc — not compatible with current pilot harness",
    },
    {
        "attack": "context_flooding",
        "defenses": ["InjectionChunkFilter"],
        "empirical": False,
        "notes": "Volume-based attack; chunk limit defense needed",
    },
    {
        "attack": "memory_poisoning",
        "defenses": ["MemoryIsolationGuard", "MemoryBoundaryGuard"],
        "empirical": False,
        "notes": "Agent memory layer",
    },
    {
        "attack": "tool_output_poisoning",
        "defenses": ["ToolOutputGuard", "ToolCallValidator"],
        "empirical": False,
        "notes": "Tool output layer",
    },
    {
        "attack": "cross_agent_poisoning",
        "defenses": ["CrossAgentBoundaryGuard"],
        "empirical": False,
        "notes": "Multi-agent boundary",
    },
    {
        "attack": "graph_propagation",
        "defenses": ["GraphBoundaryGuard"],
        "empirical": False,
        "notes": "Agent graph layer",
    },
    {
        "attack": "agent_tool_hijack",
        "defenses": ["ToolCallValidator", "ActionIntentGuard"],
        "empirical": False,
        "notes": "",
    },
    {
        "attack": "computer_use_injection",
        "defenses": ["ScreenContentGuard", "ActionIntentGuard"],
        "empirical": False,
        "notes": "Computer-use layer",
    },
    {
        "attack": "structured_output_poisoning",
        "defenses": ["StructuredOutputGuard"],
        "empirical": False,
        "notes": "Output-layer defense",
    },
    {
        "attack": "polyglot_file_injection",
        "defenses": ["InvisibleMarkupDetector", "HtmlMarkupSanitizer"],
        "empirical": False,
        "notes": "File-format multi-vector; partial coverage",
    },
    {
        "attack": "adversarial_aeo",
        "defenses": ["AeoIngestValidator", "AeoRetrievalFilter"],
        "empirical": False,
        "notes": "AEO-specific (LLMs.txt / schema.org poisoning)",
    },
]


def _load_pilot_bypass(path: str) -> dict[tuple[str, str], float]:
    """Return {(defense_type, attack_category): bypass_pct} from JSONL."""
    groups: dict[tuple, list] = defaultdict(list)
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            t = json.loads(line)
            groups[(t["defense_type"], t["attack_category"])].append(t["bypassed"])
    return {k: sum(v) / len(v) * 100 for k, v in groups.items()}


def _render_table(rows: list[dict], bypass_data: dict | None, fmt: str) -> str:
    if fmt == "markdown":
        return _render_markdown(rows, bypass_data)
    return _render_plain(rows, bypass_data)


def _render_markdown(rows: list[dict], bypass_data: dict | None) -> str:
    defenses_col_w = 55
    lines = [
        "## Defense Coverage Matrix",
        "",
        f"| {'Attack':<30} | {'Defenses':<{defenses_col_w}} | {'Empirical':>9} | {'Notes':<40} |",
        f"|{'-'*32}|{'-'*(defenses_col_w+2)}|{'-'*11}|{'-'*42}|",
    ]
    for r in rows:
        empirical = "yes" if r["empirical"] else "—"
        defenses  = ", ".join(r["defenses"])
        if len(defenses) > defenses_col_w:
            defenses = defenses[:defenses_col_w - 1] + "…"
        lines.append(
            f"| {r['attack']:<30} | {defenses:<{defenses_col_w}} | {empirical:>9} | {r['notes']:<40} |"
        )
    return "\n".join(lines)


def _render_plain(rows: list[dict], bypass_data: dict | None) -> str:
    EMPIRICAL_COUNT = sum(1 for r in rows if r["empirical"])
    TOTAL = len(rows)

    out = [
        "=" * 80,
        f"  Hemlock Defense Coverage Matrix  ({EMPIRICAL_COUNT}/{TOTAL} empirically tested)",
        "=" * 80,
        f"  {'Attack category':<30}  {'Coverage':>10}  {'Empirical':>9}  Notes",
        "-" * 80,
    ]
    for r in rows:
        empirical = "YES" if r["empirical"] else "—"
        n_defenses = len(r["defenses"])
        extra = ""
        if bypass_data and r["empirical"]:
            for prefix in ("regex_baseline", "semantic_proposed", "composite_proposed"):
                key = (prefix, r["attack"])
                if key in bypass_data:
                    short = prefix.replace("_baseline", "").replace("_proposed", "")
                    extra += f" {short}={bypass_data[key]:.0f}%"
        notes = r["notes"][:35] + "…" if len(r["notes"]) > 35 else r["notes"]
        out.append(f"  {r['attack']:<30}  {n_defenses:>6} guards  {empirical:>9}  {notes}{extra}")

    out += [
        "-" * 80,
        f"  Total: {TOTAL} attacks, {EMPIRICAL_COUNT} empirically tested, {TOTAL - EMPIRICAL_COUNT} untested",
        "=" * 80,
    ]
    return "\n".join(out)


def main() -> None:
    p = argparse.ArgumentParser(description="Defense coverage matrix")
    p.add_argument("--pilot",  default=None, help="JSONL pilot file for bypass rates")
    p.add_argument("--format", default="plain", choices=["plain", "markdown"])
    p.add_argument("--output", default=None, help="Write to file instead of stdout")
    args = p.parse_args()

    bypass_data = _load_pilot_bypass(args.pilot) if args.pilot else None
    output = _render_table(COVERAGE, bypass_data, args.format)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"Written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
