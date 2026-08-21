"""Bounty Ops Hub — lista programas, status, e roda pilots.

Usage:
    python bounty/ops.py list
    python bounty/ops.py pilot --target glean --category skill
    python bounty/ops.py finding --target glean --severity p3 --title "System prompt leak via skill"
    python bounty/ops.py status
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

TRACKER = Path(__file__).parent / "tracker.json"


def _load() -> dict:
    return json.loads(TRACKER.read_text())


def _save(data: dict) -> None:
    TRACKER.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_list(args) -> None:
    data = _load()
    programs = data["programs"]
    print(f"\n{'ID':<15} {'Name':<30} {'Platform':<12} {'Status':<20} {'Findings'}")
    print("-" * 90)
    for p in programs:
        findings = len(p.get("findings", []))
        print(f"{p['id']:<15} {p['name']:<30} {p['platform']:<12} {p['status']:<20} {findings}")
    print()
    m = data["_meta"]
    print(f"Total: {len(programs)} programs | Active: {m['active']} | "
          f"Findings submitted: {m['findings_submitted']} | Paid: ${m['total_paid']}")


def cmd_status(args) -> None:
    data = _load()
    for p in data["programs"]:
        pid = p["id"]
        print(f"\n{'='*50}")
        print(f"{p['name']} ({p['platform']})")
        print(f"  Status: {p['status']}")
        print(f"  Test URL: {p.get('test_url', 'N/A')}")
        print(f"  Rewards: P1=${p['reward_range'].get('p1','?')} P2=${p['reward_range'].get('p2','?')} P3=${p['reward_range'].get('p3','?')}")
        print(f"  Features: {', '.join(p.get('llm_features', []))}")
        pilot = p.get("pilot_results", {})
        if pilot:
            print(f"  Pilot: {' | '.join(f'{k}={v}' for k, v in pilot.items())}")
        findings = p.get("findings", [])
        if findings:
            print(f"  Findings ({len(findings)}):")
            for f in findings:
                print(f"    [{f['severity'].upper()}] {f['title']} — {f['status']}")
        print(f"  Notes: {p.get('notes', '')}")


def cmd_add(args) -> None:
    data = _load()
    pid = args.id
    if any(p["id"] == pid for p in data["programs"]):
        print(f"ERROR: program '{pid}' already exists")
        sys.exit(1)

    program = {
        "id": pid,
        "name": args.name,
        "platform": args.platform,
        "program_url": args.program_url,
        "test_url": args.test_url or "",
        "login_url": args.login_url or "",
        "status": "researching",
        "llm_features": [],
        "attack_surface": [],
        "reward_range": {},
        "prompt_injection_in_scope": None,
        "pilot_results": {},
        "notes": args.notes or "",
        "findings": [],
    }
    data["programs"].append(program)
    data["_meta"]["total_programs"] = len(data["programs"])
    _save(data)
    print(f"Added: {pid} ({args.name})")


def cmd_update_status(args) -> None:
    data = _load()
    for p in data["programs"]:
        if p["id"] == args.target:
            old = p["status"]
            p["status"] = args.status
            _save(data)
            print(f"{args.target}: {old} → {args.status}")
            return
    print(f"ERROR: target '{args.target}' not found")
    sys.exit(1)


def cmd_finding(args) -> None:
    data = _load()
    for p in data["programs"]:
        if p["id"] == args.target:
            finding = {
                "id": f"{args.target}_{len(p['findings'])+1:03d}",
                "title": args.title,
                "severity": args.severity,
                "status": "draft",
                "category": args.category or "",
                "created": datetime.now(timezone.utc).isoformat(),
                "submitted": None,
                "paid": 0,
                "notes": args.notes or "",
            }
            p["findings"].append(finding)
            data["_meta"]["findings_submitted"] = sum(
                len(pp["findings"]) for pp in data["programs"]
            )
            _save(data)
            print(f"Finding added: {finding['id']} [{finding['severity'].upper()}] {finding['title']}")
            return
    print(f"ERROR: target '{args.target}' not found")
    sys.exit(1)


def cmd_pilot(args) -> None:
    target = args.target
    category = getattr(args, "category", None)

    if target == "glean":
        _pilot_glean(category, args)
    else:
        print(f"No pilot configured for target '{target}' yet.")
        print("Add it to bounty/targets/{target}_pilot.py")


def cmd_validate(args) -> None:
    """Run bounty payloads through the Hemlock scanner (defense loop).

    Exit codes:
        0 — all payloads blocked (defenses hold)
        1 — one or more payloads passed clean (candidate findings / defense gaps)
        2 — usage / path error
    """
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scanner.scan import Scanner

    root = Path(__file__).parent / "payloads"
    if args.path:
        root = Path(args.path)

    if not root.exists():
        print(f"ERROR: path not found: {root}")
        sys.exit(2)

    patterns = ["**/*.txt", "**/*.md"]
    files = sorted({f for pat in patterns for f in root.glob(pat) if f.is_file()})
    if not files:
        print(f"No .txt/.md payloads under {root}")
        sys.exit(0)

    scanner = Scanner(
        threshold=args.threshold,
        semantic=False if args.structural_only else None,
    )

    blocked: list[tuple[Path, object]] = []
    passed: list[tuple[Path, object]] = []

    print(f"\nValidating {len(files)} payload(s) against Hemlock scanner")
    print(f"  threshold={args.threshold}  structural_only={args.structural_only}\n")

    for path in files:
        result = scanner.scan_file(path)
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        status = "BLOCKED" if not result.clean else "PASSED "
        cats = ", ".join(sorted({f.category for f in result.findings})) or "-"
        print(f"  [{status}] {rel}  verdict={result.verdict}  score={result.score}  [{cats}]")
        (blocked if not result.clean else passed).append((path, result))

    print(f"\nSummary: {len(blocked)} blocked / {len(passed)} passed (defense gaps / candidates)")
    if passed:
        print("\nCandidate findings (payloads that bypassed current defenses):")
        for path, result in passed:
            print(f"  - {path}  (verdict={result.verdict})")
        print("\nTip: only promote PASSED payloads to bounty findings after manual triage.")
        sys.exit(1)

    print("All text payloads blocked by current defense stack.")
    sys.exit(0)


def _pilot_glean(category, args):
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import subprocess
    cmd = [sys.executable, "experiments/glean_pilot.py", "--reps", "2", "--budget", "5"]
    if category:
        cmd += ["--category", category]
    result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)
    sys.exit(result.returncode)


def main():
    p = argparse.ArgumentParser(description="Bounty Ops Hub")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List all programs")
    sub.add_parser("status", help="Detailed status of all programs")

    a = sub.add_parser("add", help="Add new program")
    a.add_argument("--id", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--platform", required=True)
    a.add_argument("--program-url", required=True, dest="program_url")
    a.add_argument("--test-url", dest="test_url")
    a.add_argument("--login-url", dest="login_url")
    a.add_argument("--notes")

    us = sub.add_parser("set-status", help="Update program status")
    us.add_argument("--target", required=True)
    us.add_argument("--status", required=True,
                    choices=["researching", "access_pending", "active", "paused", "closed"])

    f = sub.add_parser("finding", help="Log a finding")
    f.add_argument("--target", required=True)
    f.add_argument("--title", required=True)
    f.add_argument("--severity", required=True, choices=["p1", "p2", "p3", "p4"])
    f.add_argument("--category")
    f.add_argument("--notes")

    pp = sub.add_parser("pilot", help="Run LLM pilot for a target")
    pp.add_argument("--target", required=True)
    pp.add_argument("--category", choices=["skill", "file_upload", "external_link"])

    v = sub.add_parser(
        "validate",
        help="Scan bounty payloads with Hemlock defenses (find gaps / candidates)",
    )
    v.add_argument(
        "--path",
        default=None,
        help="Payload root (default: bounty/payloads)",
    )
    v.add_argument("--threshold", type=float, default=0.55)
    v.add_argument(
        "--structural-only",
        action="store_true",
        help="Skip semantic embeddings (fast CI / offline)",
    )

    parsed = p.parse_args()
    if parsed.cmd == "list":
        cmd_list(parsed)
    elif parsed.cmd == "status":
        cmd_status(parsed)
    elif parsed.cmd == "add":
        cmd_add(parsed)
    elif parsed.cmd == "set-status":
        cmd_update_status(parsed)
    elif parsed.cmd == "finding":
        cmd_finding(parsed)
    elif parsed.cmd == "pilot":
        cmd_pilot(parsed)
    elif parsed.cmd == "validate":
        cmd_validate(parsed)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
