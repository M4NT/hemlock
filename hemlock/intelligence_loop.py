"""Attack intelligence loop — v9.0.

Wires scan results into replay storage, threat intel advisories, and
optional auto red-team probing. Designed to run inside ScanOrchestrator
after each scheduled scan.

Usage:
    from hemlock.intelligence_loop import IntelligenceLoop

    loop = IntelligenceLoop()
    result = loop.after_scan(hem_report, pipeline_version="v2.1.0")
    print(result.new_techniques)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class IntelligenceLoopResult:
    replay_recorded: int = 0
    advisories_fetched: int = 0
    new_techniques: list[str] = field(default_factory=list)
    auto_red_team_successes: int = 0
    auto_red_team_channels: list[str] = field(default_factory=list)
    processed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "replay_recorded": self.replay_recorded,
            "advisories_fetched": self.advisories_fetched,
            "new_techniques": self.new_techniques,
            "auto_red_team_successes": self.auto_red_team_successes,
            "auto_red_team_channels": self.auto_red_team_channels,
            "processed_at": self.processed_at,
        }


class IntelligenceLoop:
    """Post-scan intelligence: replay capture, threat intel, optional red team."""

    def __init__(
        self,
        replay_store_path: str = ".hemlock/replay_store.jsonl",
        intel_cache_path: str = ".hemlock/threat_intel_cache.json",
        seen_techniques_path: str = ".hemlock/seen_techniques.json",
        enable_auto_red_team: bool = True,
        auto_red_team_rounds: int = 1,
    ) -> None:
        self.replay_store_path = replay_store_path
        self.intel_cache_path = intel_cache_path
        self.seen_techniques_path = seen_techniques_path
        self.enable_auto_red_team = enable_auto_red_team
        self.auto_red_team_rounds = auto_red_team_rounds

    def _load_seen(self) -> set[str]:
        if not os.path.exists(self.seen_techniques_path):
            return set()
        try:
            with open(self.seen_techniques_path, encoding="utf-8") as f:
                data = json.load(f)
            return set(data.get("cve_ids", []))
        except (json.JSONDecodeError, OSError):
            return set()

    def _save_seen(self, seen: set[str]) -> None:
        os.makedirs(os.path.dirname(self.seen_techniques_path) or ".", exist_ok=True)
        with open(self.seen_techniques_path, "w", encoding="utf-8") as f:
            json.dump({"cve_ids": sorted(seen)}, f, indent=2)

    def record_replay_from_report(self, report: Any, pipeline_version: str) -> int:
        from hemlock.attack_replay import ReplayRunner, ReplayStore

        store = ReplayStore(self.replay_store_path)
        count = 0
        results = getattr(report, "results", [])
        for r in results:
            if not getattr(r, "succeeded", False):
                continue
            channel = getattr(r, "channel", "unknown")
            variant = getattr(r, "variant", channel)
            detail = getattr(r, "detail", "")
            rec = ReplayRunner.record_from_result(
                attack_name=variant,
                variant=channel,
                payload=detail or f"[hemlock] successful attack on {channel}",
                channel=channel,
                succeeded=True,
                pipeline_version=pipeline_version,
            )
            store.record(rec)
            count += 1
        return count

    def fetch_new_techniques(self) -> tuple[int, list[str]]:
        from hemlock.threat_intel import FeedConfig, ThreatIntelFeed

        feed = ThreatIntelFeed(FeedConfig(use_mock=True, cache_path=self.intel_cache_path))
        advisories = feed.fetch()
        seen = self._load_seen()
        new: list[str] = []
        for adv in advisories:
            label = f"{adv.cve_id}: {adv.title}"
            if adv.cve_id not in seen:
                new.append(label)
                seen.add(adv.cve_id)
        if new:
            self._save_seen(seen)
        return len(advisories), new

    def run_auto_red_team(self, pipeline: Any | None = None) -> tuple[int, list[str]]:
        from hemlock.auto_red_team import AgentConfig, AutoRedTeamAgent

        agent = AutoRedTeamAgent(
            pipeline=pipeline,
            config=AgentConfig(
                max_rounds=self.auto_red_team_rounds,
                budget_attacks=3,
                use_healing=False,
            ),
        )
        report = agent.run()
        return report.total_successes, report.exploited_channels

    def after_scan(
        self,
        report: Any,
        pipeline_version: str,
        pipeline: Any | None = None,
    ) -> IntelligenceLoopResult:
        result = IntelligenceLoopResult(
            processed_at=datetime.now(timezone.utc).isoformat(),
        )
        result.replay_recorded = self.record_replay_from_report(report, pipeline_version)
        fetched, new = self.fetch_new_techniques()
        result.advisories_fetched = fetched
        result.new_techniques = new

        if self.enable_auto_red_team:
            successes, channels = self.run_auto_red_team(pipeline)
            result.auto_red_team_successes = successes
            result.auto_red_team_channels = channels

        return result
