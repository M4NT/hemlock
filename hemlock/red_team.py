"""Hemlock Red Team Campaign — scheduled scans with auto-diff (v5.1).

Runs a Campaign on a schedule, diffs each result against the previous run,
and alerts when new targets become at risk or risk scores regress.

Usage:
    from hemlock.red_team import RedTeamScheduler, RedTeamConfig

    scheduler = RedTeamScheduler(
        targets=["prod", "staging", "dev"],
        config=RedTeamConfig(
            interval_seconds=3600,
            risk_regression_threshold=10,
            webhook_url="https://hooks.slack.com/...",
            history_path=".hemlock/red_team_history.json",
        ),
    )
    scheduler.run_once()   # single run + diff
    scheduler.start()      # blocking loop
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable


@dataclass
class RedTeamConfig:
    interval_seconds: int = 3600
    risk_regression_threshold: int = 10
    history_path: str = ".hemlock/red_team_history.json"
    webhook_url: str | None = None
    channels: list[str] | None = None
    max_workers: int = 4


@dataclass
class RedTeamDiff:
    timestamp: str
    new_at_risk: list[str]           # targets that became at risk
    recovered: list[str]             # targets that are no longer at risk
    regressed: list[str]             # targets whose risk score increased > threshold
    improved: list[str]              # targets whose risk score decreased
    score_deltas: dict[str, int]     # target → delta
    alert: bool

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "new_at_risk": self.new_at_risk,
            "recovered": self.recovered,
            "regressed": self.regressed,
            "improved": self.improved,
            "score_deltas": self.score_deltas,
            "alert": self.alert,
        }


@dataclass
class RedTeamHistoryEntry:
    timestamp: str
    scores: dict[str, int]          # target → risk_score
    at_risk: dict[str, list[str]]   # target → channels_at_risk
    diff: RedTeamDiff | None = None

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "scores": self.scores,
            "at_risk": self.at_risk,
        }
        if self.diff:
            d["diff"] = self.diff.to_dict()
        return d


class RedTeamScheduler:
    def __init__(
        self,
        targets: list[str],
        config: RedTeamConfig | None = None,
        on_alert: Callable[[RedTeamDiff], None] | None = None,
    ) -> None:
        self.targets = targets
        self.config = config or RedTeamConfig()
        self.on_alert = on_alert
        self._history: list[RedTeamHistoryEntry] = []
        self._load_history()

    # ── Persistence ─────────────────────────────────────────────────────────

    def _load_history(self) -> None:
        if os.path.exists(self.config.history_path):
            try:
                with open(self.config.history_path, encoding="utf-8") as f:
                    raw = json.load(f)
                for entry in raw:
                    diff = None
                    if "diff" in entry and entry["diff"]:
                        d = entry["diff"]
                        diff = RedTeamDiff(
                            timestamp=d.get("timestamp", ""),
                            new_at_risk=d.get("new_at_risk", []),
                            recovered=d.get("recovered", []),
                            regressed=d.get("regressed", []),
                            improved=d.get("improved", []),
                            score_deltas=d.get("score_deltas", {}),
                            alert=d.get("alert", False),
                        )
                    self._history.append(RedTeamHistoryEntry(
                        timestamp=entry["timestamp"],
                        scores=entry.get("scores", {}),
                        at_risk=entry.get("at_risk", {}),
                        diff=diff,
                    ))
            except (json.JSONDecodeError, KeyError):
                self._history = []

    def _save_history(self) -> None:
        os.makedirs(os.path.dirname(self.config.history_path) or ".", exist_ok=True)
        with open(self.config.history_path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._history], f, indent=2)

    # ── Core logic ──────────────────────────────────────────────────────────

    def _run_campaign(self) -> tuple[dict[str, int], dict[str, list[str]]]:
        from hemlock.campaign import Campaign, CampaignTarget

        campaign = Campaign(
            targets=[
                CampaignTarget(name=t, channels=self.config.channels)
                for t in self.targets
            ],
            max_workers=self.config.max_workers,
        )
        report = campaign.run()
        scores = {r.target_name: r.risk_score for r in report.results}
        at_risk = {r.target_name: r.channels_at_risk for r in report.results}
        return scores, at_risk

    def _diff(
        self,
        prev: RedTeamHistoryEntry | None,
        scores: dict[str, int],
        at_risk: dict[str, list[str]],
    ) -> RedTeamDiff:
        now = datetime.now(timezone.utc).isoformat()

        if prev is None:
            return RedTeamDiff(
                timestamp=now,
                new_at_risk=list(at_risk.keys()),
                recovered=[],
                regressed=[],
                improved=[],
                score_deltas={t: scores[t] for t in scores},
                alert=bool(at_risk),
            )

        prev_at_risk = set(t for t, ch in prev.at_risk.items() if ch)
        curr_at_risk = set(t for t, ch in at_risk.items() if ch)

        new_at_risk = sorted(curr_at_risk - prev_at_risk)
        recovered = sorted(prev_at_risk - curr_at_risk)

        score_deltas: dict[str, int] = {}
        regressed: list[str] = []
        improved: list[str] = []

        for t in scores:
            prev_score = prev.scores.get(t, 0)
            delta = scores[t] - prev_score
            score_deltas[t] = delta
            if delta > self.config.risk_regression_threshold:
                regressed.append(t)
            elif delta < 0:
                improved.append(t)

        alert = bool(new_at_risk or regressed)

        return RedTeamDiff(
            timestamp=now,
            new_at_risk=new_at_risk,
            recovered=recovered,
            regressed=regressed,
            improved=improved,
            score_deltas=score_deltas,
            alert=alert,
        )

    def _notify(self, diff: RedTeamDiff) -> None:
        if self.on_alert:
            self.on_alert(diff)
        if self.config.webhook_url:
            try:
                import urllib.request
                payload = json.dumps(diff.to_dict()).encode()
                req = urllib.request.Request(
                    self.config.webhook_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

    # ── Public API ───────────────────────────────────────────────────────────

    def run_once(self) -> RedTeamHistoryEntry:
        scores, at_risk = self._run_campaign()
        prev = self._history[-1] if self._history else None
        diff = self._diff(prev, scores, at_risk)

        entry = RedTeamHistoryEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            scores=scores,
            at_risk=at_risk,
            diff=diff,
        )
        self._history.append(entry)
        self._save_history()

        if diff.alert:
            self._notify(diff)

        return entry

    def start(self) -> None:
        while True:
            self.run_once()
            time.sleep(self.config.interval_seconds)

    def history(self) -> list[RedTeamHistoryEntry]:
        return list(self._history)

    def latest(self) -> RedTeamHistoryEntry | None:
        return self._history[-1] if self._history else None
