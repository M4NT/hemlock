"""Hemlock Campaign runner — parallel multi-target scans (v4.8).

A Campaign scans N targets concurrently using a thread pool and produces a
consolidated CampaignReport with per-target results and an aggregate summary.

Usage:
    from hemlock.campaign import Campaign, CampaignTarget

    campaign = Campaign(
        targets=[
            CampaignTarget(name="prod", channels=["rag", "memory"]),
            CampaignTarget(name="staging", channels=["rag"]),
        ],
        max_workers=4,
    )
    report = campaign.run()
    print(report.to_markdown())
    print(report.highest_risk_target())
"""

from __future__ import annotations

import json
import concurrent.futures
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CampaignTarget:
    name: str
    channels: list[str] | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class TargetResult:
    target_name: str
    risk_score: int
    channels_at_risk: list[str]
    succeeded_count: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class CampaignReport:
    results: list[TargetResult]

    def highest_risk_target(self) -> str | None:
        ok = [r for r in self.results if r.ok]
        if not ok:
            return None
        return max(ok, key=lambda r: r.risk_score).target_name

    def targets_at_risk(self) -> list[str]:
        return [r.target_name for r in self.results if r.ok and r.channels_at_risk]

    def mean_risk_score(self) -> float:
        ok = [r for r in self.results if r.ok]
        if not ok:
            return 0.0
        return sum(r.risk_score for r in ok) / len(ok)

    def failed_targets(self) -> list[str]:
        return [r.target_name for r in self.results if not r.ok]

    def to_dict(self) -> dict:
        return {
            "mean_risk_score": self.mean_risk_score(),
            "highest_risk_target": self.highest_risk_target(),
            "targets_at_risk": self.targets_at_risk(),
            "failed_targets": self.failed_targets(),
            "results": [
                {
                    "target": r.target_name,
                    "risk_score": r.risk_score,
                    "channels_at_risk": r.channels_at_risk,
                    "succeeded_count": r.succeeded_count,
                    "error": r.error,
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            "# Hemlock Campaign Report\n",
            f"**Mean risk score:** {self.mean_risk_score():.0f} / 100  ",
            f"**Highest risk target:** {self.highest_risk_target() or '—'}  ",
            f"**Targets at risk:** {', '.join(self.targets_at_risk()) or 'none'}  ",
            "",
            "| Target | Risk Score | Channels at Risk | Succeeded | Error |",
            "|--------|-----------|-----------------|-----------|-------|",
        ]
        for r in self.results:
            lines.append(
                f"| {r.target_name} | {r.risk_score} "
                f"| {', '.join(r.channels_at_risk) or '—'} "
                f"| {r.succeeded_count} "
                f"| {r.error or '—'} |"
            )
        return "\n".join(lines)


def _scan_target(target: CampaignTarget) -> TargetResult:
    try:
        from hemlock.hem_session import HemSession

        session = HemSession.mock(target=target.name, channels=target.channels)
        report = session.run()
        return TargetResult(
            target_name=target.name,
            risk_score=report.risk_score(),
            channels_at_risk=report.channels_at_risk(),
            succeeded_count=len(report.succeeded_attacks()),
        )
    except Exception as exc:
        return TargetResult(
            target_name=target.name,
            risk_score=0,
            channels_at_risk=[],
            succeeded_count=0,
            error=str(exc),
        )


class Campaign:
    def __init__(
        self,
        targets: list[CampaignTarget],
        max_workers: int = 4,
    ) -> None:
        self.targets = targets
        self.max_workers = max_workers

    def run(self) -> CampaignReport:
        if self.max_workers == 1:
            results = [_scan_target(t) for t in self.targets]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(_scan_target, t): t for t in self.targets}
                results = []
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
            # restore deterministic order
            order = {t.name: i for i, t in enumerate(self.targets)}
            results.sort(key=lambda r: order.get(r.target_name, 9999))

        return CampaignReport(results=results)
