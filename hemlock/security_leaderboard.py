"""Unified Security Leaderboard — v8.3.

Merges Eval benchmark entries (BenchmarkRegistry) and multi-provider security
profiles (ProviderRegistry) into one comparable leaderboard for publishing and
CI comparison.

Usage:
    from hemlock.security_leaderboard import SecurityLeaderboard, LeaderboardEntry

    board = SecurityLeaderboard()
    board.publish_from_provider_profile(profile)
    board.publish_from_eval_report(eval_report, label="gpt-4o-mini")
    print(board.to_markdown())
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class LeaderboardEntry:
    entry_id: str
    label: str
    source: str  # eval | provider | scorer
    security_score: float  # higher = safer (0–100)
    risk_score: float  # higher = riskier (0–100)
    attack_scores: dict[str, float] = field(default_factory=dict)
    category_scores: dict[str, float] = field(default_factory=dict)
    hemlock_version: str = ""
    published_at: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "label": self.label,
            "source": self.source,
            "security_score": self.security_score,
            "risk_score": self.risk_score,
            "attack_scores": self.attack_scores,
            "category_scores": self.category_scores,
            "hemlock_version": self.hemlock_version,
            "published_at": self.published_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LeaderboardEntry":
        return cls(
            entry_id=d["entry_id"],
            label=d["label"],
            source=d.get("source", "unknown"),
            security_score=float(d.get("security_score", 0.0)),
            risk_score=float(d.get("risk_score", 0.0)),
            attack_scores=dict(d.get("attack_scores", {})),
            category_scores=dict(d.get("category_scores", {})),
            hemlock_version=d.get("hemlock_version", ""),
            published_at=d.get("published_at", ""),
            metadata=dict(d.get("metadata", {})),
        )


def _entry_id(label: str, ts: str) -> str:
    return hashlib.sha256(f"{label}:{ts}".encode()).hexdigest()[:10]


class SecurityLeaderboard:
    """Persistent unified leaderboard across eval and provider benchmarks."""

    def __init__(self, path: str = ".hemlock/security_leaderboard.json") -> None:
        self._path = path
        self._entries: list[LeaderboardEntry] = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            self._entries = [LeaderboardEntry.from_dict(e) for e in data.get("entries", [])]
        except (json.JSONDecodeError, TypeError, KeyError):
            self._entries = []

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({"entries": [e.to_dict() for e in self._entries]}, f, indent=2)

    def publish(self, entry: LeaderboardEntry) -> str:
        self._entries.append(entry)
        self._save()
        return entry.entry_id

    def publish_from_eval_report(self, report: Any, label: str = "") -> str:
        from hemlock import __version__

        ts = datetime.now(timezone.utc).isoformat()
        label = label or getattr(report, "model_name", "eval")
        overall = float(report.overall_score())
        categories = dict(report.category_scores()) if hasattr(report, "category_scores") else {}
        entry = LeaderboardEntry(
            entry_id=_entry_id(label, ts),
            label=label,
            source="eval",
            security_score=round(overall, 2),
            risk_score=round(100.0 - overall, 2),
            category_scores={k: float(v) for k, v in categories.items()},
            hemlock_version=__version__,
            published_at=ts,
            metadata={"model_name": getattr(report, "model_name", label)},
        )
        return self.publish(entry)

    def publish_from_provider_profile(self, profile: Any, label: str = "") -> str:
        from hemlock import __version__

        ts = datetime.now(timezone.utc).isoformat()
        label = label or profile.provider_id
        risk = float(profile.overall_risk)
        attacks = dict(profile.attack_scores)
        entry = LeaderboardEntry(
            entry_id=_entry_id(label, ts),
            label=label,
            source="provider",
            security_score=round(100.0 - risk, 2),
            risk_score=round(risk, 2),
            attack_scores=attacks,
            hemlock_version=__version__,
            published_at=ts,
            metadata={
                "provider_id": profile.provider_id,
                "pipeline_version": profile.pipeline_version,
                "block_rate": profile.block_rate(),
            },
        )
        return self.publish(entry)

    def publish_from_scorer_json(self, data: dict, label: str = "") -> str:
        from hemlock import __version__
        from hemlock.operational_cli import attack_rates_from_scorer_json

        ts = datetime.now(timezone.utc).isoformat()
        label = label or data.get("model", "scorer")
        success_rate = float(data.get("success_rate", 0.0))
        if success_rate <= 1.0:
            success_rate *= 100.0
        risk = success_rate
        attacks = attack_rates_from_scorer_json(data)
        entry = LeaderboardEntry(
            entry_id=_entry_id(label, ts),
            label=label,
            source="scorer",
            security_score=round(100.0 - risk, 2),
            risk_score=round(risk, 2),
            attack_scores=attacks,
            hemlock_version=__version__,
            published_at=ts,
            metadata={"total_scenarios": data.get("total_scenarios", 0)},
        )
        return self.publish(entry)

    def import_registries(
        self,
        benchmark_path: str = ".hemlock/benchmark_registry.json",
        provider_path: str = ".hemlock/provider_registry.json",
    ) -> list[str]:
        """Import latest entries from benchmark and provider registries."""
        ids: list[str] = []
        if os.path.exists(benchmark_path):
            from hemlock.benchmark_registry import BenchmarkRegistry

            reg = BenchmarkRegistry(benchmark_path)
            for e in reg.leaderboard():
                ts = datetime.now(timezone.utc).isoformat()
                entry = LeaderboardEntry(
                    entry_id=_entry_id(e.label, ts),
                    label=e.label,
                    source="eval",
                    security_score=float(e.overall_score),
                    risk_score=round(100.0 - e.overall_score, 2),
                    category_scores={k: float(v) for k, v in e.category_scores.items()},
                    hemlock_version=e.hemlock_version,
                    published_at=e.published_at,
                    metadata={"registry_entry_id": e.entry_id},
                )
                ids.append(self.publish(entry))

        if os.path.exists(provider_path):
            from hemlock.provider_comparison import ProviderRegistry

            reg = ProviderRegistry(provider_path)
            for p in reg.all():
                ids.append(self.publish_from_provider_profile(p))
        return ids

    def all(self) -> list[LeaderboardEntry]:
        return list(self._entries)

    def ranked(self, top_n: int | None = None) -> list[LeaderboardEntry]:
        ordered = sorted(self._entries, key=lambda e: e.security_score, reverse=True)
        return ordered[:top_n] if top_n else ordered

    def compare(self, entry_id_a: str, entry_id_b: str) -> dict:
        a = next((e for e in self._entries if e.entry_id == entry_id_a), None)
        b = next((e for e in self._entries if e.entry_id == entry_id_b), None)
        if not a or not b:
            return {}
        all_attacks = set(a.attack_scores) | set(b.attack_scores)
        deltas = {
            atk: round(a.attack_scores.get(atk, 0.0) - b.attack_scores.get(atk, 0.0), 3)
            for atk in all_attacks
        }
        return {
            "a": {"id": a.entry_id, "label": a.label, "security_score": a.security_score},
            "b": {"id": b.entry_id, "label": b.label, "security_score": b.security_score},
            "security_delta": round(a.security_score - b.security_score, 2),
            "risk_delta": round(a.risk_score - b.risk_score, 2),
            "attack_deltas": deltas,
        }

    def to_markdown(self) -> str:
        rows = self.ranked()
        if not rows:
            return "# Hemlock Security Leaderboard\n\nNo entries yet."
        lines = [
            "# Hemlock Security Leaderboard",
            "",
            "| Rank | Label | Source | Security | Risk | Published |",
            "|------|-------|--------|----------|------|-----------|",
        ]
        for i, e in enumerate(rows, 1):
            lines.append(
                f"| {i} | {e.label} | {e.source} | {e.security_score:.1f} | "
                f"{e.risk_score:.1f} | {e.published_at[:10]} |"
            )
        return "\n".join(lines)

    def sync_from_legacy(self) -> int:
        """Import from benchmark + provider registries. Returns count imported."""
        return len(self.import_registries())
