"""Hemlock Benchmark Registry — shared, comparable benchmark results (v6.4).

A local registry of EvalReport snapshots that can be shared, compared,
and published. Lays the groundwork for the Hemlock Eval Protocol (v7.0).

Each entry carries:
    - model_version / pipeline_label
    - category scores
    - hemlock version used
    - optional provenance hash (SHA-256 of the run inputs)

Usage:
    from hemlock.benchmark_registry import BenchmarkRegistry

    registry = BenchmarkRegistry()
    entry_id = registry.publish(eval_report, label="gpt-4o-mini-2024-10")
    print(entry_id)

    entries = registry.list()
    leaderboard = registry.leaderboard()
    for rank, entry in enumerate(leaderboard, 1):
        print(f"{rank}. {entry.label}: {entry.overall_score}")
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class RegistryEntry:
    entry_id: str
    label: str
    model_version: str
    overall_score: int
    category_scores: dict[str, int]
    hemlock_version: str
    published_at: str
    provenance_hash: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "label": self.label,
            "model_version": self.model_version,
            "overall_score": self.overall_score,
            "category_scores": self.category_scores,
            "hemlock_version": self.hemlock_version,
            "published_at": self.published_at,
            "provenance_hash": self.provenance_hash,
            "metadata": self.metadata,
        }


def _provenance_hash(report: Any) -> str:
    payload = json.dumps(
        {s.attack_name: s.succeeded for s in report.scenarios}, sort_keys=True
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _entry_id(label: str, ts: str) -> str:
    payload = f"{label}:{ts}"
    return hashlib.sha256(payload.encode()).hexdigest()[:8]


class BenchmarkRegistry:
    def __init__(self, path: str = ".hemlock/benchmark_registry.json") -> None:
        self._path = path
        self._entries: list[RegistryEntry] = []
        self._load()

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path, encoding="utf-8") as f:
                    data = json.load(f)
                self._entries = [RegistryEntry(**e) for e in data]
            except (json.JSONDecodeError, TypeError):
                self._entries = []

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2)

    def publish(self, report: Any, label: str = "") -> str:
        from hemlock import __version__

        ts = datetime.now(timezone.utc).isoformat()
        entry_id = _entry_id(label or report.model_name, ts)

        entry = RegistryEntry(
            entry_id=entry_id,
            label=label or report.model_name,
            model_version=report.model_name,
            overall_score=report.overall_score(),
            category_scores=report.category_scores(),
            hemlock_version=__version__,
            published_at=ts,
            provenance_hash=_provenance_hash(report),
        )
        self._entries.append(entry)
        self._save()
        return entry_id

    def get(self, entry_id: str) -> RegistryEntry | None:
        return next((e for e in self._entries if e.entry_id == entry_id), None)

    def list(self, label: str | None = None) -> list[RegistryEntry]:
        if label:
            return [e for e in self._entries if e.label == label]
        return list(self._entries)

    def leaderboard(self, top_n: int | None = None) -> list[RegistryEntry]:
        ranked = sorted(self._entries, key=lambda e: e.overall_score, reverse=True)
        return ranked[:top_n] if top_n else ranked

    def compare(self, entry_id_a: str, entry_id_b: str) -> dict:
        a = self.get(entry_id_a)
        b = self.get(entry_id_b)
        if not a or not b:
            return {}
        all_cats = set(a.category_scores) | set(b.category_scores)
        deltas = {
            cat: a.category_scores.get(cat, 0) - b.category_scores.get(cat, 0)
            for cat in all_cats
        }
        return {
            "a": {"id": a.entry_id, "label": a.label, "score": a.overall_score},
            "b": {"id": b.entry_id, "label": b.label, "score": b.overall_score},
            "overall_delta": a.overall_score - b.overall_score,
            "category_deltas": deltas,
        }

    def delete(self, entry_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.entry_id != entry_id]
        if len(self._entries) < before:
            self._save()
            return True
        return False

    def to_markdown(self) -> str:
        if not self._entries:
            return "No entries in registry."
        lb = self.leaderboard()
        lines = [
            "# Hemlock Benchmark Leaderboard\n",
            "| Rank | Label | Model | Score | Published |",
            "|------|-------|-------|-------|-----------|",
        ]
        for i, e in enumerate(lb, 1):
            lines.append(
                f"| {i} | {e.label} | {e.model_version} | {e.overall_score} | {e.published_at[:10]} |"
            )
        return "\n".join(lines)
