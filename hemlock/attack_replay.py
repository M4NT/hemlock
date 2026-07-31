"""Attack Replay Engine — records successful attacks and re-runs them to detect regressions (v7.4).

A ReplayRecord captures a single attack execution snapshot. ReplayStore persists
records in a JSONL file (last write wins per record_id). ReplayRunner re-executes
stored records against a new pipeline version and classifies each outcome as a
regression, improvement, or unchanged result. ReplayReport summarises the run.

Usage:
    from hemlock.attack_replay import ReplayRunner, ReplayStore

    store = ReplayStore()
    rec = ReplayRunner.record_from_result(
        attack_name="direct_injection",
        variant="explicit",
        payload="Ignore all previous instructions...",
        channel="rag",
        succeeded=True,
        pipeline_version="v1.0",
    )
    store.record(rec)

    runner = ReplayRunner(store)
    report = runner.replay(
        pipeline_factory=lambda channel: my_pipeline,
        pipeline_version="v1.1",
    )
    print(report.summary())
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# ── Records ────────────────────────────────────────────────────────────────────


@dataclass
class ReplayRecord:
    record_id: str
    attack_name: str
    variant: str
    payload: str
    channel: str
    succeeded: bool
    recorded_at: str
    pipeline_version: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "attack_name": self.attack_name,
            "variant": self.variant,
            "payload": self.payload,
            "channel": self.channel,
            "succeeded": self.succeeded,
            "recorded_at": self.recorded_at,
            "pipeline_version": self.pipeline_version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReplayRecord":
        return cls(
            record_id=d["record_id"],
            attack_name=d["attack_name"],
            variant=d["variant"],
            payload=d["payload"],
            channel=d["channel"],
            succeeded=bool(d["succeeded"]),
            recorded_at=d["recorded_at"],
            pipeline_version=d["pipeline_version"],
            metadata=d.get("metadata", {}),
        )


# ── Store ───────────────────────────────────────────────────────────────────────


class ReplayStore:
    def __init__(self, path: str = ".hemlock/replay_store.jsonl") -> None:
        self.path = path

    def _ensure_dir(self) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def record(self, rec: ReplayRecord) -> None:
        self._ensure_dir()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.to_dict()) + "\n")

    def all(self) -> list[ReplayRecord]:
        if not os.path.exists(self.path):
            return []
        seen: dict[str, ReplayRecord] = {}
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    rec = ReplayRecord.from_dict(d)
                    seen[rec.record_id] = rec
                except (json.JSONDecodeError, KeyError):
                    continue
        return list(seen.values())

    def by_attack(self, attack_name: str) -> list[ReplayRecord]:
        return [r for r in self.all() if r.attack_name == attack_name]

    def successful(self) -> list[ReplayRecord]:
        return [r for r in self.all() if r.succeeded]

    def by_channel(self, channel: str) -> list[ReplayRecord]:
        return [r for r in self.all() if r.channel == channel]


# ── Results ─────────────────────────────────────────────────────────────────────


@dataclass
class ReplayResult:
    record: ReplayRecord
    new_succeeded: bool
    regression: bool
    improvement: bool
    unchanged: bool


@dataclass
class ReplayReport:
    pipeline_version: str
    replayed_at: str
    total: int
    regressions: list[ReplayResult] = field(default_factory=list)
    improvements: list[ReplayResult] = field(default_factory=list)
    unchanged: list[ReplayResult] = field(default_factory=list)

    @property
    def regression_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return len(self.regressions) / self.total

    @property
    def improvement_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return len(self.improvements) / self.total

    def to_dict(self) -> dict[str, Any]:
        def _result_to_dict(r: ReplayResult) -> dict:
            return {
                "record_id": r.record.record_id,
                "attack_name": r.record.attack_name,
                "variant": r.record.variant,
                "channel": r.record.channel,
                "original_succeeded": r.record.succeeded,
                "new_succeeded": r.new_succeeded,
                "regression": r.regression,
                "improvement": r.improvement,
                "unchanged": r.unchanged,
            }

        return {
            "pipeline_version": self.pipeline_version,
            "replayed_at": self.replayed_at,
            "total": self.total,
            "regression_rate": self.regression_rate,
            "improvement_rate": self.improvement_rate,
            "regressions": [_result_to_dict(r) for r in self.regressions],
            "improvements": [_result_to_dict(r) for r in self.improvements],
            "unchanged": [_result_to_dict(r) for r in self.unchanged],
        }

    def summary(self) -> str:
        return (
            f"Replay {self.pipeline_version}: {self.total} records — "
            f"{len(self.regressions)} regressions ({self.regression_rate:.0%}), "
            f"{len(self.improvements)} improvements ({self.improvement_rate:.0%}), "
            f"{len(self.unchanged)} unchanged"
        )


# ── Runner ───────────────────────────────────────────────────────────────────────


class ReplayRunner:
    def __init__(self, store: ReplayStore) -> None:
        self.store = store

    @staticmethod
    def _execute_replay(record: ReplayRecord, pipeline: Any) -> bool:
        run_fn = getattr(pipeline, "run", None)
        if callable(run_fn):
            result = run_fn(record.payload)
        else:
            result = str(pipeline(record.payload))
        return "INJECTION_SUCCEEDED" in str(result)

    @staticmethod
    def _classify(record: ReplayRecord, new_succeeded: bool) -> ReplayResult:
        regression = (not record.succeeded) and new_succeeded
        improvement = record.succeeded and (not new_succeeded)
        unchanged = record.succeeded == new_succeeded
        return ReplayResult(
            record=record,
            new_succeeded=new_succeeded,
            regression=regression,
            improvement=improvement,
            unchanged=unchanged,
        )

    def replay(
        self,
        pipeline_factory: Callable[[str], Any],
        pipeline_version: str,
        filter_channel: str | None = None,
        filter_attack: str | None = None,
    ) -> ReplayReport:
        records = self.store.all()

        if filter_channel is not None:
            records = [r for r in records if r.channel == filter_channel]
        if filter_attack is not None:
            records = [r for r in records if r.attack_name == filter_attack]

        regressions: list[ReplayResult] = []
        improvements: list[ReplayResult] = []
        unchanged: list[ReplayResult] = []

        for record in records:
            try:
                pipeline = pipeline_factory(record.channel)
                new_succeeded = self._execute_replay(record, pipeline)
            except Exception:
                new_succeeded = False

            result = self._classify(record, new_succeeded)

            if result.regression:
                regressions.append(result)
            elif result.improvement:
                improvements.append(result)
            else:
                unchanged.append(result)

        return ReplayReport(
            pipeline_version=pipeline_version,
            replayed_at=datetime.now(timezone.utc).isoformat(),
            total=len(records),
            regressions=regressions,
            improvements=improvements,
            unchanged=unchanged,
        )

    @staticmethod
    def record_from_result(
        attack_name: str,
        variant: str,
        payload: str,
        channel: str,
        succeeded: bool,
        pipeline_version: str,
        metadata: dict | None = None,
    ) -> ReplayRecord:
        record_id = hashlib.sha256(
            f"{attack_name}{variant}{payload[:20]}".encode()
        ).hexdigest()[:16]
        return ReplayRecord(
            record_id=record_id,
            attack_name=attack_name,
            variant=variant,
            payload=payload,
            channel=channel,
            succeeded=succeeded,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            pipeline_version=pipeline_version,
            metadata=metadata or {},
        )
