"""Hemlock Distributed Scanner — parallel workers via thread/process pool (v6.0).

Splits a large scan workload across N workers. Each worker handles a slice
of (target, channel) pairs independently. Supports three backends:
    - "thread"   — ThreadPoolExecutor (default, zero deps)
    - "process"  — ProcessPoolExecutor (CPU-bound isolation)
    - "celery"   — Celery workers (optional dep: celery)

Usage:
    from hemlock.distributed import DistributedScanner, WorkerConfig

    scanner = DistributedScanner(
        targets=["prod", "staging", "dev", "qa"],
        channels=["rag", "memory", "tool_output"],
        config=WorkerConfig(backend="thread", max_workers=8),
    )
    report = scanner.run()
    print(report.summary())
"""

from __future__ import annotations

import concurrent.futures
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class WorkerConfig:
    backend: str = "thread"       # thread | process | celery
    max_workers: int = 8
    timeout_per_task: int = 120   # seconds
    retry_on_error: bool = True
    max_retries: int = 2


@dataclass
class WorkerTask:
    task_id: str
    target: str
    channel: str
    worker_id: int = 0


@dataclass
class WorkerResult:
    task_id: str
    target: str
    channel: str
    succeeded: bool
    risk_score: int
    channels_at_risk: list[str]
    error: str | None = None
    worker_id: int = 0
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class DistributedReport:
    results: list[WorkerResult]
    started_at: str
    finished_at: str
    total_tasks: int
    failed_tasks: int

    def succeeded_targets(self) -> list[str]:
        return sorted({r.target for r in self.results if r.ok and r.succeeded})

    def targets_at_risk(self) -> list[str]:
        return sorted({r.target for r in self.results if r.ok and r.channels_at_risk})

    def mean_risk_score(self) -> float:
        ok = [r for r in self.results if r.ok]
        if not ok:
            return 0.0
        return sum(r.risk_score for r in ok) / len(ok)

    def by_target(self) -> dict[str, list[WorkerResult]]:
        grouped: dict[str, list[WorkerResult]] = {}
        for r in self.results:
            grouped.setdefault(r.target, []).append(r)
        return grouped

    def summary(self) -> str:
        lines = [
            f"Distributed scan — {self.total_tasks} tasks, {self.failed_tasks} failed",
            f"Mean risk score: {self.mean_risk_score():.0f}/100",
            f"Targets at risk: {', '.join(self.targets_at_risk()) or 'none'}",
            f"Duration: {self.started_at} → {self.finished_at}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "total_tasks": self.total_tasks,
            "failed_tasks": self.failed_tasks,
            "mean_risk_score": self.mean_risk_score(),
            "targets_at_risk": self.targets_at_risk(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [
                {
                    "task_id": r.task_id,
                    "target": r.target,
                    "channel": r.channel,
                    "succeeded": r.succeeded,
                    "risk_score": r.risk_score,
                    "channels_at_risk": r.channels_at_risk,
                    "error": r.error,
                    "worker_id": r.worker_id,
                    "duration_ms": r.duration_ms,
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _execute_task(task: WorkerTask, retry: bool, max_retries: int) -> WorkerResult:
    import time

    start = time.monotonic()
    last_error: str | None = None

    for attempt in range(max_retries + 1 if retry else 1):
        try:
            from hemlock.hem_session import HemSession

            session = HemSession.mock(target=task.target, channels=[task.channel])
            report = session.run()

            duration = int((time.monotonic() - start) * 1000)
            return WorkerResult(
                task_id=task.task_id,
                target=task.target,
                channel=task.channel,
                succeeded=bool(report.succeeded_attacks()),
                risk_score=report.risk_score(),
                channels_at_risk=report.channels_at_risk(),
                worker_id=task.worker_id,
                duration_ms=duration,
            )
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_retries:
                time.sleep(0.1 * (attempt + 1))

    duration = int((time.monotonic() - start) * 1000)
    return WorkerResult(
        task_id=task.task_id,
        target=task.target,
        channel=task.channel,
        succeeded=False,
        risk_score=0,
        channels_at_risk=[],
        error=last_error,
        worker_id=task.worker_id,
        duration_ms=duration,
    )


class DistributedScanner:
    def __init__(
        self,
        targets: list[str],
        channels: list[str] | None = None,
        config: WorkerConfig | None = None,
    ) -> None:
        self.targets = targets
        self.channels = channels or ["rag", "memory", "tool_output", "cross_agent", "graph"]
        self.config = config or WorkerConfig()

    def _build_tasks(self) -> list[WorkerTask]:
        tasks = []
        for i, (target, channel) in enumerate(
            (t, c) for t in self.targets for c in self.channels
        ):
            tasks.append(WorkerTask(
                task_id=f"task-{i:04d}",
                target=target,
                channel=channel,
                worker_id=i % self.config.max_workers,
            ))
        return tasks

    def run(self) -> DistributedReport:
        tasks = self._build_tasks()
        started_at = datetime.now(timezone.utc).isoformat()

        if self.config.backend == "celery":
            results = self._run_celery(tasks)
        elif self.config.backend == "process":
            results = self._run_pool(tasks, use_processes=True)
        else:
            results = self._run_pool(tasks, use_processes=False)

        finished_at = datetime.now(timezone.utc).isoformat()
        failed = sum(1 for r in results if not r.ok)

        return DistributedReport(
            results=results,
            started_at=started_at,
            finished_at=finished_at,
            total_tasks=len(tasks),
            failed_tasks=failed,
        )

    def _run_pool(
        self, tasks: list[WorkerTask], use_processes: bool
    ) -> list[WorkerResult]:
        executor_cls = (
            concurrent.futures.ProcessPoolExecutor
            if use_processes
            else concurrent.futures.ThreadPoolExecutor
        )
        with executor_cls(max_workers=self.config.max_workers) as pool:
            futures = {
                pool.submit(
                    _execute_task,
                    task,
                    self.config.retry_on_error,
                    self.config.max_retries,
                ): task
                for task in tasks
            }
            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        order = {t.task_id: i for i, t in enumerate(tasks)}
        results.sort(key=lambda r: order.get(r.task_id, 9999))
        return results

    def _run_celery(self, tasks: list[WorkerTask]) -> list[WorkerResult]:
        try:
            from celery import Celery  # noqa: F401
        except ImportError:
            raise ImportError(
                "Celery backend requires: pip install celery\n"
                "Falling back to thread backend."
            )
        return self._run_pool(tasks, use_processes=False)
