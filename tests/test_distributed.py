"""Tests for hemlock.distributed (v6.0)."""

import pytest
from hemlock.distributed import (
    DistributedScanner,
    DistributedReport,
    WorkerConfig,
    WorkerTask,
    WorkerResult,
    _execute_task,
)


def make_result(target="prod", channel="rag", succeeded=True, risk_score=40, error=None):
    return WorkerResult(
        task_id="task-0000",
        target=target,
        channel=channel,
        succeeded=succeeded,
        risk_score=risk_score,
        channels_at_risk=[channel] if succeeded else [],
        error=error,
    )


def test_worker_config_defaults():
    cfg = WorkerConfig()
    assert cfg.backend == "thread"
    assert cfg.max_workers == 8


def test_worker_task_fields():
    t = WorkerTask(task_id="task-0001", target="prod", channel="rag", worker_id=2)
    assert t.task_id == "task-0001"
    assert t.worker_id == 2


def test_worker_result_ok():
    r = make_result()
    assert r.ok is True


def test_worker_result_ok_false_on_error():
    r = make_result(error="timeout")
    assert r.ok is False


def test_distributed_report_succeeded_targets():
    results = [
        make_result(target="prod", succeeded=True),
        make_result(target="staging", succeeded=False),
    ]
    report = DistributedReport(
        results=results,
        started_at="2024-01-01T00:00:00+00:00",
        finished_at="2024-01-01T00:01:00+00:00",
        total_tasks=2,
        failed_tasks=0,
    )
    assert "prod" in report.succeeded_targets()
    assert "staging" not in report.succeeded_targets()


def test_distributed_report_targets_at_risk():
    results = [
        make_result(target="prod", succeeded=True, risk_score=60),
        make_result(target="dev", succeeded=False, risk_score=0),
    ]
    report = DistributedReport(
        results=results,
        started_at="",
        finished_at="",
        total_tasks=2,
        failed_tasks=0,
    )
    assert report.targets_at_risk() == ["prod"]


def test_distributed_report_mean_risk_score():
    results = [
        make_result(risk_score=40),
        make_result(risk_score=60),
    ]
    report = DistributedReport(
        results=results,
        started_at="",
        finished_at="",
        total_tasks=2,
        failed_tasks=0,
    )
    assert report.mean_risk_score() == 50.0


def test_distributed_report_mean_risk_score_no_ok():
    results = [make_result(error="err")]
    report = DistributedReport(
        results=results,
        started_at="",
        finished_at="",
        total_tasks=1,
        failed_tasks=1,
    )
    assert report.mean_risk_score() == 0.0


def test_distributed_report_by_target():
    results = [
        make_result(target="prod", channel="rag"),
        make_result(target="prod", channel="memory"),
        make_result(target="staging", channel="rag"),
    ]
    report = DistributedReport(results=results, started_at="", finished_at="", total_tasks=3, failed_tasks=0)
    grouped = report.by_target()
    assert len(grouped["prod"]) == 2
    assert len(grouped["staging"]) == 1


def test_distributed_report_summary():
    results = [make_result(risk_score=50)]
    report = DistributedReport(results=results, started_at="T0", finished_at="T1", total_tasks=1, failed_tasks=0)
    summary = report.summary()
    assert "1 tasks" in summary
    assert "T0" in summary


def test_distributed_report_to_json():
    import json
    results = [make_result()]
    report = DistributedReport(results=results, started_at="", finished_at="", total_tasks=1, failed_tasks=0)
    doc = json.loads(report.to_json())
    assert doc["total_tasks"] == 1
    assert "results" in doc


def test_distributed_scanner_build_tasks():
    scanner = DistributedScanner(targets=["a", "b"], channels=["rag", "memory"])
    tasks = scanner._build_tasks()
    assert len(tasks) == 4  # 2 targets × 2 channels
    assert all(t.task_id.startswith("task-") for t in tasks)


def test_distributed_scanner_run_thread():
    scanner = DistributedScanner(
        targets=["prod"],
        channels=["rag"],
        config=WorkerConfig(backend="thread", max_workers=2),
    )
    report = scanner.run()
    assert report.total_tasks == 1
    assert len(report.results) == 1


def test_distributed_scanner_run_multiple_targets():
    scanner = DistributedScanner(
        targets=["t1", "t2"],
        channels=["rag"],
        config=WorkerConfig(backend="thread", max_workers=2, retry_on_error=False),
    )
    report = scanner.run()
    assert report.total_tasks == 2


def test_distributed_scanner_celery_raises_without_celery():
    scanner = DistributedScanner(
        targets=["prod"],
        channels=["rag"],
        config=WorkerConfig(backend="celery"),
    )
    import sys
    celery_installed = "celery" in sys.modules
    if not celery_installed:
        with pytest.raises((ImportError, Exception)):
            scanner.run()


def test_execute_task_returns_worker_result():
    task = WorkerTask(task_id="task-test", target="test-target", channel="rag")
    result = _execute_task(task, retry=False, max_retries=0)
    assert isinstance(result, WorkerResult)
    assert result.task_id == "task-test"
