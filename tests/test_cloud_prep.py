"""Tests for hemlock.cloud_prep (v6.5)."""

import json
import os
import tempfile
import pytest
from hemlock.cloud_prep import (
    CloudConfig,
    HealthProbe,
    HealthStatus,
    CloudExporter,
    ExportResult,
    UsageTracker,
    UsageRecord,
)


class MockReport:
    def to_json(self):
        return json.dumps({"status": "mock", "score": 40})

    def to_dict(self):
        return {"status": "mock", "score": 40}


def test_cloud_config_defaults():
    cfg = CloudConfig()
    assert cfg.storage_backend == "local"
    assert cfg.region == "us-east-1"
    assert cfg.enable_usage_tracking is True


def test_cloud_config_from_env(monkeypatch):
    monkeypatch.setenv("HEMLOCK_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("HEMLOCK_TENANT_ID", "tenant-123")
    monkeypatch.setenv("HEMLOCK_REGION", "eu-west-1")
    cfg = CloudConfig.from_env()
    assert cfg.storage_backend == "s3"
    assert cfg.tenant_id == "tenant-123"
    assert cfg.region == "eu-west-1"


def test_cloud_config_to_dict():
    cfg = CloudConfig(tenant_id="t1")
    d = cfg.to_dict()
    assert d["tenant_id"] == "t1"
    assert "storage_backend" in d


def test_health_probe_liveness():
    probe = HealthProbe()
    result = probe.liveness()
    assert result["status"] == "ok"
    assert "version" in result


def test_health_probe_readiness_ok():
    probe = HealthProbe(CloudConfig(storage_backend="local"))
    result = probe.readiness()
    assert result["status"] == "ready"
    assert "checks" in result
    assert "hemlock_importable" in result["checks"]


def test_health_probe_readiness_degraded_when_s3_no_endpoint():
    probe = HealthProbe(CloudConfig(storage_backend="s3", storage_endpoint=""))
    result = probe.readiness()
    assert result["status"] == "degraded"


def test_health_status_to_dict():
    hs = HealthStatus(status="ok", version="6.5.0", checks={"a": {"status": "ok"}})
    d = hs.to_dict()
    assert d["status"] == "ok"
    assert d["version"] == "6.5.0"


def test_cloud_exporter_local(tmp_path):
    dest = str(tmp_path / "exports")
    cfg = CloudConfig(storage_backend="local")
    exporter = CloudExporter(cfg)
    result = exporter.export(MockReport(), destination=dest)
    assert result.success is True
    assert result.size_bytes > 0
    assert os.path.exists(result.destination)


def test_cloud_exporter_local_content(tmp_path):
    dest = str(tmp_path / "exports")
    exporter = CloudExporter()
    result = exporter.export(MockReport(), destination=dest)
    with open(result.destination) as f:
        data = json.load(f)
    assert data["status"] == "mock"


def test_cloud_exporter_without_to_json(tmp_path):
    dest = str(tmp_path / "exports")
    exporter = CloudExporter()

    class PlainReport:
        pass

    result = exporter.export(PlainReport(), destination=dest)
    assert result.success is True


def test_cloud_exporter_http_error():
    cfg = CloudConfig(storage_backend="http")
    exporter = CloudExporter(cfg)
    result = exporter.export(MockReport(), destination="http://localhost:0/nowhere")
    assert result.success is False
    assert result.error is not None


def test_export_result_fields():
    r = ExportResult(destination="./out", size_bytes=100, success=True)
    assert r.destination == "./out"
    assert r.success is True
    assert r.error is None


def test_usage_tracker_record_and_retrieve(tmp_path):
    path = str(tmp_path / "usage.jsonl")
    tracker = UsageTracker(path=path)
    rec = UsageRecord(
        tenant_id="t1",
        action="scan",
        timestamp="2024-01-01T00:00:00Z",
        scan_channels=3,
    )
    tracker.record(rec)
    records = tracker.usage_for_tenant("t1")
    assert len(records) == 1
    assert records[0].action == "scan"
    assert records[0].scan_channels == 3


def test_usage_tracker_filters_by_tenant(tmp_path):
    path = str(tmp_path / "usage.jsonl")
    tracker = UsageTracker(path=path)
    tracker.record(UsageRecord(tenant_id="t1", action="scan", timestamp="T"))
    tracker.record(UsageRecord(tenant_id="t2", action="scan", timestamp="T"))
    assert len(tracker.usage_for_tenant("t1")) == 1
    assert len(tracker.usage_for_tenant("t2")) == 1


def test_usage_tracker_total_scans(tmp_path):
    path = str(tmp_path / "usage.jsonl")
    tracker = UsageTracker(path=path)
    tracker.record(UsageRecord(tenant_id="t1", action="scan", timestamp="T"))
    tracker.record(UsageRecord(tenant_id="t1", action="scan", timestamp="T"))
    tracker.record(UsageRecord(tenant_id="t1", action="eval", timestamp="T"))
    assert tracker.total_scans("t1") == 2


def test_usage_tracker_empty_when_no_file(tmp_path):
    path = str(tmp_path / "nonexistent.jsonl")
    tracker = UsageTracker(path=path)
    assert tracker.usage_for_tenant("t1") == []
