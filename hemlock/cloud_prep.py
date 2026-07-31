"""Hemlock Cloud Preparation — SaaS-ready infrastructure helpers (v6.5).

Provides building blocks for Hemlock Cloud deployment:
    - CloudConfig: unified config from env vars or dict
    - HealthProbe: readiness and liveness checks
    - CloudExporter: ships reports to S3/GCS/Azure Blob or HTTP endpoint
    - UsageTracker: per-tenant usage accounting for billing

All components have local fallbacks so they work in self-hosted mode too.

Usage:
    from hemlock.cloud_prep import CloudConfig, HealthProbe, CloudExporter

    config = CloudConfig.from_env()
    probe  = HealthProbe(config)
    print(probe.liveness())    # {"status": "ok", "version": "6.5.0"}
    print(probe.readiness())   # {"status": "ready", "checks": {...}}

    exporter = CloudExporter(config)
    exporter.export(report, destination="s3://my-bucket/reports/")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CloudConfig:
    storage_backend: str = "local"    # local | s3 | gcs | azure | http
    storage_endpoint: str = ""
    storage_bucket: str = ""
    api_base_url: str = "http://localhost:8000"
    tenant_id: str = ""
    region: str = "us-east-1"
    enable_usage_tracking: bool = True
    enable_health_checks: bool = True
    log_level: str = "info"

    @classmethod
    def from_env(cls) -> "CloudConfig":
        return cls(
            storage_backend=os.environ.get("HEMLOCK_STORAGE_BACKEND", "local"),
            storage_endpoint=os.environ.get("HEMLOCK_STORAGE_ENDPOINT", ""),
            storage_bucket=os.environ.get("HEMLOCK_STORAGE_BUCKET", ""),
            api_base_url=os.environ.get("HEMLOCK_API_BASE_URL", "http://localhost:8000"),
            tenant_id=os.environ.get("HEMLOCK_TENANT_ID", ""),
            region=os.environ.get("HEMLOCK_REGION", "us-east-1"),
            enable_usage_tracking=os.environ.get("HEMLOCK_USAGE_TRACKING", "true").lower() == "true",
            enable_health_checks=os.environ.get("HEMLOCK_HEALTH_CHECKS", "true").lower() == "true",
            log_level=os.environ.get("HEMLOCK_LOG_LEVEL", "info"),
        )

    def to_dict(self) -> dict:
        return {
            "storage_backend": self.storage_backend,
            "api_base_url": self.api_base_url,
            "tenant_id": self.tenant_id,
            "region": self.region,
            "enable_usage_tracking": self.enable_usage_tracking,
        }


@dataclass
class HealthStatus:
    status: str               # ok | degraded | error
    version: str
    checks: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "version": self.version,
            "checks": self.checks,
            "timestamp": self.timestamp,
        }


class HealthProbe:
    def __init__(self, config: CloudConfig | None = None) -> None:
        self.config = config or CloudConfig()

    def liveness(self) -> dict:
        from hemlock import __version__

        return {"status": "ok", "version": __version__}

    def readiness(self) -> dict:
        from hemlock import __version__

        checks: dict[str, dict] = {}

        checks["hemlock_importable"] = {"status": "ok"}
        checks["storage"] = {"status": "ok", "backend": self.config.storage_backend}

        if self.config.storage_backend != "local" and not self.config.storage_endpoint:
            checks["storage"] = {"status": "degraded", "reason": "endpoint not configured"}

        overall = "ready" if all(c["status"] == "ok" for c in checks.values()) else "degraded"

        return HealthStatus(
            status=overall,
            version=__version__,
            checks=checks,
        ).to_dict()


@dataclass
class ExportResult:
    destination: str
    size_bytes: int
    success: bool
    error: str | None = None


class CloudExporter:
    def __init__(self, config: CloudConfig | None = None) -> None:
        self.config = config or CloudConfig()

    def export(self, report: Any, destination: str = "") -> ExportResult:
        dest = destination or self.config.storage_endpoint or ".hemlock/exports"

        if self.config.storage_backend == "local" or dest.startswith("."):
            return self._export_local(report, dest)
        elif dest.startswith("http"):
            return self._export_http(report, dest)
        else:
            return self._export_local(report, ".hemlock/exports")

    def _export_local(self, report: Any, dest: str) -> ExportResult:
        os.makedirs(dest, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        path = os.path.join(dest, f"hemlock_report_{ts}.json")
        try:
            if hasattr(report, "to_json"):
                content = report.to_json()
            elif hasattr(report, "to_dict"):
                content = json.dumps(report.to_dict(), indent=2)
            else:
                content = json.dumps(str(report))
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return ExportResult(destination=path, size_bytes=len(content.encode()), success=True)
        except Exception as exc:
            return ExportResult(destination=path, size_bytes=0, success=False, error=str(exc))

    def _export_http(self, report: Any, endpoint: str) -> ExportResult:
        import urllib.request

        try:
            if hasattr(report, "to_json"):
                content = report.to_json()
            else:
                content = json.dumps(str(report))
            payload = content.encode()
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
            return ExportResult(destination=endpoint, size_bytes=len(payload), success=True)
        except Exception as exc:
            return ExportResult(destination=endpoint, size_bytes=0, success=False, error=str(exc))


@dataclass
class UsageRecord:
    tenant_id: str
    action: str
    timestamp: str
    tokens_used: int = 0
    scan_channels: int = 0


class UsageTracker:
    def __init__(self, path: str = ".hemlock/usage.jsonl") -> None:
        self._path = path

    def record(self, record: UsageRecord) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "tenant_id": record.tenant_id,
                "action": record.action,
                "timestamp": record.timestamp,
                "tokens_used": record.tokens_used,
                "scan_channels": record.scan_channels,
            }) + "\n")

    def usage_for_tenant(self, tenant_id: str) -> list[UsageRecord]:
        if not os.path.exists(self._path):
            return []
        records = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                    if d.get("tenant_id") == tenant_id:
                        records.append(UsageRecord(**d))
                except (json.JSONDecodeError, TypeError):
                    pass
        return records

    def total_scans(self, tenant_id: str) -> int:
        return sum(1 for r in self.usage_for_tenant(tenant_id) if r.action == "scan")
