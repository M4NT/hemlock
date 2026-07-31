"""Model Inventory & Coverage Map — v7.3.

Tracks which models and pipeline versions have been scanned, surfaces
coverage gaps, and integrates with fingerprint.py (v6.1) to detect
silent model changes.

Usage:
    from hemlock.model_inventory import ModelInventory, ModelEntry, CoverageMap

    inventory = ModelInventory(".hemlock/model_inventory.json")

    # Register a scan result
    inventory.record_scan(
        model_id="claude-sonnet-4-6",
        pipeline_version="v2.3.1",
        scan_channels=["rag", "tools", "memory"],
        risk_score=34.5,
        fingerprint_hash="sha256:abcd...",  # from fingerprint.py
    )

    # Coverage analysis
    coverage = CoverageMap(inventory)
    print(coverage.gap_report())         # which models/channels were never tested
    print(coverage.stale_models(days=7)) # models not scanned in 7 days
    print(coverage.summary())
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


ALL_CHANNELS = ("rag", "tools", "memory", "agent", "cross_agent", "mcp")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ScanRecord:
    scan_id: str
    timestamp: str
    pipeline_version: str
    channels_tested: list[str]
    risk_score: float
    fingerprint_hash: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanRecord":
        meta = d.pop("metadata", {})
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__}, metadata=meta)


@dataclass
class ModelEntry:
    model_id: str
    first_seen: str
    last_seen: str
    scan_count: int = 0
    channels_ever_tested: list[str] = field(default_factory=list)
    scans: list[ScanRecord] = field(default_factory=list)
    fingerprint_history: list[str] = field(default_factory=list)

    @property
    def latest_risk_score(self) -> float:
        if not self.scans:
            return 0.0
        return self.scans[-1].risk_score

    @property
    def latest_scan(self) -> ScanRecord | None:
        return self.scans[-1] if self.scans else None

    @property
    def coverage_pct(self) -> float:
        covered = len(set(self.channels_ever_tested) & set(ALL_CHANNELS))
        return round(covered / len(ALL_CHANNELS), 3)

    def uncovered_channels(self) -> list[str]:
        return sorted(set(ALL_CHANNELS) - set(self.channels_ever_tested))

    def fingerprint_changed(self) -> bool:
        """True if the last two scans produced different fingerprint hashes."""
        hashes = [h for h in self.fingerprint_history if h]
        return len(hashes) >= 2 and hashes[-1] != hashes[-2]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scans"] = [s.to_dict() for s in self.scans]
        d["latest_risk_score"] = self.latest_risk_score
        d["coverage_pct"] = self.coverage_pct
        d["uncovered_channels"] = self.uncovered_channels()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ModelEntry":
        scans_raw = d.pop("scans", [])
        d.pop("latest_risk_score", None)
        d.pop("coverage_pct", None)
        d.pop("uncovered_channels", None)
        obj = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        obj.scans = [ScanRecord.from_dict(s) for s in scans_raw]
        return obj


# ── Inventory store ───────────────────────────────────────────────────────────

class ModelInventory:
    """Persistent JSON inventory of scanned models."""

    def __init__(self, path: str = ".hemlock/model_inventory.json") -> None:
        self._path = path
        self._models: dict[str, ModelEntry] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            for model_id, entry_data in data.items():
                entry_data.setdefault("model_id", model_id)
                self._models[model_id] = ModelEntry.from_dict(entry_data)
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    def _flush(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({mid: e.to_dict() for mid, e in self._models.items()}, f, indent=2)

    def record_scan(
        self,
        model_id: str,
        pipeline_version: str,
        scan_channels: list[str],
        risk_score: float,
        fingerprint_hash: str = "",
        scan_id: str = "",
        metadata: dict | None = None,
    ) -> ScanRecord:
        now = datetime.now(timezone.utc).isoformat()
        if not scan_id:
            import hashlib
            scan_id = hashlib.sha256(f"{model_id}{now}".encode()).hexdigest()[:12]

        record = ScanRecord(
            scan_id=scan_id,
            timestamp=now,
            pipeline_version=pipeline_version,
            channels_tested=list(scan_channels),
            risk_score=risk_score,
            fingerprint_hash=fingerprint_hash,
            metadata=metadata or {},
        )

        if model_id not in self._models:
            self._models[model_id] = ModelEntry(
                model_id=model_id,
                first_seen=now,
                last_seen=now,
            )

        entry = self._models[model_id]
        entry.last_seen = now
        entry.scan_count += 1
        entry.scans.append(record)
        for ch in scan_channels:
            if ch not in entry.channels_ever_tested:
                entry.channels_ever_tested.append(ch)
        if fingerprint_hash:
            entry.fingerprint_history.append(fingerprint_hash)

        self._flush()
        return record

    def get(self, model_id: str) -> ModelEntry | None:
        return self._models.get(model_id)

    def all_models(self) -> list[ModelEntry]:
        return list(self._models.values())

    def model_ids(self) -> list[str]:
        return list(self._models.keys())

    def remove(self, model_id: str) -> bool:
        if model_id in self._models:
            del self._models[model_id]
            self._flush()
            return True
        return False


# ── Coverage analysis ─────────────────────────────────────────────────────────

@dataclass
class GapEntry:
    model_id: str
    uncovered_channels: list[str]
    coverage_pct: float
    last_scanned: str
    scan_count: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FingerprintAlert:
    model_id: str
    previous_hash: str
    current_hash: str
    detected_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class CoverageMap:
    """Analyses coverage gaps and staleness across the model inventory."""

    def __init__(self, inventory: ModelInventory) -> None:
        self.inventory = inventory

    def gap_report(self) -> list[GapEntry]:
        """Models with uncovered attack channels."""
        gaps = []
        for entry in self.inventory.all_models():
            uncovered = entry.uncovered_channels()
            if uncovered:
                gaps.append(GapEntry(
                    model_id=entry.model_id,
                    uncovered_channels=uncovered,
                    coverage_pct=entry.coverage_pct,
                    last_scanned=entry.last_seen,
                    scan_count=entry.scan_count,
                ))
        return sorted(gaps, key=lambda g: g.coverage_pct)

    def stale_models(self, days: int = 7) -> list[ModelEntry]:
        """Models not scanned within `days` days."""
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        stale = []
        for entry in self.inventory.all_models():
            try:
                ts = datetime.fromisoformat(
                    entry.last_seen.replace("Z", "+00:00")
                ).timestamp()
                if ts < cutoff:
                    stale.append(entry)
            except (ValueError, TypeError):
                pass
        return sorted(stale, key=lambda e: e.last_seen)

    def fingerprint_alerts(self) -> list[FingerprintAlert]:
        """Models whose fingerprint changed between last two scans."""
        alerts = []
        for entry in self.inventory.all_models():
            if entry.fingerprint_changed():
                hashes = [h for h in entry.fingerprint_history if h]
                alerts.append(FingerprintAlert(
                    model_id=entry.model_id,
                    previous_hash=hashes[-2],
                    current_hash=hashes[-1],
                    detected_at=entry.last_seen,
                ))
        return alerts

    def risk_leaderboard(self) -> list[dict]:
        """Models sorted by latest risk score descending."""
        entries = self.inventory.all_models()
        return sorted(
            [{"model_id": e.model_id, "risk_score": e.latest_risk_score, "scan_count": e.scan_count}
             for e in entries],
            key=lambda x: x["risk_score"],
            reverse=True,
        )

    def fully_covered(self) -> list[ModelEntry]:
        """Models tested across all known channels."""
        return [e for e in self.inventory.all_models() if not e.uncovered_channels()]

    def never_scanned_channels(self) -> list[str]:
        """Channels not covered by any model in the inventory."""
        covered: set[str] = set()
        for e in self.inventory.all_models():
            covered |= set(e.channels_ever_tested)
        return sorted(set(ALL_CHANNELS) - covered)

    def summary(self, stale_days: int = 7) -> dict:
        models = self.inventory.all_models()
        total = len(models)
        stale = self.stale_models(stale_days)
        gaps = self.gap_report()
        fp_alerts = self.fingerprint_alerts()
        mean_cov = round(sum(e.coverage_pct for e in models) / total, 3) if total else 0.0

        return {
            "total_models": total,
            "stale_models": len(stale),
            "models_with_gaps": len(gaps),
            "fully_covered": len(self.fully_covered()),
            "fingerprint_alerts": len(fp_alerts),
            "mean_coverage_pct": mean_cov,
            "never_scanned_channels": self.never_scanned_channels(),
        }
