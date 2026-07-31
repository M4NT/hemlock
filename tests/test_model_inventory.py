"""Tests for hemlock.model_inventory (v7.3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hemlock.model_inventory import (
    ALL_CHANNELS,
    CoverageMap,
    FingerprintAlert,
    GapEntry,
    ModelEntry,
    ModelInventory,
    ScanRecord,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ts(days_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _populate(inventory: ModelInventory, model_id="gpt-4o", channels=None, risk=30.0, fp="") -> ScanRecord:
    return inventory.record_scan(
        model_id=model_id,
        pipeline_version="v1.0",
        scan_channels=channels or ["rag", "tools"],
        risk_score=risk,
        fingerprint_hash=fp,
    )


# ── ScanRecord ────────────────────────────────────────────────────────────────

class TestScanRecord:
    def test_to_dict_roundtrip(self):
        r = ScanRecord(
            scan_id="abc123",
            timestamp=_ts(),
            pipeline_version="v1.0",
            channels_tested=["rag"],
            risk_score=42.0,
            fingerprint_hash="hash-001",
        )
        d = r.to_dict()
        r2 = ScanRecord.from_dict(d)
        assert r2.scan_id == "abc123"
        assert r2.risk_score == 42.0


# ── ModelEntry ────────────────────────────────────────────────────────────────

class TestModelEntry:
    def _entry(self, channels=None, scans=None) -> ModelEntry:
        e = ModelEntry(
            model_id="test-model",
            first_seen=_ts(10),
            last_seen=_ts(),
            channels_ever_tested=channels or ["rag", "tools"],
            scans=scans or [],
        )
        return e

    def test_coverage_pct(self):
        e = self._entry(channels=list(ALL_CHANNELS))
        assert e.coverage_pct == 1.0

    def test_coverage_pct_partial(self):
        e = self._entry(channels=["rag"])
        assert 0 < e.coverage_pct < 1.0

    def test_uncovered_channels(self):
        e = self._entry(channels=["rag", "tools"])
        uncovered = e.uncovered_channels()
        assert "rag" not in uncovered
        assert "tools" not in uncovered
        assert "memory" in uncovered

    def test_latest_risk_score_no_scans(self):
        e = self._entry()
        assert e.latest_risk_score == 0.0

    def test_fingerprint_changed_true(self):
        e = self._entry()
        e.fingerprint_history = ["hash-a", "hash-b"]
        assert e.fingerprint_changed() is True

    def test_fingerprint_changed_false(self):
        e = self._entry()
        e.fingerprint_history = ["hash-a", "hash-a"]
        assert e.fingerprint_changed() is False

    def test_fingerprint_changed_single_entry(self):
        e = self._entry()
        e.fingerprint_history = ["hash-a"]
        assert e.fingerprint_changed() is False

    def test_to_dict_has_coverage_fields(self):
        e = self._entry()
        d = e.to_dict()
        assert "coverage_pct" in d
        assert "uncovered_channels" in d
        assert "latest_risk_score" in d


# ── ModelInventory ────────────────────────────────────────────────────────────

class TestModelInventory:
    def test_record_scan_creates_entry(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o")
        assert inv.get("gpt-4o") is not None

    def test_record_scan_increments_count(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o")
        _populate(inv, "gpt-4o")
        assert inv.get("gpt-4o").scan_count == 2

    def test_record_scan_accumulates_channels(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", channels=["rag"])
        _populate(inv, "gpt-4o", channels=["tools"])
        entry = inv.get("gpt-4o")
        assert "rag" in entry.channels_ever_tested
        assert "tools" in entry.channels_ever_tested

    def test_fingerprint_history(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "claude-sonnet", fp="hash-a")
        _populate(inv, "claude-sonnet", fp="hash-b")
        entry = inv.get("claude-sonnet")
        assert entry.fingerprint_history == ["hash-a", "hash-b"]

    def test_latest_risk_score(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", risk=20.0)
        _populate(inv, "gpt-4o", risk=55.0)
        assert inv.get("gpt-4o").latest_risk_score == 55.0

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "inventory.json")
        inv1 = ModelInventory(path)
        _populate(inv1, "gpt-4o")
        inv2 = ModelInventory(path)
        assert inv2.get("gpt-4o") is not None
        assert inv2.get("gpt-4o").scan_count == 1

    def test_model_ids(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o")
        _populate(inv, "claude-sonnet")
        ids = inv.model_ids()
        assert "gpt-4o" in ids
        assert "claude-sonnet" in ids

    def test_remove(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o")
        assert inv.remove("gpt-4o") is True
        assert inv.get("gpt-4o") is None

    def test_remove_nonexistent(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        assert inv.remove("nonexistent") is False

    def test_all_models(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "m1")
        _populate(inv, "m2")
        assert len(inv.all_models()) == 2

    def test_scan_id_generated(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        rec = _populate(inv, "gpt-4o")
        assert rec.scan_id != ""


# ── CoverageMap ───────────────────────────────────────────────────────────────

class TestCoverageMap:
    def test_gap_report_partial_coverage(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", channels=["rag"])  # missing most channels
        coverage = CoverageMap(inv)
        gaps = coverage.gap_report()
        assert len(gaps) == 1
        assert "rag" not in gaps[0].uncovered_channels

    def test_gap_report_full_coverage(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", channels=list(ALL_CHANNELS))
        coverage = CoverageMap(inv)
        assert coverage.gap_report() == []

    def test_stale_models_detected(self, tmp_path):
        path = str(tmp_path / "inventory.json")
        inv = ModelInventory(path)
        _populate(inv, "old-model")
        # Manually backdate last_seen
        entry = inv.get("old-model")
        entry.last_seen = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        inv._models["old-model"] = entry
        inv._flush()
        coverage = CoverageMap(inv)
        stale = coverage.stale_models(days=7)
        assert any(e.model_id == "old-model" for e in stale)

    def test_stale_models_recent_not_included(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "fresh-model")
        coverage = CoverageMap(inv)
        stale = coverage.stale_models(days=7)
        assert not any(e.model_id == "fresh-model" for e in stale)

    def test_fingerprint_alerts_when_changed(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", fp="hash-a")
        _populate(inv, "gpt-4o", fp="hash-b")
        coverage = CoverageMap(inv)
        alerts = coverage.fingerprint_alerts()
        assert len(alerts) == 1
        assert alerts[0].model_id == "gpt-4o"

    def test_fingerprint_alerts_none_when_same(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", fp="hash-same")
        _populate(inv, "gpt-4o", fp="hash-same")
        coverage = CoverageMap(inv)
        assert coverage.fingerprint_alerts() == []

    def test_risk_leaderboard_sorted(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "low-risk-model", risk=10.0)
        _populate(inv, "high-risk-model", risk=80.0)
        board = CoverageMap(inv).risk_leaderboard()
        assert board[0]["model_id"] == "high-risk-model"
        assert board[1]["model_id"] == "low-risk-model"

    def test_fully_covered(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "partial", channels=["rag"])
        _populate(inv, "full", channels=list(ALL_CHANNELS))
        coverage = CoverageMap(inv)
        full = coverage.fully_covered()
        assert any(e.model_id == "full" for e in full)
        assert not any(e.model_id == "partial" for e in full)

    def test_never_scanned_channels(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o", channels=["rag", "tools"])
        coverage = CoverageMap(inv)
        never = coverage.never_scanned_channels()
        assert "rag" not in never
        assert "tools" not in never
        assert "memory" in never

    def test_summary_keys(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "gpt-4o")
        s = CoverageMap(inv).summary()
        assert "total_models" in s
        assert "stale_models" in s
        assert "models_with_gaps" in s
        assert "fingerprint_alerts" in s
        assert "mean_coverage_pct" in s
        assert "never_scanned_channels" in s

    def test_summary_empty_inventory(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        s = CoverageMap(inv).summary()
        assert s["total_models"] == 0
        assert s["mean_coverage_pct"] == 0.0

    def test_gap_report_sorted_by_coverage_asc(self, tmp_path):
        inv = ModelInventory(str(tmp_path / "inventory.json"))
        _populate(inv, "more-covered", channels=["rag", "tools", "memory"])
        _populate(inv, "less-covered", channels=["rag"])
        gaps = CoverageMap(inv).gap_report()
        assert gaps[0].coverage_pct <= gaps[-1].coverage_pct
