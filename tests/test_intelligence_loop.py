"""Tests for hemlock.intelligence_loop (v9.0)."""

from __future__ import annotations

import json
import os

import pytest

from hemlock.intelligence_loop import IntelligenceLoop, IntelligenceLoopResult


class _ChannelResult:
    def __init__(self, channel: str, variant: str, succeeded: bool, detail: str = "x") -> None:
        self.channel = channel
        self.variant = variant
        self.succeeded = succeeded
        self.detail = detail


class _FakeReport:
    def __init__(self, results: list) -> None:
        self.results = results


@pytest.fixture()
def tmp_paths(tmp_path):
    return {
        "replay": str(tmp_path / "replay.jsonl"),
        "intel": str(tmp_path / "intel_cache.json"),
        "seen": str(tmp_path / "seen.json"),
    }


def test_record_replay_from_report(tmp_paths):
    loop = IntelligenceLoop(
        replay_store_path=tmp_paths["replay"],
        intel_cache_path=tmp_paths["intel"],
        seen_techniques_path=tmp_paths["seen"],
        enable_auto_red_team=False,
    )
    report = _FakeReport([
        _ChannelResult("rag", "direct", True, "payload text"),
        _ChannelResult("tools", "hijack", False),
    ])
    count = loop.record_replay_from_report(report, pipeline_version="v1.0")
    assert count == 1
    assert os.path.exists(tmp_paths["replay"])


def test_fetch_new_techniques_first_run(tmp_paths):
    loop = IntelligenceLoop(
        replay_store_path=tmp_paths["replay"],
        intel_cache_path=tmp_paths["intel"],
        seen_techniques_path=tmp_paths["seen"],
        enable_auto_red_team=False,
    )
    fetched, new = loop.fetch_new_techniques()
    assert fetched >= 1
    assert len(new) >= 1
    # second run should not repeat same CVEs
    fetched2, new2 = loop.fetch_new_techniques()
    assert fetched2 >= 1
    assert new2 == []


def test_after_scan_full_cycle(tmp_paths):
    loop = IntelligenceLoop(
        replay_store_path=tmp_paths["replay"],
        intel_cache_path=tmp_paths["intel"],
        seen_techniques_path=tmp_paths["seen"],
        enable_auto_red_team=True,
        auto_red_team_rounds=1,
    )
    report = _FakeReport([_ChannelResult("rag", "inject", True)])
    result = loop.after_scan(report, pipeline_version="mock-v2")
    assert isinstance(result, IntelligenceLoopResult)
    assert result.replay_recorded == 1
    assert result.advisories_fetched >= 1
    assert result.processed_at


def test_intelligence_result_to_dict():
    result = IntelligenceLoopResult(
        replay_recorded=2,
        advisories_fetched=5,
        new_techniques=["CVE-TEST: title"],
    )
    d = result.to_dict()
    assert d["replay_recorded"] == 2
    assert d["new_techniques"] == ["CVE-TEST: title"]
