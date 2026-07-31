"""Tests for hemlock.benchmark_registry (v6.4)."""

import json
import os
import tempfile
import pytest
from hemlock.benchmark_registry import BenchmarkRegistry, RegistryEntry, _provenance_hash, _entry_id


class MockScenario:
    def __init__(self, attack_name, succeeded):
        self.attack_name = attack_name
        self.succeeded = succeeded


class MockEvalReport:
    def __init__(self, model_name="gpt-test", score=75, categories=None):
        self.model_name = model_name
        self._score = score
        self._categories = categories or {"injection": 80, "exfiltration": 70}
        self.scenarios = [
            MockScenario("direct_injection", True),
            MockScenario("memory_poisoning", False),
        ]

    def overall_score(self):
        return self._score

    def category_scores(self):
        return self._categories


@pytest.fixture
def tmp_registry(tmp_path):
    path = str(tmp_path / "registry.json")
    return BenchmarkRegistry(path=path)


def test_registry_empty_on_creation(tmp_registry):
    assert tmp_registry.list() == []


def test_registry_publish_returns_entry_id(tmp_registry):
    report = MockEvalReport()
    entry_id = tmp_registry.publish(report, label="test-run")
    assert isinstance(entry_id, str)
    assert len(entry_id) == 8


def test_registry_publish_persists(tmp_path):
    path = str(tmp_path / "r.json")
    reg = BenchmarkRegistry(path=path)
    report = MockEvalReport()
    entry_id = reg.publish(report, label="test")
    reg2 = BenchmarkRegistry(path=path)
    assert reg2.get(entry_id) is not None


def test_registry_get_returns_entry(tmp_registry):
    entry_id = tmp_registry.publish(MockEvalReport(), label="x")
    entry = tmp_registry.get(entry_id)
    assert entry is not None
    assert entry.label == "x"
    assert entry.overall_score == 75


def test_registry_get_missing_returns_none(tmp_registry):
    assert tmp_registry.get("nonexistent") is None


def test_registry_list_all(tmp_registry):
    tmp_registry.publish(MockEvalReport(), label="a")
    tmp_registry.publish(MockEvalReport(), label="b")
    assert len(tmp_registry.list()) == 2


def test_registry_list_by_label(tmp_registry):
    tmp_registry.publish(MockEvalReport(), label="alpha")
    tmp_registry.publish(MockEvalReport(), label="beta")
    results = tmp_registry.list(label="alpha")
    assert len(results) == 1
    assert results[0].label == "alpha"


def test_registry_leaderboard_sorted(tmp_registry):
    tmp_registry.publish(MockEvalReport(score=50), label="low")
    tmp_registry.publish(MockEvalReport(score=90), label="high")
    tmp_registry.publish(MockEvalReport(score=70), label="mid")
    lb = tmp_registry.leaderboard()
    assert lb[0].overall_score >= lb[1].overall_score >= lb[2].overall_score


def test_registry_leaderboard_top_n(tmp_registry):
    for i in range(5):
        tmp_registry.publish(MockEvalReport(score=i * 10), label=f"run-{i}")
    lb = tmp_registry.leaderboard(top_n=3)
    assert len(lb) == 3


def test_registry_compare(tmp_registry):
    id_a = tmp_registry.publish(MockEvalReport(score=80, categories={"injection": 80}), label="a")
    id_b = tmp_registry.publish(MockEvalReport(score=60, categories={"injection": 60}), label="b")
    cmp = tmp_registry.compare(id_a, id_b)
    assert cmp["overall_delta"] == 20
    assert "injection" in cmp["category_deltas"]
    assert cmp["category_deltas"]["injection"] == 20


def test_registry_compare_missing_returns_empty(tmp_registry):
    assert tmp_registry.compare("nope", "also-nope") == {}


def test_registry_delete(tmp_registry):
    entry_id = tmp_registry.publish(MockEvalReport(), label="del-me")
    assert tmp_registry.delete(entry_id) is True
    assert tmp_registry.get(entry_id) is None


def test_registry_delete_nonexistent(tmp_registry):
    assert tmp_registry.delete("ghost") is False


def test_registry_to_markdown_empty(tmp_registry):
    md = tmp_registry.to_markdown()
    assert "No entries" in md


def test_registry_to_markdown_with_entries(tmp_registry):
    tmp_registry.publish(MockEvalReport(score=80), label="best-model")
    md = tmp_registry.to_markdown()
    assert "best-model" in md
    assert "Leaderboard" in md


def test_provenance_hash_deterministic():
    r = MockEvalReport()
    h1 = _provenance_hash(r)
    h2 = _provenance_hash(r)
    assert h1 == h2
    assert len(h1) == 16


def test_entry_id_deterministic():
    id1 = _entry_id("label", "2024-01-01")
    id2 = _entry_id("label", "2024-01-01")
    assert id1 == id2
    assert len(id1) == 8


def test_registry_entry_to_dict():
    entry = RegistryEntry(
        entry_id="abc",
        label="test",
        model_version="v1",
        overall_score=80,
        category_scores={"a": 80},
        hemlock_version="5.0.0",
        published_at="2024-01-01",
    )
    d = entry.to_dict()
    assert d["label"] == "test"
    assert d["overall_score"] == 80
