"""Tests for hemlock.provider_comparison (v7.5)."""

from __future__ import annotations

import json
import pytest

from hemlock.provider_comparison import (
    ComparisonEntry,
    ComparisonTable,
    ProviderBenchmark,
    ProviderProfile,
    ProviderRegistry,
)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _make_profile(
    provider_id: str = "openai/gpt-4o",
    overall_risk: float = 50.0,
    attack_scores: dict | None = None,
    channel_scores: dict | None = None,
    pipeline_version: str = "v1",
) -> ProviderProfile:
    return ProviderProfile(
        provider_id=provider_id,
        recorded_at="2026-01-01T00:00:00+00:00",
        pipeline_version=pipeline_version,
        attack_scores={"direct_injection": 0.5, "exfiltration": 0.4} if attack_scores is None else attack_scores,
        channel_scores={"text": 45.0} if channel_scores is None else channel_scores,
        overall_risk=overall_risk,
        metadata={},
    )


def _pipeline_factory(always_blocked: bool = False):
    def factory(channel):
        class P:
            def run(self, q: str) -> str:
                return "BLOCKED" if always_blocked else "result"
        return P()
    return factory


def _variable_factory(block_on_attacks: set[str]):
    """Blocks only if the payload contains one of the named attacks."""
    def factory(channel):
        class P:
            def run(self, q: str) -> str:
                for attack in block_on_attacks:
                    if attack in q:
                        return "BLOCKED: not allowed"
                return "result ok"
        return P()
    return factory


@pytest.fixture
def tmp_registry(tmp_path):
    path = str(tmp_path / "provider_registry.json")
    return ProviderRegistry(path=path)


@pytest.fixture
def tmp_benchmark(tmp_registry):
    return ProviderBenchmark(tmp_registry)


# ── ProviderProfile ──────────────────────────────────────────────────────────


class TestProviderProfile:
    def test_fields_accessible(self):
        p = _make_profile()
        assert p.provider_id == "openai/gpt-4o"
        assert p.pipeline_version == "v1"
        assert isinstance(p.attack_scores, dict)
        assert isinstance(p.channel_scores, dict)
        assert isinstance(p.metadata, dict)

    def test_to_dict_roundtrip(self):
        p = _make_profile()
        d = p.to_dict()
        p2 = ProviderProfile.from_dict(d)
        assert p2.provider_id == p.provider_id
        assert p2.overall_risk == p.overall_risk
        assert p2.attack_scores == p.attack_scores
        assert p2.channel_scores == p.channel_scores
        assert p2.recorded_at == p.recorded_at
        assert p2.pipeline_version == p.pipeline_version
        assert p2.metadata == p.metadata

    def test_to_dict_has_all_keys(self):
        d = _make_profile().to_dict()
        for key in (
            "provider_id", "recorded_at", "pipeline_version",
            "attack_scores", "channel_scores", "overall_risk", "metadata",
        ):
            assert key in d

    def test_block_rate_complement_of_mean_attack_scores(self):
        p = _make_profile(attack_scores={"a": 0.4, "b": 0.6})
        # mean success = 0.5 → block rate = 0.5
        assert abs(p.block_rate() - 0.5) < 1e-9

    def test_block_rate_fully_blocked(self):
        p = _make_profile(attack_scores={"a": 0.0, "b": 0.0})
        assert p.block_rate() == 1.0

    def test_block_rate_fully_open(self):
        p = _make_profile(attack_scores={"a": 1.0, "b": 1.0})
        assert p.block_rate() == 0.0

    def test_block_rate_empty_scores(self):
        p = _make_profile(attack_scores={})
        assert p.block_rate() == 1.0

    def test_from_dict_missing_optional_fields(self):
        minimal = {
            "provider_id": "x/y",
            "recorded_at": "2026-01-01T00:00:00+00:00",
        }
        p = ProviderProfile.from_dict(minimal)
        assert p.pipeline_version == ""
        assert p.attack_scores == {}
        assert p.channel_scores == {}
        assert p.overall_risk == 0.0
        assert p.metadata == {}


# ── ProviderRegistry ─────────────────────────────────────────────────────────


class TestProviderRegistry:
    def test_empty_on_creation(self, tmp_registry):
        assert tmp_registry.all() == []
        assert tmp_registry.provider_ids() == []

    def test_register_and_get(self, tmp_registry):
        p = _make_profile()
        tmp_registry.register(p)
        got = tmp_registry.get(p.provider_id)
        assert got is not None
        assert got.provider_id == p.provider_id

    def test_get_missing_returns_none(self, tmp_registry):
        assert tmp_registry.get("nonexistent/model") is None

    def test_all_returns_all_providers(self, tmp_registry):
        tmp_registry.register(_make_profile("a/m1"))
        tmp_registry.register(_make_profile("b/m2"))
        assert len(tmp_registry.all()) == 2

    def test_provider_ids(self, tmp_registry):
        tmp_registry.register(_make_profile("a/m1"))
        tmp_registry.register(_make_profile("b/m2"))
        ids = tmp_registry.provider_ids()
        assert "a/m1" in ids
        assert "b/m2" in ids

    def test_register_latest_wins(self, tmp_registry):
        p1 = _make_profile(overall_risk=10.0)
        p2 = _make_profile(overall_risk=90.0)
        tmp_registry.register(p1)
        tmp_registry.register(p2)
        assert tmp_registry.get("openai/gpt-4o").overall_risk == 90.0

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "reg.json")
        reg1 = ProviderRegistry(path=path)
        reg1.register(_make_profile("a/m1"))
        reg2 = ProviderRegistry(path=path)
        assert reg2.get("a/m1") is not None

    def test_remove_existing(self, tmp_registry):
        tmp_registry.register(_make_profile("a/m1"))
        assert tmp_registry.remove("a/m1") is True
        assert tmp_registry.get("a/m1") is None

    def test_remove_nonexistent_returns_false(self, tmp_registry):
        assert tmp_registry.remove("ghost/model") is False

    def test_remove_persisted(self, tmp_path):
        path = str(tmp_path / "reg.json")
        reg = ProviderRegistry(path=path)
        reg.register(_make_profile("a/m1"))
        reg.remove("a/m1")
        reg2 = ProviderRegistry(path=path)
        assert reg2.get("a/m1") is None

    def test_history_for_empty_initially(self, tmp_registry):
        tmp_registry.register(_make_profile())
        assert tmp_registry.history_for("openai/gpt-4o") == []

    def test_history_for_accumulates(self, tmp_registry):
        for i in range(3):
            tmp_registry.register(_make_profile(overall_risk=float(i * 10)))
        hist = tmp_registry.history_for("openai/gpt-4o")
        assert len(hist) == 2  # first two pushed to history; third is latest

    def test_history_capped_at_10(self, tmp_registry):
        for i in range(15):
            tmp_registry.register(_make_profile(overall_risk=float(i)))
        hist = tmp_registry.history_for("openai/gpt-4o", limit=20)
        assert len(hist) <= 10

    def test_history_limit_respected(self, tmp_registry):
        for i in range(5):
            tmp_registry.register(_make_profile(overall_risk=float(i)))
        hist = tmp_registry.history_for("openai/gpt-4o", limit=2)
        assert len(hist) <= 2

    def test_corrupted_file_handled_gracefully(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            f.write("{invalid json}")
        reg = ProviderRegistry(path=path)
        assert reg.all() == []


# ── ComparisonTable ──────────────────────────────────────────────────────────


class TestComparisonTable:
    def _table(self) -> ComparisonTable:
        profiles = [
            _make_profile("a/safe", overall_risk=10.0, attack_scores={"inj": 0.1, "exfil": 0.2}),
            _make_profile("b/mid",  overall_risk=50.0, attack_scores={"inj": 0.5, "exfil": 0.6}),
            _make_profile("c/risky", overall_risk=90.0, attack_scores={"inj": 0.9, "exfil": 0.8}),
        ]
        return ComparisonTable(profiles)

    def test_rank_sorted_ascending(self):
        table = self._table()
        ranked = table.rank()
        risks = [e.overall_risk for e in ranked]
        assert risks == sorted(risks)

    def test_rank_first_is_safest(self):
        table = self._table()
        assert table.rank()[0].provider_id == "a/safe"

    def test_rank_assigns_correct_rank_numbers(self):
        table = self._table()
        for i, entry in enumerate(table.rank(), 1):
            assert entry.rank == i

    def test_rank_contains_all_providers(self):
        table = self._table()
        ids = {e.provider_id for e in table.rank()}
        assert ids == {"a/safe", "b/mid", "c/risky"}

    def test_rank_block_rate_populated(self):
        table = self._table()
        for entry in table.rank():
            assert 0.0 <= entry.block_rate <= 1.0

    def test_rank_best_worst_attack(self):
        table = self._table()
        for entry in table.rank():
            assert entry.best_attack in ("inj", "exfil")
            assert entry.worst_attack in ("inj", "exfil")

    def test_safest_provider(self):
        assert self._table().safest_provider() == "a/safe"

    def test_riskiest_provider(self):
        assert self._table().riskiest_provider() == "c/risky"

    def test_safest_empty_table(self):
        assert ComparisonTable([]).safest_provider() == ""

    def test_riskiest_empty_table(self):
        assert ComparisonTable([]).riskiest_provider() == ""

    def test_attack_heatmap_structure(self):
        heatmap = self._table().attack_heatmap()
        assert "inj" in heatmap
        assert "exfil" in heatmap
        assert "a/safe" in heatmap["inj"]
        assert "b/mid" in heatmap["inj"]

    def test_attack_heatmap_values_in_range(self):
        for attack, providers in self._table().attack_heatmap().items():
            for pid, rate in providers.items():
                assert 0.0 <= rate <= 1.0

    def test_delta_positive_when_a_more_vulnerable(self):
        table = self._table()
        d = table.delta("c/risky", "a/safe")
        for v in d.values():
            assert v > 0

    def test_delta_negative_when_a_less_vulnerable(self):
        table = self._table()
        d = table.delta("a/safe", "c/risky")
        for v in d.values():
            assert v < 0

    def test_delta_only_shared_attacks(self):
        p1 = _make_profile("x", attack_scores={"a": 0.5, "b": 0.3})
        p2 = _make_profile("y", attack_scores={"b": 0.4, "c": 0.6})
        table = ComparisonTable([p1, p2])
        d = table.delta("x", "y")
        assert set(d.keys()) == {"b"}

    def test_delta_missing_provider_returns_empty(self):
        table = self._table()
        assert table.delta("a/safe", "ghost/model") == {}

    def test_to_markdown_has_header_row(self):
        md = self._table().to_markdown()
        assert "Provider" in md
        assert "Overall Risk" in md
        assert "Block Rate" in md
        assert "Best Defense" in md
        assert "Worst Defense" in md
        assert "Rank" in md

    def test_to_markdown_contains_all_providers(self):
        md = self._table().to_markdown()
        assert "a/safe" in md
        assert "b/mid" in md
        assert "c/risky" in md

    def test_to_markdown_empty_table(self):
        md = ComparisonTable([]).to_markdown()
        assert "No provider profiles available" in md

    def test_to_dict_has_expected_keys(self):
        d = self._table().to_dict()
        assert "providers" in d
        assert "ranked" in d
        assert "heatmap" in d

    def test_to_dict_providers_count(self):
        d = self._table().to_dict()
        assert len(d["providers"]) == 3


# ── ProviderBenchmark ─────────────────────────────────────────────────────────


class TestProviderBenchmark:
    def test_run_returns_provider_profile(self, tmp_benchmark):
        profile = tmp_benchmark.run("openai/gpt-4o", _pipeline_factory(always_blocked=False))
        assert isinstance(profile, ProviderProfile)

    def test_run_registers_in_registry(self, tmp_registry, tmp_benchmark):
        tmp_benchmark.run("a/m1", _pipeline_factory())
        assert tmp_registry.get("a/m1") is not None

    def test_run_attack_scores_between_0_and_1(self, tmp_benchmark):
        profile = tmp_benchmark.run("a/m1", _pipeline_factory())
        for score in profile.attack_scores.values():
            assert 0.0 <= score <= 1.0

    def test_run_all_blocked_gives_zero_attack_scores(self, tmp_benchmark):
        profile = tmp_benchmark.run("safe/model", _pipeline_factory(always_blocked=True))
        for score in profile.attack_scores.values():
            assert score == 0.0

    def test_run_none_blocked_gives_one_attack_scores(self, tmp_benchmark):
        profile = tmp_benchmark.run("risky/model", _pipeline_factory(always_blocked=False))
        for score in profile.attack_scores.values():
            assert score == 1.0

    def test_run_overall_risk_in_range(self, tmp_benchmark):
        profile = tmp_benchmark.run("a/m1", _pipeline_factory())
        assert 0.0 <= profile.overall_risk <= 100.0

    def test_run_channel_scores_populated(self, tmp_benchmark):
        profile = tmp_benchmark.run("a/m1", _pipeline_factory(), channels=["text"])
        assert "text" in profile.channel_scores

    def test_run_custom_channels(self, tmp_benchmark):
        profile = tmp_benchmark.run(
            "a/m1", _pipeline_factory(), channels=["audio", "vision"]
        )
        assert "audio" in profile.channel_scores
        assert "vision" in profile.channel_scores

    def test_run_pipeline_version_recorded(self, tmp_benchmark):
        profile = tmp_benchmark.run("a/m1", _pipeline_factory(), pipeline_version="2.0.0")
        assert profile.pipeline_version == "2.0.0"

    def test_run_all_returns_comparison_table(self, tmp_benchmark):
        providers = {
            "openai/gpt-4o": _pipeline_factory(always_blocked=True),
            "anthropic/claude": _pipeline_factory(always_blocked=False),
        }
        table = tmp_benchmark.run_all(providers)
        assert isinstance(table, ComparisonTable)

    def test_run_all_table_contains_all_providers(self, tmp_benchmark):
        providers = {
            "openai/gpt-4o": _pipeline_factory(always_blocked=True),
            "anthropic/claude": _pipeline_factory(always_blocked=False),
            "google/gemini": _pipeline_factory(always_blocked=False),
        }
        table = tmp_benchmark.run_all(providers)
        ids = {e.provider_id for e in table.rank()}
        assert ids == set(providers.keys())

    def test_run_all_safest_is_fully_blocked(self, tmp_benchmark):
        providers = {
            "safe": _pipeline_factory(always_blocked=True),
            "risky": _pipeline_factory(always_blocked=False),
        }
        table = tmp_benchmark.run_all(providers)
        assert table.safest_provider() == "safe"

    def test_run_custom_attack_suite(self, tmp_path):
        reg = ProviderRegistry(path=str(tmp_path / "r.json"))
        suite = [{"name": "custom_attack", "variants": ["alpha", "beta"]}]
        bench = ProviderBenchmark(reg, attack_suite=suite)
        profile = bench.run("x/y", _pipeline_factory())
        assert "custom_attack" in profile.attack_scores

    def test_run_default_attack_suite_has_four_attacks(self, tmp_benchmark):
        profile = tmp_benchmark.run("x/y", _pipeline_factory())
        expected = {"direct_injection", "context_override", "exfiltration", "jailbreak_via_context"}
        assert set(profile.attack_scores.keys()) == expected

    def test_run_partial_blocking_gives_intermediate_score(self, tmp_path):
        reg = ProviderRegistry(path=str(tmp_path / "r.json"))
        # Block only direct_injection; let everything else through.
        suite = [
            {"name": "direct_injection", "variants": ["v1"]},
            {"name": "exfiltration", "variants": ["v1"]},
        ]
        bench = ProviderBenchmark(reg, attack_suite=suite)
        factory = _variable_factory({"direct_injection"})
        profile = bench.run("x/y", factory, channels=["text"])
        assert profile.attack_scores["direct_injection"] == 0.0
        assert profile.attack_scores["exfiltration"] == 1.0
