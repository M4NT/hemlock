"""Tests for SwarmAttack and SwarmDefense — multi-agent mesh attack and consensus defense."""

from __future__ import annotations

import pytest

from defenses.base import DefenseReport, OutputDefense
from hemlock.swarm import (
    SwarmAttack,
    SwarmAttackReport,
    SwarmAttackResult,
    SwarmDefense,
    SwarmDefenseResult,
    SwarmDefenseVote,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _AlwaysTrigger(OutputDefense):
    name   = "AlwaysTrigger"
    covers = []
    def validate(self, response: str) -> DefenseReport:
        return DefenseReport(defense_name=self.name, triggered=True, detail="always")


class _NeverTrigger(OutputDefense):
    name   = "NeverTrigger"
    covers = []
    def validate(self, response: str) -> DefenseReport:
        return DefenseReport(defense_name=self.name, triggered=False, detail="never")


class _KeywordGuard(OutputDefense):
    name   = "KeywordGuard"
    covers = []
    def __init__(self, keyword: str) -> None:
        self._kw = keyword
    def validate(self, response: str) -> DefenseReport:
        hit = self._kw.lower() in response.lower()
        return DefenseReport(defense_name=self.name, triggered=hit, detail="kw match" if hit else "clean")


class _FakeAttackResult:
    def __init__(self, succeeded: bool, notes: str = ""):
        self.succeeded = succeeded
        self.notes     = notes


class _AlwaysSucceeds:
    """Fake attack that always succeeds."""
    name     = "AlwaysSucceeds"
    VARIANTS = ["v1", "v2", "v3"]
    def __init__(self, pipeline, *, variant="v1"):
        self.variant = variant
    def run(self):
        return _FakeAttackResult(True, f"succeeded: {self.variant}")


class _AlwaysFails:
    """Fake attack that always fails."""
    name     = "AlwaysFails"
    VARIANTS = ["v1", "v2"]
    def __init__(self, pipeline, *, variant="v1"):
        self.variant = variant
    def run(self):
        return _FakeAttackResult(False, f"failed: {self.variant}")


class _MixedAttack:
    """Fake attack that succeeds on 'evil' variants only."""
    name     = "MixedAttack"
    VARIANTS = ["clean", "evil1", "evil2"]
    def __init__(self, pipeline, *, variant="clean"):
        self.variant = variant
    def run(self):
        return _FakeAttackResult("evil" in self.variant, f"variant={self.variant}")


# ---------------------------------------------------------------------------
# TestSwarmAttackResult
# ---------------------------------------------------------------------------

class TestSwarmAttackResult:
    def test_fields(self):
        r = SwarmAttackResult(variant="v1", succeeded=True, notes="ok")
        assert r.variant   == "v1"
        assert r.succeeded is True
        assert r.notes     == "ok"


# ---------------------------------------------------------------------------
# TestSwarmAttackReport
# ---------------------------------------------------------------------------

class TestSwarmAttackReport:
    def _make(self, succeeded_flags, threshold=0.5):
        results = [
            SwarmAttackResult(variant=f"v{i}", succeeded=s, notes="")
            for i, s in enumerate(succeeded_flags)
        ]
        return SwarmAttackReport("Test", results, threshold)

    def test_success_count(self):
        report = self._make([True, True, False])
        assert report.success_count() == 2

    def test_success_rate(self):
        report = self._make([True, False])
        assert report.success_rate() == 0.5

    def test_consensus_succeeded_majority(self):
        report = self._make([True, True, False], threshold=0.5)
        assert report.consensus_succeeded() is True

    def test_consensus_failed_below_threshold(self):
        report = self._make([True, False, False], threshold=0.67)
        assert report.consensus_succeeded() is False

    def test_consensus_empty_results(self):
        report = SwarmAttackReport("Test", [], 0.5)
        assert report.success_rate() == 0.0
        assert report.consensus_succeeded() is False

    def test_to_dict_keys(self):
        report = self._make([True, False])
        d = report.to_dict()
        assert "attack_name"        in d
        assert "consensus_succeeded" in d
        assert "success_rate"       in d
        assert "variants"           in d

    def test_summary_compromised(self):
        report = self._make([True, True, True])
        assert "COMPROMISED" in report.summary()

    def test_summary_defended(self):
        report = self._make([False, False])
        assert "DEFENDED" in report.summary()

    def test_unanimity_threshold(self):
        report = self._make([True, True, False], threshold=1.0)
        assert report.consensus_succeeded() is False

    def test_always_block_threshold(self):
        report = self._make([False, False], threshold=0.0)
        assert report.consensus_succeeded() is True


# ---------------------------------------------------------------------------
# TestSwarmAttack
# ---------------------------------------------------------------------------

class TestSwarmAttack:
    def test_all_succeed(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, parallel=False)
        report = swarm.run()
        assert report.consensus_succeeded() is True
        assert len(report.individual_results) == 3

    def test_all_fail(self):
        swarm  = SwarmAttack(None, _AlwaysFails, parallel=False)
        report = swarm.run()
        assert report.consensus_succeeded() is False

    def test_mixed_majority_threshold(self):
        # 2 of 3 variants succeed → 67% > 50% threshold
        swarm  = SwarmAttack(None, _MixedAttack, majority_threshold=0.5, parallel=False)
        report = swarm.run()
        assert report.consensus_succeeded() is True

    def test_mixed_strict_threshold(self):
        # 2 of 3 variants succeed → 67% < 100% threshold
        swarm  = SwarmAttack(None, _MixedAttack, majority_threshold=1.0, parallel=False)
        report = swarm.run()
        assert report.consensus_succeeded() is False

    def test_custom_variants_subset(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, variants=["v1"], parallel=False)
        report = swarm.run()
        assert len(report.individual_results) == 1

    def test_attack_name_from_class(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, parallel=False)
        report = swarm.run()
        assert report.attack_name == "AlwaysSucceeds"

    def test_parallel_mode_returns_all_variants(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, parallel=True)
        report = swarm.run()
        assert len(report.individual_results) == 3

    def test_individual_results_have_variant_names(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, parallel=False)
        report = swarm.run()
        variants = {r.variant for r in report.individual_results}
        assert variants == set(_AlwaysSucceeds.VARIANTS)

    def test_notes_captured(self):
        swarm  = SwarmAttack(None, _AlwaysSucceeds, parallel=False)
        report = swarm.run()
        for r in report.individual_results:
            assert "succeeded" in r.notes


# ---------------------------------------------------------------------------
# TestSwarmDefenseVote
# ---------------------------------------------------------------------------

class TestSwarmDefenseVote:
    def test_fields(self):
        v = SwarmDefenseVote(defense_name="Guard", triggered=True, detail="fired")
        assert v.defense_name == "Guard"
        assert v.triggered    is True
        assert v.detail       == "fired"


# ---------------------------------------------------------------------------
# TestSwarmDefenseResult
# ---------------------------------------------------------------------------

class TestSwarmDefenseResult:
    def _make(self, triggered_flags, threshold=0.5):
        votes = [
            SwarmDefenseVote(f"G{i}", triggered=t, detail="")
            for i, t in enumerate(triggered_flags)
        ]
        triggered_count = sum(t for t in triggered_flags)
        rate            = triggered_count / len(votes) if votes else 0.0
        triggered       = rate >= threshold
        return SwarmDefenseResult(
            triggered=triggered,
            votes=votes,
            majority_threshold=threshold,
            triggered_count=triggered_count,
            content_preview="test",
        )

    def test_trigger_rate(self):
        r = self._make([True, False])
        assert r.trigger_rate() == 0.5

    def test_dissenting_defenses_when_majority_triggers(self):
        r = self._make([True, True, False])
        dissenting = r.dissenting_defenses()
        assert len(dissenting) == 1

    def test_dissenting_defenses_empty_when_unanimous(self):
        r = self._make([True, True, True])
        assert r.dissenting_defenses() == []


# ---------------------------------------------------------------------------
# TestSwarmDefense
# ---------------------------------------------------------------------------

class TestSwarmDefense:
    def test_empty_defenses_raises(self):
        with pytest.raises(ValueError):
            SwarmDefense([])

    def test_all_trigger(self):
        sd = SwarmDefense([_AlwaysTrigger(), _AlwaysTrigger()], parallel=False)
        r  = sd.validate("anything")
        assert r.triggered is True
        assert r.triggered_count == 2

    def test_none_trigger(self):
        sd = SwarmDefense([_NeverTrigger(), _NeverTrigger()], parallel=False)
        r  = sd.validate("anything")
        assert r.triggered is False
        assert r.triggered_count == 0

    def test_majority_triggers(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _AlwaysTrigger(), _NeverTrigger()],
            majority_threshold=0.5, parallel=False,
        )
        r = sd.validate("anything")
        assert r.triggered is True
        assert r.triggered_count == 2

    def test_below_majority_threshold(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _NeverTrigger(), _NeverTrigger()],
            majority_threshold=0.5, parallel=False,
        )
        r = sd.validate("anything")
        assert r.triggered is False

    def test_keyword_guard_triggers_on_match(self):
        sd = SwarmDefense(
            [_KeywordGuard("INJECT"), _NeverTrigger()],
            majority_threshold=0.5, parallel=False,
        )
        r = sd.validate("INJECT payload")
        assert r.triggered is True

    def test_keyword_guard_clean(self):
        sd = SwarmDefense(
            [_KeywordGuard("INJECT"), _NeverTrigger()],
            majority_threshold=0.5, parallel=False,
        )
        r = sd.validate("safe text")
        assert r.triggered is False

    def test_content_preview_stored(self):
        sd = SwarmDefense([_AlwaysTrigger()], parallel=False)
        r  = sd.validate("hello world")
        assert "hello world" in r.content_preview

    def test_unanimity_threshold_blocks_on_all_trigger(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _AlwaysTrigger()],
            majority_threshold=1.0, parallel=False,
        )
        r = sd.validate("x")
        assert r.triggered is True

    def test_unanimity_threshold_passes_on_partial(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _NeverTrigger()],
            majority_threshold=1.0, parallel=False,
        )
        r = sd.validate("x")
        assert r.triggered is False

    def test_votes_length_matches_defenses(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _NeverTrigger(), _KeywordGuard("x")],
            parallel=False,
        )
        r = sd.validate("test")
        assert len(r.votes) == 3

    def test_parallel_mode_produces_same_count(self):
        sd = SwarmDefense([_AlwaysTrigger(), _NeverTrigger()], parallel=True)
        r  = sd.validate("test")
        assert len(r.votes) == 2

    def test_defense_names_in_votes(self):
        sd = SwarmDefense([_AlwaysTrigger(), _NeverTrigger()], parallel=False)
        r  = sd.validate("x")
        names = {v.defense_name for v in r.votes}
        assert "AlwaysTrigger" in names
        assert "NeverTrigger"  in names

    def test_trigger_rate_computed(self):
        sd = SwarmDefense(
            [_AlwaysTrigger(), _AlwaysTrigger(), _NeverTrigger()],
            parallel=False,
        )
        r = sd.validate("x")
        assert abs(r.trigger_rate() - 2/3) < 0.01
