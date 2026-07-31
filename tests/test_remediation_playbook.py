"""Tests for RemediationPlaybook engine (v7.6) — 30+ tests, zero real API calls."""

from __future__ import annotations

import os
import tempfile

import pytest

from hemlock.remediation_playbook import (
    ExecutionStore,
    Playbook,
    PlaybookEngine,
    PlaybookExecution,
    PlaybookRegistry,
    PlaybookStep,
    StepExecution,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_step(
    step_id: str = "s1",
    action_type: str = "config",
    estimated_minutes: int = 20,
    required: bool = True,
) -> PlaybookStep:
    return PlaybookStep(
        step_id=step_id,
        title=f"Step {step_id}",
        description="A test step.",
        action_type=action_type,
        instructions="Do the thing.",
        verification_hint="Check the thing.",
        estimated_minutes=estimated_minutes,
        required=required,
    )


def _make_playbook(
    playbook_id: str = "pb-test",
    attack_category: str = "direct_injection",
    severity_applies: list[str] | None = None,
    steps: list[PlaybookStep] | None = None,
) -> Playbook:
    return Playbook(
        playbook_id=playbook_id,
        attack_category=attack_category,
        title="Test Playbook",
        description="Used in unit tests.",
        severity_applies=severity_applies or ["critical", "high"],
        steps=steps or [_make_step("s1"), _make_step("s2")],
        references=["https://example.com/docs"],
    )


@pytest.fixture()
def tmp_store(tmp_path):
    path = str(tmp_path / "executions.jsonl")
    return ExecutionStore(path=path)


@pytest.fixture()
def registry():
    return PlaybookRegistry()


@pytest.fixture()
def engine(registry, tmp_store):
    return PlaybookEngine(registry=registry, store=tmp_store)


# ── TestPlaybookStep ──────────────────────────────────────────────────────────

class TestPlaybookStep:
    def test_to_dict_roundtrip(self):
        step = _make_step("s1", "code", 45, True)
        d = step.to_dict()
        restored = PlaybookStep.from_dict(d)
        assert restored.step_id == step.step_id
        assert restored.title == step.title
        assert restored.action_type == step.action_type
        assert restored.estimated_minutes == step.estimated_minutes
        assert restored.required == step.required

    def test_to_dict_contains_all_keys(self):
        step = _make_step()
        d = step.to_dict()
        expected_keys = {
            "step_id", "title", "description", "action_type",
            "instructions", "verification_hint", "estimated_minutes", "required",
        }
        assert set(d.keys()) == expected_keys

    def test_from_dict_defaults_required_true(self):
        d = _make_step().to_dict()
        d.pop("required")
        step = PlaybookStep.from_dict(d)
        assert step.required is True

    def test_from_dict_defaults_estimated_minutes(self):
        d = _make_step().to_dict()
        d.pop("estimated_minutes")
        step = PlaybookStep.from_dict(d)
        assert step.estimated_minutes == 30

    def test_optional_step_roundtrip(self):
        step = _make_step("opt", required=False)
        assert PlaybookStep.from_dict(step.to_dict()).required is False


# ── TestPlaybook ──────────────────────────────────────────────────────────────

class TestPlaybook:
    def test_total_estimated_minutes(self):
        pb = _make_playbook(steps=[_make_step("s1", estimated_minutes=10),
                                   _make_step("s2", estimated_minutes=25)])
        assert pb.total_estimated_minutes() == 35

    def test_required_steps_filters_optional(self):
        steps = [
            _make_step("s1", required=True),
            _make_step("s2", required=False),
            _make_step("s3", required=True),
        ]
        pb = _make_playbook(steps=steps)
        req = pb.required_steps()
        assert len(req) == 2
        assert all(s.required for s in req)

    def test_required_steps_all_required(self):
        pb = _make_playbook(steps=[_make_step("s1"), _make_step("s2")])
        assert len(pb.required_steps()) == 2

    def test_to_dict_roundtrip(self):
        pb = _make_playbook()
        restored = Playbook.from_dict(pb.to_dict())
        assert restored.playbook_id == pb.playbook_id
        assert restored.attack_category == pb.attack_category
        assert len(restored.steps) == len(pb.steps)
        assert restored.references == pb.references

    def test_to_dict_contains_all_keys(self):
        d = _make_playbook().to_dict()
        expected = {
            "playbook_id", "attack_category", "title", "description",
            "severity_applies", "steps", "references",
        }
        assert set(d.keys()) == expected

    def test_from_dict_defaults_references(self):
        d = _make_playbook().to_dict()
        d.pop("references")
        pb = Playbook.from_dict(d)
        assert pb.references == []


# ── TestPlaybookRegistry ──────────────────────────────────────────────────────

class TestPlaybookRegistry:
    def test_builtin_playbooks_loaded(self):
        reg = PlaybookRegistry()
        assert len(reg.all()) >= 4

    def test_builtin_covers_direct_injection(self):
        reg = PlaybookRegistry()
        assert reg.for_attack("direct_injection")

    def test_builtin_covers_exfiltration(self):
        reg = PlaybookRegistry()
        assert reg.for_attack("exfiltration")

    def test_builtin_covers_cross_agent_poisoning(self):
        reg = PlaybookRegistry()
        assert reg.for_attack("cross_agent_poisoning")

    def test_builtin_covers_jailbreak_via_context(self):
        reg = PlaybookRegistry()
        assert reg.for_attack("jailbreak_via_context")

    def test_register_custom_playbook(self, registry):
        pb = _make_playbook(playbook_id="custom-1", attack_category="my_attack")
        registry.register(pb)
        assert registry.get("custom-1") is pb

    def test_get_nonexistent_returns_none(self, registry):
        assert registry.get("does-not-exist") is None

    def test_for_attack_returns_matching(self, registry):
        pb = _make_playbook(playbook_id="x1", attack_category="novel_attack")
        registry.register(pb)
        results = registry.for_attack("novel_attack")
        assert len(results) == 1
        assert results[0].playbook_id == "x1"

    def test_for_attack_unknown_returns_empty(self, registry):
        assert registry.for_attack("unknown_attack_xyz") == []

    def test_for_attack_returns_multiple(self, registry):
        registry.register(_make_playbook(playbook_id="a1", attack_category="shared"))
        registry.register(_make_playbook(playbook_id="a2", attack_category="shared"))
        assert len(registry.for_attack("shared")) == 2

    def test_attack_categories_contains_builtins(self):
        reg = PlaybookRegistry()
        cats = reg.attack_categories()
        assert "direct_injection" in cats
        assert "exfiltration" in cats

    def test_all_returns_list(self, registry):
        assert isinstance(registry.all(), list)

    def test_register_replaces_existing(self, registry):
        pb1 = _make_playbook(playbook_id="dup", attack_category="cat_a")
        pb2 = _make_playbook(playbook_id="dup", attack_category="cat_b")
        registry.register(pb1)
        registry.register(pb2)
        assert registry.get("dup").attack_category == "cat_b"


# ── TestStepExecution / TestPlaybookExecution ─────────────────────────────────

class TestStepExecution:
    def test_to_dict_roundtrip(self):
        se = StepExecution(
            step_id="s1", status="done",
            completed_at="2026-01-01T00:00:00+00:00",
            actor="alice", notes="all good",
        )
        restored = StepExecution.from_dict(se.to_dict())
        assert restored.step_id == se.step_id
        assert restored.status == se.status
        assert restored.actor == se.actor

    def test_from_dict_defaults_empty_strings(self):
        d = {"step_id": "s1", "status": "pending"}
        se = StepExecution.from_dict(d)
        assert se.completed_at == ""
        assert se.actor == ""
        assert se.notes == ""


class TestPlaybookExecution:
    def _make_execution(self, statuses: dict[str, str], required_map: dict[str, bool] | None = None) -> PlaybookExecution:
        """Helper: build a PlaybookExecution with given step statuses."""
        steps = {}
        for sid, status in statuses.items():
            se = StepExecution(step_id=sid, status=status, completed_at="", actor="", notes="")
            req = True if required_map is None else required_map.get(sid, True)
            se._required = req  # type: ignore[attr-defined]
            steps[sid] = se
        return PlaybookExecution(
            execution_id="exec-001",
            finding_id="f-001",
            playbook_id="pb-test",
            attack_category="direct_injection",
            started_at="2026-01-01T00:00:00+00:00",
            status="active",
            steps=steps,
        )

    def test_progress_all_pending_is_zero(self):
        ex = self._make_execution({"s1": "pending", "s2": "pending"})
        assert ex.progress() == 0.0

    def test_progress_all_done_is_one(self):
        ex = self._make_execution({"s1": "done", "s2": "done"})
        assert ex.progress() == 1.0

    def test_progress_partial(self):
        ex = self._make_execution({"s1": "done", "s2": "pending", "s3": "pending"})
        assert abs(ex.progress() - 1 / 3) < 1e-9

    def test_progress_skipped_required_not_counted(self):
        ex = self._make_execution({"s1": "done", "s2": "skipped"},
                                  required_map={"s1": True, "s2": True})
        # 1 done out of 2 required
        assert ex.progress() == 0.5

    def test_progress_optional_steps_ignored(self):
        ex = self._make_execution({"s1": "done", "s2": "skipped"},
                                  required_map={"s1": True, "s2": False})
        # only s1 is required and it is done → 1.0
        assert ex.progress() == 1.0

    def test_is_complete_all_done(self):
        ex = self._make_execution({"s1": "done", "s2": "done"})
        assert ex.is_complete() is True

    def test_is_complete_partial_not_complete(self):
        ex = self._make_execution({"s1": "done", "s2": "pending"})
        assert ex.is_complete() is False

    def test_is_complete_skipped_required_not_complete(self):
        ex = self._make_execution({"s1": "done", "s2": "skipped"},
                                  required_map={"s1": True, "s2": True})
        assert ex.is_complete() is False

    def test_to_dict_roundtrip(self):
        ex = self._make_execution({"s1": "done", "s2": "pending"})
        restored = PlaybookExecution.from_dict(ex.to_dict())
        assert restored.execution_id == ex.execution_id
        assert restored.finding_id == ex.finding_id
        assert set(restored.steps.keys()) == {"s1", "s2"}


# ── TestExecutionStore ────────────────────────────────────────────────────────

class TestExecutionStore:
    def _sample_execution(self, execution_id: str = "exec-001", finding_id: str = "f-001") -> PlaybookExecution:
        se = StepExecution(step_id="s1", status="pending", completed_at="", actor="", notes="")
        se._required = True  # type: ignore[attr-defined]
        return PlaybookExecution(
            execution_id=execution_id,
            finding_id=finding_id,
            playbook_id="pb-test",
            attack_category="direct_injection",
            started_at="2026-01-01T00:00:00+00:00",
            status="active",
            steps={"s1": se},
        )

    def test_save_and_get(self, tmp_store):
        ex = self._sample_execution()
        tmp_store.save(ex)
        fetched = tmp_store.get("exec-001")
        assert fetched is not None
        assert fetched.execution_id == "exec-001"

    def test_get_nonexistent_returns_none(self, tmp_store):
        assert tmp_store.get("nope") is None

    def test_save_updates_existing(self, tmp_store):
        ex = self._sample_execution()
        tmp_store.save(ex)
        ex.status = "completed"
        tmp_store.save(ex)
        fetched = tmp_store.get(ex.execution_id)
        assert fetched.status == "completed"

    def test_for_finding(self, tmp_store):
        tmp_store.save(self._sample_execution("e1", "find-A"))
        tmp_store.save(self._sample_execution("e2", "find-A"))
        tmp_store.save(self._sample_execution("e3", "find-B"))
        results = tmp_store.for_finding("find-A")
        assert len(results) == 2
        assert all(r.finding_id == "find-A" for r in results)

    def test_active_filters_correctly(self, tmp_store):
        ex1 = self._sample_execution("e1", "f1")
        ex2 = self._sample_execution("e2", "f2")
        ex2.status = "completed"
        tmp_store.save(ex1)
        tmp_store.save(ex2)
        active = tmp_store.active()
        assert len(active) == 1
        assert active[0].execution_id == "e1"

    def test_all_returns_all(self, tmp_store):
        tmp_store.save(self._sample_execution("e1", "f1"))
        tmp_store.save(self._sample_execution("e2", "f2"))
        assert len(tmp_store.all()) == 2

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "store.jsonl")
        store1 = ExecutionStore(path=path)
        ex = self._sample_execution()
        store1.save(ex)

        store2 = ExecutionStore(path=path)
        assert store2.get(ex.execution_id) is not None


# ── TestPlaybookEngine ────────────────────────────────────────────────────────

class TestPlaybookEngine:
    def test_start_returns_execution(self, engine):
        ex = engine.start("f-001", "direct_injection", "high")
        assert ex is not None
        assert ex.finding_id == "f-001"
        assert ex.attack_category == "direct_injection"

    def test_start_unknown_category_returns_none(self, engine):
        result = engine.start("f-001", "unknown_attack_xyz", "high")
        assert result is None

    def test_start_persists_to_store(self, engine, tmp_store):
        ex = engine.start("f-001", "direct_injection")
        assert tmp_store.get(ex.execution_id) is not None

    def test_start_selects_matching_severity(self, registry, tmp_store):
        pb_crit = _make_playbook(playbook_id="pb-crit", attack_category="novel",
                                 severity_applies=["critical"])
        pb_high = _make_playbook(playbook_id="pb-high", attack_category="novel",
                                 severity_applies=["high"])
        registry.register(pb_crit)
        registry.register(pb_high)
        eng = PlaybookEngine(registry=registry, store=tmp_store)
        ex = eng.start("f-001", "novel", "high")
        assert ex.playbook_id == "pb-high"

    def test_execution_id_is_16_hex_chars(self, engine):
        ex = engine.start("f-001", "direct_injection")
        assert len(ex.execution_id) == 16
        assert all(c in "0123456789abcdef" for c in ex.execution_id)

    def test_initial_steps_all_pending(self, engine):
        ex = engine.start("f-001", "exfiltration")
        assert all(se.status == "pending" for se in ex.steps.values())

    def test_advance_step_marks_done(self, engine):
        ex = engine.start("f-001", "direct_injection")
        step_id = next(iter(ex.steps))
        result = engine.advance_step(ex.execution_id, step_id, actor="bob", notes="done it")
        assert result is True
        updated = engine._store.get(ex.execution_id)
        assert updated.steps[step_id].status == "done"
        assert updated.steps[step_id].actor == "bob"

    def test_advance_step_nonexistent_execution_returns_false(self, engine):
        assert engine.advance_step("no-such-exec", "s1") is False

    def test_advance_step_nonexistent_step_returns_false(self, engine):
        ex = engine.start("f-001", "direct_injection")
        assert engine.advance_step(ex.execution_id, "no-such-step") is False

    def test_advance_all_required_completes_execution(self, engine, registry):
        # Use a simple 2-required-step playbook
        pb = _make_playbook(
            playbook_id="simple-2",
            attack_category="simple_cat",
            severity_applies=["high"],
            steps=[_make_step("s1", required=True), _make_step("s2", required=True)],
        )
        registry.register(pb)
        ex = engine.start("f-001", "simple_cat", "high")
        engine.advance_step(ex.execution_id, "s1")
        engine.advance_step(ex.execution_id, "s2")
        updated = engine._store.get(ex.execution_id)
        assert updated.status == "completed"

    def test_skip_step_marks_skipped(self, engine):
        ex = engine.start("f-001", "direct_injection")
        step_id = next(iter(ex.steps))
        result = engine.skip_step(ex.execution_id, step_id, actor="carol", notes="skip reason")
        assert result is True
        updated = engine._store.get(ex.execution_id)
        assert updated.steps[step_id].status == "skipped"

    def test_skip_step_nonexistent_returns_false(self, engine):
        assert engine.skip_step("no-exec", "no-step") is False

    def test_abandon_sets_status(self, engine):
        ex = engine.start("f-001", "exfiltration")
        result = engine.abandon(ex.execution_id, reason="no longer needed")
        assert result is True
        updated = engine._store.get(ex.execution_id)
        assert updated.status == "abandoned"

    def test_abandon_nonexistent_returns_false(self, engine):
        assert engine.abandon("no-such-exec") is False

    def test_status_returns_dict(self, engine):
        ex = engine.start("f-001", "direct_injection")
        s = engine.status(ex.execution_id)
        assert "execution_id" in s
        assert "progress" in s
        assert "status" in s
        assert "next_step" in s

    def test_status_progress_zero_at_start(self, engine):
        ex = engine.start("f-001", "direct_injection")
        s = engine.status(ex.execution_id)
        assert s["progress"] == 0.0

    def test_status_next_step_is_first_pending(self, engine):
        ex = engine.start("f-001", "direct_injection")
        s = engine.status(ex.execution_id)
        # First pending step should be the first step in the playbook
        assert s["next_step"] is not None
        assert isinstance(s["next_step"], PlaybookStep)

    def test_status_nonexistent_returns_empty_dict(self, engine):
        assert engine.status("no-exec") == {}

    def test_status_next_step_none_when_all_done(self, engine, registry):
        pb = _make_playbook(
            playbook_id="one-step",
            attack_category="one_step_cat",
            severity_applies=["high"],
            steps=[_make_step("only")],
        )
        registry.register(pb)
        ex = engine.start("f-001", "one_step_cat", "high")
        engine.advance_step(ex.execution_id, "only")
        s = engine.status(ex.execution_id)
        assert s["next_step"] is None
