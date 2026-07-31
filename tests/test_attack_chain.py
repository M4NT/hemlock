"""Tests for AttackChain (v3.6) — self-contained fake attacks, no real pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from hemlock.attack_chain import AttackChain, AttackChainReport, ChainStep


@dataclass
class _FakeTrace:
    response: str = ""


@dataclass
class _FakeResult:
    succeeded: bool
    trace: _FakeTrace
    notes: str = ""


class _FakePipeline:
    def __init__(self) -> None:
        self.carried: list[str] = []

    def add_texts(self, texts: list[str]) -> None:
        self.carried.extend(texts)


def _make_attack(name, succeed, response="", variants=None, raises=False):
    class _Attack:
        VARIANTS = variants or []

        def __init__(self, pipeline, variant=None):
            self.pipeline = pipeline
            self.variant = variant

        def run(self):
            if raises:
                raise RuntimeError("boom")
            return _FakeResult(
                succeeded=succeed,
                trace=_FakeTrace(response=response),
                notes=f"{name} ran",
            )

    _Attack.name = name
    _Attack.__name__ = name
    return _Attack


def test_all_steps_succeed_require_all():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", True, "resp-a")),
        ChainStep(_make_attack("b", True, "resp-b")),
    ])
    report = chain.run()
    assert isinstance(report, AttackChainReport)
    assert report.chain_succeeded() is True
    assert report.succeeded_steps() == [0, 1]


def test_require_all_fails_if_one_fails():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", True, "x")),
        ChainStep(_make_attack("b", False, "y")),
    ], require_all=True)
    report = chain.run()
    assert report.chain_succeeded() is False
    assert report.succeeded_steps() == [0]


def test_require_any_succeeds_if_one_succeeds():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", False)),
        ChainStep(_make_attack("b", True)),
    ], require_all=False)
    report = chain.run()
    assert report.chain_succeeded() is True
    assert report.succeeded_steps() == [1]


def test_carry_context_calls_add_texts():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", True, "carried-payload"), carry_context=False),
        ChainStep(_make_attack("b", True, "resp-b"), carry_context=True),
    ])
    chain.run()
    assert pipe.carried == ["carried-payload"]


def test_no_carry_when_disabled():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", True, "payload"), carry_context=False),
        ChainStep(_make_attack("b", True, "resp"), carry_context=False),
    ])
    chain.run()
    assert pipe.carried == []


def test_carry_is_best_effort_on_missing_method():
    class _BarePipeline:
        pass

    chain = AttackChain(_BarePipeline(), [
        ChainStep(_make_attack("a", True, "payload"), carry_context=False),
        ChainStep(_make_attack("b", True, "resp"), carry_context=True),
    ])
    report = chain.run()  # must not raise
    assert report.chain_succeeded() is True


def test_attack_exception_is_captured():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [
        ChainStep(_make_attack("a", True, raises=True)),
    ], require_all=False)
    report = chain.run()
    assert report.chain_succeeded() is False
    assert "error:" in report.steps[0].notes


def test_variant_label_defaults_to_first_variant():
    pipe = _FakePipeline()
    atk = _make_attack("a", True, variants=["v1", "v2"])
    chain = AttackChain(pipe, [ChainStep(atk)])
    report = chain.run()
    assert report.steps[0].variant == "v1"


def test_explicit_variant_passed_through():
    pipe = _FakePipeline()
    atk = _make_attack("a", True, variants=["v1", "v2"])
    chain = AttackChain(pipe, [ChainStep(atk, variant="v2")])
    report = chain.run()
    assert report.steps[0].variant == "v2"


def test_to_dict_and_markdown():
    pipe = _FakePipeline()
    chain = AttackChain(pipe, [ChainStep(_make_attack("a", True, "r"))])
    report = chain.run()
    d = report.to_dict()
    assert d["chain_succeeded"] is True
    assert d["steps"][0]["attack_name"] == "a"
    md = report.to_markdown()
    assert "Attack Chain Report" in md
    assert "require_all" in md


def test_empty_chain_not_succeeded():
    report = AttackChain(_FakePipeline(), []).run()
    assert report.chain_succeeded() is False
