"""Tests for hemlock.policy (v6.3)."""

import json
import pytest
from hemlock.policy import (
    Policy,
    PolicyEngine,
    PolicyRule,
    PolicyViolation,
    PolicyResult,
)


class MockResult:
    def __init__(self, channel, succeeded, severity="medium"):
        self.channel = channel
        self.succeeded = succeeded
        self.severity = severity


class MockReport:
    def __init__(self, results, score=40):
        self.results = results
        self._score = score

    def risk_score(self):
        return self._score


def make_report_with(channels_succeeded, score=40):
    results = [MockResult(ch, True) for ch in channels_succeeded]
    return MockReport(results=results, score=score)


def make_policy_from_dict(rules_data):
    return Policy.from_dict({"name": "test", "version": "1", "rules": rules_data})


def test_policy_from_dict_name():
    p = Policy.from_dict({"name": "my-policy", "version": "1", "rules": []})
    assert p.name == "my-policy"


def test_policy_from_dict_max_risk_score():
    p = make_policy_from_dict([{"max_risk_score": 50}])
    assert len(p.rules) == 1
    assert p.rules[0].rule_type == "max_risk_score"
    assert p.rules[0].params["value"] == 50


def test_policy_from_dict_must_block():
    p = make_policy_from_dict([{"must_block": {"channels": ["rag"]}}])
    assert p.rules[0].rule_type == "must_block"
    assert "rag" in p.rules[0].params.get("channels", [])


def test_policy_from_yaml_string_json_fallback():
    data = json.dumps({"name": "p", "version": "1", "rules": [{"max_risk_score": 30}]})
    p = Policy.from_yaml_string(data)
    assert p.name == "p"


def test_policy_result_passed():
    result = PolicyResult(policy_name="p", passed=True, violations=[], warnings=[])
    assert result.passed


def test_policy_result_summary_passed():
    result = PolicyResult(policy_name="p", passed=True, violations=[], warnings=[])
    assert "PASSED" in result.summary()


def test_policy_result_summary_failed():
    v = PolicyViolation(rule_type="max_risk_score", message="too high", severity="error")
    result = PolicyResult(policy_name="p", passed=False, violations=[v], warnings=[])
    assert "FAILED" in result.summary()
    assert "max_risk_score" in result.summary()


def test_policy_result_to_dict():
    result = PolicyResult(policy_name="p", passed=True, violations=[], warnings=[])
    d = result.to_dict()
    assert d["passed"] is True
    assert d["policy_name"] == "p"


def test_policy_engine_passes_when_no_violations():
    p = make_policy_from_dict([{"max_risk_score": 80}])
    engine = PolicyEngine(p)
    report = MockReport(results=[], score=40)
    result = engine.evaluate(report)
    assert result.passed


def test_policy_engine_max_risk_score_violation():
    p = make_policy_from_dict([{"max_risk_score": 30}])
    engine = PolicyEngine(p)
    report = MockReport(results=[], score=50)
    result = engine.evaluate(report)
    assert not result.passed
    assert any(v.rule_type == "max_risk_score" for v in result.violations)


def test_policy_engine_must_block_violation():
    p = make_policy_from_dict([{"must_block": {"channels": ["rag"]}}])
    engine = PolicyEngine(p)
    report = make_report_with(["rag"])
    result = engine.evaluate(report)
    assert not result.passed
    assert any(v.rule_type == "must_block" for v in result.violations)


def test_policy_engine_must_block_passes_when_not_succeeded():
    p = make_policy_from_dict([{"must_block": {"channels": ["rag"]}}])
    engine = PolicyEngine(p)
    report = MockReport(results=[MockResult("rag", False)], score=0)
    result = engine.evaluate(report)
    assert result.passed


def test_policy_engine_no_critical_channels():
    p = make_policy_from_dict([{"no_critical_channels": True}])
    engine = PolicyEngine(p)
    results = [MockResult("rag", True, severity="critical")]
    report = MockReport(results=results, score=40)
    result = engine.evaluate(report)
    assert not result.passed
    assert any(v.severity == "critical" for v in result.violations)


def test_policy_engine_require_channels_warning():
    p = make_policy_from_dict([{"require_channels": {"channels": ["rag", "memory"]}}])
    engine = PolicyEngine(p)
    report = MockReport(results=[MockResult("rag", False)], score=0)
    result = engine.evaluate(report)
    # "memory" not scanned → warning, not violation
    assert result.passed  # warnings don't fail
    assert any(w.rule_type == "require_channels" for w in result.warnings)


def test_policy_engine_warn_if_risk_above():
    p = make_policy_from_dict([{"warn_if_risk_above": 20}])
    engine = PolicyEngine(p)
    report = MockReport(results=[], score=35)
    result = engine.evaluate(report)
    assert result.passed  # warnings only
    assert any(w.rule_type == "warn_if_risk_above" for w in result.warnings)


def test_policy_result_to_json():
    result = PolicyResult(policy_name="p", passed=True, violations=[], warnings=[])
    doc = json.loads(result.to_json())
    assert doc["passed"] is True
