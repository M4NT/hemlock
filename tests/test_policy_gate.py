"""Tests for v8.4 policy gate."""

from __future__ import annotations

import json

import pytest

from hemlock.policy import Policy
from hemlock.policy_gate import PolicyGate, ScorerPolicyAdapter
from hemlock.risk_scoring import RiskMatrix, RiskScorer


def _scorer_data(success_rate: float, attacks: dict[str, float]) -> dict:
    scenarios = []
    for atk, rate in attacks.items():
        scenarios.append({"attack": atk, "attack_succeeded": rate > 0, "hardening": "baseline"})
    return {
        "model": "test",
        "success_rate": success_rate,
        "scenarios": scenarios,
    }


class TestScorerPolicyAdapter:
    def test_from_dict(self):
        data = _scorer_data(0.5, {"direct_injection": 0.5, "exfiltration": 0.0})
        adapter = ScorerPolicyAdapter.from_report(data)
        assert adapter.success_rate == 50.0
        assert "direct_injection" in adapter.attack_rates

    def test_weighted_risk_with_fintech(self):
        data = _scorer_data(0.5, {"exfiltration": 0.8, "direct_injection": 0.2})
        scorer = RiskScorer(RiskMatrix.preset_fintech())
        adapter = ScorerPolicyAdapter.from_report(data, scorer)
        assert adapter.weighted_risk > adapter.success_rate * 0.5


class TestPolicyGate:
    def test_max_success_rate_violation(self):
        policy = Policy.from_dict({
            "name": "prod",
            "version": "1",
            "rules": [{"max_success_rate": 30}],
        })
        gate = PolicyGate(policy)
        result = gate.evaluate(_scorer_data(0.5, {"direct_injection": 0.5}))
        assert not result.policy_result.passed

    def test_max_weighted_risk_fintech(self):
        policy = Policy.from_dict({
            "name": "fintech",
            "version": "1",
            "risk_preset": "fintech",
            "rules": [{"max_weighted_risk": 40}],
        })
        gate = PolicyGate(policy, RiskScorer(RiskMatrix.preset_fintech()))
        data = _scorer_data(0.5, {"exfiltration": 0.9})
        result = gate.evaluate(data)
        assert result.weighted_risk > 40
        assert not result.policy_result.passed

    def test_must_block_attacks(self):
        policy = Policy.from_dict({
            "name": "p",
            "version": "1",
            "rules": [{"must_block_attacks": {"attacks": ["exfiltration"]}}],
        })
        gate = PolicyGate(policy)
        result = gate.evaluate(_scorer_data(0.2, {"exfiltration": 0.5}))
        assert not result.policy_result.passed

    def test_regression_and_policy_combined(self, tmp_path):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(
            json.dumps({
                "name": "ci",
                "version": "1",
                "rules": [{"max_success_rate": 80}],
            }),
            encoding="utf-8",
        )
        gate = PolicyGate.from_yaml(str(policy_path))
        result = gate.evaluate(_scorer_data(0.9, {}), baseline_rate=0.1)
        assert not result.regression_passed
        assert not result.passed

    def test_passes_clean_report(self):
        policy = Policy.from_dict({
            "name": "p",
            "version": "1",
            "rules": [{"max_success_rate": 50}],
        })
        gate = PolicyGate(policy)
        result = gate.evaluate(_scorer_data(0.1, {"direct_injection": 0.1}))
        assert result.policy_result.passed
