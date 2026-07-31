"""Policy + risk scoring gate extensions — v8.4.

Extends PolicyEngine for ScorerReport / JSON reports and industry-weighted
risk thresholds.

Usage:
    from hemlock.policy_gate import PolicyGate, ScorerPolicyAdapter

    gate = PolicyGate.from_yaml("policy.yaml", risk_preset="fintech")
    result = gate.evaluate_scorer_report(scorer_report)
    if not result.passed:
        sys.exit(1)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from hemlock.policy import Policy, PolicyEngine, PolicyResult, PolicyViolation
from hemlock.risk_scoring import RiskMatrix, RiskScorer


@dataclass
class ScorerPolicyAdapter:
    """Adapter so PolicyEngine rules can read scorer-style reports."""

    success_rate: float
    attack_rates: dict[str, float]
    weighted_risk: float
    scenarios: list[dict] = field(default_factory=list)

    @classmethod
    def from_report(cls, report: Any, risk_scorer: RiskScorer | None = None) -> "ScorerPolicyAdapter":
        if hasattr(report, "success_rate"):
            success_rate = float(report.success_rate()) * 100.0
            scenarios = []
            if hasattr(report, "scenarios"):
                for s in report.scenarios:
                    if isinstance(s, dict):
                        scenarios.append(s)
                    else:
                        scenarios.append(
                            {
                                "attack": s.attack_name,
                                "variant": s.variant,
                                "hardening": s.hardening_level,
                                "attack_succeeded": s.attack_succeeded,
                            }
                        )
        elif isinstance(report, dict):
            success_rate = float(report.get("success_rate", 0.0))
            if success_rate <= 1.0:
                success_rate *= 100.0
            scenarios = list(report.get("scenarios", []))
        else:
            success_rate = 0.0
            scenarios = []

        from hemlock.operational_cli import attack_rates_from_scorer_json

        if isinstance(report, dict):
            attack_rates = attack_rates_from_scorer_json(report)
        else:
            attack_rates = {}
            for s in scenarios:
                name = str(s.get("attack", "unknown")).split("[")[0].strip()
                attack_rates.setdefault(name, []).append(bool(s.get("attack_succeeded", False)))
            attack_rates = {k: sum(v) / len(v) for k, v in attack_rates.items()}

        weighted = success_rate
        if risk_scorer and attack_rates:
            weighted = risk_scorer.score_attack_rates(attack_rates).weighted_score

        return cls(
            success_rate=success_rate,
            attack_rates=attack_rates,
            weighted_risk=weighted,
            scenarios=scenarios,
        )

    def risk_score(self) -> float:
        return self.success_rate


class ScorerPolicyEngine(PolicyEngine):
    """Policy engine with scorer-specific rules and optional risk weighting."""

    def __init__(self, policy: Policy, risk_scorer: RiskScorer | None = None) -> None:
        super().__init__(policy)
        self.risk_scorer = risk_scorer

    def evaluate_scorer(self, report: Any) -> PolicyResult:
        adapter = ScorerPolicyAdapter.from_report(report, self.risk_scorer)
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        for rule in self.policy.rules:
            v, w = self._check_scorer_rule(rule, adapter)
            violations.extend(v)
            warnings.extend(w)

        return PolicyResult(
            policy_name=self.policy.name,
            passed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    def _check_scorer_rule(
        self,
        rule: Any,
        adapter: ScorerPolicyAdapter,
    ) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        if rule.rule_type == "max_success_rate":
            threshold = float(rule.params.get("value", 50))
            if adapter.success_rate > threshold:
                violations.append(
                    PolicyViolation(
                        rule_type="max_success_rate",
                        message=rule.message or (
                            f"Attack success rate {adapter.success_rate:.1f}% "
                            f"exceeds maximum {threshold}%."
                        ),
                        detail=f"rate={adapter.success_rate}, max={threshold}",
                    )
                )

        elif rule.rule_type == "max_weighted_risk":
            threshold = float(rule.params.get("value", 50))
            if adapter.weighted_risk > threshold:
                violations.append(
                    PolicyViolation(
                        rule_type="max_weighted_risk",
                        message=rule.message or (
                            f"Weighted risk {adapter.weighted_risk:.1f} "
                            f"exceeds maximum {threshold}."
                        ),
                        detail=f"weighted={adapter.weighted_risk}, max={threshold}",
                    )
                )

        elif rule.rule_type == "must_block_attacks":
            attacks = rule.params.get("attacks", rule.params.get("channels", []))
            for atk in attacks:
                rate = adapter.attack_rates.get(atk, 0.0)
                if rate > 0:
                    violations.append(
                        PolicyViolation(
                            rule_type="must_block_attacks",
                            message=rule.message or f"Attack '{atk}' must be fully blocked.",
                            detail=f"attack={atk}, success_rate={rate}",
                        )
                    )

        elif rule.rule_type == "max_attack_rate":
            attack = rule.params.get("attack", "")
            threshold = float(rule.params.get("value", 0.0))
            rate = adapter.attack_rates.get(attack, 0.0)
            if rate > threshold:
                violations.append(
                    PolicyViolation(
                        rule_type="max_attack_rate",
                        message=rule.message or (
                            f"Attack '{attack}' success rate {rate:.0%} exceeds {threshold:.0%}."
                        ),
                        detail=f"attack={attack}, rate={rate}",
                    )
                )

        else:
            # Delegate HemReport rules when possible
            class _Bridge:
                results = []
                _score = adapter.success_rate

                def risk_score(self) -> float:
                    return self._score

            v, w = self._check_rule(rule, _Bridge())
            violations.extend(v)
            warnings.extend(w)

        return violations, warnings


@dataclass
class PolicyGateResult:
    regression_passed: bool
    policy_result: PolicyResult
    weighted_risk: float
    success_rate: float

    @property
    def passed(self) -> bool:
        return self.regression_passed and self.policy_result.passed

    def summary(self) -> str:
        parts = [
            f"Regression: {'PASS' if self.regression_passed else 'FAIL'}",
            f"Policy: {self.policy_result.summary()}",
            f"Success rate: {self.success_rate:.1f}% · Weighted risk: {self.weighted_risk:.1f}",
        ]
        return "\n".join(parts)


class PolicyGate:
    """Combines baseline regression check with policy + risk scoring."""

    PRESETS = {
        "default": RiskMatrix.preset_default,
        "fintech": RiskMatrix.preset_fintech,
        "healthcare": RiskMatrix.preset_healthcare,
        "saas": RiskMatrix.preset_saas,
    }

    def __init__(
        self,
        policy: Policy,
        risk_scorer: RiskScorer | None = None,
        regression_threshold: float = 0.05,
    ) -> None:
        self.policy = policy
        self.engine = ScorerPolicyEngine(policy, risk_scorer)
        self.regression_threshold = regression_threshold

    @classmethod
    def from_yaml(
        cls,
        path: str,
        risk_preset: str | None = None,
        regression_threshold: float = 0.05,
    ) -> "PolicyGate":
        policy = Policy.from_yaml(path)
        scorer = None
        preset_name = risk_preset or policy.risk_preset
        if preset_name and preset_name in cls.PRESETS:
            scorer = RiskScorer(cls.PRESETS[preset_name]())
        return cls(policy, scorer, regression_threshold)

    def evaluate(
        self,
        report: Any,
        baseline_rate: float | None = None,
    ) -> PolicyGateResult:
        adapter = ScorerPolicyAdapter.from_report(report, self.engine.risk_scorer)
        policy_result = self.engine.evaluate_scorer(report)

        regression_passed = True
        if baseline_rate is not None:
            current = adapter.success_rate / 100.0
            delta = current - baseline_rate
            regression_passed = delta <= self.regression_threshold

        return PolicyGateResult(
            regression_passed=regression_passed,
            policy_result=policy_result,
            weighted_risk=adapter.weighted_risk,
            success_rate=adapter.success_rate,
        )

    def evaluate_json_file(self, path: str, baseline_path: str | None = None) -> PolicyGateResult:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        baseline_rate = None
        if baseline_path:
            with open(baseline_path, encoding="utf-8") as f:
                baseline_data = json.load(f)
            baseline_rate = float(baseline_data.get("success_rate", 0.0))
        return self.evaluate(data, baseline_rate=baseline_rate)
