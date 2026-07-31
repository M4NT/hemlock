"""Hemlock Policy-as-Code — YAML security policies with CI gate (v6.3).

Define security requirements in a YAML policy file. The CI gate checks
a HemReport against the policy and exits 1 on any violation.

Policy file format:
    version: "1"
    name: "production-policy"
    rules:
      - must_block:
          channels: [direct_injection, exfiltration]
          message: "Direct injection and exfiltration must be blocked in prod"
      - max_risk_score: 40
      - no_critical_channels: true
      - require_channels:
          channels: [rag, memory]
          message: "RAG and memory must always be scanned"

Usage:
    from hemlock.policy import Policy, PolicyEngine

    policy = Policy.from_yaml("security-policy.yaml")
    engine = PolicyEngine(policy)
    result = engine.evaluate(hem_report)

    if result.violations:
        for v in result.violations:
            print(f"VIOLATION: {v.message}")
        sys.exit(1)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyRule:
    rule_type: str
    params: dict = field(default_factory=dict)
    message: str = ""


@dataclass
class PolicyViolation:
    rule_type: str
    message: str
    detail: str = ""
    severity: str = "error"


@dataclass
class PolicyResult:
    policy_name: str
    passed: bool
    violations: list[PolicyViolation]
    warnings: list[PolicyViolation]

    def to_dict(self) -> dict:
        return {
            "policy_name": self.policy_name,
            "passed": self.passed,
            "violations": [{"rule": v.rule_type, "message": v.message, "detail": v.detail} for v in self.violations],
            "warnings": [{"rule": v.rule_type, "message": v.message} for v in self.warnings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def summary(self) -> str:
        if self.passed:
            return f"Policy '{self.policy_name}' PASSED — no violations."
        lines = [f"Policy '{self.policy_name}' FAILED — {len(self.violations)} violation(s):"]
        for v in self.violations:
            lines.append(f"  [{v.severity.upper()}] {v.rule_type}: {v.message}")
        return "\n".join(lines)


@dataclass
class Policy:
    name: str
    version: str
    rules: list[PolicyRule]

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = []
        for rule_data in data.get("rules", []):
            for rule_type, params in rule_data.items():
                if isinstance(params, dict):
                    rules.append(PolicyRule(
                        rule_type=rule_type,
                        params=params,
                        message=params.pop("message", ""),
                    ))
                elif isinstance(params, (int, float, bool)):
                    rules.append(PolicyRule(rule_type=rule_type, params={"value": params}))
                else:
                    rules.append(PolicyRule(rule_type=rule_type, params={}))
        return cls(
            name=data.get("name", "unnamed"),
            version=str(data.get("version", "1")),
            rules=rules,
        )

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        try:
            import yaml
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except ImportError:
            import json as _json
            with open(path, encoding="utf-8") as f:
                data = _json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_string(cls, yaml_str: str) -> "Policy":
        try:
            import yaml
            data = yaml.safe_load(yaml_str)
        except ImportError:
            data = json.loads(yaml_str)
        return cls.from_dict(data)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "rules": [
                {r.rule_type: {**r.params, **({"message": r.message} if r.message else {})}}
                for r in self.rules
            ],
        }


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(self, report: Any) -> PolicyResult:
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        for rule in self.policy.rules:
            v, w = self._check_rule(rule, report)
            violations.extend(v)
            warnings.extend(w)

        return PolicyResult(
            policy_name=self.policy.name,
            passed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    def _check_rule(
        self, rule: PolicyRule, report: Any
    ) -> tuple[list[PolicyViolation], list[PolicyViolation]]:
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        if rule.rule_type == "must_block":
            channels = rule.params.get("channels", [])
            succeeded = {r.channel for r in report.results if r.succeeded}
            for ch in channels:
                if ch in succeeded:
                    violations.append(PolicyViolation(
                        rule_type="must_block",
                        message=rule.message or f"Channel '{ch}' must be blocked but succeeded.",
                        detail=f"channel={ch}",
                    ))

        elif rule.rule_type == "max_risk_score":
            threshold = rule.params.get("value", 50)
            score = report.risk_score()
            if score > threshold:
                violations.append(PolicyViolation(
                    rule_type="max_risk_score",
                    message=rule.message or f"Risk score {score} exceeds maximum {threshold}.",
                    detail=f"score={score}, max={threshold}",
                ))

        elif rule.rule_type == "no_critical_channels":
            if rule.params.get("value", True):
                critical = [r for r in report.results if r.severity == "critical" and r.succeeded]
                if critical:
                    channels = [r.channel for r in critical]
                    violations.append(PolicyViolation(
                        rule_type="no_critical_channels",
                        message=rule.message or f"Critical channels at risk: {', '.join(channels)}",
                        detail=f"channels={channels}",
                        severity="critical",
                    ))

        elif rule.rule_type == "require_channels":
            required = rule.params.get("channels", [])
            scanned = {r.channel for r in report.results}
            missing = [c for c in required if c not in scanned]
            if missing:
                warnings.append(PolicyViolation(
                    rule_type="require_channels",
                    message=rule.message or f"Required channels not scanned: {', '.join(missing)}",
                    detail=f"missing={missing}",
                    severity="warning",
                ))

        elif rule.rule_type == "warn_if_risk_above":
            threshold = rule.params.get("value", 30)
            score = report.risk_score()
            if score > threshold:
                warnings.append(PolicyViolation(
                    rule_type="warn_if_risk_above",
                    message=rule.message or f"Risk score {score} above warning threshold {threshold}.",
                    detail=f"score={score}",
                    severity="warning",
                ))

        return violations, warnings
