"""Hemlock LLM Behavior Fingerprinting (v6.1).

Generates a behavioral "fingerprint" of a pipeline — a vector of per-category
defense scores — that can be compared across model versions to detect silent
security regressions without a full changelog.

A fingerprint is stable when model behavior is stable. If a fine-tune or
API update changes how the model handles injection attempts, the fingerprint
diverges measurably from the previous baseline.

Usage:
    from hemlock.fingerprint import PipelineFingerprint

    fp = PipelineFingerprint.from_mock()
    vector = fp.compute()
    print(vector.scores)       # {'injection': 80, 'exfiltration': 90, ...}
    print(vector.hash)         # short hex identifier

    # Compare two fingerprints
    baseline = FingerprintVector(scores={"injection": 80}, model_version="v1", hash="abc")
    delta = vector.diff(baseline)
    print(delta.drifted_categories)   # categories that changed > threshold
    print(delta.is_regression)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FingerprintVector:
    scores: dict[str, int]           # category → defense score (0-100)
    model_version: str
    hash: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = json.dumps(self.scores, sort_keys=True) + self.model_version
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def diff(
        self,
        baseline: "FingerprintVector",
        drift_threshold: int = 5,
    ) -> "FingerprintDiff":
        deltas: dict[str, int] = {}
        drifted: list[str] = []

        all_cats = set(self.scores) | set(baseline.scores)
        for cat in all_cats:
            curr = self.scores.get(cat, 0)
            prev = baseline.scores.get(cat, 0)
            delta = curr - prev
            deltas[cat] = delta
            if abs(delta) > drift_threshold:
                drifted.append(cat)

        regression_cats = [c for c in drifted if deltas[c] < 0]

        return FingerprintDiff(
            current=self,
            baseline=baseline,
            deltas=deltas,
            drifted_categories=sorted(drifted),
            regression_categories=sorted(regression_cats),
            is_regression=bool(regression_cats),
        )

    def to_dict(self) -> dict:
        return {
            "model_version": self.model_version,
            "hash": self.hash,
            "scores": self.scores,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class FingerprintDiff:
    current: FingerprintVector
    baseline: FingerprintVector
    deltas: dict[str, int]
    drifted_categories: list[str]
    regression_categories: list[str]
    is_regression: bool

    def to_dict(self) -> dict:
        return {
            "current_hash": self.current.hash,
            "baseline_hash": self.baseline.hash,
            "deltas": self.deltas,
            "drifted_categories": self.drifted_categories,
            "regression_categories": self.regression_categories,
            "is_regression": self.is_regression,
        }

    def summary(self) -> str:
        if not self.drifted_categories:
            return "No behavioral drift detected."
        lines = [
            f"Drift detected in {len(self.drifted_categories)} categories: "
            f"{', '.join(self.drifted_categories)}"
        ]
        if self.is_regression:
            lines.append(
                f"REGRESSION in: {', '.join(self.regression_categories)}"
            )
        for cat, delta in self.deltas.items():
            if abs(delta) > 0:
                arrow = "↑" if delta > 0 else "↓"
                lines.append(f"  {cat}: {arrow}{abs(delta)}")
        return "\n".join(lines)


class PipelineFingerprint:
    def __init__(
        self,
        pipeline: Any | None = None,
        model_version: str = "mock",
        attack_names: list[str] | None = None,
        categories: list[str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.model_version = model_version
        self.attack_names = attack_names
        self.categories = categories

    @classmethod
    def from_mock(
        cls,
        model_version: str = "mock",
        categories: list[str] | None = None,
    ) -> "PipelineFingerprint":
        return cls(model_version=model_version, categories=categories)

    def compute(self) -> FingerprintVector:
        from hemlock.eval_benchmark import EvalBenchmark

        bench = EvalBenchmark.from_mock(
            model_name=self.model_version,
            attack_names=self.attack_names,
            categories=self.categories,
        )
        report = bench.run()
        scores = report.category_scores()

        return FingerprintVector(
            scores=scores,
            model_version=self.model_version,
            metadata={"overall": report.overall_score()},
        )
