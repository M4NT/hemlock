"""SwarmAttack and SwarmDefense — multi-agent mesh attack and consensus defense.

SwarmAttack:
    Runs N attack variants concurrently (or sequentially). Succeeds if at least
    ``majority_threshold`` fraction of individual attacks succeed. Useful for
    assessing whether a system can withstand a coordinated multi-vector attack.

SwarmDefense:
    Runs N OutputDefense instances against a response. Blocks if at least
    ``majority_threshold`` fraction vote triggered. Configurable to require
    unanimity (threshold=1.0) or majority (threshold=0.5).

Usage:
    from hemlock.swarm import SwarmAttack, SwarmDefense
    from defenses import InjectionSuccessGuard, CrossAgentBoundaryGuard

    # Attack — any 2 of 3 variants must succeed to flag the system as compromised
    swarm = SwarmAttack(pipeline, attack_class=IndirectInjection, majority_threshold=0.67)
    report = swarm.run()
    print(report.consensus_succeeded)

    # Defense — majority vote across 3 guards
    defense = SwarmDefense([
        InjectionSuccessGuard(),
        CrossAgentBoundaryGuard(),
        GraphBoundaryGuard(),
    ], majority_threshold=0.5)
    result = defense.validate("suspicious response")
    print(result.triggered, result.votes)
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# SwarmAttack
# ---------------------------------------------------------------------------

@dataclass
class SwarmAttackResult:
    """Result of a single attack variant within a swarm."""
    variant: str
    succeeded: bool
    notes: str


@dataclass
class SwarmAttackReport:
    """Consolidated result across all swarm attack variants."""
    attack_name: str
    individual_results: list[SwarmAttackResult]
    majority_threshold: float  # fraction of attacks that must succeed

    def success_count(self) -> int:
        return sum(1 for r in self.individual_results if r.succeeded)

    def success_rate(self) -> float:
        if not self.individual_results:
            return 0.0
        return self.success_count() / len(self.individual_results)

    def consensus_succeeded(self) -> bool:
        return self.success_rate() >= self.majority_threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_name":        self.attack_name,
            "majority_threshold": self.majority_threshold,
            "success_count":      self.success_count(),
            "success_rate":       round(self.success_rate(), 3),
            "consensus_succeeded": self.consensus_succeeded(),
            "variants": [
                {"variant": r.variant, "succeeded": r.succeeded, "notes": r.notes}
                for r in self.individual_results
            ],
        }

    def summary(self) -> str:
        verdict = "COMPROMISED" if self.consensus_succeeded() else "DEFENDED"
        return (
            f"{self.attack_name} swarm: {self.success_count()}/"
            f"{len(self.individual_results)} variants succeeded "
            f"({self.success_rate():.0%}) — {verdict}"
        )


class SwarmAttack:
    """Multi-variant attack orchestrator.

    Runs all variants of an attack class, collecting individual outcomes.
    Consensus is reached if ``majority_threshold`` fraction of variants succeed.

    Args:
        pipeline:           The RAG or agent pipeline under test.
        attack_class:       Attack class with a ``VARIANTS`` class variable and
                            ``run() → AttackResult`` instance method.
        variants:           Override variant list (default: attack_class.VARIANTS).
        majority_threshold: Fraction of variants that must succeed for consensus
                            (default 0.5 — simple majority).
        parallel:           Run variants concurrently when True (default: True).
        max_workers:        Thread pool size for parallel mode (default: 4).
    """

    def __init__(
        self,
        pipeline: Any,
        attack_class: Any,
        *,
        variants: list[str] | None = None,
        majority_threshold: float = 0.5,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        self._pipeline          = pipeline
        self._attack_class      = attack_class
        self._variants          = variants if variants is not None else list(attack_class.VARIANTS)
        self._majority_threshold = majority_threshold
        self._parallel          = parallel
        self._max_workers       = max_workers

    def _run_variant(self, variant: str) -> SwarmAttackResult:
        instance = self._attack_class(self._pipeline, variant=variant)
        result   = instance.run()
        return SwarmAttackResult(
            variant=variant,
            succeeded=bool(result.succeeded),
            notes=result.notes or "",
        )

    def run(self) -> SwarmAttackReport:
        """Execute all variants and return a SwarmAttackReport."""
        name = getattr(self._attack_class, "name", self._attack_class.__name__)

        if self._parallel and len(self._variants) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futures = {pool.submit(self._run_variant, v): v for v in self._variants}
                results = []
                for fut in concurrent.futures.as_completed(futures):
                    results.append(fut.result())
        else:
            results = [self._run_variant(v) for v in self._variants]

        return SwarmAttackReport(
            attack_name=name,
            individual_results=results,
            majority_threshold=self._majority_threshold,
        )


# ---------------------------------------------------------------------------
# SwarmDefense
# ---------------------------------------------------------------------------

@dataclass
class SwarmDefenseVote:
    """A single defense's vote in a swarm."""
    defense_name: str
    triggered: bool
    detail: str


@dataclass
class SwarmDefenseResult:
    """Result of a swarm defense consensus check."""
    triggered: bool               # True if majority (or threshold) of defenses voted triggered
    votes: list[SwarmDefenseVote]
    majority_threshold: float
    triggered_count: int
    content_preview: str

    def trigger_rate(self) -> float:
        if not self.votes:
            return 0.0
        return self.triggered_count / len(self.votes)

    def dissenting_defenses(self) -> list[str]:
        """Names of defenses that voted opposite to the consensus."""
        consensus = self.triggered
        return [v.defense_name for v in self.votes if v.triggered != consensus]


class SwarmDefense:
    """Consensus defense — majority vote across N OutputDefense instances.

    Runs all defenses against a response text. Triggers if at least
    ``majority_threshold`` fraction of defenses vote triggered.

    Args:
        defenses:           List of OutputDefense instances.
        majority_threshold: Fraction of defenses that must trigger for the
                            swarm to block (default 0.5 — simple majority).
                            Use 1.0 for unanimity, 0.0 to always block.
        parallel:           Run defenses concurrently (default: True).
        max_workers:        Thread pool size (default: 4).
    """

    def __init__(
        self,
        defenses: list,
        *,
        majority_threshold: float = 0.5,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        if not defenses:
            raise ValueError("SwarmDefense requires at least one defense.")
        self._defenses          = defenses
        self._majority_threshold = majority_threshold
        self._parallel          = parallel
        self._max_workers       = max_workers

    def _run_defense(self, defense: Any, text: str) -> SwarmDefenseVote:
        report = defense.validate(text)
        return SwarmDefenseVote(
            defense_name=getattr(defense, "name", None) or type(defense).__name__,
            triggered=report.triggered,
            detail=report.detail,
        )

    def validate(self, text: str) -> SwarmDefenseResult:
        """Run all defenses against ``text`` and return a consensus result."""
        if self._parallel and len(self._defenses) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futures = [pool.submit(self._run_defense, d, text) for d in self._defenses]
                votes   = [f.result() for f in concurrent.futures.as_completed(futures)]
        else:
            votes = [self._run_defense(d, text) for d in self._defenses]

        triggered_count = sum(1 for v in votes if v.triggered)
        trigger_rate    = triggered_count / len(votes) if votes else 0.0
        triggered       = trigger_rate >= self._majority_threshold

        return SwarmDefenseResult(
            triggered=triggered,
            votes=votes,
            majority_threshold=self._majority_threshold,
            triggered_count=triggered_count,
            content_preview=text[:120],
        )
