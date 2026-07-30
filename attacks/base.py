"""Base class for all Hemlock attack modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from hemlock.pipeline import Pipeline, RetrievalTrace


@dataclass
class AttackResult:
    attack_name: str
    reference: str
    succeeded: bool
    trace: RetrievalTrace
    notes: str = ""

    def __str__(self) -> str:
        status = "SUCCEEDED" if self.succeeded else "FAILED"
        return (
            f"[{status}] {self.attack_name}\n"
            f"  ref: {self.reference}\n"
            f"  query: {self.trace.query}\n"
            f"  response: {self.trace.response[:200]}...\n"
            f"  injection_detected: {self.trace.injected}\n"
            f"  notes: {self.notes}"
        )


class Attack(ABC):
    name: str = ""
    reference: str = ""

    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline

    @abstractmethod
    def setup(self) -> None:
        """Inject malicious documents into the pipeline."""

    @abstractmethod
    def run(self) -> AttackResult:
        """Execute the attack and return a scored result."""

    @abstractmethod
    def _score(self, trace: RetrievalTrace) -> bool:
        """Return True if the attack succeeded (model followed injected instructions)."""
