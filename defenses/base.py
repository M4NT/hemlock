"""Base classes for Hemlock defense modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from langchain_core.documents import Document


@dataclass
class DefenseReport:
    defense_name: str
    triggered: bool
    detail: str
    document: Document | None = None


class IngestDefense(ABC):
    """Applied at ingest time — can reject or sanitize documents before indexing."""

    name: str = ""
    covers: list[str] = []  # attack names this defense targets

    @abstractmethod
    def inspect(self, doc: Document) -> tuple[Document | None, DefenseReport]:
        """Return (sanitized_doc, report). Return (None, report) to reject the document."""


class RetrievalDefense(ABC):
    """Applied at query time — filters or scores retrieved chunks before they reach the LLM."""

    name: str = ""
    covers: list[str] = []

    @abstractmethod
    def filter(self, chunks: list[Document]) -> tuple[list[Document], list[DefenseReport]]:
        """Return (safe_chunks, reports). Removed chunks appear in reports with triggered=True."""


class OutputDefense(ABC):
    """Applied after generation — validates the model response."""

    name: str = ""
    covers: list[str] = []

    @abstractmethod
    def validate(self, response: str) -> DefenseReport:
        """Return a report. If triggered=True the response should be blocked or flagged."""
