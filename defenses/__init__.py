"""Defense modules for Hemlock RAG security lab."""

from .base import DefenseReport, IngestDefense, RetrievalDefense, OutputDefense
from .input_sanitizer import InjectionPatternFilter, UnicodeNormalizer, MarkdownHeaderSanitizer
from .chunk_filter import InjectionChunkFilter, ProvenanceFilter
from .prompt_hardening import get_prompt, LEVELS
from .output_validator import ExfiltrationGuard, InjectionSuccessGuard

__all__ = [
    "DefenseReport",
    "IngestDefense",
    "RetrievalDefense",
    "OutputDefense",
    "InjectionPatternFilter",
    "UnicodeNormalizer",
    "MarkdownHeaderSanitizer",
    "InjectionChunkFilter",
    "ProvenanceFilter",
    "get_prompt",
    "LEVELS",
    "ExfiltrationGuard",
    "InjectionSuccessGuard",
]
