"""Defense modules for Hemlock RAG security lab."""

from .base import DefenseReport, IngestDefense, OutputDefense, RetrievalDefense
from .chunk_filter import InjectionChunkFilter, ProvenanceFilter
from .input_sanitizer import InjectionPatternFilter, MarkdownHeaderSanitizer, UnicodeNormalizer
from .llm_classifier import LLMChunkClassifier
from .output_validator import ExfiltrationGuard, InjectionSuccessGuard, StructuredOutputGuard
from .tool_call_validator import ToolCallValidator
from .cross_agent_boundary_guard import CrossAgentBoundaryGuard
from .prompt_hardening import LEVELS, get_prompt

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
    "LLMChunkClassifier",
    "get_prompt",
    "LEVELS",
    "ExfiltrationGuard",
    "InjectionSuccessGuard",
    "StructuredOutputGuard",
    "ToolCallValidator",
    "CrossAgentBoundaryGuard",
]
