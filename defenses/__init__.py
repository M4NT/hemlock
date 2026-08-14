"""Defense modules for Hemlock RAG security lab."""

from .base import DefenseReport, IngestDefense, OutputDefense, RetrievalDefense
from .chunk_filter import InjectionChunkFilter, ProvenanceFilter
from .input_sanitizer import InjectionPatternFilter, MarkdownHeaderSanitizer, UnicodeNormalizer
from .llm_classifier import LLMChunkClassifier
from .output_validator import (
    ExfiltrationGuard,
    InjectionSuccessGuard,
    OutputDefenseChain,
    StructuredOutputGuard,
)
from .tool_call_validator import ToolCallValidator
from .cross_agent_boundary_guard import CrossAgentBoundaryGuard
from .memory_isolation_guard import MemoryIsolationGuard
from .tool_output_guard import ToolOutputGuard
from .graph_boundary_guard import GraphBoundaryGuard
from .memory_boundary_guard import MemoryBoundaryGuard, MemoryWriteReport
from .prompt_hardening import LEVELS, get_prompt
from .aeo_context_validator import AeoIngestValidator, AeoRetrievalFilter
from .computer_use_guard import ActionIntentGuard, ScreenContentGuard
from .markup_sanitizer import HtmlMarkupSanitizer, InvisibleMarkupDetector
from .citation_guard import AuthorityCitationDetector, SecurityDowngradeFilter
from .temporal_guard import TemporalClaimDetector, TemporalContextFilter
from .context_jailbreak_guard import ContextJailbreakDetector, ContextJailbreakFilter
from .chain_of_thought_guard import ChainOfThoughtDetector, ChainOfThoughtFilter
from .multi_hop_guard import MultiHopPoisonDetector, MultiHopPoisonFilter
from .cross_tenant_guard import CrossTenantMetadataDetector, CrossTenantIsolationFilter
from .semantic_backdoor_guard import SemanticBackdoorDetector, SemanticBackdoorFilter
from .semantic_intent_guard import SemanticIntentGuard, build_pilot_library, build_full_library, evaluate_threshold
from .conditional_trigger_guard import ConditionalTriggerGuard, ConditionalTriggerFilter
from .composite_guard import CompositeIngestGuard

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
    "OutputDefenseChain",
    "StructuredOutputGuard",
    "ToolCallValidator",
    "CrossAgentBoundaryGuard",
    "MemoryIsolationGuard",
    "ToolOutputGuard",
    "GraphBoundaryGuard",
    "MemoryBoundaryGuard",
    "MemoryWriteReport",
    "AeoIngestValidator",
    "AeoRetrievalFilter",
    "ScreenContentGuard",
    "ActionIntentGuard",
    "HtmlMarkupSanitizer",
    "InvisibleMarkupDetector",
    "AuthorityCitationDetector",
    "SecurityDowngradeFilter",
    "TemporalClaimDetector",
    "TemporalContextFilter",
    "ContextJailbreakDetector",
    "ContextJailbreakFilter",
    "ChainOfThoughtDetector",
    "ChainOfThoughtFilter",
    "MultiHopPoisonDetector",
    "MultiHopPoisonFilter",
    "CrossTenantMetadataDetector",
    "CrossTenantIsolationFilter",
    "SemanticBackdoorDetector",
    "SemanticBackdoorFilter",
    "SemanticIntentGuard",
    "build_pilot_library",
    "build_full_library",
    "evaluate_threshold",
    "ConditionalTriggerGuard",
    "ConditionalTriggerFilter",
    "CompositeIngestGuard",
]
