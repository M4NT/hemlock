"""Attack modules — each maps to a documented technique."""

from .base import Attack, AttackResult
from .direct_injection import DirectInjection
from .context_override import ContextOverride
from .poisoning import KnowledgePoisoning
from .indirect_injection import IndirectInjection
from .exfiltration import Exfiltration
from .jailbreak_via_context import JailbreakViaContext
from .authority_spoofing import AuthoritySpoofing
from .chain_of_thought_hijack import ChainOfThoughtHijack
from .citation_forgery import CitationForgery
from .context_flooding import ContextFlooding
from .invisible_markup import InvisibleMarkup
from .temporal_spoofing import TemporalSpoofing
from .semantic_backdoor import SemanticBackdoor
from .multi_hop_poisoning import MultiHopPoisoning
from .cross_tenant_poisoning import CrossTenantPoisoning

__all__ = [
    "Attack",
    "AttackResult",
    "DirectInjection",
    "ContextOverride",
    "KnowledgePoisoning",
    "IndirectInjection",
    "Exfiltration",
    "JailbreakViaContext",
    "AuthoritySpoofing",
    "ChainOfThoughtHijack",
    "CitationForgery",
    "ContextFlooding",
    "InvisibleMarkup",
    "TemporalSpoofing",
    "SemanticBackdoor",
    "MultiHopPoisoning",
    "CrossTenantPoisoning",
]
