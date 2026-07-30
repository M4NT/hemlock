"""Attack modules — auto-discovered via attacks.registry.

To add a new attack: create a .py file in this directory with a class
that inherits from Attack. No registration needed.
"""

from .base import Attack, AttackResult
from .registry import ATTACK_REGISTRY, discover_attacks

__all__ = [
    "Attack",
    "AttackResult",
    "ATTACK_REGISTRY",
    "discover_attacks",
]
