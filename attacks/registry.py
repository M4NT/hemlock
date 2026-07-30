"""Auto-discovery registry — scans attacks/ for Attack subclasses at import time.

Adding a new attack module:
    1. Create attacks/my_attack.py with a class that inherits from Attack.
    2. That's it. The registry picks it up automatically.

No changes needed to __init__.py, cli.py, or scorer.py.

Convention:
    Each module should define exactly one primary Attack subclass.
    The registry key is the module filename without .py (e.g. "direct_injection").
    If a module defines multiple Attack subclasses, the first one found is used.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from attacks.base import Attack

_EXCLUDE = {"base", "fuzzer", "registry", "__init__"}


def discover_attacks(package: str = "attacks") -> dict[str, type[Attack]]:
    """Return {module_name: AttackClass} for every Attack subclass found in attacks/."""
    registry: dict[str, type[Attack]] = {}
    attacks_dir = Path(__file__).parent

    for module_info in pkgutil.iter_modules([str(attacks_dir)]):
        if module_info.name in _EXCLUDE:
            continue

        full_name = f"{package}.{module_info.name}"
        try:
            module = importlib.import_module(full_name)
        except ImportError:
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Attack)
                and obj is not Attack
                and obj.__module__ == full_name
            ):
                registry[module_info.name] = obj
                break  # one primary class per module

    return registry


ATTACK_REGISTRY: dict[str, type[Attack]] = discover_attacks()
