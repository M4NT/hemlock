"""PluginRegistry — unified discovery of attacks and defenses (v4.0).

Discovers:
    - builtin attacks from ``attacks.registry.ATTACK_REGISTRY``
    - builtin defenses from the ``defenses`` package exports
    - third-party plugins via entry points ("hemlock.attacks", "hemlock.defenses")

Usage:
    from hemlock.plugin_registry import REGISTRY
    REGISTRY.discover()
    print(REGISTRY.attacks())
    print(REGISTRY.get("indirect_injection"))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PluginInfo:
    name: str
    type: str      # "attack" | "defense"
    cls: type
    source: str    # "builtin" | "entrypoint" | "path" | "manual"
    version: str


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, PluginInfo] = {}
        self._discovered = False

    def discover(self) -> None:
        self._load_builtin_attacks()
        self._load_builtin_defenses()
        self._load_entrypoints()
        self._discovered = True

    def _ensure(self) -> None:
        if not self._discovered:
            self.discover()

    def _load_builtin_attacks(self) -> None:
        try:
            from attacks.registry import ATTACK_REGISTRY
        except Exception:
            return
        for name, cls in ATTACK_REGISTRY.items():
            self._plugins[name] = PluginInfo(
                name=name,
                type="attack",
                cls=cls,
                source="builtin",
                version=self._version_of(cls),
            )

    def _load_builtin_defenses(self) -> None:
        try:
            import defenses
            from defenses.base import IngestDefense, OutputDefense, RetrievalDefense
        except Exception:
            return
        bases = (OutputDefense, IngestDefense, RetrievalDefense)
        for attr in getattr(defenses, "__all__", []):
            obj = getattr(defenses, attr, None)
            if isinstance(obj, type) and issubclass(obj, bases) and obj not in bases:
                key = self._defense_key(attr)
                self._plugins[key] = PluginInfo(
                    name=key,
                    type="defense",
                    cls=obj,
                    source="builtin",
                    version=self._version_of(obj),
                )

    def _load_entrypoints(self) -> None:
        try:
            from importlib.metadata import entry_points
        except Exception:
            return
        for group, ptype in (("hemlock.attacks", "attack"), ("hemlock.defenses", "defense")):
            try:
                eps = entry_points(group=group)
            except TypeError:  # older API returns a dict
                eps = entry_points().get(group, [])
            except Exception:
                continue
            for ep in eps:
                try:
                    cls = ep.load()
                except Exception:
                    continue
                self._plugins[ep.name] = PluginInfo(
                    name=ep.name,
                    type=ptype,
                    cls=cls,
                    source="entrypoint",
                    version=self._version_of(cls),
                )

    @staticmethod
    def _version_of(cls: type) -> str:
        return str(getattr(cls, "version", "") or getattr(cls, "__version__", "") or "builtin")

    @staticmethod
    def _defense_key(class_name: str) -> str:
        # CamelCase -> snake_case for a consistent lookup key
        out = []
        for i, ch in enumerate(class_name):
            if ch.isupper() and i > 0:
                out.append("_")
            out.append(ch.lower())
        return "".join(out)

    def attacks(self) -> dict[str, PluginInfo]:
        self._ensure()
        return {k: v for k, v in self._plugins.items() if v.type == "attack"}

    def defenses(self) -> dict[str, PluginInfo]:
        self._ensure()
        return {k: v for k, v in self._plugins.items() if v.type == "defense"}

    def get(self, name: str) -> PluginInfo | None:
        self._ensure()
        return self._plugins.get(name)

    def register(
        self,
        name: str,
        cls: type,
        *,
        type_: str,
        source: str = "manual",
    ) -> None:
        if type_ not in ("attack", "defense"):
            raise ValueError(f"type_ must be 'attack' or 'defense', got {type_!r}")
        self._plugins[name] = PluginInfo(
            name=name,
            type=type_,
            cls=cls,
            source=source,
            version=self._version_of(cls),
        )

    def to_dict(self) -> dict[str, Any]:
        self._ensure()
        return {
            "attacks": [
                {"name": p.name, "source": p.source, "version": p.version,
                 "class": p.cls.__name__}
                for p in self.attacks().values()
            ],
            "defenses": [
                {"name": p.name, "source": p.source, "version": p.version,
                 "class": p.cls.__name__}
                for p in self.defenses().values()
            ],
        }


REGISTRY = PluginRegistry()
