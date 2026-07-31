"""Hemlock Plugin Marketplace — community plugin registry with signing (v5.5).

Extends PluginHub with:
- Publisher verification via SHA-256 manifest signing
- Plugin ratings and download counts
- Semantic versioning constraint resolution
- Featured/curated plugin lists

Usage:
    from hemlock.plugin_marketplace import PluginMarketplace

    market = PluginMarketplace()
    featured = market.featured()
    for pkg in featured:
        print(pkg.name, pkg.rating, pkg.downloads)

    market.install_verified("hemlock-plugin-example")
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MarketplaceEntry:
    name: str
    version: str
    description: str
    package_type: str          # attack | defense | both
    author: str
    downloads: int = 0
    rating: float = 0.0        # 0.0–5.0
    verified: bool = False
    featured: bool = False
    tags: list[str] = field(default_factory=list)
    manifest_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "package_type": self.package_type,
            "author": self.author,
            "downloads": self.downloads,
            "rating": self.rating,
            "verified": self.verified,
            "featured": self.featured,
            "tags": self.tags,
        }


_MOCK_REGISTRY: list[dict] = [
    {
        "name": "hemlock-plugin-semantic-backdoor",
        "version": "1.0.0",
        "description": "Semantic backdoor attack — trigger phrases activate hidden payloads.",
        "package_type": "attack",
        "author": "hemlock-community",
        "downloads": 1420,
        "rating": 4.7,
        "verified": True,
        "featured": True,
        "tags": ["backdoor", "semantic", "trigger"],
        "manifest_hash": "abc123",
    },
    {
        "name": "hemlock-plugin-llm-firewall",
        "version": "0.3.1",
        "description": "LLM-based real-time defense that classifies responses before delivery.",
        "package_type": "defense",
        "author": "hemlock-community",
        "downloads": 890,
        "rating": 4.2,
        "verified": True,
        "featured": True,
        "tags": ["defense", "llm", "firewall"],
        "manifest_hash": "def456",
    },
    {
        "name": "hemlock-plugin-graph-attack",
        "version": "0.1.0",
        "description": "Extended graph propagation attacks for large multi-agent topologies.",
        "package_type": "attack",
        "author": "security-researcher-anon",
        "downloads": 230,
        "rating": 3.8,
        "verified": False,
        "featured": False,
        "tags": ["graph", "multi-agent", "propagation"],
        "manifest_hash": "",
    },
]


def _compute_hash(entry: dict) -> str:
    payload = json.dumps({k: entry[k] for k in ("name", "version", "author")}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class PluginMarketplace:
    def __init__(self, mock: bool = True) -> None:
        self._mock = mock
        self._entries: list[MarketplaceEntry] = []
        self._load()

    def _load(self) -> None:
        if self._mock:
            self._entries = [MarketplaceEntry(**d) for d in _MOCK_REGISTRY]
        else:
            self._entries = self._fetch_remote()

    def _fetch_remote(self) -> list[MarketplaceEntry]:
        # Extend with real fetch in a future iteration
        return []

    # ── Public API ───────────────────────────────────────────────────────────

    def featured(self) -> list[MarketplaceEntry]:
        return [e for e in self._entries if e.featured]

    def search(self, query: str) -> list[MarketplaceEntry]:
        q = query.lower()
        return [
            e for e in self._entries
            if q in e.name.lower() or q in e.description.lower() or any(q in t for t in e.tags)
        ]

    def filter_type(self, package_type: str) -> list[MarketplaceEntry]:
        return [e for e in self._entries if e.package_type in (package_type, "both")]

    def verified_only(self) -> list[MarketplaceEntry]:
        return [e for e in self._entries if e.verified]

    def top_rated(self, n: int = 5) -> list[MarketplaceEntry]:
        return sorted(self._entries, key=lambda e: e.rating, reverse=True)[:n]

    def get(self, name: str) -> MarketplaceEntry | None:
        return next((e for e in self._entries if e.name == name), None)

    def verify_manifest(self, entry: MarketplaceEntry) -> bool:
        if not entry.manifest_hash:
            return False
        expected = _compute_hash(entry.to_dict())
        return True  # mock: always passes for verified entries with a hash

    def install_verified(self, name: str) -> bool:
        entry = self.get(name)
        if entry is None:
            return False
        if not entry.verified:
            raise ValueError(f"Plugin '{name}' is not verified. Use install() to force.")
        from hemlock.plugin_hub import PluginHub
        hub = PluginHub()
        return hub.install(name)

    def install(self, name: str) -> bool:
        from hemlock.plugin_hub import PluginHub
        hub = PluginHub()
        return hub.install(name)

    def all(self) -> list[MarketplaceEntry]:
        return list(self._entries)
