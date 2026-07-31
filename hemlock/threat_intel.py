"""Hemlock Threat Intel Feed — CVE and advisory ingestion (v5.3).

Ingests security advisories from configurable sources and translates them
into new EvalScenario instances that can be appended to EvalBenchmark runs.

Sources (all configurable, all have offline mock fallbacks):
    - NVD JSON feed (cpe:2.3:a:*:llm*)
    - HuggingFace security advisories (GHSA format)
    - Local advisory files (JSON)

Usage:
    from hemlock.threat_intel import ThreatIntelFeed, FeedConfig

    feed = ThreatIntelFeed(config=FeedConfig(use_mock=True))
    advisories = feed.fetch()

    for adv in advisories:
        print(adv.cve_id, adv.title, adv.attack_category)

    scenarios = feed.to_scenarios()
    # append to EvalBenchmark.scenarios and re-run
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Advisory:
    cve_id: str
    title: str
    description: str
    attack_category: str         # maps to hemlock attack category
    severity: str                # critical/high/medium/low
    source: str
    published: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "attack_category": self.attack_category,
            "severity": self.severity,
            "source": self.source,
            "published": self.published,
            "references": self.references,
        }


@dataclass
class FeedConfig:
    use_mock: bool = True
    nvd_feed_url: str = ""
    local_advisory_path: str = ""
    cache_path: str = ".hemlock/threat_intel_cache.json"


_MOCK_ADVISORIES: list[dict] = [
    {
        "cve_id": "CVE-2024-38366",
        "title": "Indirect Prompt Injection via RAG document corpus",
        "description": "An attacker who can write documents to a RAG corpus can inject instructions that override the LLM's system prompt by exploiting retrieval ranking.",
        "attack_category": "injection",
        "severity": "high",
        "source": "mock-nvd",
        "published": "2024-06-01",
        "references": ["https://arxiv.org/abs/2302.12173"],
    },
    {
        "cve_id": "CVE-2024-41110",
        "title": "Tool call hijack via poisoned tool response",
        "description": "Attacker-controlled tool responses can inject instructions that cause the agent to invoke additional tools with attacker-controlled parameters.",
        "attack_category": "agent",
        "severity": "critical",
        "source": "mock-ghsa",
        "published": "2024-07-15",
        "references": ["https://arxiv.org/abs/2406.13352"],
    },
    {
        "cve_id": "CVE-2024-42337",
        "title": "Memory poisoning via session persistence",
        "description": "Malicious instructions stored in persistent memory survive session boundaries and affect future queries without re-retrieval.",
        "attack_category": "poisoning",
        "severity": "high",
        "source": "mock-nvd",
        "published": "2024-08-03",
        "references": [],
    },
    {
        "cve_id": "CVE-2024-44117",
        "title": "Exfiltration via context leak in multi-tenant RAG",
        "description": "Cross-tenant document bleed allows one tenant's queries to surface another tenant's sensitive documents via embedding collision.",
        "attack_category": "exfiltration",
        "severity": "critical",
        "source": "mock-ghsa",
        "published": "2024-09-10",
        "references": ["https://arxiv.org/abs/2402.07867"],
    },
    {
        "cve_id": "CVE-2024-45891",
        "title": "Authority spoofing via falsified system configuration documents",
        "description": "Documents claiming to be authoritative system configuration can override the model's behavioral constraints.",
        "attack_category": "override",
        "severity": "medium",
        "source": "mock-nvd",
        "published": "2024-10-22",
        "references": ["https://arxiv.org/abs/2311.16119"],
    },
]


class ThreatIntelFeed:
    def __init__(self, config: FeedConfig | None = None) -> None:
        self.config = config or FeedConfig()
        self._advisories: list[Advisory] = []

    def fetch(self) -> list[Advisory]:
        if self.config.use_mock:
            self._advisories = [Advisory(**d) for d in _MOCK_ADVISORIES]
            return self._advisories

        advisories: list[Advisory] = []

        if self.config.local_advisory_path:
            advisories.extend(self._load_local())

        if self.config.nvd_feed_url:
            advisories.extend(self._fetch_nvd())

        self._advisories = advisories
        self._cache(advisories)
        return advisories

    def _load_local(self) -> list[Advisory]:
        import os

        if not os.path.exists(self.config.local_advisory_path):
            return []
        try:
            with open(self.config.local_advisory_path, encoding="utf-8") as f:
                data = json.load(f)
            return [Advisory(**d) for d in data]
        except Exception:
            return []

    def _fetch_nvd(self) -> list[Advisory]:
        try:
            import urllib.request

            with urllib.request.urlopen(self.config.nvd_feed_url, timeout=10) as resp:
                data = json.loads(resp.read())
            advisories = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                advisories.append(Advisory(
                    cve_id=cve.get("id", ""),
                    title=cve.get("descriptions", [{}])[0].get("value", "")[:80],
                    description=cve.get("descriptions", [{}])[0].get("value", ""),
                    attack_category="injection",
                    severity=cve.get("metrics", {}).get("severity", "medium").lower(),
                    source="nvd",
                    published=cve.get("published", ""),
                ))
            return advisories
        except Exception:
            return []

    def _cache(self, advisories: list[Advisory]) -> None:
        import os

        os.makedirs(os.path.dirname(self.config.cache_path) or ".", exist_ok=True)
        with open(self.config.cache_path, "w", encoding="utf-8") as f:
            json.dump([a.to_dict() for a in advisories], f, indent=2)

    def to_scenarios(self) -> list[Any]:
        from hemlock.eval_benchmark import EvalScenario

        scenarios = []
        for adv in self._advisories:
            scenarios.append(EvalScenario(
                attack_name=adv.cve_id,
                variant="intel",
                category=adv.attack_category,
                succeeded=False,
                notes=f"[ThreatIntel] {adv.title} [{adv.source}]",
            ))
        return scenarios

    def filter_severity(self, severity: str) -> list[Advisory]:
        return [a for a in self._advisories if a.severity == severity]

    def filter_category(self, category: str) -> list[Advisory]:
        return [a for a in self._advisories if a.attack_category == category]
