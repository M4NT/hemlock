"""PluginHub — discover and install community hemlock plugins (v4.2)."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class PluginInfo:
    name: str
    version: str
    description: str
    package_type: str  # "attack" | "defense" | "unknown"


def _infer_package_type(name: str, entry_groups: list[str] | None = None) -> str:
    if entry_groups:
        if "hemlock.attacks" in entry_groups:
            return "attack"
        if "hemlock.defenses" in entry_groups:
            return "defense"
    name_lower = name.lower()
    if "attack" in name_lower:
        return "attack"
    if "defense" in name_lower or "defence" in name_lower:
        return "defense"
    return "unknown"


class PluginHub:
    PYPI_SIMPLE_URL = "https://pypi.org/simple/"
    PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"

    def search(self, query: str) -> list[PluginInfo]:
        """Filter hemlock-* packages from PyPI matching query."""
        try:
            req = urllib.request.Request(
                self.PYPI_SIMPLE_URL,
                headers={"Accept": "text/html"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="replace")
        except Exception:
            return []

        # Extract all <a href="...">name</a> pairs
        names = re.findall(r'<a\s[^>]*>([^<]+)</a>', html, re.IGNORECASE)
        query_lower = query.lower()
        results = []
        for name in names:
            name = name.strip()
            if name.startswith("hemlock-") and query_lower in name.lower():
                results.append(PluginInfo(
                    name=name,
                    version="",
                    description="",
                    package_type=_infer_package_type(name),
                ))
        return results

    def install(self, package: str) -> bool:
        """pip install the package. Return True on success."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
        )
        return result.returncode == 0

    def list_installed(self) -> list[PluginInfo]:
        """List installed hemlock plugins via importlib.metadata."""
        try:
            from importlib.metadata import distributions
        except ImportError:
            return []

        results = []
        for dist in distributions():
            try:
                name = dist.metadata.get("Name", "") or ""
            except Exception:
                continue
            if not name.lower().startswith("hemlock-"):
                continue

            version = dist.metadata.get("Version", "") or ""
            description = dist.metadata.get("Summary", "") or ""

            # Check entry point groups to infer type
            try:
                ep_groups = [ep.group for ep in dist.entry_points]
            except Exception:
                ep_groups = []

            results.append(PluginInfo(
                name=name,
                version=version,
                description=description,
                package_type=_infer_package_type(name, ep_groups),
            ))
        return results

    def info(self, package: str) -> PluginInfo | None:
        """Fetch package info from PyPI JSON API."""
        url = self.PYPI_JSON_URL.format(package=package)
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            return None
        except Exception:
            return None

        info = data.get("info", {})
        name = info.get("name", package)
        version = info.get("version", "")
        description = info.get("summary", "") or ""

        return PluginInfo(
            name=name,
            version=version,
            description=description,
            package_type=_infer_package_type(name),
        )
