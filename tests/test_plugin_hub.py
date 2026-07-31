"""Tests for hemlock.plugin_hub — all network and subprocess calls are mocked."""

from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from hemlock.plugin_hub import PluginHub, PluginInfo, _infer_package_type


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_HTML = b"""
<html><body>
<a href="/simple/hemlock-attack-injection/">hemlock-attack-injection</a>
<a href="/simple/hemlock-defense-sanitize/">hemlock-defense-sanitize</a>
<a href="/simple/hemlock-attack-prompt/">hemlock-attack-prompt</a>
<a href="/simple/requests/">requests</a>
</body></html>
"""

PYPI_JSON_RESPONSE = {
    "info": {
        "name": "hemlock-attack-injection",
        "version": "1.2.0",
        "summary": "Injection attack plugin for hemlock.",
    }
}


def _make_urlopen_response(content: bytes, status: int = 200):
    """Return a context-manager mock that mimics urlopen response."""
    resp = MagicMock()
    resp.read.return_value = content
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# search()
# ---------------------------------------------------------------------------

class TestSearch:
    def test_returns_hemlock_packages(self):
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(SIMPLE_HTML)):
            results = hub.search("hemlock")
        names = [r.name for r in results]
        assert "hemlock-attack-injection" in names
        assert "hemlock-defense-sanitize" in names
        assert "hemlock-attack-prompt" in names

    def test_filters_by_query(self):
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(SIMPLE_HTML)):
            results = hub.search("injection")
        names = [r.name for r in results]
        assert names == ["hemlock-attack-injection"]

    def test_returns_empty_when_no_hemlock_packages(self):
        html = b"<a href='/simple/requests/'>requests</a>"
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(html)):
            results = hub.search("anything")
        assert results == []

    def test_handles_network_error_gracefully(self):
        hub = PluginHub()
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            results = hub.search("injection")
        assert results == []

    def test_parses_anchor_tags_correctly(self):
        html = b"<a href='/simple/hemlock-foo/'>hemlock-foo</a>\n<a href='/simple/hemlock-bar/'>hemlock-bar</a>"
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(html)):
            results = hub.search("hemlock")
        assert len(results) == 2
        assert all(isinstance(r, PluginInfo) for r in results)

    def test_excludes_non_hemlock_packages(self):
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(SIMPLE_HTML)):
            results = hub.search("")
        names = [r.name for r in results]
        assert "requests" not in names


# ---------------------------------------------------------------------------
# install()
# ---------------------------------------------------------------------------

class TestInstall:
    def test_returns_true_on_success(self):
        hub = PluginHub()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            assert hub.install("hemlock-attack-injection") is True

    def test_returns_false_on_failure(self):
        hub = PluginHub()
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("subprocess.run", return_value=mock_result):
            assert hub.install("hemlock-nonexistent") is False

    def test_calls_pip_install(self):
        hub = PluginHub()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            hub.install("hemlock-attack-injection")
        args = mock_run.call_args[0][0]
        assert "-m" in args
        assert "pip" in args
        assert "install" in args
        assert "hemlock-attack-injection" in args


# ---------------------------------------------------------------------------
# list_installed()
# ---------------------------------------------------------------------------

class TestListInstalled:
    def _make_dist(self, name: str, version: str = "1.0.0", summary: str = "", ep_groups: list[str] | None = None):
        dist = MagicMock()
        dist.metadata = {"Name": name, "Version": version, "Summary": summary}
        if ep_groups is not None:
            eps = [MagicMock(group=g) for g in ep_groups]
        else:
            eps = []
        dist.entry_points = eps
        return dist

    def test_returns_installed_hemlock_packages(self):
        dists = [
            self._make_dist("hemlock-attack-injection", "1.0.0", "Injection attacks."),
            self._make_dist("hemlock-defense-sanitize", "2.0.0", "Sanitize defense."),
            self._make_dist("requests", "2.28.0", "HTTP library."),
        ]
        hub = PluginHub()
        with patch("importlib.metadata.distributions", return_value=dists):
            results = hub.list_installed()
        names = [r.name for r in results]
        assert "hemlock-attack-injection" in names
        assert "hemlock-defense-sanitize" in names
        assert "requests" not in names

    def test_returns_empty_when_none_installed(self):
        dists = [
            self._make_dist("requests", "2.28.0"),
            self._make_dist("typer", "0.9.0"),
        ]
        hub = PluginHub()
        with patch("importlib.metadata.distributions", return_value=dists):
            results = hub.list_installed()
        assert results == []

    def test_uses_entry_points_for_type_inference(self):
        dists = [
            self._make_dist("hemlock-myplugin", "1.0", ep_groups=["hemlock.attacks"]),
        ]
        hub = PluginHub()
        with patch("importlib.metadata.distributions", return_value=dists):
            results = hub.list_installed()
        assert results[0].package_type == "attack"

    def test_defense_entry_point(self):
        dists = [
            self._make_dist("hemlock-myplugin", "1.0", ep_groups=["hemlock.defenses"]),
        ]
        hub = PluginHub()
        with patch("importlib.metadata.distributions", return_value=dists):
            results = hub.list_installed()
        assert results[0].package_type == "defense"


# ---------------------------------------------------------------------------
# info()
# ---------------------------------------------------------------------------

class TestInfo:
    def test_returns_plugin_info_on_success(self):
        payload = json.dumps(PYPI_JSON_RESPONSE).encode()
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(payload)):
            result = hub.info("hemlock-attack-injection")
        assert result is not None
        assert result.name == "hemlock-attack-injection"
        assert result.version == "1.2.0"
        assert result.description == "Injection attack plugin for hemlock."

    def test_returns_none_on_404(self):
        hub = PluginHub()
        http_err = urllib.error.HTTPError(
            url="https://pypi.org/pypi/hemlock-missing/json",
            code=404,
            msg="Not Found",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            result = hub.info("hemlock-missing")
        assert result is None

    def test_infers_type_attack_from_name(self):
        payload = json.dumps({
            "info": {"name": "hemlock-attack-sqli", "version": "0.1.0", "summary": "SQL injection."}
        }).encode()
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(payload)):
            result = hub.info("hemlock-attack-sqli")
        assert result is not None
        assert result.package_type == "attack"

    def test_infers_type_defense_from_name(self):
        payload = json.dumps({
            "info": {"name": "hemlock-defense-guard", "version": "0.1.0", "summary": "Guard."}
        }).encode()
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(payload)):
            result = hub.info("hemlock-defense-guard")
        assert result is not None
        assert result.package_type == "defense"

    def test_infers_unknown_type_when_ambiguous(self):
        payload = json.dumps({
            "info": {"name": "hemlock-utils", "version": "0.1.0", "summary": "Utilities."}
        }).encode()
        hub = PluginHub()
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(payload)):
            result = hub.info("hemlock-utils")
        assert result is not None
        assert result.package_type == "unknown"

    def test_handles_generic_network_error(self):
        hub = PluginHub()
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = hub.info("hemlock-attack-injection")
        assert result is None


# ---------------------------------------------------------------------------
# _infer_package_type helper
# ---------------------------------------------------------------------------

class TestInferPackageType:
    def test_attack_from_entry_points(self):
        assert _infer_package_type("hemlock-foo", ["hemlock.attacks"]) == "attack"

    def test_defense_from_entry_points(self):
        assert _infer_package_type("hemlock-foo", ["hemlock.defenses"]) == "defense"

    def test_attack_from_name(self):
        assert _infer_package_type("hemlock-attack-xss") == "attack"

    def test_defense_from_name(self):
        assert _infer_package_type("hemlock-defense-rate-limit") == "defense"

    def test_unknown_when_no_signal(self):
        assert _infer_package_type("hemlock-utils") == "unknown"
