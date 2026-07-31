"""Tests for PluginRegistry (v4.0) and the API factory."""

from __future__ import annotations

import pytest

from hemlock.plugin_registry import PluginInfo, PluginRegistry


def test_discover_finds_builtin_attacks():
    reg = PluginRegistry()
    reg.discover()
    attacks = reg.attacks()
    assert "indirect_injection" in attacks
    assert attacks["indirect_injection"].type == "attack"
    assert attacks["indirect_injection"].source == "builtin"


def test_discover_finds_builtin_defenses():
    reg = PluginRegistry()
    reg.discover()
    defenses = reg.defenses()
    # CamelCase -> snake_case keys
    assert "injection_success_guard" in defenses
    assert defenses["injection_success_guard"].type == "defense"


def test_get_returns_plugin_info():
    reg = PluginRegistry()
    info = reg.get("indirect_injection")  # triggers lazy discover
    assert isinstance(info, PluginInfo)
    assert info.name == "indirect_injection"


def test_get_unknown_returns_none():
    reg = PluginRegistry()
    assert reg.get("does_not_exist") is None


def test_lazy_discovery_on_access():
    reg = PluginRegistry()
    assert reg._discovered is False
    _ = reg.attacks()
    assert reg._discovered is True


def test_manual_register():
    reg = PluginRegistry()
    reg.discover()

    class _MyAttack:
        pass

    reg.register("my_attack", _MyAttack, type_="attack", source="path")
    info = reg.get("my_attack")
    assert info.source == "path"
    assert info.type == "attack"
    assert "my_attack" in reg.attacks()


def test_register_rejects_bad_type():
    reg = PluginRegistry()
    with pytest.raises(ValueError):
        reg.register("x", object, type_="bogus")


def test_to_dict_shape():
    reg = PluginRegistry()
    reg.discover()
    d = reg.to_dict()
    assert "attacks" in d and "defenses" in d
    assert any(a["name"] == "indirect_injection" for a in d["attacks"])
    assert all({"name", "source", "version", "class"} <= set(a) for a in d["attacks"])


def test_defense_key_conversion():
    reg = PluginRegistry()
    assert reg._defense_key("InjectionSuccessGuard") == "injection_success_guard"
    assert reg._defense_key("ToolOutputGuard") == "tool_output_guard"


# ── API server ───────────────────────────────────────────────────────────────

def _client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from hemlock.api_server import create_app
    return TestClient(create_app())


def test_api_health():
    client = _client()
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_api_plugins_list():
    client = _client()
    resp = client.get("/plugins")
    assert resp.status_code == 200
    body = resp.json()
    assert any(a["name"] == "indirect_injection" for a in body["attacks"])


def test_api_plugin_detail_and_404():
    client = _client()
    ok = client.get("/plugins/indirect_injection")
    assert ok.status_code == 200
    assert ok.json()["type"] == "attack"

    missing = client.get("/plugins/nope")
    assert missing.status_code == 404


def test_api_eval():
    client = _client()
    resp = client.post("/eval", json={
        "attack_names": ["indirect_injection"],
        "variants_per_attack": 1,
        "model_name": "test",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["model_name"] == "test"
    assert "category_scores" in body


def test_api_threat_model():
    client = _client()
    resp = client.post("/threat-model", json={"channels": ["rag"]})
    assert resp.status_code == 200
    assert "risk_score" in resp.json()


def test_api_report_markdown():
    client = _client()
    resp = client.post("/report", json={"template": "executive", "channels": ["rag"]})
    assert resp.status_code == 200
    assert "markdown" in resp.json()


def test_api_report_bad_template():
    client = _client()
    resp = client.post("/report", json={"template": "bogus"})
    assert resp.status_code == 400
