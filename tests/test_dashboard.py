"""Tests for hemlock.dashboard (v4.1) — build_dashboard_html + API endpoints."""

from __future__ import annotations

import json
from unittest.mock import mock_open, patch

import pytest


# ---------------------------------------------------------------------------
# build_dashboard_html — unit tests
# ---------------------------------------------------------------------------

from hemlock.dashboard import build_dashboard_html


def test_returns_string_empty_history():
    result = build_dashboard_html([])
    assert isinstance(result, str)


def test_returns_string_with_history():
    history = [{"risk_score": 42, "timestamp": "2024-01-01T00:00:00"}]
    result = build_dashboard_html(history)
    assert isinstance(result, str)


def test_contains_chartjs_cdn():
    html = build_dashboard_html([])
    assert "https://cdn.jsdelivr.net/npm/chart.js" in html


def test_contains_canvas_tag():
    html = build_dashboard_html([])
    assert "<canvas" in html
    assert "gaugeChart" in html


def test_contains_channel_table():
    html = build_dashboard_html([])
    assert "channelTable" in html
    assert "<table" in html


def test_contains_history_table():
    html = build_dashboard_html([])
    assert "historyTable" in html


def test_contains_succeeded_list():
    html = build_dashboard_html([])
    assert "succeededList" in html


def test_risk_score_rendered_in_gauge():
    history = [{"risk_score": 77}]
    html = build_dashboard_html(history)
    assert "77" in html


def test_channel_data_rendered():
    history = [{"risk_score": 30, "channels": {"rag": {"severity": "high"}, "api": {"severity": "low"}}}]
    html = build_dashboard_html(history)
    assert "rag" in html
    assert "high" in html
    assert "api" in html
    assert "low" in html


def test_succeeded_attacks_rendered():
    history = [{"risk_score": 50, "succeeded_attacks": ["prompt_injection", "data_exfil"]}]
    html = build_dashboard_html(history)
    assert "prompt_injection" in html
    assert "data_exfil" in html


def test_empty_history_shows_no_history_placeholder():
    html = build_dashboard_html([])
    assert "No history" in html


def test_empty_channels_shows_placeholder():
    html = build_dashboard_html([{"risk_score": 10}])
    assert "No channel data" in html


def test_risk_score_clamped_above_100():
    html = build_dashboard_html([{"risk_score": 999}])
    # should render 100, not 999
    assert "100" in html


def test_risk_score_clamped_below_0():
    html = build_dashboard_html([{"risk_score": -50}])
    assert "0" in html


def test_html_escaping_in_channel_names():
    history = [{"risk_score": 10, "channels": {"<script>alert(1)</script>": {"severity": "low"}}}]
    html = build_dashboard_html(history)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_history_limited_to_last_20():
    history = [{"risk_score": i, "timestamp": f"2024-01-{i:02d}"} for i in range(1, 30)]
    html = build_dashboard_html(history)
    # The caption says "last 20 entries"
    assert "last 20 entries" in html


def test_doughnut_chart_type_in_js():
    html = build_dashboard_html([])
    assert "doughnut" in html


# ---------------------------------------------------------------------------
# FastAPI endpoint tests — /dashboard and /history
# ---------------------------------------------------------------------------


def _get_test_client():
    """Create a TestClient for the Hemlock API app, skipping if deps missing."""
    try:
        from fastapi.testclient import TestClient
        from hemlock.api_server import create_app
        return TestClient(create_app())
    except ImportError as exc:
        pytest.skip(f"FastAPI/httpx not installed: {exc}")


def test_dashboard_endpoint_returns_200():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/dashboard")
    assert resp.status_code == 200


def test_dashboard_endpoint_content_type_html():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/dashboard")
    assert "text/html" in resp.headers.get("content-type", "")


def test_dashboard_endpoint_body_contains_chartjs():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/dashboard")
    assert "chart.js" in resp.text.lower()


def test_dashboard_endpoint_with_history_file(tmp_path):
    history_data = [{"risk_score": 55, "timestamp": "2024-06-01"}]
    history_file = tmp_path / "watch_history.json"
    history_file.write_text(json.dumps(history_data), encoding="utf-8")

    client = _get_test_client()
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=json.dumps(history_data))):
        resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "55" in resp.text


def test_history_endpoint_returns_200():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/history")
    assert resp.status_code == 200


def test_history_endpoint_returns_json_with_history_key():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/history")
    data = resp.json()
    assert "history" in data
    assert isinstance(data["history"], list)


def test_history_endpoint_empty_when_no_file():
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/history")
    assert resp.json() == {"history": []}


def test_history_endpoint_returns_file_contents():
    payload = [{"risk_score": 80, "timestamp": "2024-07-01"}]
    client = _get_test_client()
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=json.dumps(payload))):
        resp = client.get("/history")
    assert resp.json() == {"history": payload}


def test_history_endpoint_handles_corrupt_file():
    client = _get_test_client()
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="NOT JSON {{{")):
        resp = client.get("/history")
    assert resp.status_code == 200
    assert resp.json() == {"history": []}


def test_watch_history_endpoint_still_works():
    """Ensure the original /watch/history endpoint wasn't broken."""
    client = _get_test_client()
    with patch("os.path.exists", return_value=False):
        resp = client.get("/watch/history")
    assert resp.status_code == 200
    assert "history" in resp.json()
