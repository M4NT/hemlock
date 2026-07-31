"""Hemlock v4.1 Web Dashboard — build_dashboard_html + FastAPI router."""

from __future__ import annotations

import json
import os
from typing import Any


def build_dashboard_html(history: list[dict]) -> str:
    """Return a self-contained HTML dashboard page."""

    # --- derive summary data from history ---
    last = history[-1] if history else {}

    # overall risk score (0-100)
    risk_score: float = 0.0
    if last:
        risk_score = float(last.get("risk_score", last.get("score", 0)) or 0)
    risk_score = max(0.0, min(100.0, risk_score))

    # per-channel breakdown
    channels: dict[str, str] = {}
    if last:
        raw_channels = last.get("channels", last.get("channel_scores", {})) or {}
        if isinstance(raw_channels, dict):
            for ch, val in raw_channels.items():
                if isinstance(val, dict):
                    channels[ch] = str(val.get("severity", val.get("worst_severity", "unknown")))
                else:
                    channels[ch] = str(val)

    # succeeded attacks
    succeeded: list[str] = []
    if last:
        succeeded = list(last.get("succeeded_attacks", last.get("attacks_succeeded", [])) or [])

    # history rows (last 20)
    history_rows = history[-20:]

    # --- build HTML ---
    channel_rows_html = ""
    for ch, sev in channels.items():
        sev_lower = sev.lower()
        color = "#ef4444" if sev_lower == "critical" else (
            "#f97316" if sev_lower == "high" else (
            "#eab308" if sev_lower == "medium" else (
            "#22c55e" if sev_lower == "low" else "#6b7280")))
        channel_rows_html += (
            f'<tr><td style="padding:6px 12px">{_esc(ch)}</td>'
            f'<td style="padding:6px 12px"><span style="color:{color};font-weight:600">'
            f'{_esc(sev)}</span></td></tr>\n'
        )
    if not channel_rows_html:
        channel_rows_html = '<tr><td colspan="2" style="padding:6px 12px;color:#6b7280">No channel data</td></tr>'

    succeeded_html = ""
    for atk in succeeded:
        succeeded_html += f'<li style="margin:4px 0">{_esc(str(atk))}</li>'
    if not succeeded_html:
        succeeded_html = '<li style="color:#6b7280">None</li>'

    history_rows_html = ""
    for entry in history_rows:
        ts = _esc(str(entry.get("timestamp", entry.get("ts", "—"))))
        score = _esc(str(entry.get("risk_score", entry.get("score", "—"))))
        n_succ = _esc(str(len(entry.get("succeeded_attacks", entry.get("attacks_succeeded", [])) or [])))
        history_rows_html += (
            f'<tr><td style="padding:4px 10px">{ts}</td>'
            f'<td style="padding:4px 10px;text-align:center">{score}</td>'
            f'<td style="padding:4px 10px;text-align:center">{n_succ}</td></tr>\n'
        )
    if not history_rows_html:
        history_rows_html = '<tr><td colspan="3" style="padding:6px 12px;color:#6b7280">No history</td></tr>'

    # gauge: remaining slice = 100 - risk_score
    remaining = 100.0 - risk_score
    gauge_color = (
        "#ef4444" if risk_score >= 75 else
        "#f97316" if risk_score >= 50 else
        "#eab308" if risk_score >= 25 else
        "#22c55e"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Hemlock Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:32px 24px}}
  h1{{font-size:1.6rem;font-weight:700;color:#f8fafc;margin-bottom:24px}}
  h2{{font-size:1.1rem;font-weight:600;color:#cbd5e1;margin-bottom:12px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}}
  .card{{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}}
  .gauge-wrap{{display:flex;flex-direction:column;align-items:center}}
  .gauge-label{{font-size:2rem;font-weight:700;margin-top:-56px;color:{gauge_color}}}
  .gauge-sub{{font-size:.85rem;color:#94a3b8;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.9rem}}
  thead th{{text-align:left;padding:6px 12px;color:#94a3b8;border-bottom:1px solid #334155;font-weight:500}}
  tbody tr:hover{{background:#273549}}
  ul{{list-style:none;padding:0}}
</style>
</head>
<body>
<h1>Hemlock AI Security Dashboard</h1>
<div class="grid">
  <!-- Gauge -->
  <div class="card">
    <h2>Overall Risk Score</h2>
    <div class="gauge-wrap">
      <canvas id="gaugeChart" width="220" height="220" aria-label="Risk score gauge"></canvas>
      <div class="gauge-label">{risk_score:.0f}</div>
      <div class="gauge-sub">/ 100</div>
    </div>
  </div>

  <!-- Per-channel breakdown -->
  <div class="card">
    <h2>Channel Breakdown</h2>
    <table id="channelTable">
      <thead><tr><th>Channel</th><th>Worst Severity</th></tr></thead>
      <tbody>
{channel_rows_html}
      </tbody>
    </table>
  </div>

  <!-- Succeeded attacks -->
  <div class="card">
    <h2>Succeeded Attacks</h2>
    <ul id="succeededList">
{succeeded_html}
    </ul>
  </div>

  <!-- History -->
  <div class="card" style="grid-column:1/-1">
    <h2>Assessment History (last {len(history_rows)} entries)</h2>
    <table id="historyTable">
      <thead><tr><th>Timestamp</th><th style="text-align:center">Risk Score</th><th style="text-align:center">Successes</th></tr></thead>
      <tbody>
{history_rows_html}
      </tbody>
    </table>
  </div>
</div>

<script>
(function(){{
  var ctx = document.getElementById('gaugeChart').getContext('2d');
  new Chart(ctx, {{
    type: 'doughnut',
    data: {{
      datasets: [{{
        data: [{risk_score:.4f}, {remaining:.4f}],
        backgroundColor: ['{gauge_color}', '#334155'],
        borderWidth: 0,
        circumference: 270,
        rotation: 225,
      }}]
    }},
    options: {{
      cutout: '75%',
      plugins: {{legend: {{display: false}}, tooltip: {{enabled: false}}}},
      animation: {{duration: 800}}
    }}
  }});
}})();
</script>
</body>
</html>"""
    return html


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def get_dashboard_router():
    """Return a FastAPI APIRouter with GET /dashboard."""
    try:
        from fastapi import APIRouter
        from fastapi.responses import HTMLResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "FastAPI is required for the dashboard router.\n"
            "Install with: pip install 'hemlock-rag[api]'"
        ) from exc

    router = APIRouter()

    @router.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        """Serve the Hemlock web dashboard."""
        path = "watch_history.json"
        history: list[dict] = []
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    history = data
            except (json.JSONDecodeError, OSError):
                pass
        return HTMLResponse(content=build_dashboard_html(history))

    return router
