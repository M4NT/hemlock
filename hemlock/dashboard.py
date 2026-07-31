"""Hemlock v4.1 Web Dashboard — build_dashboard_html + FastAPI router.

v8.1: operational dashboard integrates orchestrator runs, finding lifecycle,
model inventory, and latest executive report summary.
"""

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


def build_operational_dashboard_html(
    history: list[dict],
    operational: dict[str, Any] | None = None,
) -> str:
    """Build dashboard HTML with v8.1 operational sections."""
    base = build_dashboard_html(history)
    if not operational:
        return base

    ops = operational
    latest = ops.get("latest_run", {}) or {}
    sev = ops.get("open_by_severity", {})
    inv = ops.get("inventory_summary", {})
    exec_sum = ops.get("executive_summary", {})
    trend = ops.get("trend_series", {})
    org = ops.get("org_summary", {})
    hemlock_score = ops.get("hemlock_score")
    hemlock_grade = ops.get("hemlock_grade", "")
    hemlock_trend = ops.get("hemlock_score_trend", {})
    new_techniques = ops.get("new_attack_techniques", [])

    score_color = "#22c55e" if (hemlock_score or 0) >= 70 else "#f59e0b" if (hemlock_score or 0) >= 50 else "#ef4444"
    score_display = f"{hemlock_score:.0f}" if hemlock_score is not None else "—"
    grade_display = hemlock_grade or "—"

    hemlock_trend_arrow = {"improving": "↑", "degrading": "↓", "stable": "→"}.get(
        hemlock_trend.get("trend", "stable"), "→"
    )
    hs_labels = [p.get("timestamp", "")[:10] for p in hemlock_trend.get("points", [])]
    hs_scores = [p.get("hemlock_score", 0) for p in hemlock_trend.get("points", [])]
    hs_labels_js = json.dumps(hs_labels)
    hs_scores_js = json.dumps(hs_scores)

    technique_rows = ""
    for t in new_techniques[:8]:
        technique_rows += (
            f'<tr><td style="padding:4px 10px;font-size:.85rem">{_esc(str(t.get("label", "—")))}</td>'
            f'<td style="padding:4px 10px">{_esc(str(t.get("severity", t.get("source", "—")))}</td></tr>\n'
        )
    if not technique_rows:
        technique_rows = (
            '<tr><td colspan="2" style="padding:6px;color:#6b7280">'
            'No new techniques — run <code>hemlock orchestrate</code></td></tr>'
        )
    trend_arrow = {"improving": "↓", "degrading": "↑", "stable": "→"}.get(
        trend.get("trend", "stable"), "→"
    )
    trend_labels = [p.get("timestamp", "")[:10] for p in trend.get("points", [])]
    trend_scores = [p.get("risk_score", 0) for p in trend.get("points", [])]
    trend_labels_js = json.dumps(trend_labels)
    trend_scores_js = json.dumps(trend_scores)

    runs_rows = ""
    for r in ops.get("orchestrator_runs", [])[-10:]:
        name = _esc(str(r.get("schedule_name", "—")))
        risk = _esc(str(r.get("risk_score", "—")))
        ok = "✓" if r.get("baseline_compliant", True) else "✗"
        status = "OK" if r.get("success", True) else "FAIL"
        ts = _esc(str(r.get("finished_at", "—"))[:19])
        runs_rows += (
            f'<tr><td style="padding:4px 10px">{ts}</td>'
            f'<td style="padding:4px 10px">{name}</td>'
            f'<td style="padding:4px 10px;text-align:center">{risk}</td>'
            f'<td style="padding:4px 10px;text-align:center">{ok}</td>'
            f'<td style="padding:4px 10px">{status}</td></tr>\n'
        )
    if not runs_rows:
        runs_rows = '<tr><td colspan="5" style="padding:6px;color:#6b7280">No orchestrator runs yet — run <code>hemlock orchestrate</code></td></tr>'

    findings_rows = ""
    for f in ops.get("open_findings", []):
        findings_rows += (
            f'<tr><td style="padding:4px 10px">{_esc(str(f.get("finding_id", "—")))}</td>'
            f'<td style="padding:4px 10px">{_esc(str(f.get("severity", "—")))}</td>'
            f'<td style="padding:4px 10px">{_esc(str(f.get("channel", "—")))}</td>'
            f'<td style="padding:4px 10px">{_esc(str(f.get("state", "open")))}</td></tr>\n'
        )
    if not findings_rows:
        findings_rows = '<tr><td colspan="4" style="padding:6px;color:#6b7280">No open findings</td></tr>'

    model_rows = ""
    for m in inv.get("models", []):
        risk_val = m.get("latest_risk_score", m.get("risk_score", "-"))
        cov_val = m.get("coverage_pct", "-")
        model_rows += (
            f'<tr><td style="padding:4px 10px">{_esc(str(m.get("model_id", "-")))}</td>'
            f'<td style="padding:4px 10px;text-align:center">{_esc(str(risk_val))}</td>'
            f'<td style="padding:4px 10px;text-align:center">{_esc(str(cov_val))}</td></tr>\n'
        )
    if not model_rows:
        model_rows = '<tr><td colspan="3" style="padding:6px;color:#6b7280">No models in inventory</td></tr>'

    sla_pct = exec_sum.get("sla_compliance")
    sla_display = f"{round(float(sla_pct) * 100, 1)}%" if sla_pct is not None else "—"
    block = exec_sum.get("block_rate")
    block_display = f"{round(float(block) * 100, 1)}%" if block is not None else "—"

    org_rows = ""
    for p in org.get("projects", [])[:15]:
        org_rows += (
            f'<tr><td style="padding:4px 10px">{_esc(str(p.get("team_name", "-")))}</td>'
            f'<td style="padding:4px 10px">{_esc(str(p.get("project_name", "-")))}</td>'
            f'<td style="padding:4px 10px;text-align:center">{p.get("risk_score", 0):.1f}</td>'
            f'<td style="padding:4px 10px">{_esc(str(p.get("status", "-")))}</td>'
            f'<td style="padding:4px 10px;text-align:center">{p.get("open_findings", 0)}</td></tr>\n'
        )
    if not org_rows:
        org_rows = (
            '<tr><td colspan="5" style="padding:6px;color:#6b7280">'
            'No tenants — run <code>hemlock tenant create-team</code></td></tr>'
        )

    extra = f"""
<div class="grid" style="margin-top:20px">
  <div class="card" style="grid-column:span 1">
    <h2>Hemlock Score</h2>
    <p style="font-size:2.5rem;font-weight:700;color:{score_color};margin:8px 0">
      {score_display} <span style="font-size:1.2rem;color:#94a3b8">{grade_display}</span>
    </p>
    <p style="font-size:.85rem;color:#94a3b8">
      Pipeline-native security metric (higher = safer). Run <code>hemlock score-pipeline</code>.
    </p>
  </div>
  <div class="card" style="grid-column:span 2">
    <h2>Hemlock Score Trend {hemlock_trend_arrow} {_esc(str(hemlock_trend.get("trend", "stable")))}</h2>
    <p style="font-size:.85rem;color:#94a3b8;margin-bottom:8px">
      Current: {hemlock_trend.get("current", "—")} · Min: {hemlock_trend.get("min", "—")} · Max: {hemlock_trend.get("max", "—")}
    </p>
    <canvas id="hemlockScoreChart" height="80" aria-label="Hemlock score trend chart"></canvas>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>New Attack Techniques</h2>
    <table><thead><tr><th>Advisory / CVE</th><th>Severity / Source</th></tr></thead><tbody>{technique_rows}</tbody></table>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>Risk Trend {trend_arrow} {_esc(str(trend.get("trend", "stable")))}</h2>
    <p style="font-size:.85rem;color:#94a3b8;margin-bottom:8px">
      Current: {trend.get("current", 0):.1f} · Min: {trend.get("min", 0):.1f} · Max: {trend.get("max", 0):.1f}
    </p>
    <canvas id="trendChart" height="80" aria-label="Risk trend chart"></canvas>
  </div>
  <div class="card">
    <h2>Latest Orchestrator Run</h2>
    <p style="font-size:.9rem;color:#94a3b8;margin-bottom:8px">
      Schedule: <strong style="color:#e2e8f0">{_esc(str(latest.get("schedule_name", "—")))}</strong>
    </p>
    <table><tbody>
      <tr><td style="padding:4px 0;color:#94a3b8">Risk</td><td style="padding:4px 0">{_esc(str(latest.get("risk_score", "—")))}</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">Hemlock Score</td><td style="padding:4px 0">{_esc(str(latest.get("hemlock_score", "—")))} ({_esc(str(latest.get("hemlock_grade", "—")))})</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">Baseline</td><td style="padding:4px 0">{"compliant" if latest.get("baseline_compliant", True) else "VIOLATION"}</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">SLA violations</td><td style="padding:4px 0">{_esc(str(latest.get("sla_violations", 0)))}</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">Executive report</td><td style="padding:4px 0;font-size:.8rem">{_esc(str(latest.get("executive_report_path", "—")))}</td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <h2>Open Findings ({ops.get("open_findings_count", 0)})</h2>
    <p style="font-size:.85rem;color:#94a3b8;margin-bottom:8px">
      critical: {sev.get("critical", 0)} · high: {sev.get("high", 0)} · medium: {sev.get("medium", 0)} · low: {sev.get("low", 0)}
    </p>
    <table><thead><tr><th>ID</th><th>Sev</th><th>Channel</th><th>State</th></tr></thead><tbody>{findings_rows}</tbody></table>
  </div>
  <div class="card">
    <h2>Executive Summary</h2>
    <table><tbody>
      <tr><td style="padding:4px 0;color:#94a3b8">Rating</td><td>{_esc(str(exec_sum.get("risk_rating", "—")))}</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">SLA compliance</td><td>{sla_display}</td></tr>
      <tr><td style="padding:4px 0;color:#94a3b8">Block rate</td><td>{block_display}</td></tr>
    </tbody></table>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>Orchestrator Runs (last 10)</h2>
    <table><thead><tr><th>Time</th><th>Schedule</th><th>Risk</th><th>Baseline</th><th>Status</th></tr></thead><tbody>{runs_rows}</tbody></table>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>Model Inventory ({inv.get("total_models", 0)} models)</h2>
    <table><thead><tr><th>Model</th><th>Risk</th><th>Coverage</th></tr></thead><tbody>{model_rows}</tbody></table>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>Organization Overview ({org.get("team_count", 0)} teams · {org.get("project_count", 0)} projects)</h2>
    <p style="font-size:.85rem;color:#94a3b8;margin-bottom:8px">
      Mean risk: {org.get("mean_risk_score", 0):.1f} · Open findings: {org.get("total_open_findings", 0)} ·
      Healthy: {org.get("projects_healthy", 0)} · At risk: {org.get("projects_at_risk", 0)} ·
      Critical: {org.get("projects_critical", 0)}
    </p>
    <table><thead><tr><th>Team</th><th>Project</th><th>Risk</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>{org_rows}</tbody></table>
  </div>
</div>
<script>
(function(){{
  var ctx = document.getElementById('trendChart');
  if (ctx && typeof Chart !== 'undefined') {{
    new Chart(ctx.getContext('2d'), {{
      type: 'line',
      data: {{
        labels: {trend_labels_js},
        datasets: [{{
          label: 'Risk score',
          data: {trend_scores_js},
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56,189,248,0.15)',
          fill: true,
          tension: 0.3,
          pointRadius: 3
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          y: {{ min: 0, max: 100, grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
          x: {{ grid: {{ display: false }}, ticks: {{ color: '#94a3b8', maxRotation: 45 }} }}
        }}
      }}
    }});
  }}
}})();
(function(){{
  var ctx2 = document.getElementById('hemlockScoreChart');
  if (ctx2 && typeof Chart !== 'undefined') {{
    new Chart(ctx2.getContext('2d'), {{
      type: 'line',
      data: {{
        labels: {hs_labels_js},
        datasets: [{{
          label: 'Hemlock score',
          data: {hs_scores_js},
          borderColor: '#22c55e',
          backgroundColor: 'rgba(34,197,94,0.15)',
          fill: true,
          tension: 0.3,
          pointRadius: 3
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          y: {{ min: 0, max: 100, grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
          x: {{ grid: {{ display: false }}, ticks: {{ color: '#94a3b8', maxRotation: 45 }} }}
        }}
      }}
    }});
  }}
}})();
</script>
"""
    return base.replace("</body>", extra + "</body>")


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
        from hemlock.dashboard_data import load_operational_context, load_org_context

        ctx = load_operational_context()
        if os.path.exists(".hemlock/tenants.json"):
            ctx["org_summary"] = load_org_context()
        history = ctx.get("watch_history", [])
        html = build_operational_dashboard_html(history, operational=ctx)
        return HTMLResponse(content=html)

    @router.get("/org-dashboard", response_class=HTMLResponse)
    def org_dashboard() -> HTMLResponse:
        """Organization-wide CISO dashboard."""
        from hemlock.dashboard_data import load_operational_context, load_org_context

        ctx = load_operational_context()
        ctx["org_summary"] = load_org_context()
        html = build_operational_dashboard_html(ctx.get("watch_history", []), operational=ctx)
        return HTMLResponse(content=html)

    return router
