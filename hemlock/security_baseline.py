"""Security Baseline & SLA Tracking — v7.0.

Anchors risk assessment to a known-good state, tracks how long findings stay
open against configurable SLAs, and fans out alerts to Slack / PagerDuty /
generic webhooks.

Usage:
    from hemlock.security_baseline import (
        SecurityBaseline,
        BaselineComparison,
        SLAPolicy,
        SLATracker,
        FindingRecord,
        AlertRouter,
        SlackSink,
        PagerDutySink,
        WebhookSink,
        TrendAnalyzer,
    )

    # Capture a baseline from a good report
    baseline = SecurityBaseline.from_report(report, label="prod-2026-07-31")
    baseline.save(".hemlock/baseline.json")

    # Compare later report against baseline
    result = BaselineComparison.compare(baseline, current_report)
    if not result.compliant:
        ...

    # SLA tracking
    policy = SLAPolicy(critical_hours=4, high_hours=24, medium_hours=72)
    tracker = SLATracker(policy)
    tracker.ingest(findings)
    violations = tracker.check_violations()

    # Alert routing
    router = AlertRouter([
        SlackSink("https://hooks.slack.com/..."),
        PagerDutySink("my-routing-key"),
    ])
    router.route(violations)

    # Trend analysis
    analyzer = TrendAnalyzer(history_entries)
    print(analyzer.trend(days=30))  # "improving" | "degrading" | "stable"
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# ── Baseline capture ────────────────────────────────────────────────────────

@dataclass
class ChannelBaseline:
    channel: str
    expected_max_risk: float
    expected_blocked: list[str] = field(default_factory=list)


@dataclass
class SecurityBaseline:
    label: str
    captured_at: str
    channels: dict[str, ChannelBaseline]
    overall_max_risk: float
    tolerance: float = 0.0  # added buffer above captured risk

    @classmethod
    def from_report(
        cls,
        report: Any,
        label: str,
        tolerance: float = 0.0,
    ) -> "SecurityBaseline":
        """Capture a baseline from a report object.

        Accepts any object with:
          - risk_score() → float
          - channels_at_risk() → list[str]
          - Optional: channel_scores() → dict[str, float]
        """
        overall = float(report.risk_score()) if hasattr(report, "risk_score") else 0.0
        at_risk: list[str] = report.channels_at_risk() if hasattr(report, "channels_at_risk") else []

        channel_scores: dict[str, float] = {}
        if hasattr(report, "channel_scores"):
            channel_scores = dict(report.channel_scores())
        elif hasattr(report, "to_dict"):
            d = report.to_dict()
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, (int, float)):
                        channel_scores[k] = float(v)

        channels: dict[str, ChannelBaseline] = {}
        for ch in at_risk:
            score = channel_scores.get(ch, overall)
            channels[ch] = ChannelBaseline(
                channel=ch,
                expected_max_risk=score + tolerance,
            )

        return cls(
            label=label,
            captured_at=datetime.now(timezone.utc).isoformat(),
            channels=channels,
            overall_max_risk=overall + tolerance,
            tolerance=tolerance,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityBaseline":
        channels = {
            k: ChannelBaseline(**v) if isinstance(v, dict) else v
            for k, v in data.get("channels", {}).items()
        }
        return cls(
            label=data["label"],
            captured_at=data["captured_at"],
            channels=channels,
            overall_max_risk=data.get("overall_max_risk", 0.0),
            tolerance=data.get("tolerance", 0.0),
        )

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "captured_at": self.captured_at,
            "channels": {k: asdict(v) for k, v in self.channels.items()},
            "overall_max_risk": self.overall_max_risk,
            "tolerance": self.tolerance,
        }

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "SecurityBaseline":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ── Baseline comparison ─────────────────────────────────────────────────────

def _severity_from_delta(delta: float) -> str:
    if delta > 30:
        return "critical"
    if delta > 20:
        return "high"
    if delta > 10:
        return "medium"
    return "low"


@dataclass
class BaselineViolation:
    channel: str
    expected_max: float
    actual: float
    delta: float
    severity: str


@dataclass
class BaselineResult:
    baseline_label: str
    compared_at: str
    violations: list[BaselineViolation]
    compliant: bool
    overall_delta: float
    new_channels_at_risk: list[str]

    def to_dict(self) -> dict:
        return {
            "baseline_label": self.baseline_label,
            "compared_at": self.compared_at,
            "violations": [asdict(v) for v in self.violations],
            "compliant": self.compliant,
            "overall_delta": self.overall_delta,
            "new_channels_at_risk": self.new_channels_at_risk,
        }

    def summary(self) -> str:
        if self.compliant:
            return f"COMPLIANT with baseline '{self.baseline_label}' (Δ{self.overall_delta:+.1f})"
        return (
            f"VIOLATION of baseline '{self.baseline_label}': "
            f"{len(self.violations)} channel(s), Δ{self.overall_delta:+.1f}"
        )


class BaselineComparison:
    @staticmethod
    def compare(baseline: SecurityBaseline, report: Any) -> BaselineResult:
        current_risk = float(report.risk_score()) if hasattr(report, "risk_score") else 0.0
        current_at_risk: list[str] = (
            report.channels_at_risk() if hasattr(report, "channels_at_risk") else []
        )

        channel_scores: dict[str, float] = {}
        if hasattr(report, "channel_scores"):
            channel_scores = dict(report.channel_scores())

        violations: list[BaselineViolation] = []
        for ch in current_at_risk:
            actual = channel_scores.get(ch, current_risk)
            bl_ch = baseline.channels.get(ch)
            if bl_ch is None:
                # channel not in baseline → always a violation
                delta = actual
                violations.append(BaselineViolation(
                    channel=ch,
                    expected_max=0.0,
                    actual=actual,
                    delta=round(delta, 1),
                    severity=_severity_from_delta(delta),
                ))
            elif actual > bl_ch.expected_max_risk:
                delta = actual - bl_ch.expected_max_risk
                violations.append(BaselineViolation(
                    channel=ch,
                    expected_max=bl_ch.expected_max_risk,
                    actual=actual,
                    delta=round(delta, 1),
                    severity=_severity_from_delta(delta),
                ))

        new_channels = [ch for ch in current_at_risk if ch not in baseline.channels]
        overall_delta = round(current_risk - baseline.overall_max_risk, 1)

        return BaselineResult(
            baseline_label=baseline.label,
            compared_at=datetime.now(timezone.utc).isoformat(),
            violations=violations,
            compliant=len(violations) == 0,
            overall_delta=overall_delta,
            new_channels_at_risk=new_channels,
        )


# ── SLA tracking ─────────────────────────────────────────────────────────────

@dataclass
class FindingRecord:
    finding_id: str
    channel: str
    severity: str          # critical | high | medium | low
    first_seen: str        # ISO-8601 UTC
    last_seen: str
    resolved: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FindingRecord":
        meta = data.pop("metadata", {})
        return cls(**data, metadata=meta)


@dataclass
class SLAPolicy:
    critical_hours: int = 4
    high_hours: int = 24
    medium_hours: int = 72
    low_hours: int = 168

    def hours_for(self, severity: str) -> int:
        return {
            "critical": self.critical_hours,
            "high": self.high_hours,
            "medium": self.medium_hours,
            "low": self.low_hours,
        }.get(severity.lower(), self.low_hours)


@dataclass
class SLAViolation:
    finding: FindingRecord
    sla_hours: int
    open_hours: float
    overdue_hours: float

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "sla_hours": self.sla_hours,
            "open_hours": self.open_hours,
            "overdue_hours": self.overdue_hours,
        }


def _hours_since(iso_ts: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return 0.0


class SLATracker:
    """Persists open findings and detects SLA breaches."""

    def __init__(
        self,
        policy: SLAPolicy | None = None,
        path: str = ".hemlock/sla_findings.jsonl",
    ) -> None:
        self.policy = policy or SLAPolicy()
        self._path = path
        self._findings: dict[str, FindingRecord] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                    r = FindingRecord.from_dict(d)
                    self._findings[r.finding_id] = r
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass

    def _persist(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            for r in self._findings.values():
                f.write(json.dumps(r.to_dict()) + "\n")

    def ingest(self, findings: list[FindingRecord]) -> None:
        """Upsert findings; updates last_seen for existing ones."""
        now = datetime.now(timezone.utc).isoformat()
        for r in findings:
            if r.finding_id in self._findings:
                existing = self._findings[r.finding_id]
                existing.last_seen = now
                if r.resolved:
                    existing.resolved = True
            else:
                if not r.first_seen:
                    r.first_seen = now
                if not r.last_seen:
                    r.last_seen = now
                self._findings[r.finding_id] = r
        self._persist()

    def resolve(self, finding_id: str) -> bool:
        if finding_id in self._findings:
            self._findings[finding_id].resolved = True
            self._persist()
            return True
        return False

    def open_findings(self) -> list[FindingRecord]:
        return [r for r in self._findings.values() if not r.resolved]

    def check_violations(self) -> list[SLAViolation]:
        violations: list[SLAViolation] = []
        for r in self.open_findings():
            sla = self.policy.hours_for(r.severity)
            open_h = round(_hours_since(r.first_seen), 2)
            if open_h > sla:
                violations.append(SLAViolation(
                    finding=r,
                    sla_hours=sla,
                    open_hours=open_h,
                    overdue_hours=round(open_h - sla, 2),
                ))
        violations.sort(key=lambda v: v.overdue_hours, reverse=True)
        return violations


# ── Alert sinks ──────────────────────────────────────────────────────────────

class AlertSink:
    """Base class for alert destinations."""

    def send(self, violations: list[SLAViolation]) -> bool:
        raise NotImplementedError

    def _format_text(self, violations: list[SLAViolation]) -> str:
        lines = [f"[Hemlock] {len(violations)} SLA violation(s):"]
        for v in violations:
            lines.append(
                f"  • [{v.finding.severity.upper()}] {v.finding.channel} "
                f"— {v.finding.finding_id} "
                f"open {v.open_hours:.1f}h / SLA {v.sla_hours}h "
                f"(+{v.overdue_hours:.1f}h overdue)"
            )
        return "\n".join(lines)


class SlackSink(AlertSink):
    """Posts a message to a Slack incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, violations: list[SLAViolation]) -> bool:
        if not violations:
            return True
        import urllib.request

        text = self._format_text(violations)
        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            return True
        except Exception as exc:
            print(f"[hemlock/slack] POST failed: {exc}")
            return False


class PagerDutySink(AlertSink):
    """Triggers a PagerDuty event via Events API v2."""

    def __init__(
        self,
        routing_key: str,
        api_url: str = "https://events.pagerduty.com/v2/enqueue",
    ) -> None:
        self.routing_key = routing_key
        self.api_url = api_url

    def _severity_pd(self, violations: list[SLAViolation]) -> str:
        levels = {v.finding.severity.lower() for v in violations}
        for lvl in ("critical", "error", "warning", "info"):
            if lvl in levels or (lvl == "error" and "high" in levels):
                return lvl
        return "warning"

    def send(self, violations: list[SLAViolation]) -> bool:
        if not violations:
            return True
        import urllib.request

        summary = self._format_text(violations)
        event = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary[:1024],
                "severity": self._severity_pd(violations),
                "source": "hemlock-security-baseline",
                "custom_details": {
                    "violation_count": len(violations),
                    "findings": [v.finding.finding_id for v in violations[:10]],
                },
            },
        }
        payload = json.dumps(event).encode()
        req = urllib.request.Request(
            self.api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            return True
        except Exception as exc:
            print(f"[hemlock/pagerduty] POST failed: {exc}")
            return False


class WebhookSink(AlertSink):
    """Posts a JSON payload to a generic HTTP endpoint."""

    def __init__(self, url: str, headers: dict | None = None) -> None:
        self.url = url
        self.extra_headers = headers or {}

    def send(self, violations: list[SLAViolation]) -> bool:
        if not violations:
            return True
        import urllib.request

        payload = json.dumps({
            "source": "hemlock",
            "violation_count": len(violations),
            "violations": [v.to_dict() for v in violations],
        }).encode()
        headers = {"Content-Type": "application/json", **self.extra_headers}
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            return True
        except Exception as exc:
            print(f"[hemlock/webhook] POST failed: {exc}")
            return False


# ── Alert router ─────────────────────────────────────────────────────────────

# Default routing: critical/high → all sinks; medium/low → first sink only
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class AlertRouter:
    """Fans out SLA violations to one or more AlertSinks.

    severity_routing maps severity → list of sink indices (0-based).
    If omitted, critical/high go to all sinks; medium/low go to sinks[0].
    """

    def __init__(
        self,
        sinks: list[AlertSink],
        severity_routing: dict[str, list[int]] | None = None,
    ) -> None:
        self.sinks = sinks
        self.severity_routing = severity_routing or self._default_routing(len(sinks))

    @staticmethod
    def _default_routing(n: int) -> dict[str, list[int]]:
        all_idx = list(range(n))
        first = [0] if n > 0 else []
        return {
            "critical": all_idx,
            "high": all_idx,
            "medium": first,
            "low": first,
        }

    def route(self, violations: list[SLAViolation]) -> dict[str, bool]:
        """Route violations to appropriate sinks. Returns {sink_index: success}."""
        if not violations or not self.sinks:
            return {}

        sink_violations: dict[int, list[SLAViolation]] = {i: [] for i in range(len(self.sinks))}
        for v in violations:
            sev = v.finding.severity.lower()
            indices = self.severity_routing.get(sev, [0])
            for idx in indices:
                if idx < len(self.sinks):
                    sink_violations[idx].append(v)

        results: dict[str, bool] = {}
        for idx, vlist in sink_violations.items():
            if vlist:
                results[str(idx)] = self.sinks[idx].send(vlist)
        return results


# ── Trend analysis ────────────────────────────────────────────────────────────

class TrendAnalyzer:
    """Analyses risk score history over configurable time windows.

    history_entries: list of dicts with at least:
        - "timestamp": ISO-8601 string
        - "risk_score": float
    Compatible with WatchHistory, RedTeamHistoryEntry.to_dict(), etc.
    """

    def __init__(self, history_entries: list[dict]) -> None:
        self._entries = sorted(
            [e for e in history_entries if "timestamp" in e and "risk_score" in e],
            key=lambda e: e["timestamp"],
        )

    def _in_window(self, days: int) -> list[dict]:
        if not self._entries:
            return []
        now = datetime.now(timezone.utc)
        cutoff_ts = now.timestamp() - days * 86400
        result = []
        for e in self._entries:
            try:
                ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
                if ts >= cutoff_ts:
                    result.append(e)
            except (ValueError, TypeError):
                pass
        return result

    def window(self, days: int = 30) -> list[dict]:
        return self._in_window(days)

    def mean_risk(self, days: int = 30) -> float:
        entries = self._in_window(days)
        if not entries:
            return 0.0
        return round(sum(float(e["risk_score"]) for e in entries) / len(entries), 2)

    def max_risk(self, days: int = 30) -> float:
        entries = self._in_window(days)
        if not entries:
            return 0.0
        return max(float(e["risk_score"]) for e in entries)

    def min_risk(self, days: int = 30) -> float:
        entries = self._in_window(days)
        if not entries:
            return 0.0
        return min(float(e["risk_score"]) for e in entries)

    def trend(self, days: int = 30, stable_band: float = 5.0) -> str:
        """Returns 'improving', 'degrading', or 'stable'.

        Compares mean of first-half vs second-half of the window.
        """
        entries = self._in_window(days)
        if len(entries) < 2:
            return "stable"
        mid = len(entries) // 2
        first_half = [float(e["risk_score"]) for e in entries[:mid]]
        second_half = [float(e["risk_score"]) for e in entries[mid:]]
        mean_first = sum(first_half) / len(first_half)
        mean_second = sum(second_half) / len(second_half)
        delta = mean_second - mean_first
        if delta > stable_band:
            return "degrading"
        if delta < -stable_band:
            return "improving"
        return "stable"

    def summary(self, days: int = 30) -> dict:
        entries = self._in_window(days)
        return {
            "window_days": days,
            "data_points": len(entries),
            "mean_risk": self.mean_risk(days),
            "max_risk": self.max_risk(days),
            "min_risk": self.min_risk(days),
            "trend": self.trend(days),
        }
