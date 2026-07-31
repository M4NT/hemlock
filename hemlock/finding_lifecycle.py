"""Finding Lifecycle Management — v7.1.

Full lifecycle tracking for security findings:
    open → triaged → in_progress → resolved → verified  (or wont_fix)

Includes GitHub Issues and JIRA ticket sinks, and a RemediationVelocity
analyzer for MTTR, SLA compliance rate, and throughput metrics.

Usage:
    from hemlock.finding_lifecycle import (
        ManagedFinding, FindingStore, FindingLifecycle,
        GitHubIssueSink, JiraSink,
        RemediationVelocity,
    )

    store = FindingStore(".hemlock/findings.jsonl")
    lc    = FindingLifecycle(store, sinks=[GitHubIssueSink(token, owner, repo)])

    finding = ManagedFinding.from_sla_finding(sla_finding, title="RAG injection via PDF chunk")
    lc.ingest(finding)                    # open + auto-creates GH issue
    lc.transition("f-001", "triaged", actor="alice", notes="confirmed via manual test")
    lc.transition("f-001", "in_progress", actor="bob")
    lc.transition("f-001", "resolved", actor="bob", notes="chunk filter deployed")
    lc.transition("f-001", "verified", actor="alice")

    velocity = RemediationVelocity(store)
    print(velocity.summary())
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

VALID_STATES = ("open", "triaged", "in_progress", "resolved", "verified", "wont_fix")
TERMINAL_STATES = {"resolved", "verified", "wont_fix"}

VALID_TRANSITIONS: dict[str, set[str]] = {
    "open":        {"triaged", "in_progress", "wont_fix"},
    "triaged":     {"in_progress", "wont_fix", "open"},
    "in_progress": {"resolved", "wont_fix", "triaged"},
    "resolved":    {"verified", "open"},   # reopen if regression
    "verified":    {"open"},               # reopen if regression
    "wont_fix":    {"open"},
}


# ── Core data model ──────────────────────────────────────────────────────────

@dataclass
class LifecycleEvent:
    state: str
    timestamp: str
    actor: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LifecycleEvent":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ManagedFinding:
    finding_id: str
    channel: str
    severity: str           # critical | high | medium | low
    title: str
    description: str = ""
    first_seen: str = ""
    state: str = "open"
    history: list[LifecycleEvent] = field(default_factory=list)
    external_refs: dict[str, str] = field(default_factory=dict)  # {"github": url, "jira": key}
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = datetime.now(timezone.utc).isoformat()
        if not self.history:
            self.history = [LifecycleEvent(
                state="open",
                timestamp=self.first_seen,
                actor="hemlock",
            )]

    @classmethod
    def from_sla_finding(cls, sla_finding: Any, title: str = "", description: str = "") -> "ManagedFinding":
        """Build from a hemlock.security_baseline.FindingRecord."""
        fid = getattr(sla_finding, "finding_id", str(id(sla_finding)))
        channel = getattr(sla_finding, "channel", "unknown")
        severity = getattr(sla_finding, "severity", "medium")
        first_seen = getattr(sla_finding, "first_seen", datetime.now(timezone.utc).isoformat())
        return cls(
            finding_id=fid,
            channel=channel,
            severity=severity,
            title=title or f"[{severity.upper()}] {channel} finding {fid}",
            description=description,
            first_seen=first_seen,
        )

    def is_open(self) -> bool:
        return self.state not in TERMINAL_STATES

    def last_event(self) -> LifecycleEvent | None:
        return self.history[-1] if self.history else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["history"] = [e.to_dict() for e in self.history]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ManagedFinding":
        history = [LifecycleEvent.from_dict(e) for e in d.pop("history", [])]
        obj = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        obj.history = history
        return obj


# ── Persistent store ─────────────────────────────────────────────────────────

class FindingStore:
    """JSONL-backed finding store. One JSON object per line, keyed by finding_id."""

    def __init__(self, path: str = ".hemlock/findings.jsonl") -> None:
        self._path = path
        self._cache: dict[str, ManagedFinding] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                    obj = ManagedFinding.from_dict(d)
                    self._cache[obj.finding_id] = obj
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass

    def _flush(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            for obj in self._cache.values():
                f.write(json.dumps(obj.to_dict()) + "\n")

    def upsert(self, finding: ManagedFinding) -> None:
        self._cache[finding.finding_id] = finding
        self._flush()

    def get(self, finding_id: str) -> ManagedFinding | None:
        return self._cache.get(finding_id)

    def all(self) -> list[ManagedFinding]:
        return list(self._cache.values())

    def list_by_state(self, state: str) -> list[ManagedFinding]:
        return [f for f in self._cache.values() if f.state == state]

    def open_findings(self) -> list[ManagedFinding]:
        return [f for f in self._cache.values() if f.is_open()]

    def transition(
        self,
        finding_id: str,
        new_state: str,
        actor: str = "",
        notes: str = "",
    ) -> bool:
        """Transition a finding to a new state. Returns False if invalid."""
        finding = self._cache.get(finding_id)
        if finding is None:
            return False
        if new_state not in VALID_STATES:
            return False
        allowed = VALID_TRANSITIONS.get(finding.state, set())
        if new_state not in allowed:
            return False
        finding.state = new_state
        finding.history.append(LifecycleEvent(
            state=new_state,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            notes=notes,
        ))
        self._flush()
        return True


# ── Ticket sinks ──────────────────────────────────────────────────────────────

class TicketSink:
    """Base class for external ticket system integrations."""

    def create_ticket(self, finding: ManagedFinding) -> str | None:
        """Create a ticket; return its URL or key, or None on failure."""
        raise NotImplementedError

    def update_ticket(self, ref: str, finding: ManagedFinding) -> bool:
        """Update an existing ticket. Returns True on success."""
        raise NotImplementedError

    def _body(self, finding: ManagedFinding) -> str:
        return (
            f"**Finding ID**: `{finding.finding_id}`\n"
            f"**Channel**: {finding.channel}\n"
            f"**Severity**: {finding.severity}\n"
            f"**First seen**: {finding.first_seen}\n\n"
            f"{finding.description or '_No additional description._'}\n\n"
            f"---\n_Opened by [Hemlock](https://github.com/M4NT/hemlock)_"
        )


class GitHubIssueSink(TicketSink):
    """Creates and updates GitHub Issues via the REST API."""

    def __init__(self, token: str, owner: str, repo: str) -> None:
        self.token = token
        self.owner = owner
        self.repo = repo
        self._api = f"https://api.github.com/repos/{owner}/{repo}/issues"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def create_ticket(self, finding: ManagedFinding) -> str | None:
        severity_label = f"severity:{finding.severity}"
        payload = json.dumps({
            "title": f"[Hemlock] {finding.title}",
            "body": self._body(finding),
            "labels": ["security", "hemlock", severity_label],
        }).encode()
        req = urllib.request.Request(
            self._api,
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                data = json.loads(resp.read())
                return data.get("html_url")
        except Exception as exc:
            print(f"[hemlock/github] create issue failed: {exc}")
            return None

    def update_ticket(self, ref: str, finding: ManagedFinding) -> bool:
        issue_number = ref.rstrip("/").split("/")[-1]
        url = f"{self._api}/{issue_number}"
        gh_state = "closed" if finding.state in ("resolved", "verified", "wont_fix") else "open"
        payload = json.dumps({
            "body": self._body(finding),
            "state": gh_state,
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers=self._headers(),
            method="PATCH",
        )
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            return True
        except Exception as exc:
            print(f"[hemlock/github] update issue failed: {exc}")
            return False


class JiraSink(TicketSink):
    """Creates and updates JIRA issues via the REST API v3."""

    def __init__(self, base_url: str, token: str, project_key: str, issue_type: str = "Bug") -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.project_key = project_key
        self.issue_type = issue_type

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _priority(self, severity: str) -> str:
        return {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }.get(severity.lower(), "Medium")

    def create_ticket(self, finding: ManagedFinding) -> str | None:
        payload = json.dumps({
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[Hemlock] {finding.title}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": self._body(finding)}
                    ]}],
                },
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self._priority(finding.severity)},
                "labels": ["hemlock", "security", finding.severity],
            }
        }).encode()
        url = f"{self.base_url}/rest/api/3/issue"
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                data = json.loads(resp.read())
                key = data.get("key", "")
                return f"{self.base_url}/browse/{key}" if key else None
        except Exception as exc:
            print(f"[hemlock/jira] create issue failed: {exc}")
            return None

    def update_ticket(self, ref: str, finding: ManagedFinding) -> bool:
        key = ref.rstrip("/").split("/")[-1]
        url = f"{self.base_url}/rest/api/3/issue/{key}"
        payload = json.dumps({
            "fields": {
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": self._body(finding)}
                    ]}],
                },
            }
        }).encode()
        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="PUT")
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
            return True
        except Exception as exc:
            print(f"[hemlock/jira] update issue failed: {exc}")
            return False


# ── Lifecycle orchestrator ────────────────────────────────────────────────────

class FindingLifecycle:
    """Orchestrates finding ingestion, state transitions, and ticket sync."""

    def __init__(
        self,
        store: FindingStore,
        sinks: list[TicketSink] | None = None,
        auto_ticket: bool = True,
    ) -> None:
        self.store = store
        self.sinks = sinks or []
        self.auto_ticket = auto_ticket

    def ingest(self, finding: ManagedFinding) -> ManagedFinding:
        """Upsert a finding; creates external tickets on first ingest."""
        existing = self.store.get(finding.finding_id)
        if existing:
            existing.metadata.update(finding.metadata)
            self.store.upsert(existing)
            return existing

        self.store.upsert(finding)

        if self.auto_ticket:
            for sink in self.sinks:
                sink_name = type(sink).__name__.lower().replace("sink", "")
                if sink_name not in finding.external_refs:
                    ref = sink.create_ticket(finding)
                    if ref:
                        finding.external_refs[sink_name] = ref
            if finding.external_refs:
                self.store.upsert(finding)

        return finding

    def transition(
        self,
        finding_id: str,
        new_state: str,
        actor: str = "",
        notes: str = "",
    ) -> bool:
        """Transition state and sync to external ticket systems."""
        ok = self.store.transition(finding_id, new_state, actor=actor, notes=notes)
        if not ok:
            return False

        finding = self.store.get(finding_id)
        if finding and self.sinks:
            for sink in self.sinks:
                sink_name = type(sink).__name__.lower().replace("sink", "")
                ref = finding.external_refs.get(sink_name)
                if ref:
                    sink.update_ticket(ref, finding)

        return True

    def ingest_batch(self, findings: list[ManagedFinding]) -> list[ManagedFinding]:
        return [self.ingest(f) for f in findings]


# ── Remediation velocity ──────────────────────────────────────────────────────

def _hours_between(start_iso: str, end_iso: str) -> float:
    try:
        fmt = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
        return max(0.0, (fmt(end_iso) - fmt(start_iso)).total_seconds() / 3600)
    except (ValueError, TypeError):
        return 0.0


def _hours_since(iso_ts: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except (ValueError, TypeError):
        return 0.0


class RemediationVelocity:
    """Metrics on how fast findings move through the lifecycle."""

    def __init__(self, store: FindingStore) -> None:
        self.store = store

    def _resolved_in_window(self, days: int) -> list[ManagedFinding]:
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        result = []
        for f in self.store.all():
            for event in f.history:
                if event.state in ("resolved", "verified"):
                    try:
                        ts = datetime.fromisoformat(
                            event.timestamp.replace("Z", "+00:00")
                        ).timestamp()
                        if ts >= cutoff:
                            result.append(f)
                            break
                    except (ValueError, TypeError):
                        pass
        return result

    def mean_time_to_resolve(self, days: int = 30) -> float:
        """Average hours from first_seen to first resolved/verified event."""
        resolved = self._resolved_in_window(days)
        if not resolved:
            return 0.0
        times = []
        for f in resolved:
            for event in f.history:
                if event.state in ("resolved", "verified"):
                    h = _hours_between(f.first_seen, event.timestamp)
                    if h > 0:
                        times.append(h)
                    break
        return round(sum(times) / len(times), 1) if times else 0.0

    def sla_compliance_rate(self, sla_hours: dict[str, int] | None = None) -> float:
        """Fraction of resolved findings that were resolved within SLA. 0.0–1.0."""
        defaults = {"critical": 4, "high": 24, "medium": 72, "low": 168}
        sla = {**defaults, **(sla_hours or {})}
        resolved = self._resolved_in_window(days=365)
        if not resolved:
            return 1.0
        compliant = 0
        for f in resolved:
            max_hours = sla.get(f.severity.lower(), 168)
            for event in f.history:
                if event.state in ("resolved", "verified"):
                    h = _hours_between(f.first_seen, event.timestamp)
                    if h <= max_hours:
                        compliant += 1
                    break
        return round(compliant / len(resolved), 3)

    def open_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.store.open_findings():
            key = f.severity.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def resolved_last_n_days(self, days: int = 7) -> int:
        return len(self._resolved_in_window(days))

    def throughput(self, days: int = 30) -> float:
        """Findings resolved per day over the window."""
        count = len(self._resolved_in_window(days))
        return round(count / days, 2)

    def oldest_open(self) -> ManagedFinding | None:
        open_f = self.store.open_findings()
        if not open_f:
            return None
        return min(open_f, key=lambda f: f.first_seen)

    def summary(self, sla_hours: dict[str, int] | None = None, days: int = 30) -> dict:
        return {
            "open_by_severity": self.open_by_severity(),
            "total_open": len(self.store.open_findings()),
            "resolved_last_30d": self.resolved_last_n_days(days),
            "mean_time_to_resolve_hours": self.mean_time_to_resolve(days),
            "sla_compliance_rate": self.sla_compliance_rate(sla_hours),
            "throughput_per_day": self.throughput(days),
        }
