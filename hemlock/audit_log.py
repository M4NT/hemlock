"""Append-only audit log for Hemlock (v4.9).

Each scan, auth attempt, and admin action is recorded as a JSON line.
The log is append-only — entries are never modified or deleted.

Usage:
    from hemlock.audit_log import AuditLog, AuditEvent

    log = AuditLog()
    log.record(AuditEvent(team_id="acme", action="write:scan", resource="/scan", outcome="allowed"))

    for event in log.tail(20):
        print(event)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator


@dataclass
class AuditEvent:
    team_id: str
    action: str
    resource: str
    outcome: str            # allowed | denied | error
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "team_id": self.team_id,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "detail": self.detail,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEvent":
        return cls(
            team_id=d.get("team_id", ""),
            action=d.get("action", ""),
            resource=d.get("resource", ""),
            outcome=d.get("outcome", ""),
            detail=d.get("detail", ""),
            timestamp=d.get("timestamp", ""),
        )


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: str = ".hemlock/audit.jsonl") -> None:
        self._path = path

    def record(self, event: AuditEvent) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")

    def tail(self, n: int = 100) -> list[AuditEvent]:
        if not os.path.exists(self._path):
            return []
        events: list[AuditEvent] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(AuditEvent.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, KeyError):
                        pass
        return events[-n:]

    def all(self) -> list[AuditEvent]:
        return self.tail(n=0) if False else self._read_all()

    def _read_all(self) -> list[AuditEvent]:
        if not os.path.exists(self._path):
            return []
        events: list[AuditEvent] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(AuditEvent.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, KeyError):
                        pass
        return events

    def filter_team(self, team_id: str) -> list[AuditEvent]:
        return [e for e in self._read_all() if e.team_id == team_id]

    def filter_outcome(self, outcome: str) -> list[AuditEvent]:
        return [e for e in self._read_all() if e.outcome == outcome]
