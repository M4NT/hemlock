"""Role-Based Access Control for Hemlock multi-tenant (v4.9).

Roles:
    viewer  — read-only: GET /report, GET /history, GET /dashboard
    scanner — viewer + POST /scan, POST /eval, POST /threat-model
    admin   — scanner + tenant management, compliance, repair

Permissions are checked via RBACStore.check(team_id, action).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator


class Role(str, Enum):
    VIEWER = "viewer"
    SCANNER = "scanner"
    ADMIN = "admin"


_ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {"read:report", "read:history", "read:dashboard"},
    Role.SCANNER: {"read:report", "read:history", "read:dashboard", "write:scan", "write:eval"},
    Role.ADMIN: {
        "read:report", "read:history", "read:dashboard",
        "write:scan", "write:eval",
        "admin:tenant", "admin:compliance", "admin:repair",
    },
}


def role_permissions(role: Role) -> set[str]:
    return _ROLE_PERMISSIONS.get(role, set())


def can(role: Role, action: str) -> bool:
    return action in role_permissions(role)


@dataclass
class RBACEntry:
    team_id: str
    role: Role


class RBACStore:
    """File-backed role store.  Keyed by team_id."""

    def __init__(self, path: str = ".hemlock/rbac.json") -> None:
        self._path = path
        self._entries: dict[str, Role] = {}
        self._load()

    # ── Persistence ────────────────────────────────────────────────────────

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path, encoding="utf-8") as f:
                    data = json.load(f)
                self._entries = {k: Role(v) for k, v in data.items()}
            except (json.JSONDecodeError, ValueError):
                self._entries = {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({k: v.value for k, v in self._entries.items()}, f, indent=2)

    # ── Public API ─────────────────────────────────────────────────────────

    def assign(self, team_id: str, role: Role) -> None:
        self._entries[team_id] = role
        self._save()

    def get_role(self, team_id: str) -> Role:
        return self._entries.get(team_id, Role.VIEWER)

    def check(self, team_id: str, action: str) -> bool:
        return can(self.get_role(team_id), action)

    def revoke(self, team_id: str) -> None:
        self._entries.pop(team_id, None)
        self._save()

    def list_entries(self) -> list[RBACEntry]:
        return [RBACEntry(team_id=k, role=v) for k, v in self._entries.items()]
