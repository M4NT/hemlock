from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Team:
    team_id: str
    name: str
    api_key: str       # hashed (SHA-256 hex) for storage; raw key returned only on creation
    created_at: str    # ISO datetime string
    members: list[str] = field(default_factory=list)


@dataclass
class Project:
    project_id: str
    team_id: str
    name: str
    baseline_path: str | None
    created_at: str


class TenantStore:
    """File-based tenant store (JSON). For production, swap for DB backend."""

    def __init__(self, store_path: str = ".hemlock/tenants.json") -> None:
        self._path = store_path
        self._data: dict[str, Any] = {"teams": {}, "projects": {}}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path, encoding="utf-8") as f:
                    loaded = json.load(f)
                self._data = loaded if isinstance(loaded, dict) else {"teams": {}, "projects": {}}
            except (json.JSONDecodeError, OSError):
                self._data = {"teams": {}, "projects": {}}
        else:
            self._data = {"teams": {}, "projects": {}}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) if os.path.dirname(self._path) else ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def create_team(self, name: str) -> tuple[Team, str]:
        """Create a team. Returns (Team with hashed key, raw_api_key)."""
        raw_key = secrets.token_urlsafe(32)
        hashed = self._hash_key(raw_key)
        team_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        team_data = {
            "team_id": team_id,
            "name": name,
            "api_key": hashed,
            "created_at": now,
            "members": [],
        }
        self._data["teams"][team_id] = team_data
        self._save()
        return Team(**team_data), raw_key

    def get_team(self, team_id: str) -> Team | None:
        data = self._data["teams"].get(team_id)
        if data is None:
            return None
        return Team(**data)

    def list_teams(self) -> list[Team]:
        return [Team(**d) for d in self._data["teams"].values()]

    def delete_team(self, team_id: str) -> bool:
        if team_id not in self._data["teams"]:
            return False
        del self._data["teams"][team_id]
        # Also remove associated projects
        self._data["projects"] = {
            pid: p for pid, p in self._data["projects"].items()
            if p["team_id"] != team_id
        }
        self._save()
        return True

    def create_project(self, team_id: str, name: str, baseline_path: str | None = None) -> Project:
        if team_id not in self._data["teams"]:
            raise ValueError(f"Team not found: {team_id}")
        project_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        project_data = {
            "project_id": project_id,
            "team_id": team_id,
            "name": name,
            "baseline_path": baseline_path,
            "created_at": now,
        }
        self._data["projects"][project_id] = project_data
        self._save()
        return Project(**project_data)

    def get_project(self, project_id: str) -> Project | None:
        data = self._data["projects"].get(project_id)
        if data is None:
            return None
        return Project(**data)

    def list_projects(self, team_id: str) -> list[Project]:
        return [
            Project(**d) for d in self._data["projects"].values()
            if d["team_id"] == team_id
        ]

    def validate_api_key(self, raw_key: str) -> Team | None:
        """Find team whose stored hash matches raw_key. Returns Team or None."""
        hashed = self._hash_key(raw_key)
        for team_data in self._data["teams"].values():
            if team_data["api_key"] == hashed:
                return Team(**team_data)
        return None


class TenantMiddleware:
    """FastAPI middleware that validates X-API-Key header."""

    def __init__(self, store: TenantStore, exempt_paths: list[str] | None = None) -> None:
        self._store = store
        self._exempt = set(exempt_paths or ["/health", "/dashboard"])

    async def __call__(self, request: Any, call_next: Any) -> Any:
        from fastapi.responses import JSONResponse
        path = request.url.path
        if path in self._exempt:
            return await call_next(request)
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            return JSONResponse({"detail": "X-API-Key header required"}, status_code=401)
        team = self._store.validate_api_key(api_key)
        if team is None:
            return JSONResponse({"detail": "Invalid API key"}, status_code=403)
        return await call_next(request)
