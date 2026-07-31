from __future__ import annotations

import asyncio

import pytest

from hemlock.multitenancy import Project, Team, TenantMiddleware, TenantStore


# ---------------------------------------------------------------------------
# TenantStore — team operations
# ---------------------------------------------------------------------------


def test_create_team_returns_tuple(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    result = store.create_team("alpha")
    assert isinstance(result, tuple)
    assert len(result) == 2
    team, raw_key = result
    assert isinstance(team, Team)
    assert isinstance(raw_key, str)


def test_create_team_unique_ids(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    _, _ = store.create_team("team-a")
    _, _ = store.create_team("team-b")
    teams = store.list_teams()
    ids = [t.team_id for t in teams]
    assert len(ids) == 2
    assert ids[0] != ids[1]


def test_create_team_stores_hashed_key(tmp_path):
    import hashlib
    import json

    store_path = str(tmp_path / "tenants.json")
    store = TenantStore(store_path=store_path)
    team, raw_key = store.create_team("beta")
    expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with open(store_path, encoding="utf-8") as f:
        data = json.load(f)
    stored = data["teams"][team.team_id]["api_key"]
    assert stored == expected_hash
    assert stored != raw_key


def test_get_team_valid(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, _ = store.create_team("gamma")
    result = store.get_team(team.team_id)
    assert result is not None
    assert result.team_id == team.team_id
    assert result.name == "gamma"


def test_get_team_invalid(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    result = store.get_team("nonexistent-id")
    assert result is None


def test_list_teams_returns_all(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    store.create_team("team-x")
    store.create_team("team-y")
    store.create_team("team-z")
    teams = store.list_teams()
    assert len(teams) == 3


def test_delete_team_removes_and_returns_true(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, _ = store.create_team("delta")
    result = store.delete_team(team.team_id)
    assert result is True
    assert store.get_team(team.team_id) is None


def test_delete_team_nonexistent_returns_false(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    result = store.delete_team("does-not-exist")
    assert result is False


def test_delete_team_removes_associated_projects(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, _ = store.create_team("epsilon")
    store.create_project(team.team_id, "proj-1")
    store.create_project(team.team_id, "proj-2")
    store.delete_team(team.team_id)
    assert store.list_projects(team.team_id) == []


# ---------------------------------------------------------------------------
# TenantStore — project operations
# ---------------------------------------------------------------------------


def test_create_project_returns_correct_team_id(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, _ = store.create_team("zeta")
    project = store.create_project(team.team_id, "scan-1")
    assert isinstance(project, Project)
    assert project.team_id == team.team_id
    assert project.name == "scan-1"


def test_create_project_invalid_team_raises(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    with pytest.raises(ValueError, match="Team not found"):
        store.create_project("bad-team-id", "proj")


def test_get_project_valid(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, _ = store.create_team("eta")
    project = store.create_project(team.team_id, "proj-a")
    result = store.get_project(project.project_id)
    assert result is not None
    assert result.project_id == project.project_id


def test_get_project_invalid(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    result = store.get_project("no-such-project")
    assert result is None


def test_list_projects_scoped_to_team(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team_a, _ = store.create_team("team-a")
    team_b, _ = store.create_team("team-b")
    store.create_project(team_a.team_id, "a-proj-1")
    store.create_project(team_a.team_id, "a-proj-2")
    store.create_project(team_b.team_id, "b-proj-1")
    a_projects = store.list_projects(team_a.team_id)
    b_projects = store.list_projects(team_b.team_id)
    assert len(a_projects) == 2
    assert len(b_projects) == 1
    assert all(p.team_id == team_a.team_id for p in a_projects)


# ---------------------------------------------------------------------------
# TenantStore — API key validation
# ---------------------------------------------------------------------------


def test_validate_api_key_correct(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    team, raw_key = store.create_team("theta")
    result = store.validate_api_key(raw_key)
    assert result is not None
    assert result.team_id == team.team_id


def test_validate_api_key_wrong(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    store.create_team("iota")
    result = store.validate_api_key("totally-wrong-key")
    assert result is None


# ---------------------------------------------------------------------------
# TenantStore — persistence
# ---------------------------------------------------------------------------


def test_persistence_across_instances(tmp_path):
    store_path = str(tmp_path / "tenants.json")
    store1 = TenantStore(store_path=store_path)
    team, raw_key = store1.create_team("persistent-team")
    store1.create_project(team.team_id, "persistent-project")

    store2 = TenantStore(store_path=store_path)
    loaded_team = store2.get_team(team.team_id)
    assert loaded_team is not None
    assert loaded_team.name == "persistent-team"
    projects = store2.list_projects(team.team_id)
    assert len(projects) == 1
    assert projects[0].name == "persistent-project"
    # API key should still work
    assert store2.validate_api_key(raw_key) is not None


# ---------------------------------------------------------------------------
# TenantMiddleware
# ---------------------------------------------------------------------------


class MockURL:
    def __init__(self, path: str) -> None:
        self.path = path


class MockRequest:
    def __init__(self, path: str, headers: dict | None = None) -> None:
        self.url = MockURL(path)
        self.headers = headers or {}


async def mock_call_next(req):
    return "response"


def test_middleware_allows_exempt_path(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    middleware = TenantMiddleware(store, exempt_paths=["/health"])
    req = MockRequest("/health")
    result = asyncio.run(middleware(req, mock_call_next))
    assert result == "response"


def test_middleware_returns_401_missing_key(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    middleware = TenantMiddleware(store)
    req = MockRequest("/eval")
    response = asyncio.run(middleware(req, mock_call_next))
    assert response.status_code == 401


def test_middleware_returns_403_invalid_key(tmp_path):
    store = TenantStore(store_path=str(tmp_path / "tenants.json"))
    middleware = TenantMiddleware(store)
    req = MockRequest("/eval", headers={"X-API-Key": "bad-key-value"})
    response = asyncio.run(middleware(req, mock_call_next))
    assert response.status_code == 403
