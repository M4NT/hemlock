"""Tests for hemlock.rbac (v4.9)."""
import tempfile
import os
import pytest
from hemlock.rbac import Role, RBACStore, can, role_permissions


def test_viewer_can_read_report():
    assert can(Role.VIEWER, "read:report")


def test_viewer_cannot_scan():
    assert not can(Role.VIEWER, "write:scan")


def test_scanner_can_scan():
    assert can(Role.SCANNER, "write:scan")


def test_scanner_cannot_admin():
    assert not can(Role.SCANNER, "admin:tenant")


def test_admin_can_all():
    for action in ("read:report", "write:scan", "admin:tenant", "admin:compliance", "admin:repair"):
        assert can(Role.ADMIN, action)


def test_role_permissions_returns_set():
    perms = role_permissions(Role.SCANNER)
    assert isinstance(perms, set)
    assert len(perms) > 0


@pytest.fixture()
def store(tmp_path):
    return RBACStore(path=str(tmp_path / "rbac.json"))


def test_store_default_role_is_viewer(store):
    assert store.get_role("unknown_team") == Role.VIEWER


def test_store_assign_and_get(store):
    store.assign("team_a", Role.ADMIN)
    assert store.get_role("team_a") == Role.ADMIN


def test_store_check_allowed(store):
    store.assign("team_b", Role.SCANNER)
    assert store.check("team_b", "write:scan")


def test_store_check_denied(store):
    store.assign("team_c", Role.VIEWER)
    assert not store.check("team_c", "write:scan")


def test_store_revoke(store):
    store.assign("team_d", Role.ADMIN)
    store.revoke("team_d")
    assert store.get_role("team_d") == Role.VIEWER


def test_store_persists(tmp_path):
    path = str(tmp_path / "rbac.json")
    s1 = RBACStore(path=path)
    s1.assign("team_e", Role.ADMIN)
    s2 = RBACStore(path=path)
    assert s2.get_role("team_e") == Role.ADMIN


def test_store_list_entries(store):
    store.assign("t1", Role.VIEWER)
    store.assign("t2", Role.SCANNER)
    entries = store.list_entries()
    ids = {e.team_id for e in entries}
    assert "t1" in ids
    assert "t2" in ids
