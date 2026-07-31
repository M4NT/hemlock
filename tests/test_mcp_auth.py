"""Tests for hemlock.mcp_auth (v9.4)."""

from __future__ import annotations

import os

import pytest

from hemlock.mcp_auth import resolve_mcp_auth, should_skip_oauth_target


def test_resolve_mcp_token_from_env(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "secret")
    resolved = resolve_mcp_auth(auth_token_env="MCP_AUTH_TOKEN")
    assert resolved.token == "secret"
    assert resolved.mode == "mcp_token"


def test_resolve_oauth_bearer_from_env(monkeypatch):
    monkeypatch.setenv("IMAP_MCP_OAUTH_TOKEN", "oauth-secret")
    resolved = resolve_mcp_auth(auth_mode="oauth_bearer", oauth_token_env="IMAP_MCP_OAUTH_TOKEN")
    assert resolved.token == "oauth-secret"
    assert resolved.mode == "oauth_bearer"


def test_should_skip_oauth_without_token():
    resolved = resolve_mcp_auth(auth_mode="oauth_bearer", oauth_token_env="MISSING")
    assert should_skip_oauth_target(True, "oauth_bearer", resolved)


def test_should_not_skip_oauth_with_token(monkeypatch):
    monkeypatch.setenv("TOK", "x")
    resolved = resolve_mcp_auth(auth_mode="oauth_bearer", oauth_token_env="TOK")
    assert not should_skip_oauth_target(True, "oauth_bearer", resolved)
