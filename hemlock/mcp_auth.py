"""MCP authentication helpers for fleet audits (v9.4).

Supports shared fleet tokens (MCP_AUTH_TOKEN) and per-target OAuth bearer tokens
stored in environment variables — never commit real tokens to git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

AuthMode = Literal["mcp_token", "oauth_bearer", "none"]


@dataclass
class ResolvedMcpAuth:
    token: str | None
    mode: AuthMode
    source: str  # env key or "inline" or "none"


def resolve_mcp_auth(
    auth_mode: AuthMode = "mcp_token",
    auth_token: str | None = None,
    auth_token_env: str | None = None,
    oauth_token: str | None = None,
    oauth_token_env: str | None = None,
) -> ResolvedMcpAuth:
    """Resolve bearer token for an MCP target from inline value or environment."""
    if auth_mode == "none":
        return ResolvedMcpAuth(token=None, mode="none", source="none")

    if auth_mode == "oauth_bearer":
        if oauth_token:
            return ResolvedMcpAuth(token=oauth_token, mode="oauth_bearer", source="inline")
        if oauth_token_env:
            value = os.environ.get(oauth_token_env)
            if value:
                return ResolvedMcpAuth(token=value, mode="oauth_bearer", source=oauth_token_env)
        return ResolvedMcpAuth(token=None, mode="oauth_bearer", source=oauth_token_env or "none")

    if auth_token:
        return ResolvedMcpAuth(token=auth_token, mode="mcp_token", source="inline")
    if auth_token_env:
        value = os.environ.get(auth_token_env)
        if value:
            return ResolvedMcpAuth(token=value, mode="mcp_token", source=auth_token_env)
    return ResolvedMcpAuth(token=None, mode="mcp_token", source=auth_token_env or "none")


def should_skip_oauth_target(
    expect_auth_failure: bool,
    auth_mode: AuthMode,
    resolved: ResolvedMcpAuth,
) -> bool:
    """Skip connect when OAuth is required but no user-delegated token is available."""
    if not expect_auth_failure:
        return False
    if auth_mode == "oauth_bearer" and resolved.token:
        return False
    return True
