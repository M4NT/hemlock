"""Tests for hemlock.mcp_oauth (v9.6)."""

from __future__ import annotations

from hemlock.mcp_oauth import (
    generate_pkce_pair,
    McpOAuthStore,
    McpOAuthTokenRecord,
    parse_www_authenticate_resource_metadata,
)


def test_parse_www_authenticate():
    www = 'Bearer resource_metadata="https://imap-mcp.multipli.com.br/.well-known/oauth-protected-resource/mcp"'
    assert parse_www_authenticate_resource_metadata(www).endswith("/mcp")


def test_pkce_pair_length():
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) > 20
    assert len(challenge) > 20


def test_oauth_store_roundtrip(tmp_path):
    store_path = tmp_path / "store.json"
    store = McpOAuthStore(str(store_path))
    store.put_token(
        McpOAuthTokenRecord(
            resource="https://imap-mcp.multipli.com.br/mcp",
            access_token="abc",
            refresh_token="ref",
            expires_at=9999999999.0,
            obtained_at="t",
            client_id="cid",
        )
    )
    loaded = store.get_token("https://imap-mcp.multipli.com.br/mcp")
    assert loaded is not None
    assert loaded.access_token == "abc"
    assert store.get_valid_access_token("https://imap-mcp.multipli.com.br/mcp") == "abc"
