"""MCP OAuth 2.1 client — real user-delegated tokens for protected MCP resources (v9.6).

Discovers OAuth protected-resource metadata (WWW-Authenticate), registers a public
client, runs authorization_code + PKCE login in the browser, and stores tokens
for hemlock mcp-audit.

Multipli deployment uses https://auth.multipli.com.br with per-resource tokens.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

_RESOURCE_METADATA_RE = re.compile(r'resource_metadata="([^"]+)"', re.I)


@dataclass
class OAuthProtectedResourceMetadata:
    resource: str
    authorization_servers: list[str]
    bearer_methods_supported: list[str] = field(default_factory=list)


@dataclass
class OAuthServerMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None = None
    code_challenge_methods_supported: list[str] = field(default_factory=list)


@dataclass
class McpOAuthTokenRecord:
    resource: str
    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    obtained_at: str = ""
    client_id: str = ""


@dataclass
class McpOAuthClientRecord:
    auth_server: str
    client_id: str
    redirect_uri: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def parse_www_authenticate_resource_metadata(www_authenticate: str) -> str | None:
    match = _RESOURCE_METADATA_RE.search(www_authenticate)
    return match.group(1) if match else None


def discover_resource_metadata_from_mcp_url(mcp_url: str, timeout: float = 15.0) -> str | None:
    """Probe MCP URL and parse WWW-Authenticate resource_metadata URL."""
    try:
        response = httpx.get(mcp_url, timeout=timeout, follow_redirects=True)
        www = response.headers.get("www-authenticate", "")
        if www:
            return parse_www_authenticate_resource_metadata(www)
    except httpx.HTTPStatusError as exc:
        www = exc.response.headers.get("www-authenticate", "")
        return parse_www_authenticate_resource_metadata(www) if www else None
    except httpx.RequestError:
        return None
    return None


def fetch_protected_resource_metadata(metadata_url: str, timeout: float = 15.0) -> OAuthProtectedResourceMetadata:
    response = httpx.get(metadata_url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    data = response.json()
    return OAuthProtectedResourceMetadata(
        resource=str(data.get("resource", "")),
        authorization_servers=list(data.get("authorization_servers", [])),
        bearer_methods_supported=list(data.get("bearer_methods_supported", [])),
    )


def fetch_oauth_server_metadata(authorization_server: str, timeout: float = 15.0) -> OAuthServerMetadata:
    base = authorization_server.rstrip("/")
    candidates = [
        f"{base}/.well-known/openid-configuration",
        f"{base}/.well-known/oauth-authorization-server",
    ]
    for url in candidates:
        try:
            response = httpx.get(url, timeout=timeout)
            if response.status_code != 200:
                continue
            data = response.json()
            if data.get("authorization_endpoint") and data.get("token_endpoint"):
                return OAuthServerMetadata(
                    issuer=str(data.get("issuer", base)),
                    authorization_endpoint=str(data["authorization_endpoint"]),
                    token_endpoint=str(data["token_endpoint"]),
                    registration_endpoint=data.get("registration_endpoint"),
                    code_challenge_methods_supported=list(
                        data.get("code_challenge_methods_supported", [])
                    ),
                )
        except (httpx.HTTPError, json.JSONDecodeError):
            continue
    raise RuntimeError(f"Could not discover OAuth metadata for {authorization_server}")


def register_public_client(
    registration_endpoint: str,
    redirect_uri: str,
    client_name: str = "hemlock-mcp-audit",
    timeout: float = 20.0,
) -> str:
    payload = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    response = httpx.post(registration_endpoint, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    client_id = data.get("client_id")
    if not client_id:
        raise RuntimeError("registration response missing client_id")
    return str(client_id)


def build_authorization_url(
    metadata: OAuthServerMetadata,
    client_id: str,
    redirect_uri: str,
    resource: str,
    state: str,
    code_challenge: str,
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }
    return str(httpx.URL(metadata.authorization_endpoint, params=params))


def exchange_authorization_code(
    metadata: OAuthServerMetadata,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    resource: str,
    timeout: float = 20.0,
) -> McpOAuthTokenRecord:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
        "resource": resource,
    }
    response = httpx.post(metadata.token_endpoint, data=data, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    expires_in = body.get("expires_in")
    expires_at = time.time() + float(expires_in) if expires_in else None
    return McpOAuthTokenRecord(
        resource=resource,
        access_token=str(body["access_token"]),
        refresh_token=body.get("refresh_token"),
        expires_at=expires_at,
        obtained_at=_now_iso(),
        client_id=client_id,
    )


def refresh_access_token(
    metadata: OAuthServerMetadata,
    client_id: str,
    refresh_token: str,
    resource: str,
    timeout: float = 20.0,
) -> McpOAuthTokenRecord:
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "resource": resource,
    }
    response = httpx.post(metadata.token_endpoint, data=data, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    expires_in = body.get("expires_in")
    expires_at = time.time() + float(expires_in) if expires_in else None
    return McpOAuthTokenRecord(
        resource=resource,
        access_token=str(body["access_token"]),
        refresh_token=body.get("refresh_token") or refresh_token,
        expires_at=expires_at,
        obtained_at=_now_iso(),
        client_id=client_id,
    )


class McpOAuthStore:
    """Persist OAuth clients and tokens under .hemlock/."""

    def __init__(self, path: str = ".hemlock/mcp_oauth_store.json") -> None:
        self.path = Path(path)
        self._data: dict[str, Any] = {"clients": {}, "tokens": {}}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {"clients": {}, "tokens": {}}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def get_client(self, auth_server: str) -> McpOAuthClientRecord | None:
        row = self._data.get("clients", {}).get(auth_server)
        if not row:
            return None
        return McpOAuthClientRecord(
            auth_server=auth_server,
            client_id=str(row["client_id"]),
            redirect_uri=str(row["redirect_uri"]),
        )

    def put_client(self, record: McpOAuthClientRecord) -> None:
        self._data.setdefault("clients", {})[record.auth_server] = {
            "client_id": record.client_id,
            "redirect_uri": record.redirect_uri,
        }
        self.save()

    def get_token(self, resource: str) -> McpOAuthTokenRecord | None:
        row = self._data.get("tokens", {}).get(resource)
        if not row:
            return None
        return McpOAuthTokenRecord(
            resource=resource,
            access_token=str(row["access_token"]),
            refresh_token=row.get("refresh_token"),
            expires_at=row.get("expires_at"),
            obtained_at=str(row.get("obtained_at", "")),
            client_id=str(row.get("client_id", "")),
        )

    def put_token(self, record: McpOAuthTokenRecord) -> None:
        self._data.setdefault("tokens", {})[record.resource] = {
            "access_token": record.access_token,
            "refresh_token": record.refresh_token,
            "expires_at": record.expires_at,
            "obtained_at": record.obtained_at,
            "client_id": record.client_id,
        }
        self.save()

    def list_tokens(self) -> list[McpOAuthTokenRecord]:
        out: list[McpOAuthTokenRecord] = []
        for resource in self._data.get("tokens", {}):
            token = self.get_token(resource)
            if token:
                out.append(token)
        return out

    def get_valid_access_token(
        self,
        resource: str,
        metadata: OAuthServerMetadata | None = None,
        auth_server: str | None = None,
    ) -> str | None:
        record = self.get_token(resource)
        if not record:
            return None
        if record.expires_at and time.time() >= record.expires_at - 60:
            if not record.refresh_token:
                return None
            server = auth_server or (metadata.issuer if metadata else None)
            if not server:
                return None
            client = self.get_client(server)
            if not client or not metadata:
                return None
            refreshed = refresh_access_token(
                metadata,
                client.client_id,
                record.refresh_token,
                resource,
            )
            refreshed.client_id = client.client_id
            self.put_token(refreshed)
            return refreshed.access_token
        return record.access_token


class _OAuthCallbackServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.code: str | None = None
        self.state: str | None = None
        self.error: str | None = None
        self._server: HTTPServer | None = None

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                params = parse_qs(parsed.query)
                server.code = params.get("code", [None])[0]
                server.state = params.get("state", [None])[0]
                server.error = params.get("error", [None])[0]
                body = b"<html><body><h1>Hemlock OAuth OK</h1><p>You can close this tab.</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                threading.Thread(target=server._server.shutdown, daemon=True).start()

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def wait_for_callback(self, timeout: float = 180.0) -> None:
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._server.timeout = 1.0
        deadline = time.time() + timeout
        while time.time() < deadline and self.code is None and self.error is None:
            self._server.handle_request()
        if self._server:
            self._server.server_close()


def interactive_oauth_login(
    resource: str,
    *,
    mcp_url: str | None = None,
    redirect_port: int = 8765,
    store_path: str = ".hemlock/mcp_oauth_store.json",
    open_browser: bool = True,
) -> McpOAuthTokenRecord:
    """Run browser OAuth login for an MCP protected resource."""
    metadata_url: str | None = None
    if mcp_url:
        metadata_url = discover_resource_metadata_from_mcp_url(mcp_url)
    if not metadata_url:
        # fallback: well-known path on resource host
        parsed = urlparse(resource)
        metadata_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource/mcp"

    protected = fetch_protected_resource_metadata(metadata_url)
    if not protected.authorization_servers:
        raise RuntimeError("No authorization_servers in protected resource metadata")
    auth_server = protected.authorization_servers[0]
    oauth_meta = fetch_oauth_server_metadata(auth_server)

    store = McpOAuthStore(store_path)
    redirect_uri = f"http://127.0.0.1:{redirect_port}/callback"
    client = store.get_client(auth_server)
    if not client:
        if not oauth_meta.registration_endpoint:
            raise RuntimeError("OAuth server has no registration_endpoint")
        client_id = register_public_client(oauth_meta.registration_endpoint, redirect_uri)
        client = McpOAuthClientRecord(auth_server=auth_server, client_id=client_id, redirect_uri=redirect_uri)
        store.put_client(client)

    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    auth_url = build_authorization_url(
        oauth_meta,
        client.client_id,
        client.redirect_uri,
        protected.resource or resource,
        state,
        challenge,
    )

    callback = _OAuthCallbackServer("127.0.0.1", redirect_port)
    if open_browser:
        webbrowser.open(auth_url)

    callback.wait_for_callback()
    if callback.error:
        raise RuntimeError(f"OAuth error: {callback.error}")
    if not callback.code:
        raise RuntimeError("OAuth login timed out — no authorization code received")
    if callback.state != state:
        raise RuntimeError("OAuth state mismatch")

    token = exchange_authorization_code(
        oauth_meta,
        client.client_id,
        client.redirect_uri,
        callback.code,
        verifier,
        protected.resource or resource,
    )
    token.client_id = client.client_id
    store.put_token(token)
    return token


def resolve_oauth_access_token(
    resource: str,
    store_path: str = ".hemlock/mcp_oauth_store.json",
) -> str | None:
    """Return a valid access token for resource from store (refresh if needed)."""
    store = McpOAuthStore(store_path)
    record = store.get_token(resource)
    if not record:
        return None
    protected = fetch_protected_resource_metadata(
        f"{urlparse(resource).scheme}://{urlparse(resource).netloc}/.well-known/oauth-protected-resource/mcp"
    )
    auth_server = protected.authorization_servers[0]
    oauth_meta = fetch_oauth_server_metadata(auth_server)
    return store.get_valid_access_token(resource, metadata=oauth_meta, auth_server=auth_server)
