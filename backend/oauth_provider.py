"""Co-hosted OAuth 2.1 authorization provider for MCP-app.

The official MCP SDK implements DCR, redirect URI validation, PKCE S256,
authorization-code exchange, refresh handling, and OAuth metadata. This module
implements *only* the storage/consent hooks that the SDK delegates to us.

First stage: state is intentionally process-local. A new Quick Tunnel hostname
starts a new process and cannot reuse registrations or tokens from an old
resource URL. Stable persistent authorization will be added separately.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from .oauth_store import OAuthStore
except ImportError:
    from oauth_store import OAuthStore
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

READ_SCOPE = "mcp:read"
CODE_SECONDS = 300
ACCESS_SECONDS = 3600
REFRESH_SECONDS = 7 * 24 * 3600
MAX_CLIENTS = 128
MAX_PENDING = 64
MAX_FORM_BYTES = 4096
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    # no-referrer makes Origin: null on same-origin HTML form POST in browsers.
    # same-origin retains the correct Origin for consent POST, while preventing
    # Referer disclosure to the OAuth client's cross-origin redirect URI.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
}


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class PendingConsent:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0


class LocalConsentOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """No automatic approval: owner must type the existing app token to consent.

    Tokens issued to OAuth clients have only mcp:read. For now OAuth and
    administrative tools cannot be enabled together in the same server.
    """

    def __init__(
        self, issuer: str, resource_url: str, owner_secret: str,
        store_path: str | Path | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.resource_url = resource_url.rstrip("/")
        self._owner_secret = owner_secret
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, PendingConsent] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.access: dict[str, AccessToken] = {}
        self.refresh: dict[str, RefreshToken] = {}
        self._families: dict[str, str] = {}
        self.store = OAuthStore(store_path, self.issuer, self.resource_url) if store_path else None
        if self.store:
            self.store.remove_old_quick_tunnels()
            self.store.bind_owner(owner_secret)
            self.store.prune_expired()

    def _cleanup(self) -> None:
        now = time.time()
        for data, expiry in (
            (self.pending, lambda x: x.expires_at),
            (self.codes, lambda x: x.expires_at),
            (self.access, lambda x: x.expires_at),
            (self.refresh, lambda x: x.expires_at),
        ):
            for key, value in list(data.items()):
                end = expiry(value)
                if end is not None and end < now:
                    del data[key]
                    self._families.pop(key, None)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        # Re-read SQLite on every access: GUI revocation must take effect without
        # an application/server restart, even for already authenticated clients.
        return self.store.get_client(client_id) if self.store else self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if (self.store.count_clients() if self.store else len(self.clients)) >= MAX_CLIENTS:
            raise RegistrationError("invalid_client_metadata", "Registration capacity reached")
        if not client_info.client_id or client_info.client_id in self.clients:
            raise RegistrationError("invalid_client_metadata", "Invalid client identifier")
        if self.store:
            self.store.save_client(client_info)
        else:
            self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._cleanup()
        if self.store and not self.store.get_client(client.client_id or ""):
            raise AuthorizeError("unauthorized_client", "Client registration revoked")
        if params.resource is not None and params.resource.rstrip("/") != self.resource_url:
            raise AuthorizeError("invalid_target", "The requested resource is not this MCP server")
        if params.scopes and set(params.scopes) != {READ_SCOPE}:
            raise AuthorizeError("invalid_scope", "Only the read-only MCP scope is available")
        if len(self.pending) >= MAX_PENDING:
            raise AuthorizeError("temporarily_unavailable", "Too many pending authorization requests")
        ticket = secrets.token_urlsafe(32)
        self.pending[token_digest(ticket)] = PendingConsent(
            client=client, params=params, expires_at=time.time() + CODE_SECONDS
        )
        return f"{self.issuer}/oauth/consent?{urlencode({'request_id': ticket})}"

    def _code_for(self, pending: PendingConsent) -> str:
        assert pending.client.client_id
        code = secrets.token_urlsafe(32)
        self.codes[token_digest(code)] = AuthorizationCode(
            code=code,
            client_id=pending.client.client_id,
            scopes=[READ_SCOPE],
            expires_at=time.time() + CODE_SECONDS,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=self.resource_url,
            subject="local-owner",
        )
        return code

    async def consent(self, request: Request) -> Response:
        """HTTP consent route registered through MCPServer.custom_route.

        No secret in URLs, cookies, HTML attributes or access logs. The form
        explicitly demands the owner-held token and rejects cross-origin POSTs.
        """
        if request.method == "GET":
            ticket = request.query_params.get("request_id", "")
            pending = self.pending.get(token_digest(ticket))
            self._cleanup()
            if not pending or pending.expires_at < time.time():
                return HTMLResponse("Authorization request expired.", status_code=410, headers=SECURITY_HEADERS)
            display_name = html.escape(pending.client.client_name or pending.client.client_id or "Unknown client")
            display_uri = html.escape(str(pending.params.redirect_uri))
            safe_ticket = html.escape(ticket, quote=True)
            page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize MCP app</title></head>
<body><main><h1>Authorize MCP app access</h1>
<p>Client: <strong>{display_name}</strong></p>
<p>Return address: <code>{display_uri}</code></p>
<p>Permission: <strong>mcp:read</strong> — only safe tools in Standard profile.</p>
<p>Type the owner token shown in your MCP app. Never share this token with the requesting client.</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="request_id" value="{safe_ticket}">
<label>Owner token <input type="password" name="owner_token" autocomplete="off" required></label>
<button type="submit" name="decision" value="allow">Allow read-only access</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></main></body></html>"""
            return HTMLResponse(page, headers=SECURITY_HEADERS)
        if request.method != "POST":
            return Response(status_code=405, headers=SECURITY_HEADERS)
        # Explicit same-origin browser request, including the HTTPS tunnel origin.
        if request.headers.get("origin", "") != self.issuer:
            return Response("Invalid request origin", status_code=403, headers=SECURITY_HEADERS)
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return Response(status_code=415, headers=SECURITY_HEADERS)
        if int(request.headers.get("content-length", "0") or "0") > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        from urllib.parse import parse_qs
        try:
            fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        except (ValueError, UnicodeError):
            return Response(status_code=400, headers=SECURITY_HEADERS)
        ticket = (fields.get("request_id") or [""])[0]
        digest = token_digest(ticket)
        pending = self.pending.get(digest)
        self._cleanup()
        if not pending or pending.expires_at < time.time():
            return Response("Authorization request expired.", status_code=410, headers=SECURITY_HEADERS)
        decision = (fields.get("decision") or [""])[0]
        target = str(pending.params.redirect_uri)
        state = pending.params.state
        if decision == "deny":
            del self.pending[digest]
            return RedirectResponse(
                construct_redirect_uri(target, error="access_denied", state=state),
                status_code=303, headers=SECURITY_HEADERS,
            )
        if decision != "allow":
            return Response(status_code=400, headers=SECURITY_HEADERS)
        if self.store and not self.store.get_client(pending.client.client_id or ""):
            del self.pending[digest]
            return Response("Client access revoked.", status_code=403, headers=SECURITY_HEADERS)
        candidate = (fields.get("owner_token") or [""])[0]
        if not hmac.compare_digest(candidate.encode(), self._owner_secret.encode()):
            pending.attempts += 1
            if pending.attempts >= 5:
                del self.pending[digest]
            return Response("Owner token incorrect.", status_code=403, headers=SECURITY_HEADERS)
        del self.pending[digest]
        code = self._code_for(pending)
        return RedirectResponse(
            construct_redirect_uri(target, code=code, state=state, iss=self.issuer),
            status_code=303, headers=SECURITY_HEADERS,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        self._cleanup()
        value = self.codes.get(token_digest(authorization_code))
        return value if value and value.client_id == client.client_id else None

    def _issue_tokens(self, client_id: str, scopes: list[str], family: str) -> OAuthToken:
        now = int(time.time())
        raw_access = secrets.token_urlsafe(32)
        raw_refresh = secrets.token_urlsafe(32)
        akey = token_digest(raw_access)
        rkey = token_digest(raw_refresh)
        self.access[akey] = AccessToken(
            token=raw_access, client_id=client_id, scopes=scopes,
            expires_at=now + ACCESS_SECONDS, resource=self.resource_url, subject="local-owner",
        )
        self.refresh[rkey] = RefreshToken(
            token=raw_refresh, client_id=client_id, scopes=scopes,
            expires_at=now + REFRESH_SECONDS, resource=self.resource_url, subject="local-owner",
        )
        self._families[akey] = family
        self._families[rkey] = family
        if self.store:
            # Persist tokens before responding to the client.
            self.store.save_token(self.access[akey], "access", family)
            self.store.save_token(self.refresh[rkey], "refresh", family)
            self.store.mark_approved(client_id)
        return OAuthToken(
            access_token=raw_access, refresh_token=raw_refresh,
            expires_in=ACCESS_SECONDS, token_type="Bearer", scope=" ".join(scopes),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        key = token_digest(authorization_code.code)
        original = self.codes.pop(key, None)
        if (
            not original or original.client_id != client.client_id
            or original.expires_at < time.time() or original != authorization_code
        ):
            raise TokenError("invalid_grant", "Invalid or already used authorization code")
        if self.store and not self.store.get_client(client.client_id):
            raise TokenError("invalid_grant", "Client registration revoked")
        return self._issue_tokens(client.client_id, original.scopes, secrets.token_urlsafe(16))

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Existing manually configured Bearer tokens continue to work.
        if hmac.compare_digest(token.encode(), self._owner_secret.encode()):
            return AccessToken(
                token=token, client_id="mcp-app-user", scopes=[READ_SCOPE],
                resource=self.resource_url, subject="local-owner",
            )
        self._cleanup()
        if self.store:
            return self.store.get_token(token, "access")
        return self.access.get(token_digest(token))

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        self._cleanup()
        value = (
            self.store.get_token(refresh_token, "refresh")
            if self.store else self.refresh.get(token_digest(refresh_token))
        )
        return value if value and value.client_id == client.client_id else None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        key = token_digest(refresh_token.token)
        original = self.store.get_token(refresh_token.token, "refresh") if self.store else self.refresh.get(key)
        if (
            not original or original != refresh_token or original.client_id != client.client_id
            or original.expires_at is not None and original.expires_at < time.time()
        ):
            raise TokenError("invalid_grant", "Refresh token expired or already used")
        if not set(scopes).issubset(set(original.scopes)):
            raise TokenError("invalid_scope", "Cannot elevate token permissions")
        family = (
            self.store.consume_refresh(refresh_token.token, client.client_id)
            if self.store else self._families.get(key, "")
        )
        if not family:
            raise TokenError("invalid_grant", "Token family not found")
        self._remove_family(family)
        if self.store and not self.store.get_client(client.client_id):
            raise TokenError("invalid_grant", "Client registration revoked")
        return self._issue_tokens(client.client_id, scopes, family)

    def _remove_family(self, family: str) -> None:
        if self.store:
            self.store.revoke_family(family)
        for key, value in list(self._families.items()):
            if value == family:
                self.access.pop(key, None)
                self.refresh.pop(key, None)
                del self._families[key]

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        family = self.store.family(token.token) if self.store else self._families.get(token_digest(token.token))
        if family:
            self._remove_family(family)
