"""Co-hosted OAuth 2.1 authorization provider for MCP-app.

The official MCP SDK implements DCR, redirect URI validation, PKCE S256,
authorization-code exchange, refresh handling, and OAuth metadata. This module
implements *only* the storage/consent hooks and consent UI/redirect handling.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from app.core.logging_manager import get_logging_manager

try:
    from .oauth_store import OAuthStore, canonical_oauth_urls
except ImportError:
    from oauth_store import OAuthStore, canonical_oauth_urls

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
CSRF_COOKIE_NAME = "mcp_oauth_csrf"

_FORBIDDEN_REDIRECT_SCHEMES = frozenset({"javascript", "data", "vbscript", "blob", "file", "about"})

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    # no-referrer makes Origin: null on same-origin HTML form POST in browsers.
    # same-origin retains the correct Origin for consent POST, while preventing
    # Referer disclosure to the OAuth client's cross-origin redirect URI.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_origin(url: str) -> str:
    """Normalize HTTP/HTTPS origin (lowercased host, default ports stripped, IPv6 bracketed)."""
    raw = (url or "").strip()
    if not raw or raw.lower() == "null":
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    host_lit = f"[{host}]" if ":" in host else host
    netloc = f"{host_lit}:{port}" if port else host_lit
    return f"{scheme}://{netloc}"


def _form_action_source_for_redirect(redirect_uri: str | None) -> str:
    """Return a single safe CSP ``form-action`` source for a validated client ``redirect_uri``."""
    raw = str(redirect_uri or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    scheme = (parts.scheme or "").lower()
    if not scheme or scheme in _FORBIDDEN_REDIRECT_SCHEMES:
        return ""
    if scheme in ("http", "https"):
        return _canonical_origin(raw)
    # Native custom schemes (vscode://, cursor://, chatgpt://) require scheme-source form `scheme:` in CSP3.
    if scheme[0].isalpha() and all(ch.isalnum() or ch in "+-." for ch in scheme):
        return f"{scheme}:"
    return ""


def consent_security_headers(redirect_uri: str | None = None) -> dict[str, str]:
    """Build security headers, scoping ``form-action`` only to `'self'` and one client callback origin.

    Chromium browsers (Chrome, Edge, Electron) check ``form-action`` on 303 redirect targets after
    form POST. Without the client's validated callback origin here, Chromium blocks the OAuth callback.
    """
    headers = dict(SECURITY_HEADERS)
    extra = _form_action_source_for_redirect(redirect_uri)
    if extra:
        headers["Content-Security-Policy"] = (
            f"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {extra}; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
    return headers


def _render_error_html(
    title: str,
    heading: str,
    message: str,
    *,
    hint: str = "",
    retry_form_html: str = "",
) -> str:
    safe_title = html.escape(title)
    safe_heading = html.escape(heading)
    safe_msg = html.escape(message)
    hint_block = f"<p class='hint'>{html.escape(hint)}</p>" if hint else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_title}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background:#0f1115; color:#e6e8ec; margin:0; padding:32px 16px; }}
  main {{ max-width:520px; margin:0 auto; background:#171a21; border:1px solid #2b313d; border-radius:12px; padding:24px; }}
  h1 {{ margin:0 0 12px; font-size:20px; color:#ff7b72; }}
  p {{ line-height:1.5; color:#c9d1d9; }}
  .hint {{ font-size:13px; color:#8b949e; }}
  label {{ display:block; margin:14px 0 8px; font-weight:600; }}
  input[type=password] {{ width:100%; box-sizing:border-box; padding:10px; border-radius:8px; border:1px solid #30363d; background:#0d1117; color:#f0f6fc; }}
  .actions {{ margin-top:14px; display:flex; gap:10px; }}
  button {{ padding:9px 16px; border-radius:8px; border:0; cursor:pointer; font-weight:600; }}
  button[value=allow] {{ background:#238636; color:#fff; }}
  button[value=deny] {{ background:#30363d; color:#e6e8ec; }}
</style>
</head>
<body><main>
<h1>{safe_heading}</h1>
<p>{safe_msg}</p>
{hint_block}
{retry_form_html}
</main></body></html>"""


@dataclass
class PendingConsent:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))


class LocalConsentOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """No automatic approval: owner must type the existing app token to consent.

    Tokens issued to OAuth clients have only mcp:read.
    """

    def __init__(
        self,
        issuer: str,
        resource_url: str,
        owner_secret: str,
        store_path: str | Path | None = None,
        default_profile: str | None = None,
    ) -> None:
        canon_issuer, canon_resource = canonical_oauth_urls(resource_url or issuer)
        if canon_issuer and (not issuer or canonical_oauth_urls(issuer)[0] == canon_issuer):
            self.issuer = canon_issuer
            self.resource_url = canon_resource
        else:
            self.issuer = issuer.rstrip("/")
            self.resource_url = resource_url.rstrip("/")
        self._canonical_issuer_origin = _canonical_origin(self.issuer)
        self._owner_secret = owner_secret
        self._default_profile = default_profile
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

    @staticmethod
    def _log_oauth(level: str, event_code: str, message: str, *, req_id: str = "-") -> None:
        try:
            lm = get_logging_manager()
            lm.log("oauth", level, message, event_code=event_code, request_id=req_id)
        except Exception:  # noqa: BLE001
            pass

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
        return self.store.get_client(client_id) if self.store else self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if (self.store.count_clients() if self.store else len(self.clients)) >= MAX_CLIENTS:
            self._log_oauth("WARNING", "oauth_register_capacity", "DCR registration rejected: capacity reached")
            raise RegistrationError("invalid_client_metadata", "Registration capacity reached")
        if not client_info.client_id or client_info.client_id in self.clients:
            self._log_oauth("WARNING", "oauth_register_invalid_id", "DCR registration rejected: invalid client_id")
            raise RegistrationError("invalid_client_metadata", "Invalid client identifier")
        if self.store:
            self.store.save_client(client_info)
        else:
            self.clients[client_info.client_id] = client_info
        self._log_oauth(
            "INFO",
            "oauth_client_registered",
            f"Registered OAuth client_id={client_info.client_id} name={client_info.client_name or '-'}",
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._cleanup()
        cid = client.client_id or ""
        if self.store and not self.store.get_client(cid):
            self._log_oauth("WARNING", "oauth_authorize_revoked", f"Authorize rejected for revoked client_id={cid}")
            raise AuthorizeError("unauthorized_client", "Client registration revoked")
        if params.resource is not None:
            raw_res = params.resource.rstrip("/")
            _, canon_res = canonical_oauth_urls(params.resource)
            if raw_res != self.resource_url and canon_res != self.resource_url:
                self._log_oauth(
                    "WARNING",
                    "oauth_resource_mismatch",
                    f"Authorize rejected: resource mismatch client_id={cid} requested={canon_res or raw_res} expected={self.resource_url}",
                )
                raise AuthorizeError("invalid_target", "The requested resource is not this MCP server")
        if params.scopes and set(params.scopes) != {READ_SCOPE}:
            self._log_oauth("WARNING", "oauth_invalid_scope", f"Authorize rejected: invalid scope client_id={cid}")
            raise AuthorizeError("invalid_scope", "Only the read-only MCP scope is available")
        if len(self.pending) >= MAX_PENDING:
            self._log_oauth("WARNING", "oauth_pending_limit", "Authorize rejected: too many pending authorization requests")
            raise AuthorizeError("temporarily_unavailable", "Too many pending authorization requests")
        ticket = secrets.token_urlsafe(32)
        req_prefix = token_digest(ticket)[:12]
        self.pending[token_digest(ticket)] = PendingConsent(
            client=client, params=params, expires_at=time.time() + CODE_SECONDS
        )
        self._log_oauth(
            "INFO",
            "oauth_consent_created",
            f"Created OAuth consent session client_id={cid} redirect_origin={_form_action_source_for_redirect(str(params.redirect_uri))}",
            req_id=req_prefix,
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

    def _consent_form_html(
        self,
        pending: PendingConsent,
        ticket: str,
        *,
        error_note: str = "",
    ) -> str:
        display_name = html.escape(pending.client.client_name or pending.client.client_id or "Unknown client")
        display_uri = html.escape(str(pending.params.redirect_uri))
        safe_ticket = html.escape(ticket, quote=True)
        safe_csrf = html.escape(pending.csrf_token, quote=True)
        mode = "safe"
        if self.store:
            try:
                from .oauth_execution import ExecutionApprovals
            except ImportError:
                from oauth_execution import ExecutionApprovals
            profiles = ExecutionApprovals(self.store, default_profile=self._default_profile)
            mode = (
                profiles.profile_for(pending.client.client_id)
                if profiles.client_approved(pending.client.client_id)
                else profiles.profile()
            )
        descriptions = {
            "safe": "Safe: only server_info; no command execution.",
            "allowlist": (
                "Allowlist: Windows and SSH commands matching the owner's "
                "exact allowlists run immediately without confirmation."
            ),
            "full": (
                "FULL ACCESS: arbitrary Windows and SSH commands can run "
                "immediately with the user's privileges. HIGH RISK."
            ),
        }
        mode_description = html.escape(descriptions.get(mode, descriptions["safe"]))
        err_html = f"<p style='color:#ff7b72;font-weight:600'>{html.escape(error_note)}</p>" if error_note else ""
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize MCP app</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background:#0f1115; color:#e6e8ec; margin:0; padding:32px 16px; }}
  main {{ max-width:540px; margin:0 auto; background:#171a21; border:1px solid #2b313d; border-radius:12px; padding:24px; }}
  h1 {{ margin:0 0 12px; font-size:20px; }}
  p {{ line-height:1.5; color:#c9d1d9; }}
  code {{ background:#0d1117; padding:2px 6px; border-radius:4px; word-break:break-all; }}
  label {{ display:block; margin:14px 0 8px; font-weight:600; }}
  input[type=password] {{ width:100%; box-sizing:border-box; padding:10px; border-radius:8px; border:1px solid #30363d; background:#0d1117; color:#f0f6fc; margin-top:6px; }}
  .actions {{ margin-top:14px; display:flex; gap:10px; }}
  button {{ padding:9px 16px; border-radius:8px; border:0; cursor:pointer; font-weight:600; }}
  button[value=allow] {{ background:#238636; color:#fff; }}
  button[value=deny] {{ background:#30363d; color:#e6e8ec; }}
</style></head>
<body><main><h1>Authorize MCP app access</h1>
{err_html}
<p>Client: <strong>{display_name}</strong></p>
<p>Return address: <code>{display_uri}</code></p>
<p>OAuth compatibility scope: <strong>mcp:read</strong>.</p>
<p>Current access scenario: <strong>{mode_description}</strong></p>
<p>The owner can change this scenario for the client in the Windows app later. Only authorize
clients you trust; never share the owner token with them.</p>
<p>Type the owner token shown in your MCP app. Never share this token with the requesting client.</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="request_id" value="{safe_ticket}">
<input type="hidden" name="csrf_token" value="{safe_csrf}">
<label>Owner token <input type="password" name="owner_token" autocomplete="off" required></label>
<div class="actions">
<button type="submit" name="decision" value="allow">Allow access</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</div>
</form></main></body></html>"""

    async def consent(self, request: Request) -> Response:
        """HTTP consent route registered through MCPServer.custom_route.

        No secret in URLs, cookies, HTML attributes or access logs. Dynamically allows only the
        single validated OAuth client ``redirect_uri`` in CSP ``form-action`` so Chromium browsers
        (Chrome/Edge) follow the cross-origin 303 redirect after consent form POST.
        """
        if request.method == "GET":
            ticket = request.query_params.get("request_id", "")
            req_prefix = token_digest(ticket)[:12] if ticket else "-"
            pending = self.pending.get(token_digest(ticket))
            self._cleanup()
            if not pending or pending.expires_at < time.time():
                self._log_oauth("WARNING", "oauth_consent_expired", "Consent GET rejected: expired or unknown request_id", req_id=req_prefix)
                expired_html = _render_error_html(
                    "Authorization expired",
                    "Authorization request expired",
                    "This authorization link has expired, was already used, or the MCP server restarted.",
                    hint="Return to your AI client and click Reconnect to start a fresh authorization.",
                )
                return HTMLResponse(expired_html, status_code=410, headers=SECURITY_HEADERS)
            target_uri = str(pending.params.redirect_uri)
            headers = consent_security_headers(target_uri)
            resp = HTMLResponse(self._consent_form_html(pending, ticket), headers=headers)
            resp.set_cookie(
                CSRF_COOKIE_NAME,
                pending.csrf_token,
                max_age=CODE_SECONDS,
                path="/oauth/consent",
                httponly=True,
                samesite="lax",
                secure=self.issuer.startswith("https://") or request.url.scheme == "https",
            )
            return resp

        if request.method != "POST":
            return Response(status_code=405, headers=SECURITY_HEADERS)

        origin_hdr = request.headers.get("origin", "")
        canon_req_origin = _canonical_origin(origin_hdr)
        if not canon_req_origin or canon_req_origin != self._canonical_issuer_origin:
            self._log_oauth(
                "WARNING",
                "oauth_origin_rejected",
                f"Consent POST rejected: origin mismatch got={canon_req_origin or origin_hdr!r} expected={self._canonical_issuer_origin!r}",
            )
            err_html = _render_error_html(
                "Invalid request",
                "Security check failed (Origin)",
                "This consent form rejected the request because its Origin header does not match the active MCP server.",
                hint=f"Expected origin: {self._canonical_issuer_origin}. Restart authorization from your AI client.",
            )
            return HTMLResponse(err_html, status_code=403, headers=SECURITY_HEADERS)

        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none"):
            self._log_oauth(
                "WARNING",
                "oauth_fetch_site_rejected",
                f"Consent POST rejected: Sec-Fetch-Site={sec_fetch_site!r}",
            )
            err_html = _render_error_html(
                "Invalid request",
                "Cross-site form submission blocked",
                "Browser security header Sec-Fetch-Site indicated a cross-site submission.",
            )
            return HTMLResponse(err_html, status_code=403, headers=SECURITY_HEADERS)

        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return Response(status_code=415, headers=SECURITY_HEADERS)
        if int(request.headers.get("content-length", "0") or "0") > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            return Response(status_code=413, headers=SECURITY_HEADERS)
        try:
            fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        except (ValueError, UnicodeError):
            self._log_oauth("WARNING", "oauth_malformed_form", "Consent POST rejected: malformed form encoding")
            return HTMLResponse(
                _render_error_html(
                    "Invalid request",
                    "Invalid form submission",
                    "The submitted form payload could not be decoded.",
                ),
                status_code=400,
                headers=SECURITY_HEADERS,
            )

        ticket = (fields.get("request_id") or [""])[0]
        digest = token_digest(ticket)
        req_prefix = digest[:12] if ticket else "-"
        pending = self.pending.get(digest)
        self._cleanup()
        if not pending or pending.expires_at < time.time():
            self._log_oauth("WARNING", "oauth_consent_expired", "Consent POST rejected: expired or missing pending request", req_id=req_prefix)
            return HTMLResponse(
                _render_error_html(
                    "Authorization expired",
                    "Authorization request expired",
                    "Authorization request expired or was already completed.",
                    hint="Click Reconnect in your AI client to obtain a fresh authorization link.",
                ),
                status_code=410,
                headers=SECURITY_HEADERS,
            )

        target = str(pending.params.redirect_uri)
        resp_headers = consent_security_headers(target)

        # Double-submit / server-bound CSRF check whenever browser sends form field or cookie.
        form_csrf = (fields.get("csrf_token") or [""])[0]
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME, "")
        if form_csrf or cookie_csrf:
            valid_form = bool(form_csrf) and hmac.compare_digest(form_csrf, pending.csrf_token)
            valid_cookie = (not cookie_csrf) or hmac.compare_digest(cookie_csrf, pending.csrf_token)
            if not (valid_form and valid_cookie):
                self._log_oauth("WARNING", "oauth_csrf_rejected", "Consent POST rejected: CSRF mismatch", req_id=req_prefix)
                return HTMLResponse(
                    _render_error_html(
                        "Invalid request",
                        "Security token mismatch",
                        "The consent form session token did not match. Reload the consent page or reconnect.",
                    ),
                    status_code=403,
                    headers=resp_headers,
                )

        decision = (fields.get("decision") or [""])[0]
        state = pending.params.state
        if decision == "deny":
            del self.pending[digest]
            self._log_oauth("INFO", "oauth_consent_denied", f"Owner denied client_id={pending.client.client_id}", req_id=req_prefix)
            return RedirectResponse(
                construct_redirect_uri(target, error="access_denied", state=state),
                status_code=303,
                headers=resp_headers,
            )
        if decision != "allow":
            return HTMLResponse(
                _render_error_html("Invalid request", "Invalid decision", "Unknown consent action."),
                status_code=400,
                headers=resp_headers,
            )
        if self.store and not self.store.get_client(pending.client.client_id or ""):
            del self.pending[digest]
            self._log_oauth("WARNING", "oauth_client_revoked", f"Consent POST rejected: client revoked client_id={pending.client.client_id}", req_id=req_prefix)
            return HTMLResponse(
                _render_error_html(
                    "Client revoked",
                    "Client access revoked",
                    "This client registration was revoked in MCP-app.",
                    hint="Reconnect from your AI client to register a new OAuth client.",
                ),
                status_code=403,
                headers=resp_headers,
            )

        candidate = (fields.get("owner_token") or [""])[0]
        if not hmac.compare_digest(candidate.encode(), self._owner_secret.encode()):
            pending.attempts += 1
            remaining = max(0, 5 - pending.attempts)
            self._log_oauth(
                "WARNING",
                "oauth_bad_owner_token",
                f"Incorrect owner token entered for client_id={pending.client.client_id} remaining_attempts={remaining}",
                req_id=req_prefix,
            )
            if pending.attempts >= 5:
                del self.pending[digest]
                return HTMLResponse(
                    _render_error_html(
                        "Too many attempts",
                        "Owner token incorrect (attempts exhausted)",
                        "Authorization cancelled after 5 incorrect attempts.",
                        hint="Check the MCP Owner Token in Connections and restart authorization in your AI client.",
                    ),
                    status_code=403,
                    headers=resp_headers,
                )
            retry_html = self._consent_form_html(
                pending,
                ticket,
                error_note=f"Incorrect MCP Owner Token ({remaining} attempts remaining).",
            )
            return HTMLResponse(retry_html, status_code=403, headers=resp_headers)

        del self.pending[digest]
        code = self._code_for(pending)
        self._log_oauth(
            "INFO",
            "oauth_consent_approved",
            f"OAuth consent approved client_id={pending.client.client_id} redirect_origin={_form_action_source_for_redirect(target)}",
            req_id=req_prefix,
        )
        return RedirectResponse(
            construct_redirect_uri(target, code=code, state=state, iss=self.issuer),
            status_code=303,
            headers=resp_headers,
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
            self._log_oauth("WARNING", "oauth_code_exchange_failed", f"Code exchange failed client_id={client.client_id}")
            raise TokenError("invalid_grant", "Invalid or already used authorization code")
        if self.store and not self.store.get_client(client.client_id):
            self._log_oauth("WARNING", "oauth_code_exchange_revoked", f"Code exchange rejected for revoked client_id={client.client_id}")
            raise TokenError("invalid_grant", "Client registration revoked")
        self._log_oauth("INFO", "oauth_token_issued", f"Issued OAuth token via auth code client_id={client.client_id}")
        return self._issue_tokens(client.client_id, original.scopes, secrets.token_urlsafe(16))

    async def load_access_token(self, token: str) -> AccessToken | None:
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
            self._log_oauth("WARNING", "oauth_refresh_failed", f"Refresh token rejected client_id={client.client_id}")
            raise TokenError("invalid_grant", "Refresh token expired or already used")
        if not set(scopes).issubset(set(original.scopes)):
            raise TokenError("invalid_scope", "Cannot elevate token permissions")
        family = (
            self.store.consume_refresh(refresh_token.token, client.client_id)
            if self.store else self._families.get(key, "")
        )
        if not family:
            self._log_oauth("WARNING", "oauth_refresh_family_missing", f"Refresh family missing client_id={client.client_id}")
            raise TokenError("invalid_grant", "Token family not found")
        self._remove_family(family)
        if self.store and not self.store.get_client(client.client_id):
            raise TokenError("invalid_grant", "Client registration revoked")
        self._log_oauth("INFO", "oauth_token_refreshed", f"Refreshed OAuth token client_id={client.client_id}")
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
            self._log_oauth("INFO", "oauth_token_revoked", f"Revoked OAuth token family={family[:8]}")
