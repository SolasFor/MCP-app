"""Automated MCP server discovery, runtime checks, HTTP/SSE probing, and OAuth PKCE onboarding."""
from __future__ import annotations

import asyncio
import http.server
import queue
import shutil
import socketserver
import sys
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)

from app.core.redaction import SecretRedactor, sanitize_child_env
from app.core.secret_store import SecretStore
from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_HEADERS,
    AUTH_NONE,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
    normalize_server_id,
)
from backend.gateway.security import validate_upstream_url


@dataclass(frozen=True)
class RuntimeCheckResult:
    ok: bool
    command: str
    resolved_executable: str = ""
    missing_runtime: str = ""
    package_source: str = ""
    install_hint_ru: str = ""
    install_hint_en: str = ""
    cwd_valid: bool = True
    error_message: str = ""


@dataclass(frozen=True)
class RemoteProbeResult:
    status: str  # ok | auth_required | error
    transport: str = TRANSPORT_STREAMABLE_HTTP
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tools: tuple[str, ...] = ()
    auth_kind: str = ""  # oauth | bearer | ""
    oauth_issuer: str = ""
    message: str = ""
    warnings: tuple[str, ...] = ()


def _extract_server_meta(init_res: Any, tools_res: Any) -> tuple[str, str, str, tuple[str, ...]]:
    """Read server metadata and tools cleanly across mcp SDK snake_case/camelCase versions."""
    srv_info = getattr(init_res, "server_info", None) or getattr(init_res, "serverInfo", None)
    srv_name = str(getattr(srv_info, "name", "") or "")
    srv_ver = str(getattr(srv_info, "version", "") or "")
    proto = str(
        getattr(init_res, "protocol_version", None)
        or getattr(init_res, "protocolVersion", "")
        or ""
    )
    tool_names = tuple(t.name for t in (getattr(tools_res, "tools", None) or ()))
    return srv_name, srv_ver, proto, tool_names


def extract_package_source(command: str, args: tuple[str, ...] | list[str]) -> str:
    """Identify upstream package ecosystem & identifier from stdio launch args."""
    exe = Path(command or "").stem.lower()
    arg_list = [str(a) for a in args]
    if exe in ("npx", "pnpx", "bunx"):
        for a in arg_list:
            if a.startswith("-"):
                continue
            return f"npm:{a}"
    if exe in ("uvx", "pipx"):
        for a in arg_list:
            if a.startswith("-"):
                continue
            return f"pypi:{a}"
    if exe in ("python", "python3", "py"):
        for idx, a in enumerate(arg_list):
            if a == "-m" and idx + 1 < len(arg_list):
                return f"python -m {arg_list[idx + 1]}"
            if not a.startswith("-"):
                return f"script:{a}"
    return Path(command).name if command else ""


def _resolve_command_executable(command: str) -> str:
    cmd = (command or "").strip()
    if not cmd:
        return ""
    p = Path(cmd)
    if p.is_file():
        return str(p)
    # In frozen PyInstaller app, never treat sys.executable (MCPApp.exe) as Python interpreter.
    exe_lower = Path(cmd).name.lower()
    if getattr(sys, "frozen", False) and exe_lower in ("python", "python.exe", "python3"):
        found = shutil.which("python") or shutil.which("python3") or shutil.which("py")
        return found or ""
    if not getattr(sys, "frozen", False) and exe_lower in ("python", "python.exe", "python3"):
        return sys.executable
    return shutil.which(cmd) or ""


def inspect_stdio_runtime(
    command: str,
    args: tuple[str, ...] | list[str] = (),
    cwd: str = "",
) -> RuntimeCheckResult:
    """Check whether required local runtime (`node`, `npx`, `uv`, `python`, `.exe`) and `cwd` exist."""
    pkg = extract_package_source(command, args)
    clean_cwd = (cwd or "").strip()
    if clean_cwd and not Path(clean_cwd).is_dir():
        return RuntimeCheckResult(
            ok=False,
            command=command,
            package_source=pkg,
            cwd_valid=False,
            error_message=f"Working directory does not exist: {clean_cwd}",
        )

    resolved = _resolve_command_executable(command)
    if resolved:
        return RuntimeCheckResult(
            ok=True,
            command=command,
            resolved_executable=resolved,
            package_source=pkg,
            cwd_valid=True,
        )

    exe = Path(command or "").stem.lower()
    if exe in ("node", "npx", "npm"):
        missing = "Node.js / npx"
        ru = "Установите Node.js LTS (включает npx): winget install OpenJS.NodeJS.LTS"
        en = "Install Node.js LTS (includes npx): winget install OpenJS.NodeJS.LTS"
    elif exe in ("uv", "uvx"):
        missing = "uv / uvx"
        ru = "Установите uv (включает uvx): winget install astral-sh.uv"
        en = "Install uv (includes uvx): winget install astral-sh.uv"
    elif exe in ("python", "python3", "py"):
        missing = "Python 3"
        ru = "Установите Python 3.12+: winget install Python.Python.3.12"
        en = "Install Python 3.12+: winget install Python.Python.3.12"
    else:
        missing = Path(command).name or command
        ru = f"Убедитесь, что `{missing}` установлен и добавлен в PATH, или укажите полный путь к .exe."
        en = f"Ensure `{missing}` is installed in PATH or specify full path to the executable."

    return RuntimeCheckResult(
        ok=False,
        command=command,
        resolved_executable="",
        missing_runtime=missing,
        package_source=pkg,
        install_hint_ru=ru,
        install_hint_en=en,
        cwd_valid=True,
        error_message=f"Runtime `{missing}` not found in PATH.",
    )


async def _detect_oauth_metadata(url: str, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Check whether endpoint advertises HTTP 401/WWW-Authenticate or RFC 9728 OAuth metadata."""
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    path_suffix = parts.path.rstrip("/")
    candidates = [
        f"{origin}/.well-known/oauth-protected-resource{path_suffix}",
        f"{origin}/.well-known/oauth-protected-resource",
        f"{origin}/.well-known/oauth-authorization-server",
    ]
    async with httpx.AsyncClient(verify=True, timeout=httpx.Timeout(timeout), follow_redirects=False) as client:
        for meta_url in candidates:
            try:
                resp = await client.get(meta_url)
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        auth_srv = data.get("authorization_servers")
                        if isinstance(auth_srv, list) and auth_srv:
                            return True, str(auth_srv[0])
                        if data.get("authorization_endpoint") and data.get("token_endpoint"):
                            return True, str(data.get("issuer") or origin)
                except ValueError:
                    pass
    return False, ""


async def _preflight_auth_status(url: str, headers: dict[str, str], *, timeout: float) -> tuple[int | None, str]:
    """Perform lightweight POST/GET check to detect HTTP 401/403 before session connect."""
    try:
        async with httpx.AsyncClient(verify=True, headers=headers, timeout=httpx.Timeout(timeout), follow_redirects=False) as client:
            resp = await client.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "mcp-app-probe", "version": "1.0"}}},
                headers={"Accept": "application/json, text/event-stream"},
            )
            return resp.status_code, resp.headers.get("www-authenticate", "")
    except Exception:  # noqa: BLE001
        return None, ""


async def probe_remote_mcp_url(
    url: str,
    *,
    bearer_token: str = "",
    headers: dict[str, str] | None = None,
    allow_local_endpoint: bool = False,
    allow_redirects: bool = False,
    timeout: float = 10.0,
) -> RemoteProbeResult:
    """Validate URL, detect Streamable HTTP vs legacy SSE, check auth, and query `initialize` + `tools/list`."""
    try:
        clean_url = validate_upstream_url(url, allow_local_endpoint=allow_local_endpoint)
    except ValueError as exc:
        return RemoteProbeResult(status="error", message=str(exc))

    req_headers: dict[str, str] = dict(headers or {})
    if bearer_token.strip():
        req_headers["Authorization"] = f"Bearer {bearer_token.strip()}"

    pre_status, www_auth = await _preflight_auth_status(clean_url, req_headers, timeout=min(timeout, 6.0))
    if pre_status in (401, 403):
        has_oauth, issuer = await _detect_oauth_metadata(clean_url, timeout=min(timeout, 5.0))
        if has_oauth or "bearer" in www_auth.lower():
            return RemoteProbeResult(
                status="auth_required",
                transport=TRANSPORT_STREAMABLE_HTTP,
                auth_kind="oauth" if has_oauth else "bearer",
                oauth_issuer=issuer,
                message=f"Server requires authentication (HTTP {pre_status}).",
            )
        return RemoteProbeResult(
            status="auth_required",
            transport=TRANSPORT_STREAMABLE_HTTP,
            auth_kind="bearer",
            message=f"Server denied unauthenticated probe (HTTP {pre_status}).",
        )

    last_err = ""
    for candidate_transport in (TRANSPORT_STREAMABLE_HTTP, TRANSPORT_SSE):
        try:
            async with httpx.AsyncClient(
                verify=True,
                headers=req_headers,
                follow_redirects=allow_redirects,
                timeout=httpx.Timeout(timeout),
            ) as http_client:
                if candidate_transport == TRANSPORT_STREAMABLE_HTTP:
                    async with streamable_http_client(clean_url, http_client=http_client) as (r_stream, w_stream):
                        async with ClientSession(r_stream, w_stream, read_timeout_seconds=timeout) as session:
                            init_res = await asyncio.wait_for(session.initialize(), timeout=timeout)
                            tools_res = await asyncio.wait_for(session.list_tools(), timeout=timeout)
                else:
                    def _sse_factory(
                        headers: dict[str, str] | None = None,
                        timeout: httpx.Timeout | None = None,
                        auth: httpx.Auth | None = None,
                    ) -> httpx.AsyncClient:
                        kw: dict[str, Any] = {
                            "verify": True,
                            "follow_redirects": allow_redirects,
                            "timeout": timeout or httpx.Timeout(10.0),
                        }
                        if headers is not None:
                            kw["headers"] = headers
                        if auth is not None:
                            kw["auth"] = auth
                        return httpx.AsyncClient(**kw)

                    async with sse_client(
                        clean_url,
                        headers=req_headers,
                        timeout=min(timeout, 10.0),
                        sse_read_timeout=max(timeout, 30.0),
                        httpx_client_factory=_sse_factory,
                    ) as (r_stream, w_stream):
                        async with ClientSession(r_stream, w_stream, read_timeout_seconds=timeout) as session:
                            init_res = await asyncio.wait_for(session.initialize(), timeout=timeout)
                            tools_res = await asyncio.wait_for(session.list_tools(), timeout=timeout)

                srv_name, srv_ver, proto, tool_names = _extract_server_meta(init_res, tools_res)
                return RemoteProbeResult(
                    status="ok",
                    transport=candidate_transport,
                    server_name=srv_name,
                    server_version=srv_ver,
                    protocol_version=proto,
                    tools=tool_names,
                    message="Connected and verified MCP compatibility.",
                )
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            if "401" in text or "403" in text or "unauthorized" in text.lower():
                has_oauth, issuer = await _detect_oauth_metadata(clean_url, timeout=min(timeout, 5.0))
                return RemoteProbeResult(
                    status="auth_required",
                    transport=candidate_transport,
                    auth_kind="oauth" if has_oauth else "bearer",
                    oauth_issuer=issuer,
                    message=f"Authentication required: {SecretRedactor().redact_text(text)[:220]}",
                )
            last_err = f"{type(exc).__name__}: {text[:240]}"

    return RemoteProbeResult(
        status="error",
        message=SecretRedactor().redact_text(last_err or "Failed to connect to remote MCP server."),
    )


class SecretStoreOAuthTokenStorage(TokenStorage):
    """Persist upstream OAuth tokens & client info encrypted in DPAPI SecretStore."""

    def __init__(self, secret_store: SecretStore, server_id: str) -> None:
        self._store = secret_store
        self._sid = server_id
        self._tok_key = f"gateway_{server_id}_oauth_tokens"
        self._client_key = f"gateway_{server_id}_oauth_client"
        self._bearer_key = f"gateway_{server_id}_bearer"

    async def get_tokens(self) -> OAuthToken | None:
        raw = self._store.get_secret("external_oauth", self._tok_key)
        if not raw:
            return None
        try:
            return OAuthToken.model_validate_json(raw)
        except Exception:  # noqa: BLE001
            return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._store.set_secret("external_oauth", self._tok_key, tokens.model_dump_json())
        if getattr(tokens, "access_token", None):
            self._store.set_secret("external_oauth", self._bearer_key, str(tokens.access_token))

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        raw = self._store.get_secret("external_oauth", self._client_key)
        if not raw:
            return None
        try:
            return OAuthClientInformationFull.model_validate_json(raw)
        except Exception:  # noqa: BLE001
            return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._store.set_secret("external_oauth", self._client_key, client_info.model_dump_json())


class _LoopbackCallbackServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _start_ephemeral_oauth_callback() -> tuple[_LoopbackCallbackServer, str, queue.Queue[dict[str, str]]]:
    result_q: queue.Queue[dict[str, str]] = queue.Queue()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            payload = {k: v[0] for k, v in qs.items() if v}
            result_q.put(payload)
            body = (
                "<!doctype html><html><body style='font-family:Segoe UI,sans-serif;background:#151617;color:#F2F3F5;"
                "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
                "<div style='background:#202124;border:1px solid #2E3136;border-radius:12px;padding:24px;max-width:400px;text-align:center'>"
                "<h2>MCP-app</h2><p>Authorization complete. You may close this browser tab.</p>"
                "</div></body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

    server = _LoopbackCallbackServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}/callback", result_q


async def run_upstream_oauth_flow(
    url: str,
    *,
    server_id: str,
    secret_store: SecretStore,
    open_browser_fn: Callable[[str], object] | None = None,
    allow_local_endpoint: bool = False,
    timeout: float = 120.0,
) -> tuple[RemoteProbeResult, str]:
    """Run real OAuth 2.1 + PKCE against an upstream MCP server, storing bearer token in SecretStore."""
    try:
        clean_url = validate_upstream_url(url, allow_local_endpoint=allow_local_endpoint)
    except ValueError as exc:
        return RemoteProbeResult(status="error", message=str(exc)), ""

    srv, redirect_uri, q = _start_ephemeral_oauth_callback()
    storage = SecretStoreOAuthTokenStorage(secret_store, server_id)
    browser_opener = open_browser_fn or webbrowser.open

    async def _redirect_handler(auth_url: str) -> None:
        browser_opener(auth_url)

    async def _callback_handler() -> AuthorizationCodeResult:
        def _wait() -> dict[str, str]:
            return q.get(timeout=timeout)

        data = await asyncio.to_thread(_wait)
        if data.get("error"):
            raise PermissionError(data.get("error_description") or data["error"])
        code = data.get("code", "")
        if not code:
            raise ValueError("Missing OAuth authorization code in callback")
        return AuthorizationCodeResult(code=code, state=data.get("state"), iss=data.get("iss"))

    try:
        metadata = OAuthClientMetadata(
            client_name="MCP-app Gateway",
            redirect_uris=[redirect_uri],  # type: ignore[list-item]
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
        oauth_auth = OAuthClientProvider(
            server_url=clean_url,
            client_metadata=metadata,
            storage=storage,
            redirect_handler=_redirect_handler,
            callback_handler=_callback_handler,
        )
        async with httpx.AsyncClient(verify=True, auth=oauth_auth, timeout=httpx.Timeout(20.0)) as http_client:
            async with streamable_http_client(clean_url, http_client=http_client) as (r_stream, w_stream):
                async with ClientSession(r_stream, w_stream, read_timeout_seconds=20.0) as session:
                    init_res = await asyncio.wait_for(session.initialize(), timeout=20.0)
                    tools_res = await asyncio.wait_for(session.list_tools(), timeout=20.0)
        srv_name, srv_ver, proto, tool_names = _extract_server_meta(init_res, tools_res)
        secret_ref = SecretStore.secret_ref("external_oauth", f"gateway_{server_id}_bearer")
        return (
            RemoteProbeResult(
                status="ok",
                transport=TRANSPORT_STREAMABLE_HTTP,
                server_name=srv_name,
                server_version=srv_ver,
                protocol_version=proto,
                tools=tool_names,
                auth_kind="oauth",
                message="Upstream OAuth authentication succeeded.",
            ),
            secret_ref,
        )
    except Exception as exc:  # noqa: BLE001
        return RemoteProbeResult(status="error", message=SecretRedactor().redact_text(str(exc))[:260]), ""
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:  # noqa: BLE001
            pass


async def probe_stdio_mcp_server(
    command: str,
    args: tuple[str, ...] | list[str] = (),
    *,
    cwd: str = "",
    env: dict[str, str] | None = None,
    timeout: float = 12.0,
) -> RemoteProbeResult:
    """Explicitly launch and inspect a user-confirmed stdio MCP server for tools and serverInfo."""
    rt = inspect_stdio_runtime(command, args, cwd)
    if not rt.ok:
        return RemoteProbeResult(status="error", transport=TRANSPORT_STDIO, message=rt.error_message)
    exe = rt.resolved_executable or command
    child_env = sanitize_child_env(extra_env=env or {})
    try:
        params = StdioServerParameters(
            command=exe,
            args=list(args),
            env=child_env,
            cwd=cwd or None,
        )
        async with stdio_client(params) as (r_stream, w_stream):
            async with ClientSession(r_stream, w_stream, read_timeout_seconds=timeout) as session:
                init_res = await asyncio.wait_for(session.initialize(), timeout=timeout)
                tools_res = await asyncio.wait_for(session.list_tools(), timeout=timeout)
        srv_name, srv_ver, proto, tool_names = _extract_server_meta(init_res, tools_res)
        return RemoteProbeResult(
            status="ok",
            transport=TRANSPORT_STDIO,
            server_name=srv_name,
            server_version=srv_ver,
            protocol_version=proto,
            tools=tool_names,
            message="STDIO server initialized successfully.",
        )
    except Exception as exc:  # noqa: BLE001
        return RemoteProbeResult(
            status="error",
            transport=TRANSPORT_STDIO,
            message=SecretRedactor().redact_text(f"{type(exc).__name__}: {exc}")[:260],
        )


def build_profile_from_url_probe(
    url: str,
    probe: RemoteProbeResult,
    *,
    server_id: str | None = None,
    name: str | None = None,
    auth_mode: str = AUTH_NONE,
    auth_secret_ref: str = "",
    allow_local_endpoint: bool = False,
) -> UpstreamServerProfile:
    host_slug = urlsplit(url).hostname or "remote"
    sid = normalize_server_id(server_id or probe.server_name or host_slug)
    return UpstreamServerProfile(
        server_id=sid,
        name=(name or probe.server_name or host_slug).strip(),
        transport=probe.transport if probe.transport in (TRANSPORT_STREAMABLE_HTTP, TRANSPORT_SSE) else TRANSPORT_STREAMABLE_HTTP,
        enabled=True,
        autostart=False,
        url=url.strip(),
        auth_mode=auth_mode if auth_mode in (AUTH_NONE, AUTH_BEARER, AUTH_HEADERS) else AUTH_NONE,
        auth_secret_ref=auth_secret_ref,
        allow_local_endpoint=allow_local_endpoint or url.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")),
        min_profile="allowlist",
        approved_by_owner=True,
        notes=f"Auto-configured ({probe.transport})",
    )
