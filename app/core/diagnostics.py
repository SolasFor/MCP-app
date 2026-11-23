"""Safe, synchronous MCP connectivity diagnostics (call from a background thread).

Network requests deliberately separate the *local* Bearer-authenticated MCP
probe from *public* unauthenticated HTTP/OAuth checks. Never send the owner
token to Cloudflare or to any redirected URL.

No tokens or OAuth credentials are included in diagnostic messages.
"""
from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlopen,
)

TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 65536
PROTOCOL_VERSION = "2025-11-25"


@dataclass(frozen=True)
class ProbeResult:
    label: str
    passed: bool
    message: str


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_LOCAL_OPENER = build_opener(ProxyHandler({}), _NoRedirect())
_PUBLIC_OPENER = build_opener(_NoRedirect())


def _origin(url: str, *, public: bool) -> tuple[str, str]:
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Неверный адрес или учетные данные в ссылке")
    if parsed.query or parsed.fragment:
        raise ValueError("Адрес MCP не должен содержать query или fragment")
    if public and parsed.scheme != "https":
        raise ValueError("Публичный MCP-адрес должен использовать HTTPS")
    if not public and (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1")):
        raise ValueError("Локальная диагностика доступна только через loopback HTTP")
    if not public and parsed.port is None:
        raise ValueError("Локальный URL должен содержать порт")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")), parsed.path.rstrip("/") or "/"


def _request(
    url: str, *, public: bool, method: str = "GET", token: str = "",
    payload: dict | None = None,
) -> tuple[int, str, bytes]:
    headers = {
        "User-Agent": "MCPApp-Connection-Diagnostics",
        "Accept": "application/json, text/event-stream",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
    if token:
        if public:
            raise ValueError("Запрещено отправлять токен владельца на публичный URL")
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=data, method=method, headers=headers)
    opener = _PUBLIC_OPENER if public else _LOCAL_OPENER
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        code = response.status
        ctype = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        # SSE responses may never end. The HTTP 200 handshake is meaningful,
        # and reading the full stream can hang on otherwise healthy servers.
        body = b"" if ctype == "text/event-stream" else response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("Диагностический ответ превышает 64 KiB")
        return code, ctype, body


def _short_error(error: Exception) -> str:
    if isinstance(error, HTTPError):
        return f"HTTP {error.code}"
    if isinstance(error, URLError):
        # Avoid printing raw URLs or bearer tokens from untrusted errors.
        return f"Сетевое соединение недоступно ({type(error.reason).__name__})"
    if isinstance(error, (TimeoutError, ssl.SSLError)):
        return type(error).__name__
    if isinstance(error, ValueError):
        return str(error)
    return type(error).__name__


def _result(name: str, operation) -> ProbeResult:
    try:
        return ProbeResult(name, True, operation())
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return ProbeResult(name, False, _short_error(exc))


def _health(url: str, *, public: bool) -> str:
    status, ctype, body = _request(url, public=public)
    if status != 200:
        raise ValueError(f"HTTP {status}")
    if ctype != "application/json":
        raise ValueError("Некорректный Content-Type health")
    response = json.loads(body)
    if response.get("status") != "ok":
        raise ValueError("Health-ответ не подтверждает готовность")
    return "HTTP 200, status=ok"


def _metadata(origin: str) -> str:
    status, ctype, body = _request(
        origin + "/.well-known/oauth-authorization-server", public=True,
    )
    if status != 200 or ctype != "application/json":
        raise ValueError(f"OAuth discovery: HTTP {status}, {ctype}")
    metadata = json.loads(body)
    if metadata.get("issuer", "").rstrip("/") != origin:
        raise ValueError("OAuth issuer отличается от публичного адреса")
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        value = metadata.get(key)
        parsed = urlsplit(value) if isinstance(value, str) else None
        if parsed is None or urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) != origin:
            raise ValueError(f"Неверный OAuth endpoint: {key}")
    return "OAuth issuer и маршруты авторизации корректны"


def _mcp_initialize(mcp_url: str, owner_token: str) -> str:
    if not owner_token:
        raise ValueError("Токен владельца не задан")
    status, ctype, body = _request(
        mcp_url, public=False, method="POST", token=owner_token,
        payload={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "MCPApp-diagnostics", "version": "1"},
            },
        },
    )
    if status != 200:
        raise ValueError(f"MCP initialize: HTTP {status}")
    if ctype == "application/json":
        response = json.loads(body)
        if "result" not in response:
            raise ValueError("MCP initialize вернул ошибку")
        return "MCP initialize: JSON-RPC OK"
    if ctype == "text/event-stream":
        return "MCP initialize: HTTP 200 (SSE-соединение принято)"
    raise ValueError(f"MCP initialize: неожиданный Content-Type {ctype}")


def probe_connection(
    public_url: str, local_port: int, health_path: str,
    owner_token: str,
) -> list[ProbeResult]:
    """Return four independent results; no network operation runs on GUI thread."""
    try:
        public_origin, resource_path = _origin(public_url, public=True)
        local_origin, _ = _origin(f"http://127.0.0.1:{local_port}", public=False)
        if not health_path.startswith("/") or "?" in health_path or "#" in health_path:
            raise ValueError("Некорректный путь health")
        health_url = public_origin + health_path
        local_health_url = local_origin + health_path
        local_mcp_url = local_origin + resource_path
    except (ValueError, OverflowError) as exc:
        return [ProbeResult("Конфигурация", False, _short_error(exc))]
    return [
        _result("Локальный сервер", lambda: _health(local_health_url, public=False)),
        _result("Публичный HTTPS", lambda: _health(health_url, public=True)),
        _result("OAuth discovery", lambda: _metadata(public_origin)),
        _result("MCP initialize (локально)", lambda: _mcp_initialize(local_mcp_url, owner_token)),
    ]
