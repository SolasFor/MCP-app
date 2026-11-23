#!/usr/bin/env python3
"""MCP probe — воспроизведение сбоев внешнего подключения (PR-01, docs/audit-report.md §5).

Только стандартная библиотека Python 3.10+: запускается без установки зависимостей.
Это прототип уровней 2–5 MCP Doctor: сначала понять, ГДЕ ломается подключение,
потом чинить.

    set MCP_TOKEN=<токен>
    python tools/mcp_probe.py https://<host>.trycloudflare.com/mcp
    python tools/mcp_probe.py https://<host>.trycloudflare.com/mcp ^
        --local http://127.0.0.1:8000/mcp --json probe-report.json

Токен берётся из MCP_TOKEN (или --token) и никогда не попадает в отчёт. Скрипт вызывает
только initialize и tools/list; инструмент вызывается лишь явно через --call.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from email.message import Message
from typing import Any

PROTOCOL_VERSION = "2025-11-25"
ACCEPT_BOTH = "application/json, text/event-stream"
MAX_BODY = 256 * 1024
STREAM_TIMEOUT = 8.0
CF_ORIGIN_ERRORS = {502, 503, 504, 520, 521, 522, 523, 524, 530}


# --------------------------------------------------------------------------- модель


@dataclass
class Check:
    check_id: str
    name: str
    target: str
    status: str = "SKIP"  # PASS / FAIL / WARN / INFO / SKIP
    http_status: int | None = None
    duration_ms: int = 0
    error_code: str = ""
    root_cause: str = ""
    suggested_fix: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def fail(self, code: str, cause: str, fix: str = "") -> None:
        self.status, self.error_code, self.root_cause, self.suggested_fix = "FAIL", code, cause, fix

    def warn(self, code: str, cause: str, fix: str = "") -> None:
        self.status, self.error_code, self.root_cause, self.suggested_fix = "WARN", code, cause, fix


@dataclass
class Response:
    status: int | None
    headers: Message | None
    body: bytes
    duration_ms: int
    error: str = ""
    timed_out: bool = False

    def header(self, name: str) -> str:
        if self.headers is None:
            return ""
        return self.headers.get(name) or ""

    @property
    def content_type(self) -> str:
        return self.header("Content-Type").split(";")[0].strip().lower()


# --------------------------------------------------------------------------- HTTP


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект — это находка диагностики, а не то, что нужно молча пройти."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _read_body(resp: Any) -> tuple[bytes, bool]:
    """Читает тело по кускам; таймаут после заголовков = поток держится открытым."""
    chunks: list[bytes] = []
    total = 0
    try:
        while total < MAX_BODY:
            chunk = resp.read1(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (TimeoutError, socket.timeout):
        return b"".join(chunks), True
    return b"".join(chunks), False


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any = None,
    timeout: float = 20.0,
) -> Response:
    hdrs = {"User-Agent": "mcp-app-probe/0.1"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    started = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw, timed_out = _read_body(resp)
            note = f"body still open after {timeout:.0f}s" if timed_out else ""
            return Response(resp.status, resp.headers, raw, _ms(started), note, timed_out)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY)
        except Exception:  # noqa: BLE001
            raw = b""
        return Response(e.code, e.headers, raw, _ms(started))
    except (TimeoutError, socket.timeout):
        return Response(None, None, b"", _ms(started), f"no response within {timeout:.0f}s", True)
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            return Response(None, None, b"", _ms(started), f"no response within {timeout:.0f}s", True)
        return Response(None, None, b"", _ms(started), f"{type(e.reason).__name__}: {e.reason}")
    except Exception as e:  # noqa: BLE001
        return Response(None, None, b"", _ms(started), f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- разбор


def parse_jsonrpc(content_type: str, body: bytes) -> tuple[list[Any], str]:
    """JSON-RPC сообщения из ответа application/json или text/event-stream."""
    text = body.decode("utf-8", "replace")
    if content_type == "application/json":
        try:
            obj = json.loads(text)
        except ValueError as e:
            return [], f"invalid JSON: {e}"
        return (obj if isinstance(obj, list) else [obj]), ""
    if content_type == "text/event-stream":
        messages: list[Any] = []
        data_lines: list[str] = []
        for line in text.splitlines() + [""]:
            if line.startswith("data:"):
                value = line[5:]
                data_lines.append(value[1:] if value.startswith(" ") else value)
            elif line == "" and data_lines:
                try:
                    messages.append(json.loads("\n".join(data_lines)))
                except ValueError:
                    pass
                data_lines = []
        return messages, ""
    return [], f"unexpected Content-Type '{content_type or '(none)'}'"


def find_response(messages: list[Any], request_id: int) -> dict[str, Any] | None:
    for m in messages:
        if isinstance(m, dict) and m.get("id") == request_id and ("result" in m or "error" in m):
            return m
    return None


def as_metadata_urls(issuer: str) -> list[str]:
    """Порядок поиска метаданных сервера авторизации (RFC 8414 + OIDC, как в MCP 2025-11-25)."""
    p = urllib.parse.urlsplit(issuer)
    base = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    if not path:
        return [f"{base}/.well-known/oauth-authorization-server", f"{base}/.well-known/openid-configuration"]
    return [
        f"{base}/.well-known/oauth-authorization-server{path}",
        f"{base}/.well-known/openid-configuration{path}",
        f"{base}{path}/.well-known/openid-configuration",
    ]


def prm_url(mcp_url: str) -> str:
    p = urllib.parse.urlsplit(mcp_url)
    return f"{p.scheme}://{p.netloc}/.well-known/oauth-protected-resource{p.path.rstrip('/')}"


def same_url(a: str, b: str) -> bool:
    def norm(u: str) -> tuple[str, str, str]:
        p = urllib.parse.urlsplit(u.strip())
        return p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/")

    return norm(a) == norm(b)


def is_quick_tunnel(url: str) -> bool:
    return (urllib.parse.urlsplit(url).hostname or "").endswith(".trycloudflare.com")


def classify_failure(r: Response) -> tuple[str, str, str]:
    """(error_code, root_cause, suggested_fix) для неожиданного ответа."""
    if r.status is None:
        return (
            "TIMEOUT" if r.timed_out else "NETWORK",
            f"Нет HTTP-ответа: {r.error}",
            "Проверьте, что туннель запущен и адрес актуален: quick-адрес меняется при каждом запуске.",
        )
    body = r.body[:4000].decode("utf-8", "replace").lower()
    if 300 <= r.status < 400:
        return ("REDIRECT", f"Редирект на {r.header('Location') or '?'}", "MCP-клиенты не должны получать редирект: проверьте адрес и путь.")
    if r.status in CF_ORIGIN_ERRORS and ("cloudflare" in body or r.header("Server").lower() == "cloudflare"):
        return (
            "CF_ORIGIN",
            f"Cloudflare не достучался до локального сервера (HTTP {r.status})",
            "Проверьте, что бэкенд запущен на том порту, куда смотрит cloudflared.",
        )
    if r.status == 421:
        return (
            "HOST_REJECTED",
            "Сервер отклонил заголовок Host (защита SDK от DNS rebinding)",
            "Добавьте публичный хост в allowed_hosts транспорта (audit B4).",
        )
    if r.status == 401:
        return ("UNAUTHORIZED", "Токен отклонён", "Проверьте токен и что сервер запущен с актуальным MCP_PUBLIC_URL.")
    if r.status == 404:
        return ("NOT_FOUND", "Путь не найден или сессия неизвестна", "Проверьте путь MCP (audit E1).")
    if r.status == 406:
        return ("NOT_ACCEPTABLE", "Сервер не принял заголовок Accept", "")
    return (f"HTTP_{r.status}", f"Неожиданный статус {r.status}", "")


def initialize_body() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-app-probe", "version": "0.1"},
        },
    }


def mask(secret: str) -> str:
    return f"{secret[:4]}… ({len(secret)} chars)" if secret else "(none)"


# --------------------------------------------------------------------------- проверки


class Probe:
    def __init__(self, mcp_url: str, token: str, local_url: str = "", timeout: float = 20.0,
                 call_tool: str = "", call_args: dict[str, Any] | None = None) -> None:
        self.mcp_url = mcp_url
        self.token = token
        self.local_url = local_url
        self.timeout = timeout
        self.call_tool = call_tool
        self.call_args = call_args or {}
        self.quick = is_quick_tunnel(mcp_url)
        self.checks: list[Check] = []
        self.session_id = ""
        self.negotiated = ""
        self.prm_hint = ""
        self.auth_servers: list[str] = []

    # -- helpers
    def _new(self, check_id: str, name: str, target: str) -> Check:
        c = Check(check_id, name, target)
        self.checks.append(c)
        return c

    @staticmethod
    def _fill(c: Check, r: Response) -> None:
        c.http_status, c.duration_ms = r.status, r.duration_ms
        if r.content_type:
            c.details["content_type"] = r.content_type

    def _mcp_headers(self, accept: str = ACCEPT_BOTH) -> dict[str, str]:
        h = {"Accept": accept}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.negotiated:
            h["MCP-Protocol-Version"] = self.negotiated
        return h

    def _rpc(self, c: Check, request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        r = http("POST", self.mcp_url, headers=self._mcp_headers(),
                 body={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                 timeout=self.timeout)
        self._fill(c, r)
        if r.status != 200:
            c.fail(*classify_failure(r))
            return None
        messages, err = parse_jsonrpc(r.content_type, r.body)
        resp = find_response(messages, request_id)
        if resp is None:
            if r.timed_out:
                c.fail("STREAM_STALLED", "Ответ не дошёл: SSE-поток не закрылся за отведённое время",
                       "Включить JSON-ответы для Quick Tunnel (audit B3).")
            else:
                c.fail("NO_JSONRPC", f"В ответе нет JSON-RPC ответа на id={request_id}. {err}".strip())
            return None
        if "error" in resp:
            e = resp["error"] if isinstance(resp["error"], dict) else {}
            c.fail(f"JSONRPC_{e.get('code', '?')}", str(e.get("message", ""))[:300])
            return None
        if r.content_type == "text/event-stream":
            c.details["sse_response"] = True
        return resp.get("result") if isinstance(resp.get("result"), dict) else {}

    # -- level 2/3: HTTP и туннель
    def check_health(self) -> None:
        p = urllib.parse.urlsplit(self.mcp_url)
        url = f"{p.scheme}://{p.netloc}/health"
        c = self._new("HTTP-01", "Public /health", url)
        r = http("GET", url, timeout=self.timeout)
        self._fill(c, r)
        if r.status != 200:
            c.fail(*classify_failure(r))
            return
        try:
            ok = json.loads(r.body).get("status") == "ok"
        except (ValueError, AttributeError):
            ok = False
        if ok:
            c.status = "PASS"
        else:
            c.warn("UNEXPECTED_BODY", "200, но тело не {\"status\": \"ok\"} — возможно, отвечает не MCP-app")

    # -- level 5: авторизация
    def check_unauthenticated(self) -> None:
        c = self._new("AUTH-01", "Request without token is rejected", self.mcp_url)
        r = http("POST", self.mcp_url, headers={"Accept": ACCEPT_BOTH}, body=initialize_body(), timeout=self.timeout)
        self._fill(c, r)
        www = r.header("WWW-Authenticate")
        c.details["www_authenticate"] = www
        m = re.search(r'resource_metadata="([^"]+)"', www)
        if m:
            self.prm_hint = m.group(1)
        if r.status == 401:
            if m:
                c.status = "PASS"
            else:
                c.warn("NO_RESOURCE_METADATA",
                       "401 без resource_metadata в WWW-Authenticate: OAuth-клиенты не найдут метаданные ресурса (RFC 9728)")
        elif r.status is not None and 200 <= r.status < 300:
            c.fail("NO_AUTH", "Сервер принял запрос без токена", "Не публиковать сервер без авторизации.")
        else:
            c.fail(*classify_failure(r))

    def check_protected_resource_metadata(self) -> None:
        url = self.prm_hint or prm_url(self.mcp_url)
        c = self._new("AUTH-02", "Protected Resource Metadata", url)
        r = http("GET", url, timeout=self.timeout)
        self._fill(c, r)
        if r.status != 200:
            c.fail(*classify_failure(r))
            return
        try:
            data = json.loads(r.body)
        except ValueError as e:
            c.fail("INVALID_JSON", f"Метаданные не JSON: {e}")
            return
        resource = str(data.get("resource", ""))
        self.auth_servers = [str(s) for s in data.get("authorization_servers") or []]
        c.details.update(resource=resource, authorization_servers=self.auth_servers,
                         scopes_supported=data.get("scopes_supported"))
        if not same_url(resource, self.mcp_url):
            c.fail("RESOURCE_MISMATCH",
                   f"resource в метаданных не совпадает с публичным URL. Expected: {self.mcp_url} Received: {resource}",
                   "Перезапустите сервер с актуальным MCP_PUBLIC_URL (ротация quick-адреса).")
        elif not self.auth_servers:
            c.warn("NO_AUTH_SERVERS", "authorization_servers пуст: OAuth-клиентам некуда идти за токеном")
        else:
            c.status = "PASS"

    def check_authorization_servers(self) -> None:
        if not self.auth_servers:
            c = self._new("AUTH-03", "Authorization Server metadata", "-")
            c.root_cause = "Нет серверов авторизации для проверки"
            return
        for i, issuer in enumerate(self.auth_servers[:3]):
            c = self._new(f"AUTH-03{chr(ord('a') + i)}", "Authorization Server metadata", issuer)
            found: tuple[str, dict[str, Any]] | None = None
            tried: list[str] = []
            for url in as_metadata_urls(issuer):
                r = http("GET", url, timeout=self.timeout)
                tried.append(f"{url} -> {r.status or r.error}")
                self._fill(c, r)
                if r.status == 200:
                    try:
                        found = (url, json.loads(r.body))
                        break
                    except ValueError:
                        continue
            c.details["tried"] = tried
            if found is None:
                c.fail("AS_MISSING",
                       "Сервер авторизации объявлен в authorization_servers, но его метаданные недоступны. "
                       "OAuth-клиенты (Gemini, Claude, ChatGPT, Notion) не смогут получить токен.",
                       "Реализовать AS (PR-04). До тех пор — только клиенты, где заголовок Authorization задаётся вручную.")
                continue
            url, meta = found
            methods = meta.get("code_challenge_methods_supported") or []
            c.details.update(metadata_url=url, issuer=meta.get("issuer"),
                             registration_endpoint=bool(meta.get("registration_endpoint")),
                             code_challenge_methods_supported=methods)
            if not same_url(str(meta.get("issuer", "")), issuer):
                c.fail("ISSUER_MISMATCH", f"Expected issuer: {issuer} Received: {meta.get('issuer')}",
                       "Переподключите клиент после смены адреса туннеля.")
            elif not (meta.get("authorization_endpoint") and meta.get("token_endpoint")):
                c.fail("AS_INCOMPLETE", "В метаданных нет authorization_endpoint/token_endpoint")
            elif "S256" not in methods:
                c.warn("NO_PKCE_S256", "Не объявлен PKCE S256 — MCP-клиенты обязаны отказаться")
            else:
                c.status = "PASS"

    # -- level 4: MCP
    def check_initialize(self) -> bool:
        c = self._new("MCP-01", "initialize (Bearer)", self.mcp_url)
        if not self.token:
            c.root_cause = "Нет токена: задайте MCP_TOKEN"
            return False
        r = http("POST", self.mcp_url, headers=self._mcp_headers(), body=initialize_body(), timeout=self.timeout)
        self._fill(c, r)
        if r.status != 200:
            c.fail(*classify_failure(r))
            return False
        messages, err = parse_jsonrpc(r.content_type, r.body)
        resp = find_response(messages, 1)
        if resp is None or "error" in resp:
            if r.timed_out:
                c.fail("STREAM_STALLED", "Ответ на initialize не дошёл: SSE-поток не закрылся",
                       "Включить JSON-ответы для Quick Tunnel (audit B3).")
            elif resp is None:
                c.fail("NO_JSONRPC", f"Нет JSON-RPC ответа. {err}".strip())
            else:
                e = resp["error"] if isinstance(resp["error"], dict) else {}
                c.fail(f"JSONRPC_{e.get('code', '?')}", str(e.get("message", ""))[:300])
            return False
        result = resp.get("result") or {}
        self.negotiated = str(result.get("protocolVersion", ""))
        self.session_id = r.header("Mcp-Session-Id")
        info = result.get("serverInfo") or {}
        c.details.update(protocol_version=self.negotiated, server=f"{info.get('name')} {info.get('version')}",
                         capabilities=sorted((result.get("capabilities") or {}).keys()),
                         session=bool(self.session_id))
        if r.content_type == "text/event-stream" and self.quick:
            c.warn("SSE_ON_QUICK_TUNNEL", "Сервер ответил SSE на POST через Quick Tunnel; JSON-режим не применён",
                   "Проверить, что json_response действительно передаётся в SDK (audit B3).")
        else:
            c.status = "PASS"
        return True

    def check_initialized_notification(self) -> None:
        c = self._new("MCP-02", "notifications/initialized", self.mcp_url)
        r = http("POST", self.mcp_url, headers=self._mcp_headers(),
                 body={"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout=self.timeout)
        self._fill(c, r)
        if r.status in (200, 202, 204):
            c.status = "PASS"
        else:
            c.fail(*classify_failure(r))

    def check_tools_list(self) -> None:
        c = self._new("MCP-03", "tools/list", self.mcp_url)
        result = self._rpc(c, 2, "tools/list", {})
        if result is None:
            return
        tools = [t for t in result.get("tools") or [] if isinstance(t, dict)]
        undocumented = [t.get("name") for t in tools if not t.get("description")]
        c.details.update(count=len(tools), names=[t.get("name") for t in tools],
                         without_description=undocumented,
                         without_annotations=[t.get("name") for t in tools if not t.get("annotations")])
        if not tools:
            c.warn("NO_TOOLS", "Список инструментов пуст")
        elif undocumented:
            c.warn("TOOLS_UNDOCUMENTED", f"Инструменты без description: {', '.join(map(str, undocumented))}",
                   "Добавить docstring и annotations (audit F10).")
        else:
            c.status = "PASS"

    def check_tool_call(self) -> None:
        if not self.call_tool:
            return
        c = self._new("TOOL-01", f"tools/call {self.call_tool}", self.mcp_url)
        result = self._rpc(c, 3, "tools/call", {"name": self.call_tool, "arguments": self.call_args})
        if result is None:
            return
        c.details["is_error"] = bool(result.get("isError"))
        if result.get("isError"):
            c.fail("TOOL_ERROR", "Инструмент вернул isError=true")
        elif not isinstance(result.get("content"), list):
            c.fail("BAD_RESULT", "В результате нет массива content")
        else:
            c.status = "PASS"

    def check_get_stream(self) -> None:
        c = self._new("MCP-04", "GET stream (optional SSE channel)", self.mcp_url)
        r = http("GET", self.mcp_url, headers=self._mcp_headers(accept="text/event-stream"), timeout=STREAM_TIMEOUT)
        self._fill(c, r)
        if r.status == 405:
            c.status = "PASS"
            c.root_cause = "Сервер не предлагает GET-поток — корректно для JSON-only"
        elif r.status == 200 and r.content_type == "text/event-stream":
            if self.quick:
                c.warn("SSE_STREAM_ON_QUICK_TUNNEL",
                       "Сервер открывает SSE-поток через *.trycloudflare.com; доставка событий не гарантируется",
                       "В Quick-режиме отвечать 405 на GET (audit B1).")
            else:
                c.status = "PASS"
        elif r.status is None and r.timed_out:
            c.fail("STREAM_HANG", f"GET без ответа за {STREAM_TIMEOUT:.0f} с — клиенты, открывающие GET-поток, будут ждать",
                   "В Quick-режиме отвечать 405 на GET (audit B1).")
        else:
            c.warn(*classify_failure(r))

    def check_delete_session(self) -> None:
        c = self._new("MCP-05", "DELETE session", self.mcp_url)
        if not self.session_id:
            c.status = "INFO"
            c.root_cause = "Сервер не выдал Mcp-Session-Id (безсессионный режим)"
            return
        r = http("DELETE", self.mcp_url, headers=self._mcp_headers(), timeout=self.timeout)
        self._fill(c, r)
        if r.status in (200, 202, 204):
            c.status = "PASS"
        elif r.status == 405:
            c.status = "INFO"
            c.root_cause = "Сервер не даёт клиенту завершать сессию (допустимо по спецификации)"
        else:
            c.warn(*classify_failure(r))

    # -- локальные проверки Host (audit B4)
    def check_host_validation(self) -> None:
        if not self.local_url:
            return
        public_host = urllib.parse.urlsplit(self.mcp_url).netloc
        base = {"Accept": ACCEPT_BOTH}
        if self.token:
            base["Authorization"] = f"Bearer {self.token}"

        c = self._new("SEC-01", "Public Host header accepted by local server", self.local_url)
        r = http("POST", self.local_url, headers={**base, "Host": public_host}, body=initialize_body(),
                 timeout=self.timeout)
        self._fill(c, r)
        c.details["host_sent"] = public_host
        if r.status == 200:
            c.status = "PASS"
        elif r.status in (400, 403, 421):
            c.fail("PUBLIC_HOST_REJECTED",
                   f"Локальный сервер отклоняет Host: {public_host} (HTTP {r.status}) — именно так выглядит "
                   "отказ для запросов через туннель",
                   "Явно задать allowed_hosts с публичным хостом (audit B4).")
        else:
            c.warn(*classify_failure(r))

        c = self._new("SEC-02", "Foreign Host header rejected (DNS rebinding)", self.local_url)
        r = http("POST", self.local_url, headers={**base, "Host": "rebind.invalid"}, body=initialize_body(),
                 timeout=self.timeout)
        self._fill(c, r)
        if r.status in (400, 403, 421):
            c.status = "PASS"
        elif r.status == 200:
            c.fail("NO_HOST_VALIDATION", "Локальный порт принимает произвольный Host — нет защиты от DNS rebinding",
                   "Включить проверку Host/Origin в TransportSecuritySettings (audit B4).")
        else:
            c.warn(*classify_failure(r))

    # -- запуск
    def run(self) -> None:
        self.check_health()
        self.check_unauthenticated()
        self.check_protected_resource_metadata()
        self.check_authorization_servers()
        if self.check_initialize():
            self.check_initialized_notification()
            self.check_tools_list()
            self.check_tool_call()
            self.check_get_stream()
            self.check_delete_session()
        self.check_host_validation()

    def verdict(self) -> list[str]:
        by_id = {c.check_id: c for c in self.checks}

        def ok(*ids: str) -> bool:
            return all(i in by_id and by_id[i].status in ("PASS", "WARN", "INFO") for i in ids)

        bearer = ok("MCP-01", "MCP-02", "MCP-03") and by_id["MCP-01"].status == "PASS"
        oauth_checks = [c for c in self.checks if c.check_id.startswith("AUTH-03")]
        oauth = bool(oauth_checks) and all(c.status == "PASS" for c in oauth_checks) and ok("AUTH-01", "AUTH-02")
        lines = [
            f"Bearer MCP (initialize + tools/list): {'READY' if bearer else 'NOT READY'}",
            f"OAuth discovery (metadata only, flow NOT tested): {'OK' if oauth else 'NOT READY'}",
            "SSE: NOT VERIFIED by this probe",
        ]
        if bearer and self.quick:
            lines[0] += "  -> JSON MCP Ready via Quick Tunnel (not Full SSE Compatible)"
        first_fail = next((c for c in self.checks if c.status == "FAIL"), None)
        if first_fail:
            lines.append(f"First failure: {first_fail.check_id} {first_fail.name} — {first_fail.error_code}")
        return lines


# --------------------------------------------------------------------------- вывод


def render(checks: list[Check], verdict: list[str]) -> str:
    out: list[str] = ["MCP probe", ""]
    for c in checks:
        out.append(f"[{c.status:<4}] {c.check_id:<8} {c.name}  (HTTP {c.http_status or '-'}, {c.duration_ms} ms)")
        out.append(f"         Target     : {c.target}")
        if c.error_code:
            out.append(f"         Error code : {c.error_code}")
        if c.root_cause:
            out.append(f"         Root cause : {c.root_cause}")
        if c.suggested_fix:
            out.append(f"         Fix        : {c.suggested_fix}")
    out += [""] + verdict
    return "\n".join(out)


def redact(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # консоль Windows с cp866/cp1251
    ap = argparse.ArgumentParser(description="Сквозная проверка MCP-подключения (без сторонних зависимостей)")
    ap.add_argument("mcp_url", help="Публичный URL, например https://x.trycloudflare.com/mcp")
    ap.add_argument("--token", default=os.environ.get("MCP_TOKEN", ""),
                    help="Bearer-токен (лучше через переменную MCP_TOKEN)")
    ap.add_argument("--local", default="", help="Локальный URL для проверок Host, например http://127.0.0.1:8000/mcp")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--call", default="", help="Имя инструмента без побочных эффектов для tools/call")
    ap.add_argument("--args", default="{}", help="JSON-аргументы для --call")
    ap.add_argument("--json", dest="json_path", default="", help="Сохранить отчёт в JSON")
    a = ap.parse_args(argv)

    p = urllib.parse.urlsplit(a.mcp_url)
    if p.scheme not in ("http", "https") or not p.netloc:
        ap.error("mcp_url должен быть http(s)://host/path")
    try:
        call_args = json.loads(a.args)
    except ValueError:
        ap.error("--args: некорректный JSON")

    probe = Probe(a.mcp_url, a.token, a.local, a.timeout, a.call, call_args)
    probe.run()
    verdict = probe.verdict()
    print(redact(render(probe.checks, verdict), a.token))
    print(f"\nToken: {mask(a.token)}")
    if a.json_path:
        report = {"target": a.mcp_url, "quick_tunnel": probe.quick, "protocol_version_sent": PROTOCOL_VERSION,
                  "checks": [asdict(c) for c in probe.checks], "verdict": verdict}
        with open(a.json_path, "w", encoding="utf-8") as f:
            f.write(redact(json.dumps(report, ensure_ascii=False, indent=2), a.token))
    return 1 if any(c.status == "FAIL" for c in probe.checks) else 0


if __name__ == "__main__":
    sys.exit(main())
