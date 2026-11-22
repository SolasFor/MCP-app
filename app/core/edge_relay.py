"""Локальный мост от cloudflared к Cloudflare через прокси (см. app/core/proxy.py).

    cloudflared ──TCP──▶ 127.0.0.1:<порт> ──SOCKS5/CONNECT──▶ region1.v2.argotunnel.com:7844
    cloudflared ──HTTP─▶ 127.0.0.1:<порт> ──HTTPS через прокси──▶ api.trycloudflare.com/tunnel

Соединение туннеля. cloudflared запускается с --edge 127.0.0.1:<порт> (по одному на каждый
хост :7844 из списка) и --protocol http2: QUIC — это UDP, а SOCKS5 CONNECT и HTTP CONNECT везут
только TCP. Статические адреса --edge cloudflared поддерживает полноценно
(supervisor.NewSupervisor → edgediscovery.StaticEdge, prechecks тоже идут по ним). Сертификат
сервера cloudflared проверяет по служебному имени протокола (TLSSettings().ServerName), а не
по адресу из --edge, поэтому через мост TLS сходится без подмен.

Временный адрес. cloudflared делает POST <quick-service>/tunnel своим http.Transport без
прокси. С --quick-service http://127.0.0.1:<порт> запрос приходит сюда, и мост пересылает
его в https://api.trycloudflare.com через прокси, ответ отдаёт как есть.

Мост работает в фоновых потоках (не в цикле Qt) и слушает только 127.0.0.1.
Жизненный цикл: ServiceManager вызывает start() перед запуском туннеля, добавляет
cloudflared_args() к команде и вызывает stop() после остановки туннеля.
"""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from app.core import proxy as px

QUICK_SERVICE_HOST = "api.trycloudflare.com"
LogFn = Callable[[str], None]


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _EdgeListener:
    """127.0.0.1:<случайный порт> → через прокси → один хост :7844."""

    def __init__(self, settings: px.ProxySettings, target: tuple[str, int], log: LogFn) -> None:
        self._endpoint = settings.endpoint()
        self._target = target
        self._log = log
        self._closed = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: не делить порт с чужими сокетами
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, name=f"edge-relay-{self.port}", daemon=True).start()

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                client, _addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        host, port = self._target
        try:
            upstream = px.open_via_proxy(self._endpoint, host, port, px.TIMEOUT)
        except OSError as exc:
            self._log(f"Прокси: нет соединения с {host}:{port} — {px.describe(exc)}")
            client.close()
            return
        upstream.settimeout(None)
        client.settimeout(None)
        back = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
        back.start()
        _pipe(client, upstream)
        back.join()
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass

    def close(self) -> None:
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


class _QuickServiceHandler(BaseHTTPRequestHandler):
    server_version = "MCPAppQuickService"

    def do_POST(self) -> None:  # noqa: N802 — имя задаёт BaseHTTPRequestHandler
        bridge: ProxyBridge = self.server.bridge  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {name: value for name in ("Content-Type", "User-Agent")
                   if (value := self.headers.get(name))}
        try:
            status, resp_headers, data = px.https_request(
                bridge.settings, "POST", f"https://{QUICK_SERVICE_HOST}{self.path}", headers, body, timeout=15)
        except (OSError, ValueError) as exc:
            reason = px.describe(exc) if isinstance(exc, OSError) else str(exc)
            bridge.log(f"Прокси: {QUICK_SERVICE_HOST} недоступен — {reason}")
            status, resp_headers = 502, {"content-type": "application/json"}
            data = json.dumps({"success": False, "errors": [{"code": 502, "message": f"proxy: {reason}"}]}).encode()
        self.send_response(status)
        self.send_header("Content-Type", resp_headers.get("content-type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — без шума в stderr
        pass


class ProxyBridge:
    """Все мосты сразу. При выключенном прокси start() ничего не делает, args пустые."""

    def __init__(self, settings: px.ProxySettings, log: LogFn | None = None) -> None:
        self.settings = settings
        self.log: LogFn = log or (lambda _msg: None)
        self._listeners: list[_EdgeListener] = []
        self._http: ThreadingHTTPServer | None = None

    @property
    def active(self) -> bool:
        return bool(self._listeners or self._http)

    def start(self) -> None:
        """Поднять мосты. ValueError — неверные настройки (текст понятен пользователю)."""
        self.stop()
        if not self.settings.enabled:
            return
        errors = self.settings.validate()
        if errors:
            raise ValueError("; ".join(errors))
        try:
            for target in self.settings.edge_targets():
                self._listeners.append(_EdgeListener(self.settings, target, self.log))
            if self.settings.covers(QUICK_SERVICE_HOST, 443):
                server = ThreadingHTTPServer(("127.0.0.1", 0), _QuickServiceHandler)
                server.daemon_threads = True
                server.bridge = self  # type: ignore[attr-defined]
                threading.Thread(target=server.serve_forever, name="quick-service-relay", daemon=True).start()
                self._http = server
        except BaseException:
            self.stop()
            raise
        if self.active:
            ep = self.settings.endpoint()
            self.log(f"Прокси: хосты Cloudflare идут через {ep.scheme}://{ep.host}:{ep.port}")

    def stop(self) -> None:
        for listener in self._listeners:
            listener.close()
        self._listeners = []
        if self._http is not None:
            self._http.shutdown()
            self._http.server_close()
            self._http = None

    def cloudflared_args(self, quick: bool) -> list[str]:
        """Флаги команды `cloudflared tunnel`: вставлять сразу после «tunnel» (см. with_tunnel_args)."""
        args: list[str] = []
        for listener in self._listeners:
            args += ["--edge", f"127.0.0.1:{listener.port}"]
        if self._listeners:
            args += ["--protocol", "http2"]
        if quick and self._http is not None:
            args += ["--quick-service", f"http://127.0.0.1:{self._http.server_address[1]}"]
        return args


def with_tunnel_args(argv: list[str], extra: list[str]) -> list[str]:
    """Вставить флаги после «tunnel»: `tunnel --edge … run --token …` / `tunnel --edge … --url …`."""
    if not extra:
        return list(argv)
    try:
        index = argv.index("tunnel") + 1
    except ValueError:
        return list(argv) + list(extra)
    return argv[:index] + list(extra) + argv[index:]
