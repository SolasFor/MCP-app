"""Прокси для хостов Cloudflare, недоступных напрямую из-за региональных ограничений.

Что идёт через прокси:
  * HTTPS-запросы приложения (API Cloudflare, выдача временного адреса) —
    https_request() ниже;
  * соединения cloudflared с сетью Cloudflare (порт 7844) — через локальный
    мост app/core/edge_relay.py.

Сам cloudflared через прокси ходить не умеет: временный адрес он запрашивает
своим http.Transport без поля Proxy (HTTPS_PROXY игнорируется, см.
cmd/cloudflared/tunnel/quick_tunnel.go), а соединение туннеля — прямым TCP/UDP.
Поэтому всё проксирование живёт в приложении.

Настройки — %APPDATA%\\MCPApp\\proxy.json. Логин и пароль прокси, если нужны,
хранятся в адресе: socks5://user:pass@host:port.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

EDGE_PORT = 7844
DEFAULT_HOSTS: tuple[str, ...] = (
    "api.trycloudflare.com:443",       # выдача временного адреса
    "region1.v2.argotunnel.com:7844",  # соединение туннеля
    "region2.v2.argotunnel.com:7844",
    "api.cloudflare.com:443",          # мастер «Свой домен»
)
DEFAULT_URL = "socks5://127.0.0.1:1080"
TIMEOUT = 10.0
SCHEMES = ("socks5", "socks5h", "http")


class ProxyError(OSError):
    """Прокси недоступен или отказал в соединении."""


# ====================================================================== настройки
@dataclass(frozen=True)
class ProxyEndpoint:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    @classmethod
    def parse(cls, url: str) -> "ProxyEndpoint":
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        if scheme not in SCHEMES:
            raise ValueError("Адрес прокси должен начинаться с socks5:// или http://")
        if not parts.hostname:
            raise ValueError("В адресе прокси нет хоста")
        try:
            port = parts.port
        except ValueError:
            raise ValueError("Порт прокси должен быть числом от 1 до 65535") from None
        if port is None:
            raise ValueError("Укажите порт прокси, например socks5://127.0.0.1:1080")
        return cls(scheme, parts.hostname, port, unquote(parts.username or ""), unquote(parts.password or ""))


def parse_target(line: str) -> tuple[str, int]:
    """«host» или «host:port» → (host, port). Порт по умолчанию 443."""
    text = line.strip().lower()
    host, sep, port_text = text.rpartition(":")
    if not sep:
        host, port_text = text, "443"
    if not host or "/" in host or " " in host:
        raise ValueError(f"Хост «{line.strip()}» записан неверно: нужно host или host:port")
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ValueError(f"У хоста «{line.strip()}» неверный порт")
    return host, int(port_text)


@dataclass
class ProxySettings:
    enabled: bool = False
    url: str = DEFAULT_URL
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_HOSTS))

    def endpoint(self) -> ProxyEndpoint:
        return ProxyEndpoint.parse(self.url)

    def targets(self) -> list[tuple[str, int]]:
        result: list[tuple[str, int]] = []
        for line in self.hosts:
            if line.strip() and not line.strip().startswith("#"):
                target = parse_target(line)
                if target not in result:
                    result.append(target)
        return result

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            targets = self.targets()
        except ValueError as exc:
            errors.append(str(exc))
            targets = []
        if self.enabled:
            try:
                self.endpoint()
            except ValueError as exc:
                errors.append(str(exc))
            if not targets and not errors:
                errors.append("Список хостов пуст — проксировать нечего")
        return errors

    def covers(self, host: str, port: int) -> bool:
        if not self.enabled:
            return False
        try:
            return (host.lower(), port) in self.targets()
        except ValueError:
            return False

    def edge_targets(self) -> list[tuple[str, int]]:
        """Хосты соединения туннеля: их обслуживает локальный мост."""
        if not self.enabled:
            return []
        return [t for t in self.targets() if t[1] == EDGE_PORT]


def settings_path() -> Path:
    from app.paths import user_data_dir

    return Path(user_data_dir()) / "proxy.json"


def load() -> ProxySettings:
    try:
        raw = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ProxySettings()
    defaults = ProxySettings()
    hosts = raw.get("hosts")
    return ProxySettings(
        enabled=bool(raw.get("enabled", defaults.enabled)),
        url=str(raw.get("url") or defaults.url),
        hosts=[str(h) for h in hosts] if isinstance(hosts, list) else defaults.hosts,
    )


def save(settings: ProxySettings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ====================================================================== соединения
_SOCKS_ERRORS = {
    1: "общий сбой прокси",
    2: "запрещено правилами прокси",
    3: "сеть недоступна",
    4: "хост недоступен",
    5: "в соединении отказано",
    6: "истекло время",
    7: "команда не поддерживается",
    8: "тип адреса не поддерживается",
}


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ProxyError("Прокси закрыл соединение")
        buf += chunk
    return buf


def _socks5(sock: socket.socket, ep: ProxyEndpoint, host: str, port: int) -> None:
    methods = b"\x00\x02" if ep.username else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2)
    if version != 5:
        raise ProxyError("Это не SOCKS5-прокси")
    if method == 2:
        user, password = ep.username.encode(), ep.password.encode()
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if _recv_exact(sock, 2)[1] != 0:
            raise ProxyError("SOCKS5: неверный логин или пароль")
    elif method != 0:
        raise ProxyError("SOCKS5: прокси требует авторизацию — укажите socks5://логин:пароль@хост:порт")
    # Имя хоста отдаём прокси (DNS на его стороне): локальный DNS тоже может быть искажён.
    name = host.encode("idna")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
    head = _recv_exact(sock, 4)
    if head[1] != 0:
        reason = _SOCKS_ERRORS.get(head[1], f"ошибка {head[1]}")
        raise ProxyError(f"SOCKS5: {reason} ({host}:{port})")
    if head[3] == 1:
        _recv_exact(sock, 4 + 2)
    elif head[3] == 4:
        _recv_exact(sock, 16 + 2)
    elif head[3] == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    else:
        raise ProxyError("SOCKS5: неизвестный тип адреса в ответе")


def _http_connect(sock: socket.socket, ep: ProxyEndpoint, host: str, port: int) -> None:
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if ep.username:
        credentials = base64.b64encode(f"{ep.username}:{ep.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {credentials}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)  # по байту: всё после заголовков — уже данные туннеля
        if not chunk:
            raise ProxyError("HTTP-прокси закрыл соединение")
        data += chunk
        if len(data) > 16384:
            raise ProxyError("HTTP-прокси прислал слишком длинный ответ")
    status_line = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or parts[1] != "200":
        raise ProxyError(f"HTTP-прокси отказал: {status_line}")


def open_via_proxy(ep: ProxyEndpoint, host: str, port: int, timeout: float = TIMEOUT) -> socket.socket:
    try:
        sock = socket.create_connection((ep.host, ep.port), timeout=timeout)
    except OSError as exc:
        raise ProxyError(f"Прокси {ep.host}:{ep.port} недоступен: {describe(exc)}") from exc
    try:
        (_socks5 if ep.scheme.startswith("socks") else _http_connect)(sock, ep, host, port)
    except BaseException:
        sock.close()
        raise
    return sock


def connect(settings: ProxySettings, host: str, port: int, timeout: float = TIMEOUT) -> socket.socket:
    """TCP-соединение с host:port: через прокси, если хост в списке, иначе напрямую."""
    if settings.covers(host, port):
        return open_via_proxy(settings.endpoint(), host, port, timeout)
    return socket.create_connection((host, port), timeout=timeout)


def https_request(settings: ProxySettings, method: str, url: str, headers: dict[str, str] | None = None,
                  body: bytes | None = None, timeout: float = TIMEOUT) -> tuple[int, dict[str, str], bytes]:
    """HTTPS-запрос с учётом списка хостов. Возвращает (код, заголовки, тело)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    raw = connect(settings, host, port, timeout)
    try:
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = tls
    try:
        all_headers = {"Host": host, **(headers or {})}
        conn.request(method, path, body=body, headers=all_headers)
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


def describe(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "нет ответа (тайм-аут)"
    if isinstance(exc, ConnectionResetError):
        return "соединение сброшено"
    if isinstance(exc, ConnectionRefusedError):
        return "в соединении отказано"
    if isinstance(exc, ssl.SSLError):
        return f"ошибка TLS: {exc.reason or exc}"
    if isinstance(exc, socket.gaierror):
        return "имя не найдено в DNS"
    return str(exc) or exc.__class__.__name__


def probe(settings: ProxySettings, host: str, port: int, via_proxy: bool, timeout: float = 6.0) -> str | None:
    """Проверка доступа: None — доступен, иначе причина. Для 443 — вплоть до TLS."""
    try:
        if via_proxy:
            sock = open_via_proxy(settings.endpoint(), host, port, timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if port == 443:
                ssl.create_default_context().wrap_socket(sock, server_hostname=host).close()
        finally:
            sock.close()
        return None
    except ValueError as exc:
        return str(exc)
    except OSError as exc:
        return describe(exc)
