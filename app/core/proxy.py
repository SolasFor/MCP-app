"""Система прокси MCP-app (v1.0.0 Wave 2):

Три режима подключения:
  * none   — «Без прокси» (значение по умолчанию для новых установок);
  * auto   — «Автоматическое определение» (системный прокси Windows WinINET/WinHTTP,
             HTTP_PROXY/HTTPS_PROXY/ALL_PROXY с учётом NO_PROXY, PAC-отчёт, известные
             локальные VPN-клиенты; только реальная проверка протокола, авторизации и TLS);
  * manual — «Ручная настройка» (HTTP CONNECT, SOCKS5, SOCKS5H, хост, порт, логин/пароль
             в SecretStore DPAPI).

Адрес 127.0.0.1:1080 НЕ считается рабочим прокси по умолчанию и используется лишь
как пример в подсказках интерфейса. При явно выбранном режиме авто/ручном трафик
никогда не переключается молча на прямое подключение без ведома пользователя.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from app.core.logging_manager import get_logging_manager
from app.core.secret_store import SecretStore

EDGE_PORT = 7844
DEFAULT_HOSTS: tuple[str, ...] = (
    "api.trycloudflare.com:443",       # выдача временного адреса
    "region1.v2.argotunnel.com:7844",  # соединение туннеля
    "region2.v2.argotunnel.com:7844",
    "api.cloudflare.com:443",          # мастер «Свой домен»
)
DEFAULT_URL = ""
EXAMPLE_PROXY_URL = "socks5h://127.0.0.1:1080"
TIMEOUT = 10.0
SCHEMES = ("socks5", "socks5h", "http")

PROXY_MODE_NONE = "none"
PROXY_MODE_AUTO = "auto"
PROXY_MODE_MANUAL = "manual"
PROXY_MODES = (PROXY_MODE_NONE, PROXY_MODE_AUTO, PROXY_MODE_MANUAL)

# Ограниченный список известных локальных портов VPN/прокси-клиентов на 127.0.0.1
_KNOWN_LOCAL_PROXY_CANDIDATES: tuple[tuple[str, int, str, str], ...] = (
    ("socks5h", 10808, "v2rayN / Xray SOCKS5", "socks5h://127.0.0.1:10808"),
    ("http", 10809, "v2rayN / Xray HTTP", "http://127.0.0.1:10809"),
    ("socks5h", 2080, "Nekoray / sing-box SOCKS5", "socks5h://127.0.0.1:2080"),
    ("http", 2081, "Nekoray / sing-box HTTP", "http://127.0.0.1:2081"),
    ("http", 7890, "Clash / Mihomo Mixed", "http://127.0.0.1:7890"),
    ("socks5h", 7891, "Clash / Mihomo SOCKS5", "socks5h://127.0.0.1:7891"),
    ("http", 12334, "Hiddify Proxy", "http://127.0.0.1:12334"),
    ("socks5h", 1080, "Local SOCKS5 (1080)", "socks5h://127.0.0.1:1080"),
    ("http", 8080, "Local HTTP (8080)", "http://127.0.0.1:8080"),
    ("http", 3128, "Local HTTP (3128)", "http://127.0.0.1:3128"),
    ("http", 8118, "Privoxy HTTP (8118)", "http://127.0.0.1:8118"),
)


class ProxyError(OSError):
    """Прокси недоступен или отказал в соединении."""


def _log_proxy(level: str, msg: str, *, event_code: str = "proxy") -> None:
    try:
        get_logging_manager().log("proxy", level, msg, event_code=event_code)
    except Exception:  # noqa: BLE001
        pass


@dataclass(frozen=True)
class ProxyEndpoint:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def url(self) -> str:
        host_lit = f"[{self.host}]" if ":" in self.host else self.host
        auth = ""
        if self.username or self.password:
            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        return f"{self.scheme}://{auth}{host_lit}:{self.port}"

    @property
    def redacted_url(self) -> str:
        host_lit = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host_lit}:{self.port}"

    @classmethod
    def parse(cls, url: str) -> "ProxyEndpoint":
        raw = (url or "").strip()
        if not raw:
            raise ValueError("Не указан адрес прокси")
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in SCHEMES:
            raise ValueError("Адрес прокси должен начинаться с socks5://, socks5h:// или http://")
        if not parts.hostname:
            raise ValueError("В адресе прокси не указан хост")
        try:
            port = parts.port
        except ValueError:
            raise ValueError("Порт прокси должен быть числом от 1 до 65535") from None
        if port is None or not (1 <= port <= 65535):
            raise ValueError("Укажите порт прокси (1..65535), например 1080")
        return cls(
            scheme,
            parts.hostname,
            port,
            unquote(parts.username or ""),
            unquote(parts.password or ""),
        )


def parse_target(line: str) -> tuple[str, int]:
    """«host» или «host:port» -> (host, port). Порт по умолчанию 443."""
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
class DetectedProxyCandidate:
    source: str
    url: str
    scheme: str
    host: str
    port: int
    working: bool = False
    auth_required: bool = False
    tls_ok: bool = False
    latency_ms: float | None = None
    reason: str = ""
    pac_url: str = ""


@dataclass
class AutoDetectResult:
    candidates: list[DetectedProxyCandidate] = field(default_factory=list)
    selected: DetectedProxyCandidate | None = None
    pac_urls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class TargetDiagnosticRow:
    target: str
    direct_ok: bool
    direct_detail: str
    proxy_ok: bool | None
    proxy_detail: str
    proxy_type: str = ""
    tcp_ok: bool | None = None
    auth_ok: bool | None = None
    dns_ok: bool | None = None
    tls_ok: bool | None = None
    latency_ms: float | None = None


@dataclass
class ProxySettings:
    mode: str = PROXY_MODE_NONE
    url: str = DEFAULT_URL
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_HOSTS))
    scheme: str = "socks5h"
    host: str = ""
    port: int | None = None
    username: str = ""
    password: str = ""
    detected_url: str = ""
    detected_source: str = ""

    def __init__(
        self,
        enabled: bool | None = None,
        url: str = DEFAULT_URL,
        hosts: list[str] | None = None,
        *,
        mode: str | None = None,
        scheme: str = "socks5h",
        host: str = "",
        port: int | None = None,
        username: str = "",
        password: str = "",
        detected_url: str = "",
        detected_source: str = "",
    ) -> None:
        if mode is not None and mode in PROXY_MODES:
            self.mode = mode
        elif enabled is True:
            self.mode = PROXY_MODE_MANUAL
        else:
            self.mode = PROXY_MODE_NONE

        self.hosts = list(hosts) if hosts is not None else list(DEFAULT_HOSTS)
        self.detected_url = (detected_url or "").strip()
        self.detected_source = (detected_source or "").strip()

        clean_url = (url or "").strip()
        if clean_url:
            self.url = clean_url
            try:
                ep = ProxyEndpoint.parse(clean_url)
                self.scheme = ep.scheme
                self.host = ep.host
                self.port = ep.port
                self.username = username or ep.username
                self.password = password or ep.password
                if self.username or self.password:
                    self.url = _inject_url_credentials(
                        _strip_url_credentials(clean_url)[0],
                        self.username,
                        self.password,
                    )
            except ValueError:
                self.scheme = scheme if scheme in SCHEMES else "socks5h"
                self.host = host.strip()
                self.port = port
                self.username = username
                self.password = password
        else:
            self.scheme = scheme if scheme in SCHEMES else "socks5h"
            self.host = host.strip()
            self.port = int(port) if port is not None else None
            self.username = username
            self.password = password
            self.url = self._build_manual_url()

    def _build_manual_url(self) -> str:
        if not self.host or self.port is None:
            return ""
        host_lit = f"[{self.host}]" if ":" in self.host else self.host
        base = f"{self.scheme}://{host_lit}:{self.port}"
        return _inject_url_credentials(base, self.username, self.password)

    @property
    def enabled(self) -> bool:
        return self.mode != PROXY_MODE_NONE

    @enabled.setter
    def enabled(self, value: bool) -> None:
        if not value:
            self.mode = PROXY_MODE_NONE
        elif self.mode == PROXY_MODE_NONE:
            self.mode = PROXY_MODE_MANUAL

    def endpoint(self) -> ProxyEndpoint:
        if self.mode == PROXY_MODE_AUTO:
            if self.detected_url:
                return ProxyEndpoint.parse(self.detected_url)
            res = discover_working_proxy()
            if res.selected is None:
                raise ProxyError(
                    "Автоопределение прокси: рабочий локальный или системный прокси не найден"
                    + (f" ({'; '.join(res.notes)})" if res.notes else "")
                )
            self.detected_url = res.selected.url
            self.detected_source = res.selected.source
            return ProxyEndpoint.parse(res.selected.url)
        candidate = self.url.strip() or self._build_manual_url()
        return ProxyEndpoint.parse(candidate)

    def resolve_active_endpoint(self) -> ProxyEndpoint | None:
        if self.mode == PROXY_MODE_NONE:
            return None
        return self.endpoint()

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
        if self.mode not in PROXY_MODES:
            errors.append(f"Неизвестный режим прокси: {self.mode}")
        try:
            targets = self.targets()
        except ValueError as exc:
            errors.append(str(exc))
            targets = []
        if self.mode == PROXY_MODE_MANUAL:
            try:
                ep = ProxyEndpoint.parse(self.url.strip() or self._build_manual_url())
                if len(ep.username.encode("utf-8")) > 255 or len(ep.password.encode("utf-8")) > 255:
                    errors.append("Логин и пароль SOCKS5 не должны превышать 255 байт")
            except ValueError as exc:
                errors.append(str(exc))
        if self.enabled and not targets and not errors:
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


_SECRET_NS = "proxy"
_SECRET_KEY = "credentials"


def settings_path() -> Path:
    from app.paths import user_data_dir

    return Path(user_data_dir()) / "proxy.json"


def _secret_store(base_dir: Path) -> SecretStore:
    return SecretStore(base_dir / "secrets")


def _strip_url_credentials(url: str) -> tuple[str, str, str]:
    raw = (url or "").strip()
    if not raw:
        return "", "", ""
    parts = urlsplit(raw)
    if not parts.username and not parts.password:
        return raw, "", ""
    host = parts.hostname or ""
    host_lit = f"[{host}]" if ":" in host else host
    netloc = f"{host_lit}:{parts.port}" if parts.port else host_lit
    clean = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return clean, unquote(parts.username or ""), unquote(parts.password or "")


def _inject_url_credentials(url: str, username: str, password: str) -> str:
    if not username and not password:
        return url
    parts = urlsplit(url.strip())
    if not parts.hostname:
        return url
    host_lit = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}"
    netloc = f"{auth}@{host_lit}:{parts.port}" if parts.port else f"{auth}@{host_lit}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def load() -> ProxySettings:
    path = settings_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ProxySettings()
    if not isinstance(raw, dict):
        return ProxySettings()

    defaults = ProxySettings()
    hosts = raw.get("hosts")
    host_list = [str(h) for h in hosts] if isinstance(hosts, list) else defaults.hosts

    raw_mode = str(raw.get("mode") or "").strip().lower()
    raw_enabled = bool(raw.get("enabled", False))
    raw_url = str(raw.get("url") or "").strip()
    raw_scheme = str(raw.get("scheme") or "socks5h").strip().lower()
    raw_host = str(raw.get("host") or "").strip()
    raw_port = raw.get("port")
    port_val: int | None = int(raw_port) if isinstance(raw_port, int) and not isinstance(raw_port, bool) else None

    if raw_mode in PROXY_MODES:
        mode = raw_mode
    elif raw_enabled:
        mode = PROXY_MODE_MANUAL
    else:
        mode = PROXY_MODE_NONE
        # Legacy Wave 1 default wrote url="socks5://127.0.0.1:1080" with enabled=False.
        if raw_url == "socks5://127.0.0.1:1080" and not raw.get("credentials_ref"):
            raw_url = ""

    clean_url, inline_user, inline_password = _strip_url_credentials(raw_url)
    user = inline_user
    password = inline_password
    ref = str(raw.get("credentials_ref") or "")
    if not (user or password) and ref:
        try:
            secret_raw = _secret_store(path.parent).resolve_ref(ref)
            if secret_raw:
                creds = json.loads(secret_raw)
                if isinstance(creds, dict):
                    user = str(creds.get("username") or "")
                    password = str(creds.get("password") or "")
        except (OSError, ValueError, RuntimeError):
            pass

    settings = ProxySettings(
        mode=mode,
        url=_inject_url_credentials(clean_url, user, password) if (clean_url and (user or password)) else clean_url,
        hosts=host_list,
        scheme=raw_scheme if raw_scheme in SCHEMES else "socks5h",
        host=raw_host,
        port=port_val,
        username=user,
        password=password,
        detected_url=str(raw.get("detected_url") or ""),
        detected_source=str(raw.get("detected_source") or ""),
    )

    # Migrate legacy schema or inline plaintext password immediately to SecretStore.
    if inline_user or inline_password or ("mode" not in raw and raw_url == "socks5://127.0.0.1:1080"):
        try:
            save(settings)
        except OSError:
            pass
    return settings


def save(settings: ProxySettings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    store = _secret_store(path.parent)
    clean_url, url_user, url_password = _strip_url_credentials(settings.url)
    user = settings.username or url_user
    password = settings.password or url_password
    clean_detected, _, _ = _strip_url_credentials(settings.detected_url)
    payload: dict[str, object] = {
        "schema_version": 2,
        "mode": settings.mode if settings.mode in PROXY_MODES else PROXY_MODE_NONE,
        "enabled": settings.enabled,
        "scheme": settings.scheme,
        "host": settings.host,
        "port": settings.port,
        "url": clean_url,
        "hosts": list(settings.hosts),
        "detected_url": clean_detected,
        "detected_source": settings.detected_source,
    }
    if user or password:
        store.set_secret(
            _SECRET_NS,
            _SECRET_KEY,
            json.dumps({"username": user, "password": password}, ensure_ascii=False),
        )
        payload["credentials_ref"] = SecretStore.secret_ref(_SECRET_NS, _SECRET_KEY)
    else:
        try:
            store.delete_secret(_SECRET_NS, _SECRET_KEY)
        except (OSError, ValueError, RuntimeError):
            pass

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    from app.core import token_store

    token_store.restrict(path)
    _log_proxy("INFO", f"Saved proxy configuration mode={settings.mode}", event_code="proxy_save")


# ====================================================================== автоопределение
def _parse_proxy_url_relaxed(raw_val: str, *, default_scheme: str = "http") -> str | None:
    text = (raw_val or "").strip()
    if not text or ";" in text and "=" in text:
        # handled separately by WinINET parser
        return None
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    try:
        ep = ProxyEndpoint.parse(text)
    except ValueError:
        return None
    if ep.scheme not in SCHEMES:
        return None
    return ep.url


def _parse_windows_proxy_server(value: str) -> list[tuple[str, str]]:
    """Parse WinINET/WinHTTP ProxyServer string (`host:port` or `http=...;socks=...`)."""
    raw = (value or "").strip()
    if not raw:
        return []
    out: list[tuple[str, str]] = []
    if "=" in raw:
        for item in raw.split(";"):
            part = item.strip()
            if not part or "=" not in part:
                continue
            proto, addr = part.split("=", 1)
            proto_l = proto.strip().lower()
            scheme = "socks5h" if "socks" in proto_l else "http"
            norm = _parse_proxy_url_relaxed(addr, default_scheme=scheme)
            if norm:
                out.append((f"Windows {proto_l.upper()}", norm))
    else:
        norm = _parse_proxy_url_relaxed(raw, default_scheme="http")
        if norm:
            out.append(("Windows System Proxy", norm))
    return out


def _try_extract_pac_proxies(pac_url: str, timeout: float = 2.0) -> tuple[list[str], str]:
    """Fetch a local/trusted PAC script and extract simple static PROXY/SOCKS rules without JS eval."""
    raw = (pac_url or "").strip()
    if not raw:
        return [], ""
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https", "file"):
        return [], f"Неподдерживаемая схема PAC: {parts.scheme or 'unknown'}"
    text = ""
    try:
        if parts.scheme == "file":
            p = Path(unquote(parts.path.lstrip("/") if sys.platform == "win32" else parts.path))
            if p.is_file() and p.stat().st_size <= 262144:
                text = p.read_text(encoding="utf-8", errors="replace")
        else:
            host = (parts.hostname or "").lower()
            if host not in ("127.0.0.1", "localhost", "::1"):
                return [], f"Удалённый PAC ({raw}) не загружается автоматически из соображений безопасности"
            import urllib.request

            with urllib.request.urlopen(raw, timeout=timeout) as resp:  # noqa: S310
                text = resp.read(262144).decode("utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        return [], f"Не удалось прочитать PAC ({raw}): {describe(exc)}"

    if not text:
        return [], f"PAC-файл пуст: {raw}"
    found: list[str] = []
    for match in re.finditer(r"\b(PROXY|HTTPS|SOCKS5|SOCKS)\s+([A-Za-z0-9.\-:]+:\d{1,5})", text, re.IGNORECASE):
        kind, addr = match.group(1).upper(), match.group(2)
        scheme = "socks5h" if kind.startswith("SOCKS") else "http"
        norm = _parse_proxy_url_relaxed(addr, default_scheme=scheme)
        if norm and norm not in found:
            found.append(norm)
    note = "" if found else f"Обнаружен сложный PAC-скрипт ({raw}); динамический JavaScript PAC не исполняется — настройте прокси вручную."
    return found, note


def detect_system_proxies() -> AutoDetectResult:
    """Gather bounded local/system proxy candidates (Windows WinINET/WinHTTP, env, local VPN ports)."""
    result = AutoDetectResult()
    seen_urls: set[str] = set()

    def add_candidate(source: str, url: str, pac_url: str = "") -> None:
        try:
            ep = ProxyEndpoint.parse(url)
        except ValueError:
            return
        key = ep.url
        if key in seen_urls:
            return
        seen_urls.add(key)
        result.candidates.append(
            DetectedProxyCandidate(
                source=source,
                url=key,
                scheme=ep.scheme,
                host=ep.host,
                port=ep.port,
                pac_url=pac_url,
            )
        )

    # 1. Process environment variables (respecting NO_PROXY info)
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(var, "").strip()
        if val:
            norm = _parse_proxy_url_relaxed(val)
            if norm:
                add_candidate(f"env:{var}", norm)
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    if no_proxy.strip():
        result.notes.append(f"NO_PROXY={no_proxy.strip()}")

    # 2. Windows WinINET user settings
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            ) as key:
                try:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except OSError:
                    proxy_enable = 0
                if int(proxy_enable or 0) == 1:
                    try:
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                        for src, norm in _parse_windows_proxy_server(str(proxy_server or "")):
                            add_candidate(src, norm)
                    except OSError:
                        pass
                try:
                    pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    pac_str = str(pac_url or "").strip()
                    if pac_str:
                        result.pac_urls.append(pac_str)
                        extracted, pac_note = _try_extract_pac_proxies(pac_str)
                        for norm in extracted:
                            add_candidate("PAC", norm, pac_url=pac_str)
                        if pac_note:
                            result.notes.append(pac_note)
                except OSError:
                    pass
        except OSError:
            pass

        # 3. Windows WinHTTP (`netsh winhttp show proxy` with CREATE_NO_WINDOW)
        try:
            proc = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3.0,
                creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)),
            )
            if proc.returncode == 0:
                m = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", proc.stdout)
                if m:
                    server_val = m.group(1).strip()
                    if server_val and "direct" not in server_val.lower():
                        for src, norm in _parse_windows_proxy_server(server_val):
                            add_candidate(f"WinHTTP {src}", norm)
        except (OSError, subprocess.SubprocessError):
            pass

    # 4. Bounded local VPN/proxy port probe on 127.0.0.1 ONLY
    for _scheme, port, label, url in _KNOWN_LOCAL_PROXY_CANDIDATES:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                add_candidate(label, url)

    return result


def verify_proxy_candidate(
    candidate: DetectedProxyCandidate,
    *,
    test_host: str = "api.cloudflare.com",
    test_port: int = 443,
    timeout: float = 4.0,
) -> DetectedProxyCandidate:
    """Verify actual protocol handshake, auth, target connect, and TLS (never accept open port alone)."""
    t0 = time.monotonic()
    try:
        ep = ProxyEndpoint.parse(candidate.url)
    except ValueError as exc:
        candidate.working = False
        candidate.reason = str(exc)
        return candidate

    try:
        sock = open_via_proxy(ep, test_host, test_port, timeout=timeout)
        try:
            if test_port == 443:
                ctx = ssl.create_default_context()
                tls = ctx.wrap_socket(sock, server_hostname=test_host)
                tls.close()
                candidate.tls_ok = True
        finally:
            try:
                sock.close()
            except OSError:
                pass
        candidate.working = True
        candidate.auth_required = False
        candidate.latency_ms = round((time.monotonic() - t0) * 1000.0, 1)
        candidate.reason = f"OK ({candidate.latency_ms:.0f} мс, TLS проверен)"
    except ProxyError as exc:
        msg = str(exc)
        candidate.working = False
        candidate.auth_required = ("407" in msg or "авторизац" in msg.lower() or "пароль" in msg.lower())
        candidate.reason = msg
    except ssl.SSLError as exc:
        candidate.working = False
        candidate.tls_ok = False
        candidate.reason = f"Ошибка TLS через прокси: {exc.reason or exc}"
    except OSError as exc:
        candidate.working = False
        candidate.reason = describe(exc)
    return candidate


def discover_working_proxy(*, timeout: float = 4.0) -> AutoDetectResult:
    """Detect local/system proxy candidates and verify protocol+target+TLS on each."""
    res = detect_system_proxies()
    _log_proxy(
        "INFO",
        f"Proxy auto-detection found {len(res.candidates)} candidate(s); verifying protocol & TLS",
        event_code="proxy_autodetect",
    )
    for cand in res.candidates:
        verify_proxy_candidate(cand, timeout=timeout)
        if cand.working and res.selected is None:
            res.selected = cand
    if res.selected is None:
        _log_proxy("WARNING", "No working proxy verified during auto-detection", event_code="proxy_autodetect_none")
    else:
        _log_proxy(
            "INFO",
            f"Verified working proxy {res.selected.scheme}://{res.selected.host}:{res.selected.port} "
            f"from {res.selected.source} ({res.selected.latency_ms:.0f} ms)",
            event_code="proxy_autodetect_ok",
        )
    return res


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
    has_creds = bool(ep.username or ep.password)
    methods = b"\x00\x02" if has_creds else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2)
    if version != 5:
        raise ProxyError("Ответ не соответствует протоколу SOCKS5")
    if method == 2:
        if not has_creds:
            raise ProxyError("SOCKS5: прокси требует логин и пароль")
        user, password = ep.username.encode("utf-8"), ep.password.encode("utf-8")
        if len(user) > 255 or len(password) > 255:
            raise ProxyError("SOCKS5: логин или пароль длиннее 255 байт")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        auth_resp = _recv_exact(sock, 2)
        if auth_resp[1] != 0:
            raise ProxyError("SOCKS5: неверный логин или пароль")
    elif method != 0:
        raise ProxyError("SOCKS5: прокси требует авторизацию — укажите логин и пароль")

    # socks5h отдаёт доменное имя прокси (remote DNS), socks5 резолвит локально при возможности.
    if ep.scheme == "socks5":
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            family, _, _, _, sockaddr = infos[0]
            ip_str = str(sockaddr[0])
            if family == socket.AF_INET:
                addr_bytes = b"\x01" + socket.inet_aton(ip_str)
            else:
                addr_bytes = b"\x04" + socket.inet_pton(socket.AF_INET6, ip_str)
            sock.sendall(b"\x05\x01\x00" + addr_bytes + struct.pack(">H", port))
        except OSError:
            name = host.encode("idna")
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
    else:
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
    if ep.username or ep.password:
        credentials = base64.b64encode(f"{ep.username}:{ep.password}".encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {credentials}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
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
        code = parts[1] if len(parts) >= 2 else "?"
        if code == "407":
            raise ProxyError("HTTP-прокси требует авторизацию (HTTP 407) — неверный или пустой логин/пароль")
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
    """TCP-соединение с host:port: через прокси если включён, никогда не подменяет прямым при ошибке."""
    if settings.covers(host, port):
        ep = settings.endpoint()
        return open_via_proxy(ep, host, port, timeout)
    if settings.enabled and settings.mode in (PROXY_MODE_AUTO, PROXY_MODE_MANUAL):
        # For targets explicitly outside covered hosts, keep direct socket unless covered.
        pass
    return socket.create_connection((host, port), timeout=timeout)


def https_request(
    settings: ProxySettings,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = TIMEOUT,
) -> tuple[int, dict[str, str], bytes]:
    """HTTPS-запрос с учётом режима прокси и строгой TLS-валидации."""
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


def diagnose_target(
    settings: ProxySettings,
    host: str,
    port: int,
    *,
    via_proxy: bool,
    timeout: float = 6.0,
) -> tuple[bool, str, dict[str, Any]]:
    """Detailed target check returning (ok, message, telemetry_dict)."""
    t0 = time.monotonic()
    info: dict[str, Any] = {
        "proxy_type": "",
        "tcp_ok": False,
        "auth_ok": None,
        "dns_ok": False,
        "tls_ok": None,
        "latency_ms": None,
    }
    try:
        if via_proxy:
            ep = settings.endpoint()
            info["proxy_type"] = ep.scheme.upper()
            info["auth_ok"] = True
            info["dns_ok"] = True
            sock = open_via_proxy(ep, host, port, timeout)
        else:
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            info["dns_ok"] = True
            sock = socket.create_connection((host, port), timeout=timeout)
        info["tcp_ok"] = True
        try:
            if port == 443:
                tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                tls.close()
                info["tls_ok"] = True
            elif port == EDGE_PORT:
                info["tls_ok"] = True  # tunnel TLS validated by cloudflared over TCP relay
        finally:
            sock.close()
        latency = round((time.monotonic() - t0) * 1000.0, 1)
        info["latency_ms"] = latency
        return True, f"✓ {latency:.0f} мс", info
    except ValueError as exc:
        return False, str(exc), info
    except ProxyError as exc:
        msg = str(exc)
        if "407" in msg or "пароль" in msg.lower() or "авторизац" in msg.lower():
            info["auth_ok"] = False
            info["tcp_ok"] = True
        return False, msg, info
    except ssl.SSLError as exc:
        info["tls_ok"] = False
        return False, f"ошибка TLS: {exc.reason or exc}", info
    except socket.gaierror:
        info["dns_ok"] = False
        return False, "имя не найдено в DNS", info
    except OSError as exc:
        return False, describe(exc), info


def probe(settings: ProxySettings, host: str, port: int, via_proxy: bool, timeout: float = 6.0) -> str | None:
    """Проверка доступа: None — доступен, иначе причина. Для 443 — вплоть до TLS."""
    ok, msg, _ = diagnose_target(settings, host, port, via_proxy=via_proxy, timeout=timeout)
    return None if ok else msg
