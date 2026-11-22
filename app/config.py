"""Настройки приложения: %APPDATA%\\MCPApp\\settings.json.

Без секретов: Bearer-токен живёт в app/core/token_store.py (отдельный файл
с ограниченным доступом), SSH-ключи — у бэкенда.

Новые поля безопасно добавлять: если в старом settings.json их нет,
берётся значение по умолчанию. Неизвестные поля из старых версий игнорируются.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from app.paths import user_data_dir

SETTINGS_FILE = "settings.json"

# Режимы туннеля
TUNNEL_NAMED = "named"   # свой домен: config.yml + `cloudflared tunnel run`
TUNNEL_QUICK = "quick"   # временный адрес *.trycloudflare.com: `cloudflared tunnel --url …`
TUNNEL_MODES = (TUNNEL_NAMED, TUNNEL_QUICK)

DEFAULT_MCP_PATH = "/mcp"
DEFAULT_PUBLIC_URL = "https://mcp.souron.space/mcp"
DEFAULT_CLOUDFLARED_CONFIG = str(Path.home() / ".cloudflared" / "config.yml")


def normalize_mcp_path(value: str) -> str:
    path = (value or "").strip()
    if not path:
        return DEFAULT_MCP_PATH
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or DEFAULT_MCP_PATH


def normalize_public_url(value: str, mcp_path: str = DEFAULT_MCP_PATH) -> str:
    """Привести ввод пользователя к каноническому виду; '' — если это не адрес.

        mcp.example.com            -> https://mcp.example.com/mcp
        https://MCP.example.com/   -> https://mcp.example.com/mcp
        https://host/что-угодно    -> https://host/mcp

    Путь всегда равен mcp_path: сервер отвечает только там, и любой другой путь
    в ссылке дал бы клиентам 404.
    """
    raw = (value or "").strip()
    if not raw or any(ch.isspace() for ch in raw):
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or "@" in parts.netloc:
        return ""
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:  # неверный порт
        return ""
    if not host or ("." not in host and host != "localhost"):
        return ""
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme, netloc, normalize_mcp_path(mcp_path), "", ""))


@dataclass
class Settings:
    # Сеть
    public_url: str = DEFAULT_PUBLIC_URL  # свой домен (режим named)
    mcp_path: str = DEFAULT_MCP_PATH      # путь MCP-эндпоинта на сервере
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    server_health_path: str = "/health"  # server.py отвечает тут без токена и без записи в лог
    metrics_port: int = 20241        # cloudflared --metrics -> /ready для индикатора

    # Cloudflare Tunnel
    tunnel_mode: str = TUNNEL_NAMED  # named | quick
    cloudflared_path: str = ""       # пусто = автопоиск (встроенный в сборку, Program Files, PATH)
    cloudflared_config: str = DEFAULT_CLOUDFLARED_CONFIG  # только для named
    # Протокол связи с Cloudflare: "http2" (TCP) | "quic" (UDP 7844) | "auto".
    # http2 по умолчанию: провайдеры часто блокируют исходящий UDP, и QUIC не поднимается.
    # Пустая строка = не передавать флаг (тогда решает config.yml или cloudflared).
    tunnel_protocol: str = "http2"

    # Бэкенд
    backend_workdir: str = ""        # пусто = paths.default_backend_workdir()
    # ?token=… в ссылке вместо заголовка Authorization (для клиентов, где заголовок
    # не задать). Токен вырезается из логов.
    allow_query_token: bool = True

    # Поведение
    start_services_on_launch: bool = False
    minimize_to_tray_on_close: bool = True
    auto_restart: bool = True

    # ------------------------------------------------------------------ свойства
    @property
    def is_quick_tunnel(self) -> bool:
        return self.tunnel_mode == TUNNEL_QUICK

    def local_host(self) -> str:
        """Адрес, по которому стучаться к серверу с этой же машины."""
        return "127.0.0.1" if self.server_host in ("0.0.0.0", "::", "") else self.server_host

    def has_named_tunnel_config(self) -> bool:
        return Path(self.cloudflared_config).expanduser().is_file()

    # ------------------------------------------------------------------ файл
    @classmethod
    def path(cls) -> Path:
        return user_data_dir() / SETTINGS_FILE

    @classmethod
    def load(cls) -> "Settings":
        try:
            data = json.loads(cls.path().read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls.first_run()
        except (OSError, ValueError):
            # Битый файл не должен мешать старту — работаем на дефолтах.
            return cls()
        if not isinstance(data, dict):
            return cls()
        known = {f.name for f in fields(cls)}
        try:
            settings = cls(**{k: v for k, v in data.items() if k in known})
        except TypeError:
            return cls()
        settings.sanitize()
        return settings

    @classmethod
    def first_run(cls) -> "Settings":
        """Первый запуск (нет settings.json).

        На чистой машине нет ~/.cloudflared/config.yml — именованный туннель не
        запустится. Тогда сразу выбираем «Временный адрес»: он работает без домена
        и без аккаунта Cloudflare, и кнопка «Запустить» срабатывает с первого раза.
        """
        settings = cls()
        if not settings.has_named_tunnel_config():
            settings.tunnel_mode = TUNNEL_QUICK
        try:
            settings.save()
        except OSError:
            pass
        return settings

    def sanitize(self) -> None:
        """Подправить значения, которые могли быть отредактированы вручную."""
        if self.tunnel_mode not in TUNNEL_MODES:
            self.tunnel_mode = TUNNEL_NAMED
        self.mcp_path = normalize_mcp_path(self.mcp_path)
        self.server_health_path = normalize_mcp_path(self.server_health_path)
        self.public_url = normalize_public_url(self.public_url, self.mcp_path) or DEFAULT_PUBLIC_URL

    def save(self) -> None:
        target = self.path()
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)  # атомарная запись
