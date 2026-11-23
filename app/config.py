"""Настройки приложения: %APPDATA%\\MCPApp\\settings.json.

Без секретов: Bearer-токен живёт в app/core/token_store.py (отдельный файл
с ограниченным доступом), SSH-ключи — у бэкенда.

Новые поля безопасно добавлять: если в старом settings.json их нет,
берётся значение по умолчанию. Неизвестные поля из старых версий игнорируются.

Своего домена по умолчанию нет: режим «Временный адрес», public_url пустой.
Домен пользователь подключает сам — по инструкции «Подключение» → «Как подключить свой
домен» (app/ui/domain_guide.py, docs/custom-domain.md).
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
DEFAULT_TUNNEL_MODE = TUNNEL_QUICK

DEFAULT_MCP_PATH = "/mcp"
DEFAULT_PUBLIC_URL = ""  # своего домена по умолчанию нет
DEFAULT_CLOUDFLARED_CONFIG = str(Path.home() / ".cloudflared" / "config.yml")

# До 0.4.0 здесь стоял адрес автора, и он попадал в settings.json на любой машине.
# Убираем его, если на машине нет своего config.yml, — значит, домен не настраивали.
_LEGACY_DEFAULT_PUBLIC_URLS = ("https://mcp.souron.space/mcp",)


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
    public_url: str = DEFAULT_PUBLIC_URL  # свой домен (режим named); '' = ещё не настроен
    mcp_path: str = DEFAULT_MCP_PATH      # путь MCP-эндпоинта на сервере
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    server_health_path: str = "/health"  # server.py отвечает тут без токена и без записи в лог
    metrics_port: int = 20241        # cloudflared --metrics -> /ready для индикатора

    # Cloudflare Tunnel
    tunnel_mode: str = DEFAULT_TUNNEL_MODE  # quick | named
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
    allow_query_token: bool = False  # на новых установках секрет не помещаем в URL по умолчанию
    # Все инструменты, кроме server_info, скрыты в стандартном режиме.
    # Временный ручной opt-in через settings.json; GUI-переключатели — в отдельном PR.
    enable_advanced_tools: bool = False
    enable_execution_tools: bool = False
    enable_oauth: bool = True  # OAuth DCR + browser consent for read-only external MCP clients

    # Поведение
    start_services_on_launch: bool = False
    minimize_to_tray_on_close: bool = True
    auto_restart: bool = True

    # ------------------------------------------------------------------ свойства
    @property
    def is_quick_tunnel(self) -> bool:
        return self.tunnel_mode == TUNNEL_QUICK

    @property
    def has_public_url(self) -> bool:
        """Адрес своего домена задан (без него режим named не запустится)."""
        return bool(self.public_url)

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
        """Первый запуск (нет settings.json): всегда «Временный адрес» без домена.

        Он работает без аккаунта Cloudflare. Свой домен пользователь включает сам,
        когда настроит туннель, — даже если config.yml уже есть, мы не знаем, какой
        из его адресов отдать клиентам.
        """
        settings = cls()
        try:
            settings.save()
        except OSError:
            pass
        return settings

    def sanitize(self) -> None:
        """Подправить значения, которые могли быть отредактированы вручную."""
        for field in ("allow_query_token", "enable_advanced_tools", "enable_execution_tools", "enable_oauth"):
            if not isinstance(getattr(self, field), bool):
                setattr(self, field, False)
        if not self.enable_advanced_tools:
            self.enable_execution_tools = False
        if self.tunnel_mode not in TUNNEL_MODES:
            self.tunnel_mode = DEFAULT_TUNNEL_MODE
        self.mcp_path = normalize_mcp_path(self.mcp_path)
        self.server_health_path = normalize_mcp_path(self.server_health_path)
        url = normalize_public_url(self.public_url, self.mcp_path)
        if (urlsplit(url).hostname or "").endswith(".trycloudflare.com"):
            url = ""  # временный адрес — не свой домен
        if url in _LEGACY_DEFAULT_PUBLIC_URLS and not self.has_named_tunnel_config():
            url = ""
        self.public_url = url
        if not self.public_url and self.tunnel_mode == TUNNEL_NAMED and not self.has_named_tunnel_config():
            # Домен не настроен вообще — «Свой домен» не запустится, остаётся временный.
            self.tunnel_mode = TUNNEL_QUICK

    def save(self) -> None:
        target = self.path()
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)  # атомарная запись
