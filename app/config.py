"""Настройки приложения: %APPDATA%\\SouronMCP\\settings.json.

Секреты (Bearer-токены, SSH-ключи) сюда НЕ кладём — их читает сам
бэкенд из переменных окружения или .env.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from app.paths import user_data_dir

SETTINGS_FILE = "settings.json"


@dataclass
class Settings:
    # Сеть
    public_url: str = "https://mcp.souron.space/mcp"
    server_host: str = "127.0.0.1"
    server_port: int = 8000          # должен совпадать с портом в backend/server.py
    metrics_port: int = 20241        # cloudflared --metrics -> /ready для индикатора

    # Cloudflare Tunnel
    cloudflared_path: str = ""       # пусто = автопоиск (bin/, Program Files, PATH)
    cloudflared_config: str = str(Path.home() / ".cloudflared" / "config.yml")

    # Бэкенд
    backend_workdir: str = ""        # пусто = paths.default_backend_workdir()

    # Поведение
    start_services_on_launch: bool = False
    minimize_to_tray_on_close: bool = True
    auto_restart: bool = True

    @classmethod
    def path(cls) -> Path:
        return user_data_dir() / SETTINGS_FILE

    @classmethod
    def load(cls) -> "Settings":
        try:
            data = json.loads(cls.path().read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError):
            # Битый файл не должен мешать старту — работаем на дефолтах.
            return cls()
        if not isinstance(data, dict):
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        target = self.path()
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)  # атомарная запись
