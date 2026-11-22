"""Состояние «своего домена»: настроен ли он и чем запускать туннель.

Два способа настройки считаются рабочими:
  * мастер (app/ui/domain_wizard.py) — %APPDATA%\\MCPApp\\domain.json с именем хоста и
    токеном туннеля; запуск: `cloudflared tunnel run --token <токен>`;
  * ручная настройка по инструкции — ~/.cloudflared/config.yml, в котором есть tunnel и
    существующий credentials-file; запуск: `cloudflared tunnel run`.

domain_ready() — единственная проверка для кнопки «Свой домен»: True → просто
переключить режим, False → открыть мастер. Инструкция — только по ссылке.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from app.paths import user_data_dir


@dataclass
class DomainState:
    hostname: str = ""
    tunnel_id: str = ""
    tunnel_token: str = ""
    zone_name: str = ""

    @property
    def public_url(self) -> str:
        return f"https://{self.hostname}" if self.hostname else ""


def state_path() -> Path:
    return user_data_dir() / "domain.json"


def load() -> DomainState:
    try:
        raw = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DomainState()
    return DomainState(**{key: str(raw.get(key, "")) for key in DomainState.__dataclass_fields__})


def save(state: DomainState) -> None:
    path = state_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(state), ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def clear() -> None:
    try:
        state_path().unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------- ручная настройка
def cloudflared_config_path() -> Path:
    return Path.home() / ".cloudflared" / "config.yml"


def _yaml_value(text: str, key: str) -> str:
    """Значение ключа верхнего уровня из простого config.yml (без зависимости от PyYAML)."""
    match = re.search(rf"^{re.escape(key)}\s*:\s*(.+?)\s*$", text, re.MULTILINE)
    if not match:
        return ""
    value = match.group(1).split(" #", 1)[0].strip()
    return value.strip("'\"")


def manual_config_ready() -> bool:
    try:
        text = cloudflared_config_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if not _yaml_value(text, "tunnel"):
        return False
    credentials = _yaml_value(text, "credentials-file")
    return bool(credentials) and Path(os.path.expandvars(credentials)).expanduser().is_file()


def manual_hostname() -> str:
    """Первый hostname из ingress ручного config.yml (для показа адреса)."""
    try:
        text = cloudflared_config_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    match = re.search(r"hostname\s*:\s*['\"]?([A-Za-z0-9.-]+)", text)
    return match.group(1) if match else ""


# ---------------------------------------------------------------- для GUI и туннеля
def domain_ready() -> bool:
    state = load()
    return bool(state.hostname and state.tunnel_token) or manual_config_ready()


def current_hostname() -> str:
    state = load()
    if state.hostname and state.tunnel_token:
        return state.hostname
    return manual_hostname()


def tunnel_run_args() -> list[str]:
    """Аргументы cloudflared для своего домена (без пути к exe).

    Токен передаётся через переменную окружения TUNNEL_TOKEN (см. tunnel_env), чтобы он
    не попадал в строку запуска и в журнал.
    """
    return ["tunnel", "--no-autoupdate", "run"]


def tunnel_env() -> dict[str, str]:
    state = load()
    if state.hostname and state.tunnel_token:
        return {"TUNNEL_TOKEN": state.tunnel_token}
    return {}
