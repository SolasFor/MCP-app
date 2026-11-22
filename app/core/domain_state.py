"""Свой домен, настроенный мастером (app/ui/domain_wizard.py): %APPDATA%\\MCPApp\\domain.json.

Здесь имя хоста и ключ (токен) туннеля для `cloudflared tunnel run`. Ключ — секрет:
файл получает ACL только для текущего пользователя (как token.json), а cloudflared
получает ключ переменной окружения TUNNEL_TOKEN, а не аргументом (аргументы видны
в Диспетчере задач и попадают в журнал).

Ручная настройка по инструкции (config.yml) живёт в Settings.cloudflared_config;
какой способ считается «доменом настроен», решает ServiceManager.has_domain().
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from app.core import token_store
from app.paths import user_data_dir

DOMAIN_FILE = "domain.json"


@dataclass
class DomainState:
    hostname: str = ""
    tunnel_id: str = ""
    tunnel_token: str = ""
    zone_name: str = ""

    @property
    def is_configured(self) -> bool:
        return bool(self.hostname and self.tunnel_token)


def state_path():
    return user_data_dir() / DOMAIN_FILE


def load() -> DomainState:
    try:
        raw = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DomainState()
    if not isinstance(raw, dict):
        return DomainState()
    return DomainState(**{key: str(raw.get(key) or "") for key in DomainState.__dataclass_fields__})


def save(state: DomainState) -> None:
    target = state_path()
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(state), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(target)
    token_store.restrict(target)


def clear() -> None:
    try:
        state_path().unlink()
    except FileNotFoundError:
        pass
