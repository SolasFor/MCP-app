"""Свой домен, настроенный мастером (app/ui/domain_wizard.py): %APPDATA%\\MCPApp\\domain.json.

Имя хоста и метаданные хранятся в domain.json, а секретный ключ туннеля
(`tunnel_token`) защищён в SecretStore (`secret://tunnel/cloudflare_named_token`).
Прежний открытый `domain.json` автоматически мигрируется при чтении.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.core import token_store
from app.core.secret_store import SecretStore
from app.paths import user_data_dir

DOMAIN_FILE = "domain.json"
_SECRET_NS = "tunnel"
_SECRET_KEY = "cloudflare_named_token"


@dataclass
class DomainState:
    hostname: str = ""
    tunnel_id: str = ""
    tunnel_token: str = ""
    zone_name: str = ""

    @property
    def is_configured(self) -> bool:
        return bool(self.hostname and self.tunnel_token)


def state_path() -> Path:
    return user_data_dir() / DOMAIN_FILE


def _store(base_dir: Path | None = None) -> SecretStore:
    root = base_dir if base_dir is not None else state_path().parent
    return SecretStore(root / "secrets")


def load() -> DomainState:
    target = state_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DomainState()
    if not isinstance(raw, dict):
        return DomainState()

    store = _store(target.parent)
    legacy_token = str(raw.get("tunnel_token") or "")
    if legacy_token:
        state = DomainState(
            hostname=str(raw.get("hostname") or ""),
            tunnel_id=str(raw.get("tunnel_id") or ""),
            tunnel_token=legacy_token,
            zone_name=str(raw.get("zone_name") or ""),
        )
        try:
            save(state)
        except OSError:
            pass
        return state

    token = ""
    ref = str(raw.get("tunnel_token_ref") or "")
    if ref:
        try:
            token = store.resolve_ref(ref) or ""
        except (OSError, ValueError, RuntimeError):
            token = ""
    else:
        try:
            token = store.get_secret(_SECRET_NS, _SECRET_KEY) or ""
        except (OSError, ValueError, RuntimeError):
            token = ""

    return DomainState(
        hostname=str(raw.get("hostname") or ""),
        tunnel_id=str(raw.get("tunnel_id") or ""),
        tunnel_token=token,
        zone_name=str(raw.get("zone_name") or ""),
    )


def save(state: DomainState) -> None:
    target = state_path()
    store = _store(target.parent)
    ref = ""
    if state.tunnel_token:
        store.set_secret(_SECRET_NS, _SECRET_KEY, state.tunnel_token)
        ref = SecretStore.secret_ref(_SECRET_NS, _SECRET_KEY)
    else:
        store.delete_secret(_SECRET_NS, _SECRET_KEY)

    payload = {
        "hostname": state.hostname,
        "tunnel_id": state.tunnel_id,
        "zone_name": state.zone_name,
        "tunnel_token_ref": ref,
    }
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(target)
    token_store.restrict(target)


def clear() -> None:
    target = state_path()
    try:
        _store(target.parent).delete_secret(_SECRET_NS, _SECRET_KEY)
    except (OSError, ValueError, RuntimeError):
        pass
    try:
        target.unlink()
    except FileNotFoundError:
        pass
