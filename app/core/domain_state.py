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
    setup_mode: str = ""
    public_url: str = ""
    decrypt_error: str = ""

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
    hostname = str(raw.get("hostname") or "").strip().lower()
    tunnel_id = str(raw.get("tunnel_id") or "").strip()
    zone_name = str(raw.get("zone_name") or "").strip()
    setup_mode = str(raw.get("setup_mode") or "").strip()
    if not setup_mode and hostname:
        setup_mode = "api" if (zone_name or tunnel_id) else "token"
    public_url = str(raw.get("public_url") or "").strip()

    legacy_token = str(raw.get("tunnel_token") or "")
    if legacy_token:
        state = DomainState(
            hostname=hostname,
            tunnel_id=tunnel_id,
            tunnel_token=legacy_token,
            zone_name=zone_name,
            setup_mode=setup_mode,
            public_url=public_url,
        )
        try:
            save(state)
        except OSError:
            pass
        return state

    token = ""
    decrypt_error = ""
    ref = str(raw.get("tunnel_token_ref") or "")
    if ref:
        try:
            token = store.resolve_ref(ref) or ""
        except (OSError, ValueError, RuntimeError) as exc:
            token = ""
            decrypt_error = f"{type(exc).__name__}: {exc}"
    else:
        try:
            token = store.get_secret(_SECRET_NS, _SECRET_KEY) or ""
        except (OSError, ValueError, RuntimeError) as exc:
            token = ""
            decrypt_error = f"{type(exc).__name__}: {exc}"

    return DomainState(
        hostname=hostname,
        tunnel_id=tunnel_id,
        tunnel_token=token,
        zone_name=zone_name,
        setup_mode=setup_mode,
        public_url=public_url,
        decrypt_error=decrypt_error,
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

    mode = state.setup_mode.strip() or ("api" if (state.zone_name or state.tunnel_id) else ("token" if state.hostname else ""))
    payload = {
        "hostname": state.hostname,
        "tunnel_id": state.tunnel_id,
        "zone_name": state.zone_name,
        "setup_mode": mode,
        "public_url": state.public_url,
        "tunnel_token_ref": ref,
    }
    from app.core.atomic_io import atomic_write_json

    atomic_write_json(target, payload, indent=2, restrict_acl=False)
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
