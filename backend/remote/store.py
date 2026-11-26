"""Persistent devices.json store, SecretStore('ssh') refs, and safe ~/.ssh/config importer."""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

import paramiko

from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from backend.remote.models import DevicePermissions, DeviceProfile, validate_device_id

_HOST_DIRECTIVE_RE = re.compile(r"^\s*Host\s+(.+)$", re.IGNORECASE)


def import_ssh_config(path: Path | None = None) -> list[DeviceProfile]:
    """Parse explicit host entries from OpenSSH ~/.ssh/config safely (ignores ProxyCommand & wildcards)."""
    cfg_path = Path(path).expanduser() if path is not None else (Path.home() / ".ssh" / "config")
    if not cfg_path.is_file():
        return []
    raw_text = cfg_path.read_text(encoding="utf-8", errors="replace")
    filtered_lines: list[str] = []
    aliases: list[str] = []
    in_wildcard_or_match = False
    for line in raw_text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("match "):
            in_wildcard_or_match = True
            continue
        m = _HOST_DIRECTIVE_RE.match(stripped)
        if m:
            literal = [t for t in m.group(1).split() if not any(ch in t for ch in ("*", "?", "!", "%"))]
            in_wildcard_or_match = not literal
            if not in_wildcard_or_match:
                filtered_lines.append("Host " + " ".join(literal))
                for token in literal:
                    if token not in aliases:
                        aliases.append(token)
            continue
        if in_wildcard_or_match or low.startswith("proxycommand"):
            continue
        filtered_lines.append(stripped)

    cfg = paramiko.SSHConfig.from_text("\n".join(filtered_lines))

    profiles: list[DeviceProfile] = []
    for alias in aliases:
        entry = cfg.lookup(alias)
        hostname = str(entry.get("hostname") or alias).strip()
        user = str(entry.get("user") or "").strip()
        port_raw = entry.get("port")
        port = int(port_raw) if port_raw and str(port_raw).isdigit() else 22
        ident_files = entry.get("identityfile") or []
        key_path = str(ident_files[0]).strip() if isinstance(ident_files, list) and ident_files else ""
        safe_id = re.sub(r"[^a-zA-Z0-9_.-]+", "_", alias).strip("._-") or "device"
        try:
            profiles.append(
                DeviceProfile(
                    device_id=safe_id[:64],
                    name=alias,
                    host=hostname,
                    port=port,
                    username=user,
                    group="imported",
                    auth_method="key" if key_path else "agent",
                    key_path=key_path,
                    permissions=DevicePermissions(),
                    enabled=True,
                )
            )
        except ValueError:
            continue
    return profiles


class DeviceStore:
    """Atomic JSON storage for remote SSH/SFTP device profiles + DPAPI/Keychain secrets."""

    def __init__(
        self,
        config_path: Path | None = None,
        *,
        secret_store: SecretStore | None = None,
    ) -> None:
        from app.core.atomic_io import try_init_private_dir

        self.path = Path(config_path) if config_path is not None else (user_data_dir() / "remote" / "devices.json")
        try_init_private_dir(self.path.parent)
        self._secrets = secret_store
        self._lock = threading.RLock()

    def _secret_store(self) -> SecretStore:
        if self._secrets is None:
            env_dir = os.environ.get("MCP_SECRETS_DIR")
            self._secrets = SecretStore(Path(env_dir)) if env_dir else SecretStore(self.path.parent.parent / "secrets")
        return self._secrets

    def _atomic_write_json(self, payload: dict[str, Any]) -> None:
        from app.core.atomic_io import atomic_write_json

        atomic_write_json(self.path, payload, indent=2, restrict_acl=True)

    def load_all(self) -> dict[str, DeviceProfile]:
        with self._lock:
            if not self.path.is_file():
                return {}
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {}
            items = raw.get("devices") if isinstance(raw, dict) else {}
            out: dict[str, DeviceProfile] = {}
            if isinstance(items, dict):
                for _k, rec in items.items():
                    if isinstance(rec, dict):
                        try:
                            prof = DeviceProfile.from_dict(rec)
                            out[prof.device_id] = prof
                        except (ValueError, TypeError):
                            continue
            return out

    def save_all(self, devices: dict[str, DeviceProfile]) -> None:
        with self._lock:
            payload = {
                "version": 1,
                "devices": {k: v.to_dict() for k, v in sorted(devices.items())},
            }
            self._atomic_write_json(payload)

    def get(self, device_id: str) -> DeviceProfile | None:
        return self.load_all().get(validate_device_id(device_id))

    def upsert(self, profile: DeviceProfile) -> None:
        with self._lock:
            all_devs = self.load_all()
            all_devs[profile.device_id] = profile
            self.save_all(all_devs)

    def remove(self, device_id: str) -> DeviceProfile | None:
        clean = validate_device_id(device_id)
        with self._lock:
            all_devs = self.load_all()
            removed = all_devs.pop(clean, None)
            if removed is not None:
                self.save_all(all_devs)
            return removed

    def set_secret(self, device_id: str, kind: str, value: str) -> str:
        clean_id = validate_device_id(device_id)
        if kind not in ("password", "passphrase"):
            raise ValueError(f"Unsupported SSH secret kind: {kind!r}")
        key = f"{clean_id}__{kind}"
        self._secret_store().set_secret("ssh", key, value)
        return SecretStore.secret_ref("ssh", key)

    def resolve_secret_ref(self, ref: str) -> str:
        if not ref:
            return ""
        return self._secret_store().resolve_ref(ref) or ""

    def collect_secret_values(self) -> list[str]:
        vals: list[str] = []
        store = self._secret_store()
        for dev in self.load_all().values():
            for ref in (dev.password_ref, dev.passphrase_ref):
                if ref:
                    sec = store.resolve_ref(ref) or ""
                    if sec:
                        vals.append(sec)
        return vals

    def export_redacted(self) -> dict[str, Any]:
        """Export device registry without plaintext passwords or passphrases."""
        return {
            "version": 1,
            "devices": {k: v.to_dict() for k, v in sorted(self.load_all().items())},
        }
