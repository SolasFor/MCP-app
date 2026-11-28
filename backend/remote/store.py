"""Persistent devices.json store, WAL transaction recovery, SecretStore('ssh') refs, and safe ~/.ssh/config importer."""
from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from pathlib import Path
from typing import Any

from app.core.atomic_io import (
    atomic_write_bytes,
    atomic_write_json,
    cross_process_lock,
    is_reparse_or_symlink,
    try_init_private_dir,
)
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from backend.remote.models import DeviceProfile, validate_device_id

SCHEMA_VERSION = 2
MAX_DEVICES_FILE_BYTES = 8 * 1024 * 1024
_MAX_TX_BYTES = 16 * 1024 * 1024
_MAX_PREIMAGE_BYTES = 8 * 1024 * 1024
_TX_TOP_KEYS = frozenset({"schema_version", "files", "created_secrets"})


def _canonical_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def import_ssh_config(path: Path | None = None) -> list[DeviceProfile]:
    """Parse explicit host entries from OpenSSH ~/.ssh/config safely (ignores ProxyCommand & wildcards)."""
    from backend.remote.onboarding import inspect_ssh_config

    report = inspect_ssh_config(path)
    return [cand.profile for cand in report.candidates]


class DeviceStore:
    """Atomic JSON storage for remote SSH/SFTP device profiles + DPAPI/Keychain secrets."""

    def __init__(
        self,
        config_path: Path | None = None,
        *,
        secret_store: SecretStore | None = None,
    ) -> None:
        self.path = Path(config_path) if config_path is not None else (user_data_dir() / "remote" / "devices.json")
        try_init_private_dir(self.path.parent)
        self._secrets = secret_store
        self._lock = threading.RLock()
        self._init_marker = self.path.parent / f".{self.path.name}.initialized"

    @property
    def managed_known_hosts_path(self) -> Path:
        return self.path.parent / "known_hosts"

    @property
    def tx_journal_path(self) -> Path:
        return self.path.with_name(".n05_device_tx.json")

    def lock(self, timeout: float = 10.0):
        """Return a thread-reentrant cross-process lock covering this device store."""
        return cross_process_lock(self.path.with_name(".devices.lock"), timeout=timeout)

    def _secret_store(self) -> SecretStore:
        if self._secrets is None:
            env_dir = os.environ.get("MCP_SECRETS_DIR")
            self._secrets = SecretStore(Path(env_dir)) if env_dir else SecretStore(self.path.parent.parent / "secrets")
        return self._secrets

    def _allowed_tx_paths(self) -> dict[str, Path]:
        return {
            _canonical_path_key(p): p
            for p in (self.path, self.managed_known_hosts_path, self._init_marker)
        }

    @staticmethod
    def _parse_tx_file_entry(
        entry: Any,
        allowed: dict[str, Path],
    ) -> tuple[Path, bool, bytes | None]:
        if not isinstance(entry, dict):
            raise ValueError("Invalid N05 tx file entry")
        p_str = entry.get("path")
        existed = entry.get("existed")
        b64 = entry.get("content_b64")
        if not isinstance(p_str, str) or type(existed) is not bool:
            raise ValueError("Invalid N05 tx file metadata")
        target = allowed.get(_canonical_path_key(Path(p_str)))
        if target is None or is_reparse_or_symlink(target):
            raise ValueError(f"Forbidden or symlink N05 tx path: {p_str!r}")
        if not existed:
            return (target, False, None)
        if not isinstance(b64, str):
            raise ValueError("Missing preimage bytes in N05 tx journal")
        try:
            data = base64.b64decode(b64.encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Corrupt base64 preimage in N05 tx journal") from exc
        if len(data) > _MAX_PREIMAGE_BYTES:
            raise ValueError("Oversized preimage in N05 tx journal")
        return (target, True, data)

    @staticmethod
    def _parse_tx_secret_entry(pair: Any) -> tuple[str, str]:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or pair[0] != "ssh"
            or not isinstance(pair[1], str)
            or not pair[1].strip()
        ):
            raise ValueError("Invalid N05 tx secret entry")
        return ("ssh", pair[1])

    def _validate_tx_journal(self) -> tuple[list[tuple[Path, bool, bytes | None]], list[tuple[str, str]]]:
        tx_path = self.tx_journal_path
        if is_reparse_or_symlink(tx_path) or tx_path.stat().st_size > _MAX_TX_BYTES:
            raise ValueError("Invalid N05 device transaction journal")
        raw = json.loads(tx_path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, dict) or set(raw.keys()) != _TX_TOP_KEYS:
            raise ValueError("Malformed N05 device transaction journal structure")
        ver = raw.get("schema_version")
        if type(ver) is not int or ver != 1:
            raise ValueError("Unsupported N05 device transaction schema version")
        files_raw = raw.get("files")
        secrets_raw = raw.get("created_secrets")
        if not isinstance(files_raw, list) or not isinstance(secrets_raw, list):
            raise ValueError("Malformed N05 device transaction entries")
        allowed = self._allowed_tx_paths()
        files_out = [self._parse_tx_file_entry(entry, allowed) for entry in files_raw]
        secrets_out = [self._parse_tx_secret_entry(pair) for pair in secrets_raw]
        return files_out, secrets_out

    def recover_pending_tx_unlocked(self) -> None:
        """Recover and roll back an interrupted device onboarding/rotation transaction."""
        tx_path = self.tx_journal_path
        if not os.path.lexists(tx_path):
            return
        files_out, secrets_out = self._validate_tx_journal()
        for target, existed, data in files_out:
            if existed:
                assert data is not None
                atomic_write_bytes(target, data, restrict_acl=True)
            else:
                target.unlink(missing_ok=True)
        store = self._secret_store()
        for ns, key in secrets_out:
            try:
                store.delete_secret(ns, key)
            except Exception:  # noqa: BLE001
                pass
        tx_path.unlink(missing_ok=True)

    def _has_prior_init_evidence(self) -> bool:
        return self._init_marker.exists()

    def _atomic_write_json(self, payload: dict[str, Any]) -> None:
        atomic_write_json(self.path, payload, indent=2, restrict_acl=True)
        if not self._init_marker.exists():
            atomic_write_json(self._init_marker, {"schema_version": SCHEMA_VERSION}, indent=None, restrict_acl=True)

    @staticmethod
    def _decode_strict_profiles(items: dict[str, Any]) -> dict[str, DeviceProfile]:
        out: dict[str, DeviceProfile] = {}
        for key, rec in items.items():
            if not isinstance(rec, dict):
                raise ValueError(f"Malformed device record for key {key!r}")
            prof = DeviceProfile.from_dict(rec)
            if prof.device_id != key:
                raise ValueError(f"Device key mismatch: {key!r} != {prof.device_id!r}")
            out[prof.device_id] = prof
        return out

    def _parse_strict_document(self) -> dict[str, DeviceProfile]:
        if is_reparse_or_symlink(self.path):
            raise ValueError("Refusing symlink/reparse device config file")
        if not self.path.exists():
            if self._has_prior_init_evidence():
                raise ValueError(f"Device configuration file is missing after initialization: {self.path}")
            return {}
        if self.path.stat().st_size > MAX_DEVICES_FILE_BYTES:
            raise ValueError("Device configuration file exceeds size limit")
        raw_text = self.path.read_text(encoding="utf-8")
        if not raw_text.strip():
            raise ValueError("Device configuration file is empty")
        raw = json.loads(raw_text)
        if not isinstance(raw, dict):
            raise ValueError("Device configuration root must be a JSON object")
        ver = raw.get("version", 1)
        if type(ver) is not int or ver not in (1, SCHEMA_VERSION):
            raise ValueError(f"Unsupported devices.json version: {ver!r}")
        items = raw.get("devices")
        if not isinstance(items, dict):
            raise ValueError("Device configuration 'devices' field must be an object")
        return self._decode_strict_profiles(items)

    def load_all(self, *, strict: bool = False) -> dict[str, DeviceProfile]:
        with self.lock():
            with self._lock:
                self.recover_pending_tx_unlocked()
                if strict:
                    return self._parse_strict_document()
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
        with self.lock():
            with self._lock:
                payload = {
                    "version": SCHEMA_VERSION,
                    "devices": {k: v.to_dict() for k, v in sorted(devices.items())},
                }
                self._atomic_write_json(payload)

    def get(self, device_id: str, *, strict: bool = False) -> DeviceProfile | None:
        return self.load_all(strict=strict).get(validate_device_id(device_id))

    def upsert(self, profile: DeviceProfile) -> None:
        with self.lock():
            with self._lock:
                all_devs = self.load_all(strict=True)
                all_devs[profile.device_id] = profile
                self.save_all(all_devs)

    def remove(self, device_id: str) -> DeviceProfile | None:
        clean = validate_device_id(device_id)
        with self.lock():
            with self._lock:
                all_devs = self.load_all(strict=True)
                removed = all_devs.pop(clean, None)
                if removed is not None:
                    self.save_all(all_devs)
                return removed

    def set_secret(self, device_id: str, kind: str, value: str, *, suffix: str = "") -> str:
        clean_id = validate_device_id(device_id)
        if kind not in ("password", "passphrase"):
            raise ValueError(f"Unsupported SSH secret kind: {kind!r}")
        key = f"{clean_id}__{kind}__{suffix}" if suffix else f"{clean_id}__{kind}"
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
            "version": SCHEMA_VERSION,
            "devices": {k: v.to_dict() for k, v in sorted(self.load_all().items())},
        }
