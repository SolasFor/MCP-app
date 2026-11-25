"""Persistent extension registry, trusted Ed25519 keys, per-extension data & logs, and SecretStore adapter."""
from __future__ import annotations

import json
import os
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.paths import resource_dir, user_data_dir
from app.platform import get_platform
from backend.extensions.models import InstalledExtension, validate_extension_id

_MAX_LOG_BYTES = 256 * 1024


def official_extensions_dir() -> Path:
    """Locate bundled official extensions directory in dev and frozen PyInstaller builds."""
    bundled = resource_dir() / "extensions_official"
    if bundled.is_dir():
        return bundled
    return Path(__file__).resolve().parents[2] / "extensions_official"


class ExtensionStore:
    """Atomic JSON store for installed extensions, trusted keys, backups, data, and logs."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        secret_store: SecretStore | None = None,
    ) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else (user_data_dir() / "extensions")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        get_platform().restrict_path_acl(self.base_dir, is_dir=True)
        self.installed_root = self.base_dir / "installed"
        self.backups_root = self.base_dir / "backups"
        self.data_root = self.base_dir / "data"
        self.logs_root = self.base_dir / "logs"
        for folder in (self.installed_root, self.backups_root, self.data_root, self.logs_root):
            folder.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.base_dir / "registry.json"
        self.trusted_keys_path = self.base_dir / "trusted_keys.json"
        self._secrets = secret_store
        self._lock = threading.RLock()

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        get_platform().restrict_path_acl(path, is_dir=False)

    def _load_json(self, path: Path, default: dict[str, Any]) -> dict[str, Any]:
        if not path.is_file():
            return dict(default)
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
            return obj if isinstance(obj, dict) else dict(default)
        except (OSError, json.JSONDecodeError):
            return dict(default)

    def load_all(self) -> dict[str, InstalledExtension]:
        with self._lock:
            raw = self._load_json(self.registry_path, {"version": 1, "extensions": {}})
            items = raw.get("extensions") or {}
            out: dict[str, InstalledExtension] = {}
            if isinstance(items, dict):
                for _ext_id, rec in items.items():
                    if isinstance(rec, dict):
                        try:
                            ext = InstalledExtension.from_dict(rec)
                            out[ext.manifest.id] = ext
                        except (ValueError, TypeError):
                            continue
            return out

    def save_all(self, extensions: dict[str, InstalledExtension]) -> None:
        with self._lock:
            payload = {
                "version": 1,
                "extensions": {k: v.to_dict() for k, v in sorted(extensions.items())},
            }
            self._atomic_write_json(self.registry_path, payload)

    def get(self, ext_id: str) -> InstalledExtension | None:
        return self.load_all().get(validate_extension_id(ext_id))

    def upsert(self, ext: InstalledExtension) -> None:
        with self._lock:
            all_ext = self.load_all()
            all_ext[ext.manifest.id] = ext
            self.save_all(all_ext)

    def remove(self, ext_id: str) -> InstalledExtension | None:
        clean = validate_extension_id(ext_id)
        with self._lock:
            all_ext = self.load_all()
            removed = all_ext.pop(clean, None)
            if removed is not None:
                self.save_all(all_ext)
            return removed

    def trusted_keys(self) -> dict[str, str]:
        with self._lock:
            raw = self._load_json(self.trusted_keys_path, {"version": 1, "keys": {}})
            keys = raw.get("keys") or {}
            if not isinstance(keys, dict):
                return {}
            return {str(k): str(v) for k, v in keys.items() if str(k).strip() and str(v).strip()}

    def add_trusted_key(self, key_id: str, public_key_b64: str) -> None:
        clean_id = (key_id or "").strip()
        if not clean_id or not (public_key_b64 or "").strip():
            raise ValueError("key_id and public_key_b64 are required")
        with self._lock:
            keys = self.trusted_keys()
            keys[clean_id] = public_key_b64.strip()
            self._atomic_write_json(self.trusted_keys_path, {"version": 1, "keys": keys})

    def remove_trusted_key(self, key_id: str) -> bool:
        with self._lock:
            keys = self.trusted_keys()
            if key_id not in keys:
                return False
            keys.pop(key_id, None)
            self._atomic_write_json(self.trusted_keys_path, {"version": 1, "keys": keys})
            return True

    def version_dir(self, ext_id: str, version: str) -> Path:
        return self.installed_root / validate_extension_id(ext_id) / version

    def backup_dir(self, ext_id: str, version: str) -> Path:
        return self.backups_root / validate_extension_id(ext_id) / version

    def data_dir(self, ext_id: str) -> Path:
        d = self.data_root / validate_extension_id(ext_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def log_path(self, ext_id: str) -> Path:
        return self.logs_root / f"{validate_extension_id(ext_id)}.log"

    def append_log(self, ext_id: str, line: str, *, redactor: SecretRedactor | None = None) -> None:
        clean = redactor.redact_text(line) if redactor is not None else line
        path = self.log_path(ext_id)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file() and path.stat().st_size > _MAX_LOG_BYTES:
                tail = path.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
                path.write_text("\n".join(tail) + "\n", encoding="utf-8")
            with path.open("a", encoding="utf-8") as fh:
                fh.write(clean.rstrip("\r\n") + "\n")

    def read_logs(self, ext_id: str, *, tail: int = 100) -> list[str]:
        path = self.log_path(ext_id)
        if not path.is_file():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-max(1, min(tail, 500)):]

    def _secret_store(self) -> SecretStore:
        if self._secrets is None:
            secrets_env = os.environ.get("MCP_SECRETS_DIR")
            self._secrets = SecretStore(Path(secrets_env)) if secrets_env else SecretStore(self.base_dir / "secrets")
        return self._secrets

    @staticmethod
    def _secret_key(ext_id: str, key: str) -> str:
        return f"{validate_extension_id(ext_id)}__{key.strip()}"

    def set_secret(self, ext_id: str, key: str, value: str) -> str:
        clean_key = self._secret_key(ext_id, key)
        self._secret_store().set_secret("extensions", clean_key, value)
        return SecretStore.secret_ref("extensions", clean_key)

    def delete_secret(self, ext_id: str, key: str) -> None:
        self._secret_store().delete_secret("extensions", self._secret_key(ext_id, key))

    def get_declared_secrets(self, ext_id: str, keys: tuple[str, ...]) -> dict[str, str]:
        if not keys:
            return {}
        store = self._secret_store()
        out: dict[str, str] = {}
        for k in keys:
            val = store.get_secret("extensions", self._secret_key(ext_id, k))
            if val:
                out[k] = val
        return out

    def collect_secret_values(self) -> list[str]:
        vals: list[str] = []
        store = self._secret_store()
        for ext in self.load_all().values():
            for key in ext.manifest.secret_keys:
                secret = store.get_secret("extensions", self._secret_key(ext.manifest.id, key))
                if secret:
                    vals.append(secret)
        return vals

    def copy_tree_clean(self, src: Path, dst: Path) -> None:
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(
            src,
            dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
        )


def runtime_entrypoint_prefix(entrypoint: Path) -> list[str]:
    """Return command vector to run an extension script in dev or frozen executable."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--run-extension", str(entrypoint)]
    return [sys.executable, "-u", str(entrypoint)]
