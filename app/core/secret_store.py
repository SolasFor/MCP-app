"""Unified DPAPI / Credential Manager / POSIX encrypted secret store.

Windows:
  * Primary encrypted vault (`secrets.vault.enc`) encrypted with a Fernet data key
    protected by Windows DPAPI (`secrets.key` with `DPAPI1:` prefix).
  * Optional Windows Credential Manager integration (`MCPApp/<namespace>/<key>`).
POSIX:
  * User-private (`0700` dir / `0600` key) Fernet vault (`POSIX1:` prefix).
    Not OS keychain protection; documented in `docs/stability-security.md`.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.paths import user_data_dir
from app.platform import get_platform

VALID_NAMESPACES = frozenset({
    "owner",
    "tunnel",
    "external_oauth",
    "api",
    "ssh",
    "proxy",
})
_KEY_PREFIX_WIN = b"DPAPI1:"
_KEY_PREFIX_POSIX = b"POSIX1:"
_KEY_FILE = "secrets.key"
_VAULT_FILE = "secrets.vault.enc"
_REF_PREFIX = "secret://"


class SecretStoreError(RuntimeError):
    """Raised when the encrypted secret vault cannot be unlocked or written."""


class SecretStore:
    """Namespace-isolated encrypted secret store with atomic writes and ACLs."""

    def __init__(self, vault_dir: Path | None = None, *, use_credman: bool = False) -> None:
        self._dir = Path(vault_dir) if vault_dir is not None else (user_data_dir() / "secrets")
        self._use_credman = use_credman
        self._lock = threading.RLock()
        self._platform = get_platform()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._platform.restrict_path_acl(self._dir, is_dir=True)
        self._key_path = self._dir / _KEY_FILE
        self._vault_path = self._dir / _VAULT_FILE

    @property
    def vault_dir(self) -> Path:
        return self._dir

    @staticmethod
    def _validate_namespace(namespace: str) -> str:
        ns = (namespace or "").strip().lower()
        if ns not in VALID_NAMESPACES:
            raise ValueError(f"Unsupported secret namespace: {namespace!r}")
        return ns

    @staticmethod
    def _validate_key(key: str) -> str:
        clean = (key or "").strip()
        if not clean or len(clean) > 128 or any(ch in clean for ch in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("Invalid secret key name")
        return clean

    @classmethod
    def secret_ref(cls, namespace: str, key: str) -> str:
        ns = cls._validate_namespace(namespace)
        k = cls._validate_key(key)
        return f"{_REF_PREFIX}{ns}/{k}"

    @classmethod
    def parse_ref(cls, ref: str) -> tuple[str, str]:
        if not isinstance(ref, str) or not ref.startswith(_REF_PREFIX):
            raise ValueError("Invalid secret reference")
        rest = ref[len(_REF_PREFIX):]
        if "/" not in rest:
            raise ValueError("Invalid secret reference")
        ns, key = rest.split("/", 1)
        return cls._validate_namespace(ns), cls._validate_key(key)

    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists():
            data = self._key_path.read_bytes()
            if sys.platform == "win32" and data.startswith(_KEY_PREFIX_WIN):
                return self._platform.dpapi_unprotect(data[len(_KEY_PREFIX_WIN):])
            if sys.platform != "win32" and data.startswith(_KEY_PREFIX_POSIX):
                mode = self._key_path.stat().st_mode
                if mode & 0o077:
                    raise PermissionError("SecretStore key must not be group/world readable")
                return data[len(_KEY_PREFIX_POSIX):]
            raise SecretStoreError("SecretStore key is not readable on this platform")

        if self._vault_path.exists() and self._vault_path.stat().st_size > 0:
            raise FileNotFoundError("SecretStore encryption key missing for existing vault")

        key = Fernet.generate_key()
        stored = (
            _KEY_PREFIX_WIN + self._platform.dpapi_protect(key, "MCPApp SecretStore key")
            if sys.platform == "win32"
            else _KEY_PREFIX_POSIX + key
        )
        tmp = self._key_path.with_suffix(".key.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(stored)
        os.replace(tmp, self._key_path)
        self._platform.restrict_path_acl(self._key_path, is_dir=False)
        return key

    def _cipher(self) -> Fernet:
        return Fernet(self._load_or_create_key())

    def _read_vault(self) -> dict[str, dict[str, str]]:
        if not self._vault_path.exists():
            return {}
        raw = self._vault_path.read_bytes()
        if not raw:
            return {}
        try:
            decrypted = self._cipher().decrypt(raw)
            parsed = json.loads(decrypted.decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
            raise SecretStoreError(f"Failed to decrypt SecretStore vault: {type(exc).__name__}") from exc
        if not isinstance(parsed, dict):
            return {}
        return {
            str(ns): {str(k): str(v) for k, v in items.items()}
            for ns, items in parsed.items()
            if isinstance(items, dict)
        }

    def _write_vault(self, data: dict[str, dict[str, str]]) -> None:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = self._cipher().encrypt(payload)
        tmp = self._vault_path.with_suffix(".vault.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(encrypted)
        os.replace(tmp, self._vault_path)
        self._platform.restrict_path_acl(self._vault_path, is_dir=False)

    @staticmethod
    def _credman_target(namespace: str, key: str) -> str:
        return f"MCPApp/{namespace}/{key}"

    def set_secret(self, namespace: str, key: str, value: str) -> None:
        ns = self._validate_namespace(namespace)
        k = self._validate_key(key)
        if not isinstance(value, str):
            raise TypeError("Secret value must be a string")
        with self._lock:
            if self._use_credman and sys.platform == "win32":
                encoded = value.encode("utf-8")
                if self._platform.credman_write(self._credman_target(ns, k), encoded):
                    # Remove any stale vault fallback entry for this key
                    data = self._read_vault()
                    if ns in data and k in data[ns]:
                        del data[ns][k]
                        if not data[ns]:
                            del data[ns]
                        self._write_vault(data)
                    return
            data = self._read_vault()
            bucket = data.setdefault(ns, {})
            bucket[k] = value
            self._write_vault(data)

    def get_secret(self, namespace: str, key: str) -> str | None:
        ns = self._validate_namespace(namespace)
        k = self._validate_key(key)
        with self._lock:
            if self._use_credman and sys.platform == "win32":
                blob = self._platform.credman_read(self._credman_target(ns, k))
                if blob is not None:
                    return blob.decode("utf-8", errors="replace")
            data = self._read_vault()
            return data.get(ns, {}).get(k)

    def delete_secret(self, namespace: str, key: str) -> bool:
        ns = self._validate_namespace(namespace)
        k = self._validate_key(key)
        removed = False
        with self._lock:
            if self._use_credman and sys.platform == "win32":
                if self._platform.credman_delete(self._credman_target(ns, k)):
                    removed = True
            data = self._read_vault()
            if ns in data and k in data[ns]:
                del data[ns][k]
                if not data[ns]:
                    del data[ns]
                self._write_vault(data)
                removed = True
        return removed

    def resolve_ref(self, ref: str) -> str | None:
        ns, key = self.parse_ref(ref)
        return self.get_secret(ns, key)

    def list_keys(self, namespace: str | None = None) -> list[tuple[str, str]]:
        target_ns = self._validate_namespace(namespace) if namespace is not None else None
        with self._lock:
            data = self._read_vault()
            items: list[tuple[str, str]] = []
            for ns, bucket in sorted(data.items()):
                if target_ns is not None and ns != target_ns:
                    continue
                for key in sorted(bucket):
                    items.append((ns, key))
            return items

    def export_metadata(self) -> dict:
        """Non-secret inventory safe for diagnostics and backups."""
        keys = self.list_keys()
        return {
            "storage_capabilities": self._platform.capabilities(),
            "vault_present": self._vault_path.exists(),
            "secret_count": len(keys),
            "refs": [self.secret_ref(ns, k) for ns, k in keys],
        }
