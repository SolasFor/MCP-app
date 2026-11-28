"""Persistent devices.json store, WAL transaction recovery, SecretStore('ssh') refs, and safe ~/.ssh/config importer."""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
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
TX_SCHEMA_VERSION = 2
TX_ALLOWED_OPS = frozenset({"wizard_commit", "host_key_rotate"})
MAX_DEVICES_FILE_BYTES = 8 * 1024 * 1024
MAX_KNOWN_HOSTS_FILE_BYTES = 1 * 1024 * 1024
MAX_INIT_MARKER_BYTES = 4096
MAX_TX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_TX_SECRETS = 2
TX_ID_RE = re.compile(r"^[0-9a-f]{24}$")
_SECRET_SUFFIX_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_TX_TOP_KEYS = frozenset({"schema_version", "tx_id", "op", "device_id", "files", "created_secrets"})
_TX_FILE_ENTRY_KEYS = frozenset({"path", "existed", "content_b64"})


def _canonical_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _assert_no_reparse_ancestors(path: Path, label: str = "path") -> None:
    """Reject traversal, control characters, and symlinks/reparse points across all path segments."""
    raw = os.fspath(path)
    if not raw or any(ch in raw for ch in ("\x00", "\r", "\n")):
        raise ValueError(f"Invalid characters in {label}")
    p = Path(raw)
    if ".." in p.parts:
        raise ValueError(f"Traversal segments prohibited in {label}")
    abs_p = Path(os.path.abspath(raw))
    seen: set[str] = set()
    for candidate in (p, *p.parents, abs_p, *abs_p.parents):
        key = _canonical_path_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        if is_reparse_or_symlink(candidate):
            raise ValueError(f"Refusing symlink/reparse point in {label}: {candidate}")


def _extract_profile_secret_keys(
    secret_store: SecretStore,
    profiles: dict[str, DeviceProfile],
) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for prof in profiles.values():
        for ref in (prof.password_ref, prof.passphrase_ref):
            if ref:
                try:
                    refs.add(secret_store.parse_ref(ref))
                except ValueError:
                    continue
    return refs


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

    def _allowed_tx_specs(self) -> dict[str, tuple[Path, str, int]]:
        return {
            _canonical_path_key(self.path): (self.path, "devices", MAX_DEVICES_FILE_BYTES),
            _canonical_path_key(self.managed_known_hosts_path): (
                self.managed_known_hosts_path,
                "known_hosts",
                MAX_KNOWN_HOSTS_FILE_BYTES,
            ),
            _canonical_path_key(self._init_marker): (
                self._init_marker,
                "init_marker",
                MAX_INIT_MARKER_BYTES,
            ),
        }

    @staticmethod
    def _validate_preimage_bytes(kind: str, data: bytes) -> dict[str, DeviceProfile] | None:
        if kind == "devices":
            return DeviceStore._parse_devices_bytes_strict(data)
        if kind == "known_hosts":
            text = data.decode("utf-8")
            if "\x00" in text:
                raise ValueError("NUL byte in known_hosts preimage")
            return None
        if kind == "init_marker":
            raw = json.loads(data.decode("utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("Invalid init marker preimage in N05 tx journal")
            ver = raw.get("schema_version")
            if type(ver) is not int or ver not in (1, SCHEMA_VERSION):
                raise ValueError("Unsupported init marker schema_version in N05 tx journal")
            return None
        raise ValueError(f"Unsupported N05 tx file kind: {kind!r}")

    @staticmethod
    def _parse_tx_file_entry(
        entry: Any,
        allowed: dict[str, tuple[Path, str, int]],
        seen_paths: set[str],
    ) -> tuple[Path, str, bool, bytes | None, dict[str, DeviceProfile] | None]:
        if not isinstance(entry, dict) or set(entry.keys()) != _TX_FILE_ENTRY_KEYS:
            raise ValueError("Invalid N05 tx file entry")
        p_str = entry.get("path")
        existed = entry.get("existed")
        b64 = entry.get("content_b64")
        if not isinstance(p_str, str) or not p_str.strip() or type(existed) is not bool:
            raise ValueError("Invalid N05 tx file metadata")
        entry_path = Path(p_str)
        if not entry_path.is_absolute():
            raise ValueError(f"Relative path prohibited in N05 tx journal: {p_str!r}")
        _assert_no_reparse_ancestors(entry_path, "N05 tx file entry")
        canon = _canonical_path_key(entry_path)
        spec = allowed.get(canon)
        if spec is None or canon in seen_paths:
            raise ValueError(f"Forbidden or duplicate N05 tx path: {p_str!r}")
        seen_paths.add(canon)
        target, kind, max_bytes = spec
        _assert_no_reparse_ancestors(target, "N05 tx target")
        if not existed:
            if b64 is not None:
                raise ValueError("Non-null content_b64 for non-existent preimage in N05 tx journal")
            return (target, kind, False, None, None)
        if not isinstance(b64, str):
            raise ValueError("Missing preimage bytes in N05 tx journal")
        try:
            data = base64.b64decode(b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError("Corrupt base64 preimage in N05 tx journal") from exc
        if len(data) > max_bytes:
            raise ValueError("Oversized preimage in N05 tx journal")
        parsed_devs = DeviceStore._validate_preimage_bytes(kind, data)
        return (target, kind, True, data, parsed_devs)

    @staticmethod
    def _parse_tx_secret_entry(pair: Any, *, device_id: str, tx_id: str) -> tuple[str, str]:
        if not isinstance(pair, list) or len(pair) != 2 or pair[0] != "ssh" or not isinstance(pair[1], str):
            raise ValueError("Invalid N05 tx secret entry")
        key = pair[1]
        if key != SecretStore._validate_key(key):
            raise ValueError("Invalid secret key format in N05 tx journal")
        allowed_keys = (f"{device_id}__password__{tx_id}", f"{device_id}__passphrase__{tx_id}")
        if key not in allowed_keys:
            raise ValueError("Unbound or mismatched transaction secret key in N05 tx journal")
        return ("ssh", key)

    def _collect_protected_secret_keys(
        self,
        preimage_devices: dict[str, DeviceProfile],
        tx_device_id: str,
    ) -> set[tuple[str, str]]:
        sec_store = self._secret_store()
        protected = _extract_profile_secret_keys(sec_store, preimage_devices)
        if os.path.lexists(self.path) and not is_reparse_or_symlink(self.path):
            try:
                if self.path.stat().st_size <= MAX_DEVICES_FILE_BYTES:
                    live = self._parse_devices_bytes_strict(self.path.read_bytes())
                    others = {k: v for k, v in live.items() if k != tx_device_id}
                    protected.update(_extract_profile_secret_keys(sec_store, others))
            except (OSError, ValueError):
                pass
        return protected

    @staticmethod
    def _read_tx_journal_dict(tx_path: Path) -> dict[str, Any]:
        _assert_no_reparse_ancestors(tx_path, "N05 tx journal")
        st = tx_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > MAX_TX_JOURNAL_BYTES:
            raise ValueError("Invalid N05 device transaction journal size or file type")
        try:
            raw = json.loads(tx_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise ValueError("Corrupt N05 device transaction journal") from exc
        if not isinstance(raw, dict) or set(raw.keys()) != _TX_TOP_KEYS:
            raise ValueError("Malformed N05 device transaction journal structure")
        return raw

    @staticmethod
    def _validate_tx_header(raw: dict[str, Any]) -> tuple[str, str, str]:
        ver = raw.get("schema_version")
        if type(ver) is not int or ver != TX_SCHEMA_VERSION:
            raise ValueError("Unsupported N05 device transaction schema version")
        tx_id = raw.get("tx_id")
        op = raw.get("op")
        raw_dev_id = raw.get("device_id")
        if not isinstance(tx_id, str) or not TX_ID_RE.fullmatch(tx_id):
            raise ValueError("Malformed N05 device transaction id")
        if not isinstance(op, str) or op not in TX_ALLOWED_OPS or not isinstance(raw_dev_id, str):
            raise ValueError("Malformed N05 device transaction operation or device_id")
        return tx_id, op, validate_device_id(raw_dev_id)

    def _validate_tx_files(
        self,
        files_raw: Any,
    ) -> tuple[list[tuple[Path, bool, bytes | None]], dict[str, DeviceProfile]]:
        allowed = self._allowed_tx_specs()
        if not isinstance(files_raw, list) or len(files_raw) != len(allowed):
            raise ValueError("Malformed N05 device transaction file entries")
        seen_paths: set[str] = set()
        parsed_entries = [self._parse_tx_file_entry(entry, allowed, seen_paths) for entry in files_raw]
        if seen_paths != set(allowed.keys()):
            raise ValueError("Incomplete N05 device transaction file preimage set")
        dev_existed = next(existed for _, kind, existed, _, _ in parsed_entries if kind == "devices")
        marker_existed = next(existed for _, kind, existed, _, _ in parsed_entries if kind == "init_marker")
        if marker_existed and not dev_existed:
            raise ValueError("Inconsistent init marker state in N05 tx journal")
        preimage_devices = next(
            (devs for _, kind, _, _, devs in parsed_entries if kind == "devices" and devs is not None),
            {},
        )
        files_out = [(target, existed, data) for target, _kind, existed, data, _devs in parsed_entries]
        return files_out, preimage_devices

    def _validate_tx_secrets(
        self,
        secrets_raw: Any,
        *,
        op: str,
        device_id: str,
        tx_id: str,
        preimage_devices: dict[str, DeviceProfile],
    ) -> list[tuple[str, str]]:
        if not isinstance(secrets_raw, list) or len(secrets_raw) > MAX_TX_SECRETS:
            raise ValueError("Invalid N05 device transaction secrets list")
        if op == "host_key_rotate" and secrets_raw:
            raise ValueError("host_key_rotate transaction cannot declare created_secrets")
        secrets_out: list[tuple[str, str]] = []
        seen_secrets: set[tuple[str, str]] = set()
        for pair in secrets_raw:
            parsed_pair = self._parse_tx_secret_entry(pair, device_id=device_id, tx_id=tx_id)
            if parsed_pair in seen_secrets:
                raise ValueError("Duplicate secret entry in N05 tx journal")
            seen_secrets.add(parsed_pair)
            secrets_out.append(parsed_pair)
        protected = self._collect_protected_secret_keys(preimage_devices, device_id)
        for pair in secrets_out:
            if pair in protected:
                raise ValueError(f"Refusing to delete preserved SSH secret during tx recovery: {pair[1]!r}")
        return secrets_out

    def _validate_tx_journal(self) -> tuple[list[tuple[Path, bool, bytes | None]], list[tuple[str, str]]]:
        raw = self._read_tx_journal_dict(self.tx_journal_path)
        tx_id, op, clean_dev_id = self._validate_tx_header(raw)
        files_out, preimage_devices = self._validate_tx_files(raw.get("files"))
        secrets_out = self._validate_tx_secrets(
            raw.get("created_secrets"),
            op=op,
            device_id=clean_dev_id,
            tx_id=tx_id,
            preimage_devices=preimage_devices,
        )
        return files_out, secrets_out

    def write_tx_journal(
        self,
        *,
        tx_id: str,
        op: str,
        device_id: str,
        preimages: list[dict[str, Any]],
        created_secrets: list[tuple[str, str]],
    ) -> None:
        """Validate, bound, and atomically write a v2 device WAL transaction journal."""
        _assert_no_reparse_ancestors(self.tx_journal_path, "N05 tx journal")
        raw_payload: dict[str, Any] = {
            "schema_version": TX_SCHEMA_VERSION,
            "tx_id": tx_id,
            "op": op,
            "device_id": device_id,
            "files": preimages,
            "created_secrets": [[ns, k] for ns, k in created_secrets],
        }
        _, valid_op, clean_dev_id = self._validate_tx_header(raw_payload)
        _, preimage_devices = self._validate_tx_files(preimages)
        self._validate_tx_secrets(
            raw_payload["created_secrets"],
            op=valid_op,
            device_id=clean_dev_id,
            tx_id=tx_id,
            preimage_devices=preimage_devices,
        )
        encoded = json.dumps(raw_payload, ensure_ascii=False, indent=2).encode("utf-8")
        if len(encoded) > MAX_TX_JOURNAL_BYTES:
            raise ValueError("N05 tx journal exceeds safety size limit")
        atomic_write_bytes(self.tx_journal_path, encoded, restrict_acl=True)

    def recover_pending_tx_unlocked(self) -> None:
        """Recover and roll back an interrupted device onboarding/rotation transaction."""
        with self.lock():
            with self._lock:
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
                    store.delete_secret(ns, key)
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

    @classmethod
    def _parse_devices_bytes_strict(cls, data: bytes) -> dict[str, DeviceProfile]:
        if len(data) > MAX_DEVICES_FILE_BYTES:
            raise ValueError("Device configuration file exceeds size limit")
        try:
            raw_text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Device configuration file is not valid UTF-8") from exc
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
        return cls._decode_strict_profiles(items)

    def _parse_strict_document(self) -> dict[str, DeviceProfile]:
        _assert_no_reparse_ancestors(self.path, "device config file")
        if not self.path.exists():
            if self._has_prior_init_evidence():
                raise ValueError(f"Device configuration file is missing after initialization: {self.path}")
            return {}
        if self.path.stat().st_size > MAX_DEVICES_FILE_BYTES:
            raise ValueError("Device configuration file exceeds size limit")
        return self._parse_devices_bytes_strict(self.path.read_bytes())

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
        if suffix and not _SECRET_SUFFIX_RE.fullmatch(suffix):
            raise ValueError("Invalid SSH secret key suffix")
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
