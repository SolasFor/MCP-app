"""Data models and path/service/command validators for Remote Management."""
from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

DEFAULT_SFTP_MAX_BYTES = 10 * 1024 * 1024
MAX_SFTP_HARD_LIMIT = 64 * 1024 * 1024
VALID_DETECTED_OS = frozenset({"", "linux", "windows", "unknown"})

_DEVICE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_SERVICE_RE = re.compile(r"^[a-zA-Z0-9_.@-]{1,64}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.@\\-]{0,127}$")
_SHELL_META_RE = re.compile(r"[;&|`$<>()\n\r]")


def _strict_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _strict_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _strict_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def _strict_str_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    return tuple(value)


def validate_device_id(device_id: str) -> str:
    clean = (device_id or "").strip()
    if not _DEVICE_ID_RE.match(clean):
        raise ValueError(f"Invalid device_id: {device_id!r}")
    return clean


def _parse_ip_literal(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _validate_ip_target(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, raw_host: str) -> str:
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        raise ValueError(f"Non-routable SSH target IP is prohibited: {raw_host!r}")
    if isinstance(ip_obj, ipaddress.IPv4Address) and int(ip_obj) == 0xFFFFFFFF:
        raise ValueError(f"Broadcast SSH target IP is prohibited: {raw_host!r}")
    return str(ip_obj)


def validate_host(host: str) -> str:
    """Validate and canonicalize an SSH hostname, IPv4, or IPv6 literal (no URL/option injection)."""
    if not isinstance(host, str):
        raise ValueError("Host must be a string")
    clean = host.strip()
    forbidden = ("\x00", "\r", "\n", "\t", " ", "/", "\\", "@", "?", "#", "%")
    if not clean or len(clean) > 253 or clean.startswith("-") or any(ch in clean for ch in forbidden):
        raise ValueError(f"Invalid host: {host!r}")

    ip_obj = _parse_ip_literal(clean)
    if ip_obj is not None:
        return _validate_ip_target(ip_obj, host)

    if ":" in clean or clean.startswith("[") or clean.endswith("]"):
        raise ValueError(f"Invalid host or IPv6 literal: {host!r}")

    labels = clean.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(lbl) for lbl in labels) or labels[-1].isdigit():
        raise ValueError(f"Invalid hostname: {host!r}")
    return clean


def validate_ssh_username(username: str, *, required: bool = False) -> str:
    """Validate an optional or required SSH username against option/shell injection."""
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    clean = username.strip()
    if not clean:
        if required:
            raise ValueError("SSH username is required")
        return ""
    if any(ch in clean for ch in ("\x00", "\r", "\n", "\t", " ")) or _SHELL_META_RE.search(clean):
        raise ValueError(f"Invalid SSH username: {username!r}")
    if not _SSH_USER_RE.fullmatch(clean):
        raise ValueError(f"Invalid SSH username: {username!r}")
    return clean


def format_known_hosts_host(host: str, port: int = 22) -> str:
    """Format canonical OpenSSH known_hosts host token for `(host, port)`."""
    clean_host = validate_host(host)
    port_num = _strict_int(port, "port")
    if not (1 <= port_num <= 65535):
        raise ValueError(f"Invalid SSH port: {port_num}")
    if port_num == 22 and ":" not in clean_host:
        return clean_host
    return f"[{clean_host}]:{port_num}"


def canonical_endpoint_key(host: str, port: int = 22, username: str = "") -> tuple[str, int, str]:
    """Return canonical `(host_casefolded, port, username)` identity tuple."""
    clean_host = validate_host(host)
    port_num = _strict_int(port, "port")
    clean_user = validate_ssh_username(username, required=False)
    ip_obj = _parse_ip_literal(clean_host)
    host_norm = str(ip_obj) if ip_obj is not None else clean_host.casefold()
    return (host_norm, port_num, clean_user)


def validate_service_name(name: str) -> str:
    clean = (name or "").strip()
    if not _SERVICE_RE.match(clean) or ".." in clean:
        raise ValueError(f"Invalid service name: {name!r}")
    return clean


def contains_shell_metacharacters(command: str) -> bool:
    return bool(_SHELL_META_RE.search(command or ""))


def normalize_posix_path(raw: str) -> str:
    s = (raw or "").strip().replace("\\", "/")
    if not s or "\x00" in s or "\r" in s or "\n" in s:
        raise ValueError("Invalid remote path")
    if not s.startswith("/"):
        raise ValueError(f"Remote SFTP path must be absolute: {raw!r}")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"Traversal segments ('..') prohibited in remote path: {raw!r}")
    return posixpath.normpath("/" + "/".join(parts))


def validate_remote_posix_path(raw: str, allowed_roots: tuple[str, ...]) -> str:
    """Validate absolute canonical POSIX path stays inside at least one allowed SFTP root."""
    if not allowed_roots:
        raise PermissionError("No SFTP roots configured for this device")
    clean = normalize_posix_path(raw)
    for root_raw in allowed_roots:
        root = normalize_posix_path(root_raw)
        if root == "/" or clean == root or clean.startswith(root.rstrip("/") + "/"):
            return clean
    raise PermissionError(f"Remote path {clean!r} is outside allowed SFTP roots")


@dataclass(frozen=True)
class DevicePermissions:
    """Per-device capability gates (default fail-closed False)."""

    execute: bool = False
    sftp_read: bool = False
    sftp_write: bool = False
    service_control: bool = False
    metrics: bool = False
    docker_read: bool = False

    def __post_init__(self) -> None:
        for fname in ("execute", "sftp_read", "sftp_write", "service_control", "metrics", "docker_read"):
            _strict_bool(getattr(self, fname), f"permissions.{fname}")

    def to_dict(self) -> dict[str, bool]:
        return {
            "execute": self.execute,
            "sftp_read": self.sftp_read,
            "sftp_write": self.sftp_write,
            "service_control": self.service_control,
            "metrics": self.metrics,
            "docker_read": self.docker_read,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DevicePermissions:
        if not isinstance(data, dict):
            raise ValueError("permissions must be an object")
        return cls(
            execute=_strict_bool(data.get("execute", False), "permissions.execute"),
            sftp_read=_strict_bool(data.get("sftp_read", False), "permissions.sftp_read"),
            sftp_write=_strict_bool(data.get("sftp_write", False), "permissions.sftp_write"),
            service_control=_strict_bool(data.get("service_control", False), "permissions.service_control"),
            metrics=_strict_bool(data.get("metrics", False), "permissions.metrics"),
            docker_read=_strict_bool(data.get("docker_read", False), "permissions.docker_read"),
        )


@dataclass
class DeviceProfile:
    """SSH/SFTP target device profile with strict host-key verification and scoped quotas."""

    device_id: str
    name: str
    host: str
    port: int = 22
    username: str = ""
    group: str = "default"
    auth_method: str = "agent"
    key_path: str = ""
    password_ref: str = ""
    passphrase_ref: str = ""
    known_hosts_path: str = ""
    strict_host_key: bool = True
    allowed_sftp_roots: tuple[str, ...] = ()
    sftp_max_bytes: int = DEFAULT_SFTP_MAX_BYTES
    allowed_commands: tuple[str, ...] = ()
    allowed_services: tuple[str, ...] = ()
    remote_workspace_root: str = ""
    min_profile: str = "allowlist"
    allowed_clients: tuple[str, ...] = ()
    permissions: DevicePermissions = field(default_factory=DevicePermissions)
    enabled: bool = True
    notes: str = ""
    allow_oauth_clients: bool = True
    pinned_host_key_algorithm: str = ""
    pinned_host_key_sha256: str = ""
    pinned_host_key_base64: str = ""
    detected_os: str = ""
    detected_capabilities: tuple[str, ...] = ()

    def _normalize_text_fields(self) -> None:
        for sfield in ("key_path", "password_ref", "passphrase_ref", "known_hosts_path", "remote_workspace_root", "notes"):
            val = _strict_str(getattr(self, sfield), sfield)
            if "\x00" in val:
                raise ValueError(f"NUL byte prohibited in {sfield}")
            setattr(self, sfield, val.strip())

    def _normalize_allowlists_and_os(self) -> None:
        self.sftp_max_bytes = max(1024, min(_strict_int(self.sftp_max_bytes, "sftp_max_bytes"), MAX_SFTP_HARD_LIMIT))
        self.allowed_sftp_roots = tuple(normalize_posix_path(r) for r in self.allowed_sftp_roots if r.strip())
        self.allowed_commands = tuple(c.strip() for c in self.allowed_commands if c.strip())
        self.allowed_services = tuple(validate_service_name(s) for s in self.allowed_services if s.strip())
        self.allowed_clients = tuple(c.strip() for c in self.allowed_clients if c.strip())
        self.detected_os = _strict_str(self.detected_os, "detected_os").strip().lower()
        if self.detected_os not in VALID_DETECTED_OS:
            raise ValueError(f"Unsupported detected_os: {self.detected_os!r}")
        self.detected_capabilities = tuple(
            c.strip() for c in self.detected_capabilities if isinstance(c, str) and c.strip()
        )

    def __post_init__(self) -> None:
        self.device_id = validate_device_id(self.device_id)
        self.name = (_strict_str(self.name, "name") or self.device_id).strip()
        self.host = validate_host(self.host)
        self.port = _strict_int(self.port, "port")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid SSH port: {self.port}")
        self.username = validate_ssh_username(self.username, required=False)
        self.group = _strict_str(self.group, "group").strip() or "default"
        if self.auth_method not in ("agent", "key", "password_ref"):
            raise ValueError(f"Unsupported SSH auth_method: {self.auth_method!r}")
        if not _strict_bool(self.strict_host_key, "strict_host_key"):
            raise ValueError("strict_host_key cannot be disabled (RejectPolicy is mandatory)")
        if self.min_profile not in ("allowlist", "full"):
            raise ValueError(f"Unsupported device min_profile: {self.min_profile!r}")
        _strict_bool(self.enabled, "enabled")
        _strict_bool(self.allow_oauth_clients, "allow_oauth_clients")
        self._normalize_text_fields()
        self._normalize_allowlists_and_os()
        self._validate_pinned_host_key()

    def _validate_pinned_host_key(self) -> None:
        alg = _strict_str(self.pinned_host_key_algorithm, "pinned_host_key_algorithm").strip()
        sha = _strict_str(self.pinned_host_key_sha256, "pinned_host_key_sha256").strip()
        b64 = _strict_str(self.pinned_host_key_base64, "pinned_host_key_base64").strip()
        self.pinned_host_key_algorithm = alg
        self.pinned_host_key_sha256 = sha
        self.pinned_host_key_base64 = b64
        if not any((alg, sha, b64)):
            return
        if not all((alg, sha, b64)):
            raise ValueError("Pinned SSH host key fields must all be set together")
        from backend.remote.host_keys import compute_host_key_sha256, load_public_host_key

        pkey = load_public_host_key(alg, b64)
        expected_sha = compute_host_key_sha256(pkey)
        if sha.rstrip("=") != expected_sha:
            raise ValueError("Pinned SSH host key SHA-256 does not match public key bytes")
        self.pinned_host_key_sha256 = expected_sha

    def has_pinned_host_key(self) -> bool:
        return bool(self.pinned_host_key_algorithm and self.pinned_host_key_sha256 and self.pinned_host_key_base64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "group": self.group,
            "auth_method": self.auth_method,
            "key_path": self.key_path,
            "password_ref": self.password_ref,
            "passphrase_ref": self.passphrase_ref,
            "known_hosts_path": self.known_hosts_path,
            "strict_host_key": True,
            "allowed_sftp_roots": list(self.allowed_sftp_roots),
            "sftp_max_bytes": self.sftp_max_bytes,
            "allowed_commands": list(self.allowed_commands),
            "allowed_services": list(self.allowed_services),
            "remote_workspace_root": self.remote_workspace_root,
            "min_profile": self.min_profile,
            "allowed_clients": list(self.allowed_clients),
            "permissions": self.permissions.to_dict(),
            "enabled": self.enabled,
            "notes": self.notes,
            "allow_oauth_clients": self.allow_oauth_clients,
            "pinned_host_key_algorithm": self.pinned_host_key_algorithm,
            "pinned_host_key_sha256": self.pinned_host_key_sha256,
            "pinned_host_key_base64": self.pinned_host_key_base64,
            "detected_os": self.detected_os,
            "detected_capabilities": list(self.detected_capabilities),
        }

    @staticmethod
    def _opt_str(data: dict[str, Any], key: str, default: str = "") -> str:
        raw = data.get(key)
        return _strict_str(default if raw is None else raw, key).strip()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceProfile:
        if not isinstance(data, dict):
            raise ValueError("Device profile record must be an object")
        raw_port = 22 if data.get("port") is None else data.get("port")
        raw_sftp_max = DEFAULT_SFTP_MAX_BYTES if data.get("sftp_max_bytes") is None else data.get("sftp_max_bytes")
        perms_val = data.get("permissions")
        perms_raw: Any = {} if perms_val is None else perms_val
        allow_oauth = (
            _strict_bool(data["allow_oauth_clients"], "allow_oauth_clients")
            if "allow_oauth_clients" in data
            else True
        )
        return cls(
            device_id=cls._opt_str(data, "device_id"),
            name=cls._opt_str(data, "name"),
            host=cls._opt_str(data, "host"),
            port=_strict_int(raw_port, "port"),
            username=cls._opt_str(data, "username"),
            group=cls._opt_str(data, "group", "default") or "default",
            auth_method=cls._opt_str(data, "auth_method", "agent") or "agent",
            key_path=cls._opt_str(data, "key_path"),
            password_ref=cls._opt_str(data, "password_ref"),
            passphrase_ref=cls._opt_str(data, "passphrase_ref"),
            known_hosts_path=cls._opt_str(data, "known_hosts_path"),
            strict_host_key=_strict_bool(data.get("strict_host_key", True), "strict_host_key"),
            allowed_sftp_roots=_strict_str_tuple(data.get("allowed_sftp_roots"), "allowed_sftp_roots"),
            sftp_max_bytes=_strict_int(raw_sftp_max, "sftp_max_bytes"),
            allowed_commands=_strict_str_tuple(data.get("allowed_commands"), "allowed_commands"),
            allowed_services=_strict_str_tuple(data.get("allowed_services"), "allowed_services"),
            remote_workspace_root=cls._opt_str(data, "remote_workspace_root"),
            min_profile=cls._opt_str(data, "min_profile", "allowlist") or "allowlist",
            allowed_clients=_strict_str_tuple(data.get("allowed_clients"), "allowed_clients"),
            permissions=DevicePermissions.from_dict(perms_raw),
            enabled=_strict_bool(data.get("enabled", True), "enabled"),
            notes=cls._opt_str(data, "notes"),
            allow_oauth_clients=allow_oauth,
            pinned_host_key_algorithm=cls._opt_str(data, "pinned_host_key_algorithm"),
            pinned_host_key_sha256=cls._opt_str(data, "pinned_host_key_sha256"),
            pinned_host_key_base64=cls._opt_str(data, "pinned_host_key_base64"),
            detected_os=cls._opt_str(data, "detected_os"),
            detected_capabilities=_strict_str_tuple(data.get("detected_capabilities"), "detected_capabilities"),
        )


@dataclass
class RemoteJobRecord:
    """Tracked async remote command execution with honest disconnect semantics."""

    job_id: str
    device_id: str
    command_redacted: str
    state: str = "running"
    exit_code: int | None = None
    output: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    disconnect_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "device_id": self.device_id,
            "command_redacted": self.command_redacted,
            "state": self.state,
            "exit_code": self.exit_code,
            "output": self.output,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "disconnect_note": self.disconnect_note,
        }
