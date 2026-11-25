"""Data models and path/service/command validators for Remote Management."""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

DEFAULT_SFTP_MAX_BYTES = 10 * 1024 * 1024
MAX_SFTP_HARD_LIMIT = 64 * 1024 * 1024

_DEVICE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_SERVICE_RE = re.compile(r"^[a-zA-Z0-9_.@-]{1,64}$")
_HOST_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,255}$")
_SHELL_META_RE = re.compile(r"[;&|`$<>()\n\r]")


def validate_device_id(device_id: str) -> str:
    clean = (device_id or "").strip()
    if not _DEVICE_ID_RE.match(clean):
        raise ValueError(f"Invalid device_id: {device_id!r}")
    return clean


def validate_host(host: str) -> str:
    clean = (host or "").strip()
    if not _HOST_RE.match(clean):
        raise ValueError(f"Invalid host: {host!r}")
    return clean


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
        return cls(
            execute=bool(data.get("execute", False)),
            sftp_read=bool(data.get("sftp_read", False)),
            sftp_write=bool(data.get("sftp_write", False)),
            service_control=bool(data.get("service_control", False)),
            metrics=bool(data.get("metrics", False)),
            docker_read=bool(data.get("docker_read", False)),
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

    def __post_init__(self) -> None:
        self.device_id = validate_device_id(self.device_id)
        self.name = (self.name or self.device_id).strip()
        self.host = validate_host(self.host)
        self.port = int(self.port)
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid SSH port: {self.port}")
        if self.auth_method not in ("agent", "key", "password_ref"):
            raise ValueError(f"Unsupported SSH auth_method: {self.auth_method!r}")
        if not self.strict_host_key:
            raise ValueError("strict_host_key cannot be disabled (RejectPolicy is mandatory)")
        if self.min_profile not in ("allowlist", "full"):
            raise ValueError(f"Unsupported device min_profile: {self.min_profile!r}")
        self.sftp_max_bytes = max(1024, min(int(self.sftp_max_bytes), MAX_SFTP_HARD_LIMIT))
        self.allowed_sftp_roots = tuple(normalize_posix_path(r) for r in self.allowed_sftp_roots if r.strip())
        self.allowed_commands = tuple(c.strip() for c in self.allowed_commands if c.strip())
        self.allowed_services = tuple(validate_service_name(s) for s in self.allowed_services if s.strip())
        self.allowed_clients = tuple(c.strip() for c in self.allowed_clients if c.strip())

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
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceProfile:
        return cls(
            device_id=str(data.get("device_id") or "").strip(),
            name=str(data.get("name") or "").strip(),
            host=str(data.get("host") or "").strip(),
            port=int(data.get("port") or 22),
            username=str(data.get("username") or "").strip(),
            group=str(data.get("group") or "default").strip() or "default",
            auth_method=str(data.get("auth_method") or "agent").strip(),
            key_path=str(data.get("key_path") or "").strip(),
            password_ref=str(data.get("password_ref") or "").strip(),
            passphrase_ref=str(data.get("passphrase_ref") or "").strip(),
            known_hosts_path=str(data.get("known_hosts_path") or "").strip(),
            strict_host_key=bool(data.get("strict_host_key", True)),
            allowed_sftp_roots=tuple(str(r) for r in (data.get("allowed_sftp_roots") or ())),
            sftp_max_bytes=int(data.get("sftp_max_bytes") or DEFAULT_SFTP_MAX_BYTES),
            allowed_commands=tuple(str(c) for c in (data.get("allowed_commands") or ())),
            allowed_services=tuple(str(s) for s in (data.get("allowed_services") or ())),
            remote_workspace_root=str(data.get("remote_workspace_root") or "").strip(),
            min_profile=str(data.get("min_profile") or "allowlist").strip(),
            allowed_clients=tuple(str(c) for c in (data.get("allowed_clients") or ())),
            permissions=DevicePermissions.from_dict(dict(data.get("permissions") or {})),
            enabled=bool(data.get("enabled", True)),
            notes=str(data.get("notes") or "").strip(),
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
