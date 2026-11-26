"""Domain models and validation rules for MCP-app Workspaces (v0.9.5)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.core.secret_store import SecretStore

SCHEMA_VERSION = 1
MAX_WORKSPACES = 64
MAX_CONFIG_BYTES = 512 * 1024

MAX_READ_BYTES = 256 * 1024
MAX_WRITE_BYTES = 512 * 1024
MAX_TREE_ENTRIES = 500
MAX_SEARCH_MATCHES = 200
MAX_HISTORY_SNAPSHOTS = 20

WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
COMMAND_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
WORKSPACE_MIN_PROFILES = ("allowlist", "full")
PERMISSION_FLAGS = ("read", "write", "delete", "execute", "git")


def validate_workspace_id(workspace_id: str) -> str:
    clean = (workspace_id or "").strip()
    if not WORKSPACE_ID_RE.fullmatch(clean):
        raise ValueError(f"Invalid workspace_id: {workspace_id!r}")
    return clean


@dataclass(frozen=True)
class WorkspacePermissions:
    """Granular per-workspace or per-client capability flags (default read-only)."""

    read: bool = True
    write: bool = False
    delete: bool = False
    execute: bool = False
    git: bool = False

    def allows(self, required: tuple[str, ...]) -> bool:
        for flag in required:
            if flag not in PERMISSION_FLAGS:
                return False
            if not getattr(self, flag, False):
                return False
        return True

    def to_dict(self) -> dict[str, bool]:
        return {
            "read": bool(self.read),
            "write": bool(self.write),
            "delete": bool(self.delete),
            "execute": bool(self.execute),
            "git": bool(self.git),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> WorkspacePermissions:
        if not isinstance(data, dict):
            return cls()
        return cls(
            read=bool(data.get("read", True)),
            write=bool(data.get("write", False)),
            delete=bool(data.get("delete", False)),
            execute=bool(data.get("execute", False)),
            git=bool(data.get("git", False)),
        )


@dataclass(frozen=True)
class WorkspaceProfile:
    """Owner-registered project workspace profile (no plaintext secrets)."""

    workspace_id: str
    name: str
    root_path: str
    language: str = ""
    git_root: str = ""
    python_venv: str = ""
    node_path: str = ""
    commands: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    env_secret_refs: dict[str, str] = field(default_factory=dict)
    linked_servers: tuple[str, ...] = ()
    linked_tasks: tuple[str, ...] = ()
    linked_extensions: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    permissions: WorkspacePermissions = field(default_factory=WorkspacePermissions)
    client_permissions: dict[str, WorkspacePermissions] = field(default_factory=dict)
    allowed_clients: tuple[str, ...] = ()
    min_profile: str = "allowlist"
    trust_git_hooks: bool = False
    enabled: bool = True
    description: str = ""

    def validate(self) -> None:
        validate_workspace_id(self.workspace_id)
        if not isinstance(self.name, str) or not self.name.strip() or "\x00" in self.name:
            raise ValueError("Workspace name is required")
        if not isinstance(self.root_path, str) or not self.root_path.strip() or "\x00" in self.root_path:
            raise ValueError("Workspace root_path is required")
        if self.min_profile not in WORKSPACE_MIN_PROFILES:
            raise ValueError(f"Invalid min_profile: {self.min_profile!r}")
        for path_field in (self.git_root, self.python_venv, self.node_path):
            if "\x00" in path_field:
                raise ValueError("Invalid NUL byte in workspace metadata")
        if not isinstance(self.commands, dict) or len(self.commands) > 32:
            raise ValueError("Invalid workspace commands map")
        for cname, cmd in self.commands.items():
            if not COMMAND_NAME_RE.fullmatch(cname):
                raise ValueError(f"Invalid workspace command name: {cname!r}")
            if not isinstance(cmd, str) or not cmd.strip() or any(c in cmd for c in ("\x00", "\r", "\n")):
                raise ValueError(f"Invalid command text for {cname!r}")
        if not isinstance(self.env, dict) or len(self.env) > 128:
            raise ValueError("Invalid env dictionary")
        for key, value in self.env.items():
            if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
                raise ValueError(f"Invalid env key: {key!r}")
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError(f"Invalid env value for {key!r}")
        if not isinstance(self.env_secret_refs, dict) or len(self.env_secret_refs) > 64:
            raise ValueError("Invalid env_secret_refs dictionary")
        for key, ref in self.env_secret_refs.items():
            if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
                raise ValueError(f"Invalid secret env key: {key!r}")
            SecretStore.parse_ref(ref)
        for cid in self.allowed_clients:
            if not CLIENT_ID_RE.fullmatch(cid):
                raise ValueError(f"Invalid allowed client_id: {cid!r}")
        for cid in self.client_permissions:
            if not CLIENT_ID_RE.fullmatch(cid):
                raise ValueError(f"Invalid client_permissions key: {cid!r}")
        for pat in self.exclude_patterns:
            if not isinstance(pat, str) or not pat.strip() or "\x00" in pat:
                raise ValueError("Invalid exclude pattern")

    def permissions_for(self, client_id: str) -> WorkspacePermissions:
        return self.client_permissions.get(client_id, self.permissions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "name": self.name,
            "root_path": self.root_path,
            "language": self.language,
            "git_root": self.git_root,
            "python_venv": self.python_venv,
            "node_path": self.node_path,
            "commands": dict(self.commands),
            "env": dict(self.env),
            "env_secret_refs": dict(self.env_secret_refs),
            "linked_servers": list(self.linked_servers),
            "linked_tasks": list(self.linked_tasks),
            "linked_extensions": list(self.linked_extensions),
            "exclude_patterns": list(self.exclude_patterns),
            "permissions": self.permissions.to_dict(),
            "client_permissions": {
                cid: perms.to_dict()
                for cid, perms in sorted(self.client_permissions.items())
            },
            "allowed_clients": list(self.allowed_clients),
            "min_profile": self.min_profile,
            "trust_git_hooks": bool(self.trust_git_hooks),
            "enabled": bool(self.enabled),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, workspace_id: str, data: dict[str, Any]) -> WorkspaceProfile:
        if not isinstance(data, dict):
            raise ValueError(f"Invalid workspace entry for {workspace_id!r}")
        raw_cmds = data.get("commands") or {}
        raw_env = data.get("env") or {}
        raw_refs = data.get("env_secret_refs") or {}
        raw_client_perms = data.get("client_permissions") or {}
        if not isinstance(raw_cmds, dict) or not isinstance(raw_env, dict) or not isinstance(raw_refs, dict):
            raise ValueError(f"Invalid workspace config map for {workspace_id!r}")
        if not isinstance(raw_client_perms, dict):
            raise ValueError(f"Invalid client_permissions for {workspace_id!r}")

        profile = cls(
            workspace_id=str(data.get("workspace_id") or workspace_id).strip(),
            name=str(data.get("name") or workspace_id).strip(),
            root_path=str(data.get("root_path") or "").strip(),
            language=str(data.get("language") or "").strip(),
            git_root=str(data.get("git_root") or "").strip(),
            python_venv=str(data.get("python_venv") or "").strip(),
            node_path=str(data.get("node_path") or "").strip(),
            commands={str(k): str(v) for k, v in raw_cmds.items()},
            env={str(k): str(v) for k, v in raw_env.items()},
            env_secret_refs={str(k): str(v) for k, v in raw_refs.items()},
            linked_servers=tuple(str(x).strip() for x in (data.get("linked_servers") or ()) if str(x).strip()),
            linked_tasks=tuple(str(x).strip() for x in (data.get("linked_tasks") or ()) if str(x).strip()),
            linked_extensions=tuple(str(x).strip() for x in (data.get("linked_extensions") or ()) if str(x).strip()),
            exclude_patterns=tuple(str(x).strip() for x in (data.get("exclude_patterns") or ()) if str(x).strip()),
            permissions=WorkspacePermissions.from_dict(data.get("permissions")),
            client_permissions={
                str(cid): WorkspacePermissions.from_dict(p)
                for cid, p in raw_client_perms.items()
                if isinstance(p, dict)
            },
            allowed_clients=tuple(str(x).strip() for x in (data.get("allowed_clients") or ()) if str(x).strip()),
            min_profile=str(data.get("min_profile") or "allowlist").strip() or "allowlist",
            trust_git_hooks=bool(data.get("trust_git_hooks", False)),
            enabled=bool(data.get("enabled", True)),
            description=str(data.get("description") or "").strip(),
        )
        profile.validate()
        return profile
