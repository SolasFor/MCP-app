"""Models, manifest schema validation, and API compatibility checks for Extensions."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

SDK_API_VERSION = "1.0"
SUPPORTED_API_MAJOR = 1
SUPPORTED_API_MINOR = 2

ALLOWED_EXTENSION_PERMISSIONS = frozenset({
    "read_metrics",
    "git_read",
    "git_write",
    "docker_read",
    "docker_control",
    "browser_control",
    "process_info",
    "secrets_read",
    "workspace_read",
    "network_local",
})

ALLOWED_UI_COMPONENT_TYPES = frozenset({
    "status_card",
    "metric",
    "action_button",
    "table",
    "notice",
})

_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_API_VERSION_RE = re.compile(r"^(\d+)\.(\d+)$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


def validate_extension_id(ext_id: str) -> str:
    clean = (ext_id or "").strip()
    if not _ID_RE.match(clean):
        raise ValueError(f"Invalid extension id: {ext_id!r}")
    return clean


def validate_semver(version: str) -> str:
    clean = (version or "").strip()
    if not _VERSION_RE.match(clean):
        raise ValueError(f"Invalid extension version (expected X.Y.Z): {version!r}")
    return clean


def check_api_compatibility(api_version: str) -> tuple[bool, str]:
    """Verify whether extension SDK api_version matches supported major/minor bounds."""
    clean = (api_version or "").strip()
    match = _API_VERSION_RE.match(clean)
    if not match:
        return False, f"Malformed api_version {api_version!r} (expected '<major>.<minor>')"
    major = int(match.group(1))
    minor = int(match.group(2))
    if major != SUPPORTED_API_MAJOR:
        return False, (
            f"Incompatible extension api_version {clean!r}: "
            f"core supports {SUPPORTED_API_MAJOR}.0..{SUPPORTED_API_MAJOR}.{SUPPORTED_API_MINOR}"
        )
    if minor > SUPPORTED_API_MINOR:
        return False, (
            f"Extension requires newer SDK api_version {clean!r} "
            f"(max supported {SUPPORTED_API_MAJOR}.{SUPPORTED_API_MINOR})"
        )
    return True, "ok"


def validate_entrypoint(entrypoint: str) -> str:
    raw = (entrypoint or "").strip().replace("\\", "/")
    if not raw or "\x00" in raw or raw.startswith("/") or ":" in raw:
        raise ValueError(f"Unsafe extension entrypoint: {entrypoint!r}")
    posix = PurePosixPath(raw)
    if posix.is_absolute() or any(part in ("", ".", "..") for part in posix.parts):
        raise ValueError(f"Invalid relative extension entrypoint: {entrypoint!r}")
    if not raw.lower().endswith(".py"):
        raise ValueError(f"Extension entrypoint must be a .py script: {entrypoint!r}")
    return raw


@dataclass(frozen=True)
class ExtensionToolSpec:
    """Tool exported by an extension and gated by extension/OAuth permissions."""

    name: str
    description: str = ""
    permission: str = ""
    read_only: bool = True
    input_schema: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.match(self.name):
            raise ValueError(f"Invalid extension tool name: {self.name!r}")
        if self.permission and self.permission not in ALLOWED_EXTENSION_PERMISSIONS:
            raise ValueError(f"Unknown extension permission: {self.permission!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "permission": self.permission,
            "read_only": self.read_only,
            "input_schema": dict(self.input_schema),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExtensionToolSpec:
        return cls(
            name=str(data.get("name") or "").strip(),
            description=str(data.get("description") or "").strip(),
            permission=str(data.get("permission") or "").strip(),
            read_only=bool(data.get("read_only", True)),
            input_schema=dict(data.get("input_schema") or {}),
        )


@dataclass(frozen=True)
class DeclarativeUIComponent:
    """Safe declarative UI widget descriptor rendered by the core GUI."""

    id: str
    type: str
    title: str
    description: str = ""
    tool: str = ""
    default_args: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Declarative UI component id is required")
        if self.type not in ALLOWED_UI_COMPONENT_TYPES:
            raise ValueError(f"Unsupported declarative UI component type: {self.type!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "tool": self.tool,
            "default_args": dict(self.default_args),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeclarativeUIComponent:
        return cls(
            id=str(data.get("id") or "").strip(),
            type=str(data.get("type") or "").strip(),
            title=str(data.get("title") or "").strip(),
            description=str(data.get("description") or "").strip(),
            tool=str(data.get("tool") or "").strip(),
            default_args=dict(data.get("default_args") or {}),
        )


@dataclass(frozen=True)
class ExtensionManifest:
    """Validated manifest.json describing an MCP-app out-of-process extension."""

    id: str
    name: str
    version: str
    api_version: str
    entrypoint: str
    description: str = ""
    author: str = ""
    official: bool = False
    permissions: tuple[str, ...] = ()
    tools: tuple[ExtensionToolSpec, ...] = ()
    ui_components: tuple[DeclarativeUIComponent, ...] = ()
    secret_keys: tuple[str, ...] = ()
    min_profile: str = "allowlist"

    def __post_init__(self) -> None:
        validate_extension_id(self.id)
        if not self.name.strip():
            raise ValueError("Extension name is required")
        validate_semver(self.version)
        ok, msg = check_api_compatibility(self.api_version)
        if not ok:
            raise ValueError(msg)
        validate_entrypoint(self.entrypoint)
        for perm in self.permissions:
            if perm not in ALLOWED_EXTENSION_PERMISSIONS:
                raise ValueError(f"Unsupported extension permission: {perm!r}")
        for tool in self.tools:
            if tool.permission and tool.permission not in self.permissions:
                raise ValueError(
                    f"Tool {tool.name!r} requires undeclared permission {tool.permission!r}"
                )
        if self.min_profile not in ("allowlist", "full"):
            raise ValueError(f"Unsupported extension min_profile: {self.min_profile!r}")
        for key in self.secret_keys:
            if not key.strip() or len(key) > 64 or "/" in key or "\\" in key:
                raise ValueError(f"Invalid secret key declaration: {key!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "api_version": self.api_version,
            "entrypoint": self.entrypoint,
            "description": self.description,
            "author": self.author,
            "official": self.official,
            "permissions": list(self.permissions),
            "tools": [t.to_dict() for t in self.tools],
            "ui_components": [c.to_dict() for c in self.ui_components],
            "secret_keys": list(self.secret_keys),
            "min_profile": self.min_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExtensionManifest:
        if not isinstance(data, dict):
            raise ValueError("Manifest JSON must be an object")
        raw_tools = data.get("tools") or []
        raw_ui = data.get("ui_components") or []
        if not isinstance(raw_tools, list) or not isinstance(raw_ui, list):
            raise ValueError("Manifest 'tools' and 'ui_components' must be arrays")
        return cls(
            id=str(data.get("id") or "").strip(),
            name=str(data.get("name") or "").strip(),
            version=str(data.get("version") or "").strip(),
            api_version=str(data.get("api_version") or "").strip(),
            entrypoint=validate_entrypoint(str(data.get("entrypoint") or "")),
            description=str(data.get("description") or "").strip(),
            author=str(data.get("author") or "").strip(),
            official=bool(data.get("official", False)),
            permissions=tuple(str(p).strip() for p in (data.get("permissions") or []) if str(p).strip()),
            tools=tuple(ExtensionToolSpec.from_dict(item) for item in raw_tools if isinstance(item, dict)),
            ui_components=tuple(DeclarativeUIComponent.from_dict(item) for item in raw_ui if isinstance(item, dict)),
            secret_keys=tuple(str(k).strip() for k in (data.get("secret_keys") or []) if str(k).strip()),
            min_profile=str(data.get("min_profile") or "allowlist").strip(),
        )


@dataclass
class InstalledExtension:
    """Persisted registry record for an installed extension."""

    manifest: ExtensionManifest
    enabled: bool = False
    source: str = "zip"
    package_sha256: str = ""
    verified_by: str = ""
    granted_permissions: tuple[str, ...] = ()
    allowed_clients: tuple[str, ...] = ()
    approved_tools: tuple[str, ...] = ()
    install_dir: str = ""
    data_dir: str = ""
    previous_version: str = ""
    installed_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "enabled": self.enabled,
            "source": self.source,
            "package_sha256": self.package_sha256,
            "verified_by": self.verified_by,
            "granted_permissions": list(self.granted_permissions),
            "allowed_clients": list(self.allowed_clients),
            "approved_tools": list(self.approved_tools),
            "install_dir": self.install_dir,
            "data_dir": self.data_dir,
            "previous_version": self.previous_version,
            "installed_at": self.installed_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InstalledExtension:
        return cls(
            manifest=ExtensionManifest.from_dict(dict(data.get("manifest") or {})),
            enabled=bool(data.get("enabled", False)),
            source=str(data.get("source") or "zip"),
            package_sha256=str(data.get("package_sha256") or ""),
            verified_by=str(data.get("verified_by") or ""),
            granted_permissions=tuple(str(x) for x in (data.get("granted_permissions") or [])),
            allowed_clients=tuple(str(x) for x in (data.get("allowed_clients") or [])),
            approved_tools=tuple(str(x) for x in (data.get("approved_tools") or [])),
            install_dir=str(data.get("install_dir") or ""),
            data_dir=str(data.get("data_dir") or ""),
            previous_version=str(data.get("previous_version") or ""),
            installed_at=float(data.get("installed_at") or 0.0),
            updated_at=float(data.get("updated_at") or 0.0),
        )


@dataclass
class ExtensionRuntimeStatus:
    """Live worker process state for an extension."""

    extension_id: str
    state: str = "stopped"
    pid: int | None = None
    restarts: int = 0
    last_error: str = ""
    ui: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "state": self.state,
            "pid": self.pid,
            "restarts": self.restarts,
            "last_error": self.last_error,
            "ui": dict(self.ui),
        }
