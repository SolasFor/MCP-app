"""Data models and strict validators for MCP Gateway upstream servers."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

TRANSPORT_STDIO = "stdio"
TRANSPORT_STREAMABLE_HTTP = "streamable_http"
TRANSPORT_SSE = "sse"
VALID_TRANSPORTS = frozenset({TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP, TRANSPORT_SSE})

ISOLATION_PER_CLIENT = "per_client"
ISOLATION_SHARED = "shared_service"
VALID_ISOLATIONS = frozenset({ISOLATION_PER_CLIENT, ISOLATION_SHARED})

AUTH_NONE = "none"
AUTH_BEARER = "bearer"
AUTH_HEADERS = "headers"
VALID_AUTH_MODES = frozenset({AUTH_NONE, AUTH_BEARER, AUTH_HEADERS})

VALID_PROFILES = frozenset({"safe", "allowlist", "full"})
SERVER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")


def normalize_server_id(raw: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "_", (raw or "").strip().lower()).strip("_-")
    if len(slug) < 2:
        slug = (slug + "_srv")[:4]
    return slug[:32]


@dataclass
class UpstreamServerProfile:
    server_id: str
    name: str
    transport: str = TRANSPORT_STDIO
    enabled: bool = True
    autostart: bool = False
    command: str = ""
    args: tuple[str, ...] = ()
    cwd: str = ""
    env: dict[str, str] = field(default_factory=dict)
    env_secret_refs: dict[str, str] = field(default_factory=dict)
    url: str = ""
    auth_mode: str = AUTH_NONE
    auth_secret_ref: str = ""
    headers_secret_refs: dict[str, str] = field(default_factory=dict)
    allow_local_endpoint: bool = False
    allow_redirects: bool = False
    session_isolation: str = ISOLATION_PER_CLIENT
    min_profile: str = "allowlist"
    allowed_clients: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    denied_tools: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    max_response_bytes: int = 2 * 1024 * 1024
    approved_by_owner: bool = False
    notes: str = ""

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not SERVER_ID_RE.fullmatch(self.server_id):
            errors.append("server_id must match ^[a-z0-9][a-z0-9_-]{1,31}$.")
        if not (self.name or "").strip():
            errors.append("Server name is required.")
        if self.transport not in VALID_TRANSPORTS:
            errors.append(f"Unsupported transport: {self.transport!r}.")
        if self.session_isolation not in VALID_ISOLATIONS:
            errors.append(f"Unsupported session_isolation: {self.session_isolation!r}.")
        if self.min_profile not in VALID_PROFILES:
            errors.append(f"Unsupported min_profile: {self.min_profile!r}.")
        if self.auth_mode not in VALID_AUTH_MODES:
            errors.append(f"Unsupported auth_mode: {self.auth_mode!r}.")
        if self.transport == TRANSPORT_STDIO:
            if not (self.command or "").strip():
                errors.append("stdio server requires command executable.")
        else:
            if not (self.url or "").strip():
                errors.append("Remote HTTP/SSE server requires URL.")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 600:
            errors.append("timeout_seconds must be within (0, 600].")
        if self.max_response_bytes < 1024 or self.max_response_bytes > 16 * 1024 * 1024:
            errors.append("max_response_bytes must be within 1 KiB..16 MiB.")
        return errors

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        raw["args"] = list(self.args)
        raw["allowed_clients"] = list(self.allowed_clients)
        raw["allowed_tools"] = list(self.allowed_tools)
        raw["denied_tools"] = list(self.denied_tools)
        return raw

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UpstreamServerProfile":
        return cls(
            server_id=str(data.get("server_id") or "").strip(),
            name=str(data.get("name") or "").strip(),
            transport=str(data.get("transport") or TRANSPORT_STDIO).strip(),
            enabled=bool(data.get("enabled", True)),
            autostart=bool(data.get("autostart", False)),
            command=str(data.get("command") or "").strip(),
            args=tuple(str(x) for x in (data.get("args") or ())),
            cwd=str(data.get("cwd") or "").strip(),
            env={str(k): str(v) for k, v in (data.get("env") or {}).items()},
            env_secret_refs={str(k): str(v) for k, v in (data.get("env_secret_refs") or {}).items()},
            url=str(data.get("url") or "").strip(),
            auth_mode=str(data.get("auth_mode") or AUTH_NONE).strip(),
            auth_secret_ref=str(data.get("auth_secret_ref") or "").strip(),
            headers_secret_refs={str(k): str(v) for k, v in (data.get("headers_secret_refs") or {}).items()},
            allow_local_endpoint=bool(data.get("allow_local_endpoint", False)),
            allow_redirects=bool(data.get("allow_redirects", False)),
            session_isolation=str(data.get("session_isolation") or ISOLATION_PER_CLIENT).strip(),
            min_profile=str(data.get("min_profile") or "allowlist").strip(),
            allowed_clients=tuple(str(x) for x in (data.get("allowed_clients") or ())),
            allowed_tools=tuple(str(x) for x in (data.get("allowed_tools") or ())),
            denied_tools=tuple(str(x) for x in (data.get("denied_tools") or ())),
            timeout_seconds=float(data.get("timeout_seconds", 30.0)),
            max_response_bytes=int(data.get("max_response_bytes", 2 * 1024 * 1024)),
            approved_by_owner=bool(data.get("approved_by_owner", False)),
            notes=str(data.get("notes") or ""),
        )


@dataclass(frozen=True)
class UpstreamToolEntry:
    namespaced_name: str
    server_id: str
    raw_name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class GatewayServerStatus:
    server_id: str
    name: str
    transport: str
    health: str  # stopped | healthy | degraded | error
    tool_count: int
    capabilities: tuple[str, ...] = ()
    last_error: str = ""
    logs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImportPreviewItem:
    profile: UpstreamServerProfile
    inline_secrets: dict[str, str]
    warnings: tuple[str, ...]
