"""Domain models and strict schema validation for MCP-app Server Manager (v0.9.4)."""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore

SCHEMA_VERSION = 2
MAX_SERVERS = 64
MAX_CONFIG_BYTES = 512 * 1024

SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

TEMPLATES = (
    "custom",
    "python_fastapi",
    "python_flask",
    "node_express",
    "vite_next",
    "docker_compose",
    "static_http",
)
LIFECYCLES = ("controlled", "independent")
RESTART_POLICIES = ("never", "on-failure", "always")
READINESS_KINDS = ("none", "tcp", "http")
SERVER_MIN_PROFILES = ("allowlist", "full")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

STATUS_STOPPED = "stopped"
STATUS_STARTING = "starting"
STATUS_RUNNING = "running"
STATUS_HEALTHY = "healthy"
STATUS_UNHEALTHY = "unhealthy"
STATUS_RESTARTING = "restarting"
STATUS_FAILED = "failed"


def validate_server_name(name: str) -> str:
    clean = (name or "").strip()
    if not SERVER_NAME_RE.fullmatch(clean):
        raise ValueError(f"Invalid server name: {name!r}")
    return clean


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ch == "\x7f" for ch in value)


@dataclass(frozen=True)
class ReadinessConfig:
    """TCP or HTTP readiness probe specification."""

    kind: str = "none"
    host: str = "127.0.0.1"
    port: int | None = None
    http_path: str = "/health"
    expected_status: tuple[int, ...] = (200, 204)
    timeout_seconds: float = 15.0
    interval_seconds: float = 0.25
    request_timeout_seconds: float = 2.0

    def validate(self) -> None:
        if self.kind not in READINESS_KINDS:
            raise ValueError(f"Invalid readiness kind: {self.kind!r}")
        if not isinstance(self.host, str) or not self.host.strip() or _has_control_chars(self.host):
            raise ValueError("Invalid readiness host")
        if self.port is not None and not (1 <= int(self.port) <= 65535):
            raise ValueError("Invalid readiness port (must be 1..65535)")
        if self.kind == "http":
            if not isinstance(self.http_path, str) or not self.http_path.startswith("/") or _has_control_chars(self.http_path):
                raise ValueError("Readiness http_path must start with '/'")
            if not self.expected_status or any(not (100 <= int(code) <= 599) for code in self.expected_status):
                raise ValueError("Invalid readiness expected_status codes")
        if not (0.5 <= float(self.timeout_seconds) <= 300.0):
            raise ValueError("Readiness timeout_seconds must be between 0.5 and 300")
        if not (0.05 <= float(self.interval_seconds) <= 10.0):
            raise ValueError("Readiness interval_seconds must be between 0.05 and 10")
        if not (0.1 <= float(self.request_timeout_seconds) <= 30.0):
            raise ValueError("Readiness request_timeout_seconds must be between 0.1 and 30")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "http_path": self.http_path,
            "expected_status": list(self.expected_status),
            "timeout_seconds": float(self.timeout_seconds),
            "interval_seconds": float(self.interval_seconds),
            "request_timeout_seconds": float(self.request_timeout_seconds),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ReadinessConfig:
        if not isinstance(data, dict):
            return cls()
        raw_port = data.get("port")
        port = int(raw_port) if raw_port not in (None, "") else None
        raw_codes = data.get("expected_status", (200, 204))
        codes = tuple(int(c) for c in raw_codes) if isinstance(raw_codes, (list, tuple)) else (200, 204)
        cfg = cls(
            kind=str(data.get("kind", "none")).strip().lower(),
            host=str(data.get("host", "127.0.0.1")).strip() or "127.0.0.1",
            port=port,
            http_path=str(data.get("http_path", "/health")).strip() or "/health",
            expected_status=codes,
            timeout_seconds=float(data.get("timeout_seconds", 15.0)),
            interval_seconds=float(data.get("interval_seconds", 0.25)),
            request_timeout_seconds=float(data.get("request_timeout_seconds", 2.0)),
        )
        cfg.validate()
        return cfg


@dataclass(frozen=True)
class RestartConfig:
    """Automatic restart policy with bounded exponential backoff."""

    policy: str = "never"
    max_attempts: int = 5
    base_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 30.0
    stable_uptime_seconds: float = 30.0

    def validate(self) -> None:
        if self.policy not in RESTART_POLICIES:
            raise ValueError(f"Invalid restart policy: {self.policy!r}")
        if not (0 <= int(self.max_attempts) <= 50):
            raise ValueError("max_attempts must be between 0 and 50")
        if not (0.1 <= float(self.base_backoff_seconds) <= 60.0):
            raise ValueError("base_backoff_seconds must be between 0.1 and 60")
        if not (float(self.base_backoff_seconds) <= float(self.max_backoff_seconds) <= 600.0):
            raise ValueError("max_backoff_seconds must be >= base_backoff_seconds and <= 600")
        if not (1.0 <= float(self.stable_uptime_seconds) <= 3600.0):
            raise ValueError("stable_uptime_seconds must be between 1 and 3600")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "max_attempts": int(self.max_attempts),
            "base_backoff_seconds": float(self.base_backoff_seconds),
            "max_backoff_seconds": float(self.max_backoff_seconds),
            "stable_uptime_seconds": float(self.stable_uptime_seconds),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> RestartConfig:
        if not isinstance(data, dict):
            return cls()
        cfg = cls(
            policy=str(data.get("policy", "never")).strip().lower(),
            max_attempts=int(data.get("max_attempts", 5)),
            base_backoff_seconds=float(data.get("base_backoff_seconds", 1.0)),
            max_backoff_seconds=float(data.get("max_backoff_seconds", 30.0)),
            stable_uptime_seconds=float(data.get("stable_uptime_seconds", 30.0)),
        )
        cfg.validate()
        return cfg


@dataclass(frozen=True)
class ServerProfile:
    """Declarative owner-configured managed server profile (no plaintext secrets)."""

    name: str
    display_name: str = ""
    template: str = "custom"
    argv: tuple[str, ...] = ()
    cwd: str = ""
    env: dict[str, str] = field(default_factory=dict)
    env_secret_refs: dict[str, str] = field(default_factory=dict)
    lifecycle: str = "controlled"
    host: str = "127.0.0.1"
    port: int | None = None
    expose_externally: bool = False
    readiness: ReadinessConfig = field(default_factory=ReadinessConfig)
    depends_on: tuple[str, ...] = ()
    restart: RestartConfig = field(default_factory=RestartConfig)
    autostart: bool = False
    enabled: bool = True
    min_profile: str = "full"
    allowed_clients: tuple[str, ...] = ()
    allow_shared_control: bool = False
    workspace_scoped: bool = False
    pre_start_task_command: str = ""
    template_params: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def validate(self) -> None:
        validate_server_name(self.name)
        if self.template not in TEMPLATES:
            raise ValueError(f"Unsupported template: {self.template!r}")
        if self.lifecycle not in LIFECYCLES:
            raise ValueError(f"Invalid managed server lifecycle: {self.lifecycle!r}")
        if self.min_profile not in SERVER_MIN_PROFILES:
            raise ValueError(f"Invalid server min_profile: {self.min_profile!r}")
        if not self.argv or len(self.argv) > 64:
            raise ValueError("Invalid argv (must contain 1..64 strings)")
        for item in self.argv:
            if not isinstance(item, str) or not item or "\x00" in item:
                raise ValueError("Invalid argv element")
        if not isinstance(self.cwd, str) or not self.cwd or "\x00" in self.cwd:
            raise ValueError("Invalid cwd")
        if not isinstance(self.host, str) or not self.host.strip() or any(ch.isspace() for ch in self.host) or _has_control_chars(self.host):
            raise ValueError("Invalid host")
        if self.host.strip().lower() not in LOOPBACK_HOSTS and not self.expose_externally:
            raise ValueError(
                f"Non-loopback host {self.host!r} requires explicit expose_externally=True"
            )
        if self.port is not None and not (1 <= int(self.port) <= 65535):
            raise ValueError("Invalid server port (must be 1..65535)")
        if not isinstance(self.env, dict) or len(self.env) > 128:
            raise ValueError("Invalid env dictionary")
        for key, value in self.env.items():
            if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
                raise ValueError(f"Invalid env variable name: {key!r}")
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError(f"Invalid env value for {key!r}")
        if not isinstance(self.env_secret_refs, dict) or len(self.env_secret_refs) > 64:
            raise ValueError("Invalid env_secret_refs dictionary")
        for key, ref in self.env_secret_refs.items():
            if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
                raise ValueError(f"Invalid secret env variable name: {key!r}")
            SecretStore.parse_ref(ref)
        seen_deps: set[str] = set()
        for dep in self.depends_on:
            clean_dep = validate_server_name(dep)
            if clean_dep == self.name:
                raise ValueError(f"Server {self.name!r} cannot depend on itself")
            if clean_dep in seen_deps:
                raise ValueError(f"Duplicate dependency {clean_dep!r}")
            seen_deps.add(clean_dep)
        for cid in self.allowed_clients:
            if not isinstance(cid, str) or not CLIENT_ID_RE.fullmatch(cid):
                raise ValueError(f"Invalid allowed client id: {cid!r}")
        if not isinstance(self.pre_start_task_command, str) or "\x00" in self.pre_start_task_command:
            raise ValueError("Invalid pre_start_task_command")
        self.readiness.validate()
        self.restart.validate()

    def validate_launchable(self) -> tuple[list[str], Path]:
        """Verify executable and working directory exist and obey OS rules right before launch."""
        self.validate()
        executable = Path(self.argv[0])
        directory = Path(self.cwd)
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError("Use an absolute executable file path")
        if os.name == "nt" and executable.suffix.lower() != ".exe":
            raise ValueError("Use a direct .exe rather than a shell script")
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError("Use an existing absolute working directory")
        return list(self.argv), directory

    def effective_readiness(self) -> ReadinessConfig:
        if self.readiness.kind == "none":
            return self.readiness
        port = self.readiness.port if self.readiness.port is not None else self.port
        host = self.readiness.host or self.host or "127.0.0.1"
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        return ReadinessConfig(
            kind=self.readiness.kind,
            host=host,
            port=port,
            http_path=self.readiness.http_path,
            expected_status=self.readiness.expected_status,
            timeout_seconds=self.readiness.timeout_seconds,
            interval_seconds=self.readiness.interval_seconds,
            request_timeout_seconds=self.readiness.request_timeout_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "template": self.template,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env": dict(self.env),
            "env_secret_refs": dict(self.env_secret_refs),
            "lifecycle": self.lifecycle,
            "host": self.host,
            "port": self.port,
            "expose_externally": bool(self.expose_externally),
            "readiness": self.readiness.to_dict(),
            "depends_on": list(self.depends_on),
            "restart": self.restart.to_dict(),
            "autostart": bool(self.autostart),
            "enabled": bool(self.enabled),
            "min_profile": self.min_profile,
            "allowed_clients": list(self.allowed_clients),
            "allow_shared_control": bool(self.allow_shared_control),
            "workspace_scoped": bool(self.workspace_scoped),
            "pre_start_task_command": self.pre_start_task_command,
            "template_params": dict(self.template_params),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> ServerProfile:
        if not isinstance(data, dict):
            raise ValueError(f"Invalid server entry for {name!r}")
        raw_argv = data.get("argv")
        if not isinstance(raw_argv, (list, tuple)) or any(not isinstance(v, str) for v in raw_argv):
            raise ValueError(f"Invalid argv for server {name!r}")
        raw_port = data.get("port")
        port = int(raw_port) if raw_port not in (None, "") else None
        raw_env = data.get("env") or {}
        if not isinstance(raw_env, dict):
            raise ValueError(f"Invalid env for server {name!r}")
        raw_refs = data.get("env_secret_refs") or {}
        if not isinstance(raw_refs, dict):
            raise ValueError(f"Invalid env_secret_refs for server {name!r}")
        raw_deps = data.get("depends_on") or ()
        if not isinstance(raw_deps, (list, tuple)):
            raise ValueError(f"Invalid depends_on for server {name!r}")
        raw_clients = data.get("allowed_clients") or ()
        if not isinstance(raw_clients, (list, tuple)):
            raise ValueError(f"Invalid allowed_clients for server {name!r}")
        raw_tparams = data.get("template_params") or {}
        if not isinstance(raw_tparams, dict):
            raw_tparams = {}

        profile = cls(
            name=str(data.get("name") or name).strip(),
            display_name=str(data.get("display_name") or "").strip(),
            template=str(data.get("template") or "custom").strip() or "custom",
            argv=tuple(raw_argv),
            cwd=str(data.get("cwd") or ""),
            env={str(k): str(v) for k, v in raw_env.items()},
            env_secret_refs={str(k): str(v) for k, v in raw_refs.items()},
            lifecycle=str(data.get("lifecycle") or "controlled").strip() or "controlled",
            host=str(data.get("host") or "127.0.0.1").strip() or "127.0.0.1",
            port=port,
            expose_externally=bool(data.get("expose_externally", False)),
            readiness=ReadinessConfig.from_dict(data.get("readiness")),
            depends_on=tuple(str(d).strip() for d in raw_deps if str(d).strip()),
            restart=RestartConfig.from_dict(data.get("restart")),
            autostart=bool(data.get("autostart", False)),
            enabled=bool(data.get("enabled", True)),
            min_profile=str(data.get("min_profile") or "full").strip() or "full",
            allowed_clients=tuple(str(c).strip() for c in raw_clients if str(c).strip()),
            allow_shared_control=bool(data.get("allow_shared_control", False)),
            workspace_scoped=bool(data.get("workspace_scoped", False)),
            pre_start_task_command=str(data.get("pre_start_task_command") or ""),
            template_params=dict(raw_tparams),
            description=str(data.get("description") or "").strip(),
        )
        profile.validate()
        return profile


@dataclass
class ServerRuntimeState:
    """Mutable runtime snapshot for one managed server."""

    name: str
    status: str = STATUS_STOPPED
    running: bool = False
    healthy: bool = False
    health_detail: str = ""
    pid: int | None = None
    create_time: float | None = None
    lifecycle: str = "controlled"
    owner_client_id: str | None = None
    run_id: str | None = None
    exit_code: int | None = None
    started_at: float | None = None
    stopped_at: float | None = None
    restart_count: int = 0
    next_restart_at: float | None = None
    host: str = "127.0.0.1"
    port: int | None = None
    last_error: str = ""
    linked_task_id: str | None = None

    def uptime_seconds(self) -> float:
        if not self.running or self.started_at is None:
            return 0.0
        return max(0.0, time.time() - self.started_at)

    def to_dict(self, redactor: SecretRedactor | None = None) -> dict[str, Any]:
        err = redactor.redact_text(self.last_error) if (redactor and self.last_error) else self.last_error
        detail = (
            redactor.redact_text(self.health_detail)
            if (redactor and self.health_detail)
            else self.health_detail
        )
        return {
            "name": self.name,
            "status": self.status,
            "running": self.running,
            "healthy": self.healthy,
            "health_detail": detail,
            "pid": self.pid,
            "create_time": self.create_time,
            "lifecycle": self.lifecycle,
            "owner_client_id": self.owner_client_id,
            "run_id": self.run_id,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "uptime_seconds": round(self.uptime_seconds(), 3),
            "restart_count": self.restart_count,
            "next_restart_at": self.next_restart_at,
            "host": self.host,
            "port": self.port,
            "last_error": err,
            "linked_task_id": self.linked_task_id,
        }
