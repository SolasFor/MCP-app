"""Transport provider abstractions, connection identity model, and route ownership registry."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from app.core.secret_store import SecretStore
from app.platform import ProcessIdentity, get_platform

PROVIDER_CF_QUICK = "cloudflare_quick"
PROVIDER_CF_NAMED = "cloudflare_named"
PROVIDER_NGROK = "ngrok"
PROVIDER_TAILSCALE = "tailscale_funnel"
PROVIDER_LOCAL = "local_only"
PROVIDER_NONE = "none"

UI_PROVIDERS: tuple[str, ...] = (
    PROVIDER_CF_QUICK,
    PROVIDER_CF_NAMED,
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
)

ALL_PROVIDERS: tuple[str, ...] = UI_PROVIDERS

EXTERNAL_PROVIDERS: tuple[str, ...] = UI_PROVIDERS


class ProviderState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass(frozen=True)
class ProviderDetection:
    installed: bool
    executable: str = ""
    version: str = ""
    detail: str = ""


@dataclass(frozen=True)
class ConnectionIdentity:
    """Explicit separation between public HTTPS URL and private tunnel/local identity."""

    provider_id: str
    is_public_url: bool
    public_url: str
    local_url: str
    private_tunnel_id: str
    oauth_issuer: str
    oauth_resource_url: str
    is_ephemeral: bool
    supports_sse: bool


@dataclass(frozen=True)
class ProviderStatus:
    provider_id: str
    state: ProviderState
    identity: ConnectionIdentity
    message: str = ""
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiagnosticCheck:
    label: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class LaunchSpec:
    program: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    workdir: str = ""
    uses_managed_process: bool = True
    ready_hint: str = ""


@dataclass(frozen=True)
class IssuerTransitionWarning:
    issuer_changed: bool
    previous_issuer: str
    next_issuer: str
    message: str


def run_cli_capture(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> tuple[int, str, str]:
    """Run a short synchronous CLI probe without spawning a visible console window."""
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "env": merged_env,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
    proc = subprocess.run(cmd, **kwargs)
    return int(proc.returncode), proc.stdout, proc.stderr


class RouteOwnershipStore:
    """Persists MCP-app-owned PIDs (with create_time) and external routes so stops never touch foreign resources."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._platform = get_platform()

    def _load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"processes": {}, "routes": {}}
        if not isinstance(raw, dict):
            return {"processes": {}, "routes": {}}
        return {
            "processes": dict(raw.get("processes") or {}),
            "routes": dict(raw.get("routes") or {}),
        }

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._platform.restrict_path_acl(self._path.parent, is_dir=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path)
        self._platform.restrict_path_acl(self._path, is_dir=False)

    def record_process(self, provider_id: str, pid: int, executable: str = "") -> None:
        ident = self._platform.capture_process_identity(pid)
        data = self._load()
        data["processes"][provider_id] = {
            "pid": int(pid),
            "create_time": ident.create_time if ident else 0.0,
            "executable": ident.executable if ident else executable,
        }
        self._save(data)

    def verify_owned_process(self, provider_id: str, pid: int) -> bool:
        data = self._load()
        entry = data["processes"].get(provider_id)
        if not isinstance(entry, dict):
            return False
        if int(entry.get("pid") or 0) != int(pid):
            return False
        recorded_ct = float(entry.get("create_time") or 0.0)
        recorded_exe = str(entry.get("executable") or "")
        if recorded_ct <= 0.0:
            return self._platform.capture_process_identity(pid) is not None
        expected = ProcessIdentity(pid=int(pid), create_time=recorded_ct, executable=recorded_exe)
        return self._platform.verify_process_identity(expected, tolerance_s=2.0)

    def clear_process(self, provider_id: str) -> None:
        data = self._load()
        if provider_id in data["processes"]:
            del data["processes"][provider_id]
            self._save(data)

    def record_route(self, provider_id: str, route: dict[str, Any]) -> None:
        data = self._load()
        data["routes"][provider_id] = dict(route)
        self._save(data)

    def get_route(self, provider_id: str) -> dict[str, Any] | None:
        data = self._load()
        entry = data["routes"].get(provider_id)
        return dict(entry) if isinstance(entry, dict) else None

    def clear_route(self, provider_id: str) -> None:
        data = self._load()
        if provider_id in data["routes"]:
            del data["routes"][provider_id]
            self._save(data)


class TunnelProvider(ABC):
    """Unified contract implemented by every transport provider."""

    provider_id: str = ""
    is_external: bool = True

    def __init__(self, secret_store: SecretStore, ownership: RouteOwnershipStore) -> None:
        self._secrets = secret_store
        self._ownership = ownership
        self._config: dict[str, Any] = {}

    def load_config(self, config: dict[str, Any]) -> None:
        self._config = dict(config or {})

    def export_config(self) -> dict[str, Any]:
        return dict(self._config)

    @abstractmethod
    def detect(self) -> ProviderDetection:
        """Detect binary/platform prerequisites without raising."""

    def version(self) -> str:
        return self.detect().version

    @abstractmethod
    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        """Return list of validation errors; empty list means valid."""

    def configure(self, config: dict[str, Any], *, secrets: dict[str, str] | None = None) -> list[str]:
        """Validate and persist non-secret config + secret refs via SecretStore."""
        merged = dict(self._config)
        merged.update(config or {})
        errors = self.validate_config(merged)
        if errors:
            return errors
        self._config = merged
        return []

    @abstractmethod
    def connection_identity(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
    ) -> ConnectionIdentity:
        """Compute canonical URL vs private tunnel identity & OAuth issuer/resource."""

    def build_launch_spec(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> LaunchSpec | None:
        """Return subprocess command + env for managed daemons, or None when daemonless."""
        return None

    @abstractmethod
    def status(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
        running: bool = False,
    ) -> ProviderStatus:
        """Return live provider status snapshot."""

    @abstractmethod
    def diagnose(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        """Run non-destructive provider diagnostics."""

    def start(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> tuple[bool, str]:
        """Activate daemonless/CLI-registered route if needed; ManagedProcess hosts CLI daemons."""
        return True, ""

    def stop(self) -> tuple[bool, str]:
        """Tear down ONLY MCP-app-owned routes/processes cleanly."""
        return True, ""

    def secret_refs(self) -> list[str]:
        """Return SecretStore refs owned by this provider for redaction/metadata."""
        return []

    def summary_dict(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
        running: bool = False,
        detection: ProviderDetection | None = None,
    ) -> dict[str, Any]:
        det = detection if detection is not None else self.detect()
        st = self.status(
            local_host=local_host,
            local_port=local_port,
            mcp_path=mcp_path,
            runtime_url=runtime_url,
            running=running,
        )
        return {
            "provider_id": self.provider_id,
            "is_external": self.is_external,
            "detection": asdict(det),
            "status": {
                "state": st.state.value,
                "message": st.message,
                "warnings": list(st.warnings),
                "identity": asdict(st.identity),
            },
        }
