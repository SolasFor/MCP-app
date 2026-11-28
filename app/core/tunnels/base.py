"""Transport provider abstractions, connection identity model, and route ownership registry."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
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


@dataclass(frozen=True)
class BoundedCliResult:
    """Result of streaming bounded subprocess capture with hard byte, deadline, and cancel limits."""

    returncode: int | None
    stdout: str
    stderr: str
    stdout_bytes_read: int = 0
    stderr_bytes_read: int = 0
    stdout_limit_exceeded: bool = False
    stderr_limit_exceeded: bool = False
    timed_out: bool = False
    cancelled: bool = False


def _read_bounded_stream(
    stream: Any,
    limit: int,
    chunk_size: int,
    abort_event: threading.Event,
    buf: bytearray,
    stats: dict[str, Any],
    key: str,
) -> None:
    try:
        while not abort_event.is_set():
            remaining = (limit + 1) - len(buf)
            if remaining <= 0:
                stats[f"{key}_exceeded"] = True
                abort_event.set()
                return
            to_read = min(chunk_size, remaining)
            read_fn = getattr(stream, "read1", stream.read)
            chunk = read_fn(to_read)
            if not chunk:
                return
            buf.extend(chunk)
            stats[f"{key}_read"] += len(chunk)
            if len(buf) > limit:
                stats[f"{key}_exceeded"] = True
                abort_event.set()
                return
    except (OSError, ValueError):
        return


def _kill_and_reap(proc: subprocess.Popen[bytes]) -> None:
    try:
        proc.kill()
        proc.wait(timeout=2.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _terminate_owned_cli_process(proc: subprocess.Popen[bytes], ident: ProcessIdentity | None) -> None:
    if proc.poll() is not None:
        return
    platform = get_platform()
    if ident is not None:
        if not platform.verify_process_identity(ident):
            return
        platform.terminate_process_tree(ident, grace_seconds=0.4, include_parent=True)
    elif proc.poll() is None:
        _kill_and_reap(proc)
        return
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        if ident is not None and platform.verify_process_identity(ident):
            _kill_and_reap(proc)


def _close_stream_quietly(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def _finalize_bounded_cli_process(
    proc: subprocess.Popen[bytes],
    ident: ProcessIdentity | None,
    t_out: threading.Thread,
    t_err: threading.Thread,
    *,
    force_terminate: bool,
) -> None:
    if force_terminate or proc.poll() is None:
        _terminate_owned_cli_process(proc, ident)
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    t_out.join(timeout=2.0)
    t_err.join(timeout=2.0)
    _close_stream_quietly(proc.stdout)
    _close_stream_quietly(proc.stderr)
    if t_out.is_alive():
        t_out.join(timeout=0.5)
    if t_err.is_alive():
        t_err.join(timeout=0.5)


def _wait_for_bounded_cli(
    proc: subprocess.Popen[bytes],
    t_out: threading.Thread,
    t_err: threading.Thread,
    abort_event: threading.Event,
    deadline: float,
    cancel_event: threading.Event | None,
) -> tuple[bool, bool]:
    timed_out = False
    cancelled = False
    while True:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            abort_event.set()
            break
        if abort_event.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            abort_event.set()
            break
        if proc.poll() is not None and not t_out.is_alive() and not t_err.is_alive():
            break
        abort_event.wait(timeout=min(0.02, max(0.001, remaining)))
    return timed_out, cancelled


def run_cli_capture_bounded(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 8.0,
    max_stdout_bytes: int = 1024 * 1024,
    max_stderr_bytes: int = 64 * 1024,
    cancel_event: threading.Event | None = None,
    chunk_size: int = 8192,
) -> BoundedCliResult:
    """Run a CLI subprocess streaming stdout/stderr with hard byte limits, total deadline, and cancellation."""
    if max_stdout_bytes < 1 or max_stderr_bytes < 1 or timeout <= 0:
        raise ValueError("Invalid bounded CLI capture limits")
    if cancel_event is not None and cancel_event.is_set():
        return BoundedCliResult(returncode=None, stdout="", stderr="", cancelled=True)

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": merged_env,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = int(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))

    proc: subprocess.Popen[bytes] = subprocess.Popen(cmd, **popen_kwargs)
    ident = get_platform().capture_process_identity(proc.pid)
    out_buf, err_buf = bytearray(), bytearray()
    stats: dict[str, Any] = {
        "stdout_read": 0,
        "stderr_read": 0,
        "stdout_exceeded": False,
        "stderr_exceeded": False,
    }
    abort_event = threading.Event()
    t_out = threading.Thread(
        target=_read_bounded_stream,
        args=(proc.stdout, max_stdout_bytes, max(256, chunk_size), abort_event, out_buf, stats, "stdout"),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_read_bounded_stream,
        args=(proc.stderr, max_stderr_bytes, max(256, chunk_size), abort_event, err_buf, stats, "stderr"),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    timed_out = False
    cancelled = False
    try:
        timed_out, cancelled = _wait_for_bounded_cli(
            proc,
            t_out,
            t_err,
            abort_event,
            time.monotonic() + float(timeout),
            cancel_event,
        )
    finally:
        force_stop = timed_out or cancelled or stats["stdout_exceeded"] or stats["stderr_exceeded"]
        _finalize_bounded_cli_process(proc, ident, t_out, t_err, force_terminate=force_stop)

    aborted = timed_out or cancelled or stats["stdout_exceeded"] or stats["stderr_exceeded"]
    stdout_text = "" if aborted else bytes(out_buf).decode("utf-8", errors="replace")
    stderr_text = "" if aborted else bytes(err_buf).decode("utf-8", errors="replace")
    return BoundedCliResult(
        returncode=proc.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        stdout_bytes_read=int(stats["stdout_read"]),
        stderr_bytes_read=int(stats["stderr_read"]),
        stdout_limit_exceeded=bool(stats["stdout_exceeded"]),
        stderr_limit_exceeded=bool(stats["stderr_exceeded"]),
        timed_out=timed_out,
        cancelled=cancelled,
    )


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
        from app.core.atomic_io import atomic_write_json

        atomic_write_json(self._path, data, indent=2, restrict_acl=True)

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
