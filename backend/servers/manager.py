"""Supervisor & runtime orchestration for MCP-app Server Manager (v0.9.4+)."""
from __future__ import annotations

import inspect
import json
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.core.atomic_io import atomic_write_json, cross_process_lock
from app.core.reconnect import BackoffPolicy
from app.core.redaction import SecretRedactor
from app.platform import ProcessIdentity, get_platform
from backend.output_stream import OutputSpoolManager
from backend.process_runner import ManagedHandle, ProcessRunner
from backend.servers.models import (
    STATUS_FAILED,
    STATUS_HEALTHY,
    STATUS_RESTARTING,
    STATUS_RUNNING,
    STATUS_STARTING,
    STATUS_STOPPED,
    STATUS_UNHEALTHY,
    ServerProfile,
    ServerRuntimeState,
    validate_server_name,
)
from backend.servers.probes import check_port_conflict, collect_process_metrics, probe_readiness
from backend.servers.store import ServerConfigStore, resolve_start_order

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}


@dataclass
class _ManagedEntry:
    profile: ServerProfile
    owner_client_id: str | None
    handle: ManagedHandle | None
    state: ServerRuntimeState
    backoff: BackoffPolicy
    owner_workspace_id: str = ""
    remote_manager_id: str = ""
    spool_dir: str = ""
    stop_requested: bool = False
    healthy_since: float | None = None
    last_health_probe_at: float = 0.0
    health_history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=25))


class ServerManager:
    """Lifecycle, readiness, dependency, metrics, logs, and backoff supervisor for managed servers."""

    def __init__(
        self,
        store: ServerConfigStore,
        runner: ProcessRunner | None = None,
        *,
        redactor: SecretRedactor | None = None,
        task_store: Any = None,
        auth_rechecker: Callable[..., None] | None = None,
        workspace_authorizer: Callable[..., list[str]] | None = None,
        live_client_authorizer: Callable[[str | None, str], str] | None = None,
        supervisor_poll_seconds: float = 0.2,
    ) -> None:
        self.store = store
        self._owns_runner = runner is None
        self.runner = runner or ProcessRunner(
            spool_dir=store.path.parent / "spool",
            redactor=redactor,
        )
        self.redactor = redactor or self.runner.redactor
        self.task_store = task_store
        self.auth_rechecker = auth_rechecker
        self.workspace_authorizer = workspace_authorizer
        self.live_client_authorizer = live_client_authorizer
        self._poll_seconds = max(0.05, float(supervisor_poll_seconds))
        self._platform = get_platform()
        self._manager_id = uuid.uuid4().hex
        self._runtime_path = self.store.path.parent / "managed_servers.runtime.json"
        self._runtime_lock_path = self.store.path.parent / ".managed_servers.runtime.lock"
        self._lock = threading.RLock()
        self._entries: dict[str, _ManagedEntry] = {}
        self._closed = False
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._supervisor = threading.Thread(
            target=self._supervisor_loop,
            name="mcp-server-supervisor",
            daemon=True,
        )
        self._supervisor.start()

    def _runtime_lock(self, timeout: float = 10.0):
        return cross_process_lock(self._runtime_lock_path, timeout=timeout)

    @staticmethod
    def _is_owner(client_id: str | None) -> bool:
        return client_id in (None, "", "owner")

    def _authorize_profile(
        self,
        profile: ServerProfile,
        *,
        client_id: str | None,
        client_profile: str,
    ) -> None:
        if self._is_owner(client_id):
            return
        if not profile.enabled:
            raise PermissionError(f"Server {profile.name!r} is disabled")
        rank = _PROFILE_RANK.get(client_profile, 0)
        needed = _PROFILE_RANK.get(profile.min_profile, 2)
        if rank < needed:
            raise PermissionError(
                f"Server {profile.name!r} requires at least {profile.min_profile} access profile"
            )
        if profile.allowed_clients and client_id not in profile.allowed_clients:
            raise PermissionError(
                f"Client {client_id!r} is not authorized for server {profile.name!r}"
            )

    def _authorize_workspace(
        self,
        server_name: str,
        *,
        client_id: str | None,
        client_profile: str,
        mode: Literal["read", "control"],
        workspace_id: str = "",
    ) -> list[str]:
        if self.workspace_authorizer is None:
            return []
        return list(
            self.workspace_authorizer(
                server_name,
                client_id=client_id,
                client_profile=client_profile,
                mode=mode,
                workspace_id=workspace_id,
            )
        )

    def _resolve_live_profile(
        self,
        client_id: str | None,
        fallback_profile: str,
        tool_name: str,
    ) -> str:
        if self.live_client_authorizer is None:
            return fallback_profile
        return str(self.live_client_authorizer(client_id, tool_name))

    def _call_auth_rechecker(self, client_id: str, profile: ServerProfile, workspace_id: str) -> None:
        if self.auth_rechecker is None:
            return
        try:
            sig = inspect.signature(self.auth_rechecker)
            if "workspace_id" in sig.parameters or len(sig.parameters) >= 3:
                self.auth_rechecker(client_id, profile, workspace_id)
                return
        except (TypeError, ValueError):
            pass
        self.auth_rechecker(client_id, profile)

    def _authorize_step_live(
        self,
        step_name: str,
        *,
        tool_name: str,
        client_id: str | None,
        fallback_profile: str,
        workspace_id: str,
    ) -> tuple[ServerProfile, str, list[str]]:
        profiles = self.store.load_profiles(strict=True)
        prof = profiles.get(step_name)
        if prof is None:
            raise ValueError(f"Unknown server profile: {step_name!r}")
        live_profile = self._resolve_live_profile(client_id, fallback_profile, tool_name)
        self._authorize_profile(prof, client_id=client_id, client_profile=live_profile)
        linked_wids = self._authorize_workspace(
            step_name,
            client_id=client_id,
            client_profile=live_profile,
            mode="control",
            workspace_id=workspace_id,
        )
        if not self._is_owner(client_id):
            assert isinstance(client_id, str) and client_id
            self._call_auth_rechecker(client_id, prof, workspace_id)
        return prof, live_profile, linked_wids

    @staticmethod
    def _make_backoff(profile: ServerProfile) -> BackoffPolicy:
        return BackoffPolicy(
            base_seconds=profile.restart.base_backoff_seconds,
            max_seconds=profile.restart.max_backoff_seconds,
            jitter_ratio=0.0,
            max_attempts=max(1, profile.restart.max_attempts),
            stable_uptime_seconds=profile.restart.stable_uptime_seconds,
        )

    def _entry_for(self, profile: ServerProfile) -> _ManagedEntry:
        with self._lock:
            entry = self._entries.get(profile.name)
            if entry is None:
                entry = _ManagedEntry(
                    profile=profile,
                    owner_client_id=None,
                    handle=None,
                    state=ServerRuntimeState(
                        name=profile.name,
                        lifecycle=profile.lifecycle,
                        host=profile.host,
                        port=profile.port,
                    ),
                    backoff=self._make_backoff(profile),
                    spool_dir=str(self.runner.spool.spool_dir),
                )
                self._entries[profile.name] = entry
            else:
                entry.profile = profile
                entry.backoff = self._make_backoff(profile)
                entry.state.lifecycle = profile.lifecycle
                entry.state.host = profile.host
                entry.state.port = profile.port
            return entry

    def _remote_identity(self, entry: _ManagedEntry) -> ProcessIdentity | None:
        if entry.state.pid and entry.state.create_time is not None:
            return ProcessIdentity(pid=int(entry.state.pid), create_time=float(entry.state.create_time))
        return None

    def _is_entry_alive(self, entry: _ManagedEntry) -> tuple[bool, int | None]:
        handle = entry.handle
        if handle is not None:
            code = handle.process.poll()
            if code is None:
                return True, None
            return False, code
        ident = self._remote_identity(entry)
        if entry.state.running and ident is not None and self._platform.verify_process_identity(ident):
            return True, None
        return False, entry.state.exit_code

    def _entry_live_pids(self, entry: _ManagedEntry) -> list[int]:
        if entry.handle is not None and entry.handle.process.poll() is None:
            pids: list[int] = []
            if entry.handle.identity is not None:
                pids.append(entry.handle.identity.pid)
            pid = getattr(entry.handle.process, "pid", None)
            if isinstance(pid, int) and pid > 0:
                pids.append(pid)
            return pids
        if entry.state.running and entry.state.pid:
            ident = self._remote_identity(entry)
            if ident is not None and self._platform.verify_process_identity(ident):
                return [ident.pid]
        return []

    def _owned_pids(self) -> set[int]:
        with self._lock:
            pids: set[int] = set()
            for entry in self._entries.values():
                pids.update(self._entry_live_pids(entry))
            return pids

    def _refresh_remote_entry_state(self, entry: _ManagedEntry) -> None:
        if not entry.state.running:
            return
        ident = self._remote_identity(entry)
        if ident is not None and self._platform.verify_process_identity(ident):
            return
        entry.state.running = False
        entry.state.healthy = False
        if entry.state.status in (STATUS_STARTING, STATUS_RUNNING, STATUS_HEALTHY, STATUS_UNHEALTHY):
            entry.state.status = STATUS_STOPPED
        entry.state.stopped_at = entry.state.stopped_at or time.time()

    def _refresh_entry_state(self, entry: _ManagedEntry) -> None:
        if entry.handle is None:
            self._refresh_remote_entry_state(entry)
            return
        alive, code = self._is_entry_alive(entry)
        if alive:
            entry.state.running = True
            entry.state.exit_code = None
            return
        entry.state.running = False
        entry.state.exit_code = code
        entry.state.stopped_at = entry.state.stopped_at or time.time()
        if entry.state.status in (STATUS_STARTING, STATUS_RUNNING, STATUS_HEALTHY):
            stopped_ok = entry.stop_requested or (code == 0 and entry.profile.restart.policy != "always")
            entry.state.status = (
                STATUS_STOPPED if stopped_ok else (STATUS_FAILED if entry.profile.restart.policy == "never" else STATUS_RESTARTING)
            )
            entry.state.healthy = False

    def _read_ledger_raw(self) -> dict[str, Any]:
        if not self._runtime_path.is_file():
            return {}
        try:
            raw = json.loads(self._runtime_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        servers = raw.get("servers")
        return servers if isinstance(servers, dict) else {}

    @staticmethod
    def _apply_verified_ledger_row(
        entry: _ManagedEntry,
        row: dict[str, Any],
        pid: int,
        ctime: float,
        row_mgr: str,
        default_spool: Path,
    ) -> None:
        entry.handle = None
        entry.remote_manager_id = row_mgr
        entry.spool_dir = str(row.get("spool_dir") or entry.spool_dir or default_spool)
        entry.owner_client_id = row.get("owner_client_id")
        entry.owner_workspace_id = str(row.get("owner_workspace_id") or "")
        entry.state.running = True
        entry.state.healthy = bool(row.get("healthy", True))
        entry.state.health_detail = str(row.get("health_detail") or "")
        entry.state.status = str(row.get("status") or STATUS_RUNNING)
        entry.state.pid = pid
        entry.state.create_time = ctime
        entry.state.lifecycle = str(row.get("lifecycle") or entry.profile.lifecycle)
        entry.state.owner_client_id = entry.owner_client_id
        entry.state.run_id = row.get("run_id")
        entry.state.exit_code = None
        entry.state.started_at = row.get("started_at")
        entry.state.stopped_at = None
        entry.state.restart_count = int(row.get("restart_count") or 0)
        entry.state.linked_task_id = row.get("linked_task_id")
        entry.state.last_error = str(row.get("last_error") or "")

    def _retire_local_handle(self, entry: _ManagedEntry) -> None:
        handle = entry.handle
        if handle is None:
            return
        if entry.profile.lifecycle == "controlled":
            try:
                self.runner.stop_managed(handle, grace_seconds=0.2)
            except Exception:  # noqa: BLE001
                pass
        elif handle.job is not None:
            self._platform.close_job(handle.job)
        entry.handle = None

    def _apply_inactive_ledger_row(self, entry: _ManagedEntry, row: dict[str, Any], row_running: bool) -> bool:
        row_mgr = str(row.get("owner_manager_id") or "")
        row_stop = bool(row.get("stop_requested"))
        if entry.handle is not None:
            remote_stopped = row_stop or (
                not row_running
                and row_mgr not in ("", self._manager_id)
                and entry.handle.process.poll() is not None
            )
            if not remote_stopped:
                return False
            entry.stop_requested = True
            entry.state.next_restart_at = None
            self._retire_local_handle(entry)
        entry.remote_manager_id = ""
        entry.state.running = False
        entry.state.healthy = False
        if row_running:
            entry.state.status = STATUS_STOPPED
            entry.state.stopped_at = entry.state.stopped_at or time.time()
            return True
        if row_stop:
            entry.state.status = STATUS_STOPPED
            entry.state.stopped_at = row.get("stopped_at") or entry.state.stopped_at or time.time()
        if row.get("run_id") and not entry.state.run_id:
            entry.state.run_id = row.get("run_id")
            entry.spool_dir = str(row.get("spool_dir") or entry.spool_dir or self.runner.spool.spool_dir)
            entry.state.exit_code = row.get("exit_code")
            entry.state.stopped_at = row.get("stopped_at")
            entry.state.last_error = str(row.get("last_error") or "")
        return False

    def _apply_ledger_row(self, entry: _ManagedEntry, row: dict[str, Any]) -> bool:
        pid = row.get("pid")
        ctime = row.get("create_time")
        row_running = bool(row.get("running"))
        row_mgr = str(row.get("owner_manager_id") or "")
        row_run_id = row.get("run_id")
        row_stop = bool(row.get("stop_requested"))
        if (
            row_mgr == self._manager_id
            and entry.handle is not None
            and row_run_id == entry.handle.run_id
            and not row_stop
        ):
            return False

        verified = (
            row_running
            and isinstance(pid, int)
            and pid > 0
            and isinstance(ctime, (int, float))
            and self._platform.verify_process_identity(ProcessIdentity(pid=pid, create_time=float(ctime)))
        )
        if verified:
            assert isinstance(pid, int) and isinstance(ctime, (int, float))
            if entry.handle is not None and row_run_id != entry.handle.run_id:
                self._retire_local_handle(entry)
            self._apply_verified_ledger_row(entry, row, pid, float(ctime), row_mgr, self.runner.spool.spool_dir)
            return False
        return self._apply_inactive_ledger_row(entry, row, row_running)

    def _sync_from_ledger_under_runtime_lock(self, names: list[str] | None = None) -> None:
        rows = self._read_ledger_raw()
        if not rows:
            return
        targets = names if names is not None else sorted(rows)
        stale_cleaned = False
        with self._lock:
            for name in targets:
                row = rows.get(name)
                if not isinstance(row, dict):
                    continue
                entry = self._entries.get(name)
                if entry is None:
                    continue
                if self._apply_ledger_row(entry, row):
                    stale_cleaned = True
        if stale_cleaned:
            self._persist_ledger_under_runtime_lock()

    def _entry_to_ledger_row(self, entry: _ManagedEntry) -> dict[str, Any]:
        st = entry.state
        owner_mgr = self._manager_id if entry.handle is not None else entry.remote_manager_id
        return {
            "name": st.name,
            "status": st.status,
            "running": bool(st.running),
            "healthy": bool(st.healthy),
            "health_detail": st.health_detail,
            "pid": st.pid,
            "create_time": st.create_time,
            "lifecycle": st.lifecycle,
            "owner_client_id": st.owner_client_id,
            "owner_workspace_id": entry.owner_workspace_id,
            "owner_manager_id": owner_mgr,
            "stop_requested": bool(entry.stop_requested),
            "run_id": st.run_id,
            "spool_dir": entry.spool_dir or str(self.runner.spool.spool_dir),
            "exit_code": st.exit_code,
            "started_at": st.started_at,
            "stopped_at": st.stopped_at,
            "restart_count": int(st.restart_count),
            "next_restart_at": st.next_restart_at,
            "host": st.host,
            "port": st.port,
            "last_error": self.redactor.redact_text(st.last_error) if st.last_error else "",
            "linked_task_id": st.linked_task_id,
        }

    def _existing_remote_row_alive(self, existing: Any, entry: _ManagedEntry) -> bool:
        if not isinstance(existing, dict) or not existing.get("running"):
            return False
        other_mgr = str(existing.get("owner_manager_id") or "")
        other_run = existing.get("run_id")
        local_run = entry.handle.run_id if entry.handle is not None else entry.state.run_id
        if other_mgr in ("", self._manager_id) and other_run == local_run:
            return False
        pid = existing.get("pid")
        ctime = existing.get("create_time")
        return (
            isinstance(pid, int)
            and pid > 0
            and ctime is not None
            and self._platform.verify_process_identity(ProcessIdentity(pid=pid, create_time=float(ctime)))
        )

    def _persist_ledger_under_runtime_lock(self) -> None:
        merged = self._read_ledger_raw()
        with self._lock:
            for name, entry in self._entries.items():
                self._refresh_entry_state(entry)
                if not entry.state.running and self._existing_remote_row_alive(merged.get(name), entry):
                    continue
                merged[name] = self._entry_to_ledger_row(entry)
        atomic_write_json(
            self._runtime_path,
            {"schema_version": 1, "servers": merged},
            indent=2,
            restrict_acl=True,
        )

    def _sync_entry_and_ledger(self, prof: ServerProfile) -> _ManagedEntry:
        with self._runtime_lock():
            entry = self._entry_for(prof)
            self._sync_from_ledger_under_runtime_lock([prof.name])
            return entry

    def _check_already_alive_payload(
        self,
        entry: _ManagedEntry,
        profile: ServerProfile,
        *,
        client_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            self._refresh_entry_state(entry)
            alive, _ = self._is_entry_alive(entry)
            if not alive:
                return None
            if (
                not self._is_owner(client_id)
                and entry.owner_client_id not in (None, client_id)
                and not profile.allow_shared_control
            ):
                raise PermissionError("Server already managed by another client")
            return entry.state.to_dict(self.redactor)

    def _spawn_new_managed_entry(
        self,
        entry: _ManagedEntry,
        profile: ServerProfile,
        *,
        argv: list[str],
        cwd: Path,
        merged_env: dict[str, str],
        client_id: str,
        wait_readiness: bool,
        linked_task_id: str | None,
        is_restart: bool,
        workspace_id: str,
    ) -> None:
        if self.live_client_authorizer is not None:
            live_prof = self._resolve_live_profile(client_id, "full", "server_start")
            self._authorize_profile(profile, client_id=client_id, client_profile=live_prof)
        conflict = check_port_conflict(profile.host, profile.port, owned_pids=self._owned_pids())
        if conflict is not None:
            with self._lock:
                entry.state.status = STATUS_FAILED
                entry.state.last_error = str(conflict["detail"])
            self._persist_ledger_under_runtime_lock()
            raise RuntimeError(str(conflict["detail"]))

        readiness_cfg = profile.effective_readiness()
        with self._lock:
            entry.stop_requested = False
            entry.state.next_restart_at = None
            entry.owner_workspace_id = workspace_id
            if not is_restart:
                entry.state.restart_count = 0
                entry.healthy_since = None
            if linked_task_id is not None:
                entry.state.linked_task_id = linked_task_id or None

            handle = self.runner.spawn_managed(
                argv,
                cwd=cwd,
                client_id=client_id,
                name=profile.name,
                lifecycle=profile.lifecycle,  # type: ignore[arg-type]
                env=merged_env,
            )
            entry.handle = handle
            entry.remote_manager_id = self._manager_id
            entry.spool_dir = str(self.runner.spool.spool_dir)
            entry.owner_client_id = client_id
            entry.state.owner_client_id = client_id
            entry.state.run_id = handle.run_id
            entry.state.pid = handle.identity.pid if handle.identity else getattr(handle.process, "pid", None)
            entry.state.create_time = handle.identity.create_time if handle.identity else None
            entry.state.started_at = handle.started_at
            entry.state.stopped_at = None
            entry.state.exit_code = None
            entry.state.running = True
            entry.state.last_error = ""
            entry.state.status = (
                STATUS_STARTING if (wait_readiness and readiness_cfg.kind != "none") else STATUS_RUNNING
            )
            entry.state.healthy = readiness_cfg.kind == "none"
        self._persist_ledger_under_runtime_lock()

    def _launch_single(
        self,
        profile: ServerProfile,
        *,
        client_id: str,
        wait_readiness: bool,
        linked_task_id: str | None = None,
        is_restart: bool = False,
        workspace_id: str = "",
        pre_spawn_check: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        argv, cwd = profile.validate_launchable()
        merged_env, secret_vals = self.store.resolve_profile_env(profile)
        for secret in secret_vals:
            self.redactor.register(secret)

        if pre_spawn_check is not None:
            pre_spawn_check()

        with self._runtime_lock():
            entry = self._entry_for(profile)
            self._sync_from_ledger_under_runtime_lock([profile.name])
            already_live = self._check_already_alive_payload(entry, profile, client_id=client_id)
            if already_live is None:
                self._spawn_new_managed_entry(
                    entry,
                    profile,
                    argv=argv,
                    cwd=cwd,
                    merged_env=merged_env,
                    client_id=client_id,
                    wait_readiness=wait_readiness,
                    linked_task_id=linked_task_id,
                    is_restart=is_restart,
                    workspace_id=workspace_id,
                )

        if already_live is not None:
            return self.status_server(profile.name)

        self._finish_launch_readiness(entry, profile, wait_readiness=wait_readiness)
        self._wake_event.set()
        return self.status_server(profile.name)

    def _handle_readiness_failure(self, entry: _ManagedEntry, profile: ServerProfile, detail: str) -> None:
        if profile.lifecycle == "controlled" and entry.handle is not None:
            entry.stop_requested = True
            try:
                self.runner.stop_managed(entry.handle, grace_seconds=1.0)
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            alive_now, code_now = self._is_entry_alive(entry)
            entry.state.running = alive_now
            entry.state.exit_code = code_now
            entry.state.status = STATUS_UNHEALTHY if alive_now else STATUS_FAILED
            if not alive_now:
                entry.state.stopped_at = entry.state.stopped_at or time.time()
        with self._runtime_lock():
            self._persist_ledger_under_runtime_lock()
        raise RuntimeError(f"Server {profile.name!r} failed readiness check: {detail}")

    def _finish_launch_readiness(
        self,
        entry: _ManagedEntry,
        profile: ServerProfile,
        *,
        wait_readiness: bool,
    ) -> None:
        readiness_cfg = profile.effective_readiness()
        if not wait_readiness or readiness_cfg.kind == "none":
            with self._lock:
                entry.state.healthy = readiness_cfg.kind == "none"
                entry.state.health_detail = (
                    "Running (readiness check skipped)" if readiness_cfg.kind == "none" else "Starting"
                )
                if entry.healthy_since is None and readiness_cfg.kind == "none":
                    entry.healthy_since = time.monotonic()
            with self._runtime_lock():
                self._persist_ledger_under_runtime_lock()
            return

        ok, detail = self._wait_for_readiness(entry, readiness_cfg)
        now = time.time()
        with self._lock:
            entry.state.healthy = ok
            entry.state.health_detail = detail
            entry.last_health_probe_at = now
            entry.health_history.append({"ts": now, "ok": ok, "detail": detail})
            if ok:
                entry.state.status = STATUS_HEALTHY
                entry.healthy_since = entry.healthy_since or time.monotonic()
            else:
                entry.state.last_error = detail
        if not ok:
            self._handle_readiness_failure(entry, profile, detail)
        with self._runtime_lock():
            self._persist_ledger_under_runtime_lock()

    def _wait_for_readiness(self, entry: _ManagedEntry, cfg: Any) -> tuple[bool, str]:
        deadline = time.monotonic() + float(cfg.timeout_seconds)
        last_detail = "Readiness probe timed out"
        while time.monotonic() < deadline and not self._stop_event.is_set():
            with self._lock:
                alive, code = self._is_entry_alive(entry)
            if not alive:
                return False, f"Process exited prematurely with code {code}"
            ok, detail = probe_readiness(cfg)
            last_detail = detail
            if ok:
                return True, detail
            time.sleep(float(cfg.interval_seconds))
        return False, last_detail

    def _resolve_linked_workspaces(
        self,
        prof: ServerProfile,
        linked_workspaces: list[str] | None,
    ) -> list[str]:
        if linked_workspaces is not None:
            return list(linked_workspaces)
        if self.workspace_authorizer is None:
            return []
        try:
            return self._authorize_workspace(
                prof.name,
                client_id="owner",
                client_profile="full",
                mode="read",
            )
        except PermissionError:
            return []

    def _state_payload(
        self,
        entry: _ManagedEntry,
        *,
        linked_workspaces: list[str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._refresh_entry_state(entry)
            payload = entry.state.to_dict(self.redactor)
            prof = entry.profile
            linked_tid = entry.state.linked_task_id

        payload["template"] = prof.template
        payload["display_name"] = prof.display_name or prof.name
        payload["depends_on"] = list(prof.depends_on)
        payload["min_profile"] = prof.min_profile
        payload["autostart"] = prof.autostart
        payload["enabled"] = prof.enabled
        payload["workspace_scoped"] = prof.workspace_scoped
        payload["restart_policy"] = prof.restart.policy
        payload["readiness_kind"] = prof.readiness.kind
        payload["linked_workspaces"] = self._resolve_linked_workspaces(prof, linked_workspaces)
        if self.task_store is not None and linked_tid:
            try:
                trec = self.task_store.get_task(linked_tid)
                if trec is not None:
                    payload["linked_task"] = {
                        "task_id": trec.task_id,
                        "status": trec.status,
                        "title": self.redactor.redact_text(trec.title),
                    }
            except Exception:  # noqa: BLE001
                pass
        return payload

    def list_servers(
        self,
        *,
        client_id: str | None = None,
        client_profile: str = "full",
        workspace_id: str = "",
    ) -> list[dict[str, Any]]:
        profiles = self.store.load_profiles(strict=False)
        authorized: list[tuple[ServerProfile, list[str]]] = []
        for name in sorted(profiles):
            prof = profiles[name]
            if not self._is_owner(client_id):
                try:
                    self._authorize_profile(prof, client_id=client_id, client_profile=client_profile)
                except PermissionError:
                    continue
            try:
                linked_wids = self._authorize_workspace(
                    prof.name,
                    client_id=client_id,
                    client_profile=client_profile,
                    mode="read",
                    workspace_id=workspace_id,
                )
            except PermissionError:
                continue
            authorized.append((prof, linked_wids))

        entries: list[tuple[_ManagedEntry, list[str]]] = []
        with self._runtime_lock():
            for prof, linked_wids in authorized:
                entries.append((self._entry_for(prof), linked_wids))
            self._sync_from_ledger_under_runtime_lock([p.name for p, _ in authorized])
        return [self._state_payload(entry, linked_workspaces=wids) for entry, wids in entries]

    def _authorize_start_order(
        self,
        profiles: dict[str, ServerProfile],
        order: list[str],
        target_name: str,
        *,
        client_id: str | None,
        client_profile: str,
        workspace_id: str,
    ) -> dict[str, list[str]]:
        linked_wids_by_step: dict[str, list[str]] = {}
        for step_name in order:
            live_prof = self._resolve_live_profile(client_id, client_profile, "server_start")
            self._authorize_profile(profiles[step_name], client_id=client_id, client_profile=live_prof)
            step_wid = workspace_id if step_name == target_name else ""
            linked_wids_by_step[step_name] = self._authorize_workspace(
                step_name,
                client_id=client_id,
                client_profile=live_prof,
                mode="control",
                workspace_id=step_wid,
            )
            if not self._is_owner(client_id):
                assert isinstance(client_id, str) and client_id
                self._call_auth_rechecker(client_id, profiles[step_name], step_wid)
        return linked_wids_by_step

    def _running_step_result(
        self,
        prof: ServerProfile,
        *,
        is_target: bool,
        client_id: str | None,
        actor: str,
        linked_wids: list[str] | None,
    ) -> dict[str, Any] | None:
        entry = self._sync_entry_and_ledger(prof)
        with self._lock:
            self._refresh_entry_state(entry)
            alive, _ = self._is_entry_alive(entry)
            if not alive:
                return None
            if (
                is_target
                and not self._is_owner(client_id)
                and entry.owner_client_id != actor
                and not prof.allow_shared_control
            ):
                raise PermissionError("Server already managed by another client")
        return self._state_payload(entry, linked_workspaces=linked_wids) if is_target else {}

    def _run_start_step(
        self,
        step_name: str,
        *,
        is_target: bool,
        client_id: str | None,
        client_profile: str,
        actor: str,
        linked_task_id: str | None,
        wait_readiness: bool,
        workspace_id: str,
        fallback_wids: list[str],
    ) -> dict[str, Any] | None:
        fresh_prof, _live_prof, step_wids = self._authorize_step_live(
            step_name,
            tool_name="server_start",
            client_id=client_id,
            fallback_profile=client_profile,
            workspace_id=workspace_id,
        )
        existing_payload = self._running_step_result(
            fresh_prof,
            is_target=is_target,
            client_id=client_id,
            actor=actor,
            linked_wids=step_wids,
        )
        if existing_payload is not None:
            return existing_payload if is_target else None

        def _pre_spawn() -> None:
            self._authorize_step_live(
                step_name,
                tool_name="server_start",
                client_id=client_id,
                fallback_profile=client_profile,
                workspace_id=workspace_id,
            )

        res = self._launch_single(
            fresh_prof,
            client_id=actor,
            wait_readiness=wait_readiness or not is_target,
            linked_task_id=linked_task_id if is_target else None,
            workspace_id=workspace_id,
            pre_spawn_check=_pre_spawn,
        )
        if is_target:
            res["linked_workspaces"] = list(step_wids or fallback_wids)
            return res
        return None

    def start_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        start_dependencies: bool = True,
        wait_readiness: bool = True,
        linked_task_id: str | None = None,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        clean = validate_server_name(name)
        profiles = self.store.load_profiles(strict=True)
        if clean not in profiles:
            raise ValueError("Unknown server profile")

        actor = client_id or "owner"
        order = resolve_start_order(profiles, clean) if start_dependencies else [clean]
        linked_wids_by_step = self._authorize_start_order(
            profiles,
            order,
            clean,
            client_id=client_id,
            client_profile=client_profile,
            workspace_id=workspace_id,
        )

        result: dict[str, Any] = {}
        for step_name in order:
            is_target = step_name == clean
            step_res = self._run_start_step(
                step_name,
                is_target=is_target,
                client_id=client_id,
                client_profile=client_profile,
                actor=actor,
                linked_task_id=linked_task_id,
                wait_readiness=wait_readiness,
                workspace_id=workspace_id if is_target else "",
                fallback_wids=linked_wids_by_step.get(clean, []),
            )
            if step_res is not None:
                result = step_res
        return result

    def _stop_remote_controlled(
        self,
        entry: _ManagedEntry,
        *,
        grace_seconds: float,
    ) -> bool:
        ident = self._remote_identity(entry)
        if ident is None or not self._platform.verify_process_identity(ident):
            return False
        self._platform.terminate_process_tree(ident, grace_seconds=grace_seconds, include_parent=True)
        return True

    def _prepare_stop_entry(
        self, clean: str, client_id: str | None
    ) -> tuple[_ManagedEntry, ManagedHandle | None, bool, str]:
        self._sync_from_ledger_under_runtime_lock([clean])
        with self._lock:
            entry = self._entries.get(clean)
            if entry is None:
                msg = "No managed process for this client" if not self._is_owner(client_id) else "Unknown server profile"
                raise ValueError(msg)
            self._refresh_entry_state(entry)
            if (
                not self._is_owner(client_id)
                and entry.owner_client_id != client_id
                and not entry.profile.allow_shared_control
            ):
                raise PermissionError("No managed process for this client")
            entry.stop_requested = True
            entry.state.next_restart_at = None
            handle = entry.handle
            lifecycle = handle.lifecycle if handle is not None else entry.state.lifecycle
            return entry, handle, entry.state.running, lifecycle

    def stop_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        grace_seconds: float = 2.0,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        clean = validate_server_name(name)
        prof = self.store.load_profiles(strict=False).get(clean)
        if prof is not None:
            self._authorize_profile(prof, client_id=client_id, client_profile=client_profile)
        elif self._is_owner(client_id):
            raise ValueError("Unknown server profile")
        linked_wids = self._authorize_workspace(
            clean, client_id=client_id, client_profile=client_profile, mode="control", workspace_id=workspace_id
        )

        with self._runtime_lock():
            if prof is not None:
                self._entry_for(prof)
            entry, handle, is_running, lifecycle = self._prepare_stop_entry(clean, client_id)
            if not is_running and handle is None:
                if not self._is_owner(client_id):
                    raise ValueError("No managed process for this client")
                with self._lock:
                    entry.state.status = STATUS_STOPPED
                    entry.state.healthy = False
                self._persist_ledger_under_runtime_lock()
                return {**self._state_payload(entry, linked_workspaces=linked_wids), "stopped": True}

            if lifecycle == "independent":
                with self._lock:
                    self._refresh_entry_state(entry)
                self._persist_ledger_under_runtime_lock()
                return {
                    **self._state_payload(entry, linked_workspaces=linked_wids),
                    "stopped": False,
                    "note": "Independent process runs detached and is intentionally not terminated by MCP-app",
                }

            if handle is not None:
                self.runner.stop_managed(handle, grace_seconds=grace_seconds)
            else:
                self._stop_remote_controlled(entry, grace_seconds=grace_seconds)
            with self._lock:
                self._refresh_entry_state(entry)
                entry.stop_requested = True
                if entry.handle is None:
                    entry.remote_manager_id = self._manager_id
                entry.state.status = STATUS_STOPPED
                entry.state.healthy = False
                entry.state.running = False
                entry.state.stopped_at = time.time()
            self._persist_ledger_under_runtime_lock()
            return {**self._state_payload(entry, linked_workspaces=linked_wids), "stopped": True}

    def restart_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        wait_readiness: bool = True,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        clean = validate_server_name(name)
        st = self.status_server(
            clean,
            client_id=client_id,
            client_profile=client_profile,
            workspace_id=workspace_id,
        )
        if st.get("running"):
            stopped = self.stop_server(
                clean, client_id=client_id, client_profile=client_profile, workspace_id=workspace_id
            )
            if stopped.get("lifecycle") == "independent" and stopped.get("running"):
                raise RuntimeError("Cannot automatically restart an independent detached process")
        return self.start_server(
            clean,
            client_id=client_id,
            client_profile=client_profile,
            start_dependencies=True,
            wait_readiness=wait_readiness,
            workspace_id=workspace_id,
        )

    def _require_entry_for_read(
        self,
        name: str,
        *,
        client_id: str | None,
        client_profile: str,
        workspace_id: str = "",
    ) -> tuple[_ManagedEntry, list[str]]:
        clean = validate_server_name(name)
        prof = self.store.load_profiles(strict=False).get(clean)
        if prof is None:
            with self._lock:
                existing = self._entries.get(clean)
            if existing is None:
                raise ValueError("Unknown server profile")
            prof = existing.profile

        self._authorize_profile(prof, client_id=client_id, client_profile=client_profile)
        linked_wids = self._authorize_workspace(
            clean,
            client_id=client_id,
            client_profile=client_profile,
            mode="read",
            workspace_id=workspace_id,
        )
        entry = self._sync_entry_and_ledger(prof)
        with self._lock:
            self._refresh_entry_state(entry)
            if (
                not self._is_owner(client_id)
                and entry.owner_client_id not in (None, client_id)
                and not entry.profile.allow_shared_control
            ):
                raise PermissionError("Server is managed by another client")
        return entry, linked_wids

    def status_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        workspace_id: str = "",
    ) -> dict[str, Any]:
        entry, linked_wids = self._require_entry_for_read(
            name, client_id=client_id, client_profile=client_profile, workspace_id=workspace_id
        )
        return self._state_payload(entry, linked_workspaces=linked_wids)

    def logs_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        stream: Literal["stdout", "stderr"] = "stdout",
        offset: int = 0,
        limit: int = 8000,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        entry, _ = self._require_entry_for_read(
            name, client_id=client_id, client_profile=client_profile, workspace_id=workspace_id
        )
        with self._lock:
            handle = entry.handle
            run_id = entry.state.run_id
            spool_dir = Path(entry.spool_dir) if entry.spool_dir else self.runner.spool.spool_dir
        safe_stream: Literal["stdout", "stderr"] = "stderr" if stream == "stderr" else "stdout"
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit), 32000))

        text = ""
        total_bytes = 0
        if handle is not None:
            buf = handle.stderr_buffer if safe_stream == "stderr" else handle.stdout_buffer
            total_bytes = buf.total_bytes
            text = buf.render(
                offset=safe_offset,
                limit=safe_limit,
                redactor=self.redactor,
                spool_manager=self.runner.spool,
            )
        elif run_id:
            spool = OutputSpoolManager(spool_dir)
            page = spool.read_page(
                run_id,
                safe_stream,
                offset=safe_offset,
                limit=safe_limit,
                redactor=self.redactor,
            )
            text = page.text
            total_bytes = page.total_bytes

        returned_bytes = len(text.encode("utf-8", errors="replace"))
        return {
            "name": entry.profile.name,
            "run_id": run_id,
            "stream": safe_stream,
            "offset": safe_offset,
            "limit": safe_limit,
            "total_bytes": total_bytes,
            "has_more": (safe_offset + safe_limit) < total_bytes,
            "text": self.redactor.redact_text(text),
            "returned_bytes": returned_bytes,
        }

    def metrics_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        workspace_id: str = "",
    ) -> dict[str, Any]:
        entry, _ = self._require_entry_for_read(
            name, client_id=client_id, client_profile=client_profile, workspace_id=workspace_id
        )
        with self._lock:
            self._refresh_entry_state(entry)
            identity = (
                entry.handle.identity
                if entry.handle is not None
                else self._remote_identity(entry)
            )
            alive = entry.state.running
        metrics = collect_process_metrics(identity if alive else None, include_children=True)
        return {
            "name": entry.profile.name,
            "status": entry.state.status,
            **metrics,
        }

    def _record_probe_result(self, entry: _ManagedEntry, ok: bool, detail: str) -> None:
        now = time.time()
        with self._lock:
            entry.state.healthy = ok
            entry.state.health_detail = detail
            entry.last_health_probe_at = now
            entry.health_history.append({"ts": now, "ok": ok, "detail": detail})
            alive_now, _ = self._is_entry_alive(entry)
            if alive_now:
                entry.state.status = STATUS_HEALTHY if ok else STATUS_UNHEALTHY
                entry.healthy_since = (entry.healthy_since or time.monotonic()) if ok else None
        with self._runtime_lock():
            self._persist_ledger_under_runtime_lock()

    def health_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
        run_probe: bool = True,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        entry, _ = self._require_entry_for_read(
            name, client_id=client_id, client_profile=client_profile, workspace_id=workspace_id
        )
        with self._lock:
            self._refresh_entry_state(entry)
            running = entry.state.running
            cfg = entry.profile.effective_readiness()
            if not running:
                entry.state.healthy = False
                return {
                    "name": entry.profile.name,
                    "running": False,
                    "healthy": False,
                    "status": entry.state.status,
                    "detail": entry.state.last_error or "Server is not running",
                    "history": list(entry.health_history),
                }
        if run_probe:
            ok, detail = probe_readiness(cfg)
            self._record_probe_result(entry, ok, detail)
        return {
            "name": entry.profile.name,
            "running": entry.state.running,
            "healthy": entry.state.healthy,
            "status": entry.state.status,
            "detail": entry.state.health_detail,
            "history": list(entry.health_history),
        }

    def start_autostart_servers(self) -> list[dict[str, Any]]:
        """Start all enabled autostart profiles in topological dependency order."""
        started: list[dict[str, Any]] = []
        profiles = self.store.load_profiles(strict=False)
        for name in sorted(profiles):
            prof = profiles[name]
            if not (prof.enabled and prof.autostart):
                continue
            try:
                started.append(
                    self.start_server(name, client_id="owner", start_dependencies=True, wait_readiness=True)
                )
            except Exception as exc:  # noqa: BLE001
                with self._runtime_lock():
                    entry = self._entry_for(prof)
                    with self._lock:
                        entry.state.status = STATUS_FAILED
                        entry.state.last_error = str(exc)
                    self._persist_ledger_under_runtime_lock()
        return started

    def _supervisor_loop(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self._poll_seconds)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            try:
                self._supervisor_tick()
            except Exception:  # noqa: BLE001
                pass

    def _schedule_or_exhaust_restart(self, entry: _ManagedEntry, code: int | None, now: float) -> None:
        if entry.backoff.should_reset_attempts(entry.healthy_since):
            entry.state.restart_count = 0
        entry.healthy_since = None
        entry.state.restart_count += 1
        entry.state.running = False
        entry.state.exit_code = code
        entry.state.healthy = False
        entry.state.stopped_at = entry.state.stopped_at or now
        if entry.backoff.exhausted(entry.state.restart_count):
            entry.state.restart_count -= 1
            entry.state.status = STATUS_FAILED
            entry.state.last_error = f"Exceeded restart limit ({entry.profile.restart.max_attempts})"
            return
        entry.state.status = STATUS_RESTARTING
        entry.state.next_restart_at = now + entry.backoff.next_delay(entry.state.restart_count)

    def _evaluate_independent_tick(self, entry: _ManagedEntry, now: float) -> None:
        assert entry.handle is not None
        alive = (
            entry.handle.identity is not None
            and self._platform.verify_process_identity(entry.handle.identity)
        )
        entry.state.running = alive
        if not alive and entry.state.status != STATUS_STOPPED:
            entry.state.status = STATUS_STOPPED
            entry.state.healthy = False
            entry.state.stopped_at = entry.state.stopped_at or now

    def _evaluate_entry_tick(self, entry: _ManagedEntry, now: float) -> tuple[str, str, str] | None:
        if entry.handle is None:
            return None
        if entry.profile.lifecycle == "independent":
            self._evaluate_independent_tick(entry, now)
            return None

        alive, code = self._is_entry_alive(entry)
        if alive:
            return None

        policy = entry.profile.restart.policy
        should_restart = not entry.stop_requested and (policy == "always" or (policy == "on-failure" and code != 0))
        if not should_restart:
            entry.state.running = False
            entry.state.exit_code = code
            entry.state.healthy = False
            entry.state.status = STATUS_STOPPED if (entry.stop_requested or code == 0) else STATUS_FAILED
            entry.state.stopped_at = entry.state.stopped_at or now
            return None

        if entry.state.next_restart_at is None:
            self._schedule_or_exhaust_restart(entry, code, now)
            return None

        if now >= entry.state.next_restart_at:
            entry.state.next_restart_at = None
            return (entry.profile.name, entry.owner_client_id or "owner", entry.owner_workspace_id)
        return None

    def _attempt_auto_restart(self, srv_name: str, owner: str, owner_wid: str) -> None:
        try:
            fresh_prof, _live_prof, _wids = self._authorize_step_live(
                srv_name,
                tool_name="server_start",
                client_id=owner,
                fallback_profile="full",
                workspace_id=owner_wid,
            )
            if not fresh_prof.enabled or fresh_prof.restart.policy == "never":
                raise PermissionError(f"Auto-restart disabled for {srv_name!r}")

            def _pre_spawn() -> None:
                self._authorize_step_live(
                    srv_name,
                    tool_name="server_start",
                    client_id=owner,
                    fallback_profile="full",
                    workspace_id=owner_wid,
                )

            self._launch_single(
                fresh_prof,
                client_id=owner,
                wait_readiness=(fresh_prof.effective_readiness().kind != "none"),
                is_restart=True,
                workspace_id=owner_wid,
                pre_spawn_check=_pre_spawn,
            )
        except Exception as exc:  # noqa: BLE001
            with self._runtime_lock():
                with self._lock:
                    entry = self._entries.get(srv_name)
                    if entry is not None:
                        entry.state.status = STATUS_FAILED
                        entry.state.running = False
                        entry.state.healthy = False
                        entry.state.last_error = f"Auto-restart blocked: {exc}"
                self._persist_ledger_under_runtime_lock()

    def _supervisor_tick(self) -> None:
        with self._lock:
            exited_controlled = [
                name
                for name, entry in self._entries.items()
                if (
                    entry.handle is not None
                    and entry.profile.lifecycle == "controlled"
                    and entry.handle.process.poll() is not None
                )
            ]
        if exited_controlled:
            try:
                with self._runtime_lock(timeout=1.0):
                    self._sync_from_ledger_under_runtime_lock(exited_controlled)
            except TimeoutError:
                pass

        to_restart: list[tuple[str, str, str]] = []
        now = time.time()
        with self._lock:
            for entry in list(self._entries.values()):
                item = self._evaluate_entry_tick(entry, now)
                if item is not None:
                    to_restart.append(item)

        for srv_name, owner, owner_wid in to_restart:
            if self._stop_event.is_set():
                break
            self._attempt_auto_restart(srv_name, owner, owner_wid)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop_event.set()
            self._wake_event.set()
            entries = list(self._entries.values())

        if self._supervisor.is_alive():
            self._supervisor.join(timeout=2.0)

        for entry in entries:
            if entry.handle is not None and entry.profile.lifecycle == "controlled":
                entry.stop_requested = True
                try:
                    self.runner.stop_managed(entry.handle, grace_seconds=1.0)
                except Exception:  # noqa: BLE001
                    pass
                entry.handle = None
                entry.state.running = False
                entry.state.healthy = False
                entry.state.status = STATUS_STOPPED
                entry.state.stopped_at = entry.state.stopped_at or time.time()

        try:
            with self._runtime_lock(timeout=2.0):
                self._persist_ledger_under_runtime_lock()
        except Exception:  # noqa: BLE001
            pass

        if self._owns_runner:
            self.runner.close()
