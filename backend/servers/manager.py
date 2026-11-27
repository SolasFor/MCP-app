"""Supervisor & runtime orchestration for MCP-app Server Manager (v0.9.4)."""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

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
        auth_rechecker: Callable[[str, ServerProfile], None] | None = None,
        workspace_authorizer: Callable[..., list[str]] | None = None,
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
        self._poll_seconds = max(0.05, float(supervisor_poll_seconds))
        self._platform = get_platform()
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
                )
                self._entries[profile.name] = entry
            else:
                entry.profile = profile
                entry.backoff = self._make_backoff(profile)
                entry.state.lifecycle = profile.lifecycle
                entry.state.host = profile.host
                entry.state.port = profile.port
            return entry

    def _is_entry_alive(self, entry: _ManagedEntry) -> tuple[bool, int | None]:
        handle = entry.handle
        if handle is None:
            return False, entry.state.exit_code
        code = handle.process.poll()
        if code is None:
            return True, None
        return False, code

    def _owned_pids(self) -> set[int]:
        with self._lock:
            pids: set[int] = set()
            for entry in self._entries.values():
                if entry.handle is not None and entry.handle.process.poll() is None:
                    if entry.handle.identity is not None:
                        pids.add(entry.handle.identity.pid)
                    pid = getattr(entry.handle.process, "pid", None)
                    if isinstance(pid, int) and pid > 0:
                        pids.add(pid)
            return pids

    def _refresh_entry_state(self, entry: _ManagedEntry) -> None:
        handle = entry.handle
        if handle is None:
            return
        alive, code = self._is_entry_alive(entry)
        if alive:
            entry.state.running = True
            entry.state.exit_code = None
            return
        entry.state.running = False
        entry.state.exit_code = code
        if entry.state.stopped_at is None:
            entry.state.stopped_at = time.time()
        if entry.state.status in (STATUS_STARTING, STATUS_RUNNING, STATUS_HEALTHY):
            if entry.stop_requested:
                entry.state.status = STATUS_STOPPED
            elif code == 0 and entry.profile.restart.policy != "always":
                entry.state.status = STATUS_STOPPED
            else:
                entry.state.status = STATUS_FAILED if entry.profile.restart.policy == "never" else STATUS_RESTARTING
            entry.state.healthy = False

    def _launch_single(
        self,
        profile: ServerProfile,
        *,
        client_id: str,
        wait_readiness: bool,
        linked_task_id: str | None = None,
        is_restart: bool = False,
    ) -> dict[str, Any]:
        argv, cwd = profile.validate_launchable()
        merged_env, secret_vals = self.store.resolve_profile_env(profile)
        for secret in secret_vals:
            self.redactor.register(secret)

        with self._lock:
            entry = self._entry_for(profile)
            alive, _ = self._is_entry_alive(entry)
            if alive:
                if (
                    not self._is_owner(client_id)
                    and entry.owner_client_id not in (None, client_id)
                    and not profile.allow_shared_control
                ):
                    raise PermissionError("Server already managed by another client")
                return self._state_payload(entry)

            conflict = check_port_conflict(
                profile.host,
                profile.port,
                owned_pids=self._owned_pids(),
            )
            if conflict is not None:
                entry.state.status = STATUS_FAILED
                entry.state.last_error = str(conflict["detail"])
                raise RuntimeError(str(conflict["detail"]))

            entry.stop_requested = False
            entry.state.next_restart_at = None
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
            entry.owner_client_id = client_id
            entry.state.owner_client_id = client_id
            entry.state.run_id = handle.run_id
            entry.state.pid = handle.identity.pid if handle.identity else getattr(handle.process, "pid", None)
            entry.state.create_time = handle.identity.create_time if handle.identity else None
            entry.state.started_at = handle.started_at
            entry.state.stopped_at = None
            entry.state.exit_code = None
            entry.state.last_error = ""
            readiness_cfg = profile.effective_readiness()
            entry.state.status = STATUS_STARTING if (wait_readiness and readiness_cfg.kind != "none") else STATUS_RUNNING
            entry.state.healthy = readiness_cfg.kind == "none"

        if wait_readiness and readiness_cfg.kind != "none":
            ok, detail = self._wait_for_readiness(entry, readiness_cfg)
            with self._lock:
                entry.state.healthy = ok
                entry.state.health_detail = detail
                entry.last_health_probe_at = time.time()
                entry.health_history.append({
                    "ts": entry.last_health_probe_at,
                    "ok": ok,
                    "detail": detail,
                })
                if ok:
                    entry.state.status = STATUS_HEALTHY
                    if entry.healthy_since is None:
                        entry.healthy_since = time.monotonic()
                else:
                    entry.state.last_error = detail
            if not ok:
                if profile.lifecycle == "controlled":
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
                raise RuntimeError(f"Server {profile.name!r} failed readiness check: {detail}")
        else:
            with self._lock:
                entry.state.healthy = readiness_cfg.kind == "none"
                entry.state.health_detail = "Running (readiness check skipped)" if readiness_cfg.kind == "none" else "Starting"
                if entry.healthy_since is None and readiness_cfg.kind == "none":
                    entry.healthy_since = time.monotonic()

        self._wake_event.set()
        return self.status_server(profile.name)

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

    def _state_payload(
        self,
        entry: _ManagedEntry,
        *,
        linked_workspaces: list[str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._refresh_entry_state(entry)
            payload = entry.state.to_dict(self.redactor)
            payload["template"] = entry.profile.template
            payload["display_name"] = entry.profile.display_name or entry.profile.name
            payload["depends_on"] = list(entry.profile.depends_on)
            payload["min_profile"] = entry.profile.min_profile
            payload["autostart"] = entry.profile.autostart
            payload["enabled"] = entry.profile.enabled
            payload["restart_policy"] = entry.profile.restart.policy
            payload["readiness_kind"] = entry.profile.readiness.kind
            if linked_workspaces is not None:
                payload["linked_workspaces"] = list(linked_workspaces)
            elif self.workspace_authorizer is not None:
                try:
                    payload["linked_workspaces"] = self._authorize_workspace(
                        entry.profile.name,
                        client_id="owner",
                        client_profile="full",
                        mode="read",
                    )
                except PermissionError:
                    payload["linked_workspaces"] = []
            else:
                payload["linked_workspaces"] = []
            if self.task_store is not None and entry.state.linked_task_id:
                try:
                    trec = self.task_store.get_task(entry.state.linked_task_id)
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
        items: list[dict[str, Any]] = []
        with self._lock:
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
                entry = self._entry_for(prof)
                items.append(self._state_payload(entry, linked_workspaces=linked_wids))
        return items

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
            self._authorize_profile(profiles[step_name], client_id=client_id, client_profile=client_profile)
            linked_wids_by_step[step_name] = self._authorize_workspace(
                step_name,
                client_id=client_id,
                client_profile=client_profile,
                mode="control",
                workspace_id=workspace_id if step_name == target_name else "",
            )
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
        with self._lock:
            entry = self._entry_for(prof)
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
            prof = profiles[step_name]
            is_target = step_name == clean
            existing_payload = self._running_step_result(
                prof,
                is_target=is_target,
                client_id=client_id,
                actor=actor,
                linked_wids=linked_wids_by_step.get(clean),
            )
            if existing_payload is not None:
                if is_target:
                    result = existing_payload
                continue
            result = self._launch_single(
                prof,
                client_id=actor,
                wait_readiness=wait_readiness or not is_target,
                linked_task_id=linked_task_id if is_target else None,
            )
            if is_target:
                result["linked_workspaces"] = list(linked_wids_by_step.get(clean, ()))
        return result

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
        profiles = self.store.load_profiles(strict=False)
        prof = profiles.get(clean)
        if prof is not None:
            self._authorize_profile(prof, client_id=client_id, client_profile=client_profile)
        linked_wids = self._authorize_workspace(
            clean,
            client_id=client_id,
            client_profile=client_profile,
            mode="control",
            workspace_id=workspace_id,
        )

        with self._lock:
            entry = self._entries.get(clean)
            if entry is None or entry.handle is None:
                if not self._is_owner(client_id):
                    raise ValueError("No managed process for this client")
                if prof is None:
                    raise ValueError("Unknown server profile")
                entry = self._entry_for(prof)
                entry.stop_requested = True
                entry.state.status = STATUS_STOPPED
                entry.state.next_restart_at = None
                return {**self._state_payload(entry, linked_workspaces=linked_wids), "stopped": True}

            if (
                not self._is_owner(client_id)
                and entry.owner_client_id != client_id
                and not entry.profile.allow_shared_control
            ):
                raise PermissionError("No managed process for this client")

            entry.stop_requested = True
            entry.state.next_restart_at = None
            handle = entry.handle
            if handle.lifecycle == "independent":
                self._refresh_entry_state(entry)
                payload = self._state_payload(entry, linked_workspaces=linked_wids)
                payload["stopped"] = False
                payload["note"] = (
                    "Independent process runs detached and is intentionally not terminated by MCP-app"
                )
                return payload

        self.runner.stop_managed(handle, grace_seconds=grace_seconds)
        with self._lock:
            self._refresh_entry_state(entry)
            entry.state.status = STATUS_STOPPED
            entry.state.healthy = False
            entry.state.running = False
            entry.state.stopped_at = time.time()
            payload = self._state_payload(entry, linked_workspaces=linked_wids)
            payload["stopped"] = True
            return payload

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
        with self._lock:
            entry = self._entries.get(clean)
            running = bool(entry is not None and entry.handle is not None and entry.handle.process.poll() is None)
        if running:
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
        with self._lock:
            entry = self._entries.get(clean)
            if prof is not None:
                self._authorize_profile(prof, client_id=client_id, client_profile=client_profile)
                entry = self._entry_for(prof)
            elif entry is None:
                raise ValueError("Unknown server profile")
            else:
                self._authorize_profile(entry.profile, client_id=client_id, client_profile=client_profile)
            linked_wids = self._authorize_workspace(
                clean,
                client_id=client_id,
                client_profile=client_profile,
                mode="read",
                workspace_id=workspace_id,
            )
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
            spool = OutputSpoolManager(self.runner.spool.spool_dir)
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
            identity: ProcessIdentity | None = entry.handle.identity if entry.handle is not None else None
            alive = entry.state.running
        metrics = collect_process_metrics(identity if alive else None, include_children=True)
        return {
            "name": entry.profile.name,
            "status": entry.state.status,
            **metrics,
        }

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
            now = time.time()
            with self._lock:
                entry.state.healthy = ok
                entry.state.health_detail = detail
                entry.last_health_probe_at = now
                entry.health_history.append({"ts": now, "ok": ok, "detail": detail})
                if entry.handle is not None and entry.handle.process.poll() is None:
                    entry.state.status = STATUS_HEALTHY if ok else STATUS_UNHEALTHY
                    if ok and entry.healthy_since is None:
                        entry.healthy_since = time.monotonic()
                    elif not ok:
                        entry.healthy_since = None
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
                with self._lock:
                    entry = self._entry_for(prof)
                    entry.state.status = STATUS_FAILED
                    entry.state.last_error = str(exc)
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

    def _supervisor_tick(self) -> None:
        to_restart: list[tuple[ServerProfile, str]] = []
        now = time.time()
        with self._lock:
            for entry in list(self._entries.values()):
                if entry.handle is None:
                    continue
                if entry.profile.lifecycle == "independent":
                    alive = (
                        entry.handle.identity is not None
                        and self._platform.verify_process_identity(entry.handle.identity)
                    )
                    entry.state.running = alive
                    if not alive and entry.state.status != STATUS_STOPPED:
                        entry.state.status = STATUS_STOPPED
                        entry.state.healthy = False
                        entry.state.stopped_at = entry.state.stopped_at or now
                    continue

                alive, code = self._is_entry_alive(entry)
                if alive:
                    continue

                if entry.stop_requested:
                    entry.state.running = False
                    entry.state.exit_code = code
                    entry.state.status = STATUS_STOPPED
                    entry.state.healthy = False
                    entry.state.stopped_at = entry.state.stopped_at or now
                    continue

                # Unexpected exit for a controlled server -> apply restart policy & backoff
                policy = entry.profile.restart.policy
                should_restart = policy == "always" or (policy == "on-failure" and code != 0)
                if not should_restart:
                    entry.state.running = False
                    entry.state.exit_code = code
                    entry.state.healthy = False
                    entry.state.status = STATUS_STOPPED if code == 0 else STATUS_FAILED
                    entry.state.stopped_at = entry.state.stopped_at or now
                    continue

                if entry.state.next_restart_at is None:
                    if entry.backoff.should_reset_attempts(entry.healthy_since):
                        entry.state.restart_count = 0
                    entry.healthy_since = None
                    entry.state.restart_count += 1
                    if entry.backoff.exhausted(entry.state.restart_count):
                        entry.state.restart_count -= 1
                        entry.state.running = False
                        entry.state.exit_code = code
                        entry.state.healthy = False
                        entry.state.status = STATUS_FAILED
                        entry.state.last_error = (
                            f"Exceeded restart limit ({entry.profile.restart.max_attempts})"
                        )
                        entry.state.stopped_at = entry.state.stopped_at or now
                        continue
                    delay = entry.backoff.next_delay(entry.state.restart_count)
                    entry.state.running = False
                    entry.state.exit_code = code
                    entry.state.healthy = False
                    entry.state.status = STATUS_RESTARTING
                    entry.state.next_restart_at = now + delay
                    entry.state.stopped_at = entry.state.stopped_at or now
                    continue

                if now >= entry.state.next_restart_at:
                    entry.state.next_restart_at = None
                    owner = entry.owner_client_id or "owner"
                    to_restart.append((entry.profile, owner))

        for prof, owner in to_restart:
            if self._stop_event.is_set():
                break
            try:
                if self.auth_rechecker is not None and not self._is_owner(owner):
                    self.auth_rechecker(owner, prof)
                self._launch_single(
                    prof,
                    client_id=owner,
                    wait_readiness=(prof.effective_readiness().kind != "none"),
                    is_restart=True,
                )
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    entry = self._entry_for(prof)
                    entry.state.status = STATUS_FAILED
                    entry.state.running = False
                    entry.state.healthy = False
                    entry.state.last_error = str(exc)

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
                entry.state.running = False
                entry.state.healthy = False
                entry.state.status = STATUS_STOPPED
                entry.state.stopped_at = entry.state.stopped_at or time.time()

        if self._owns_runner:
            self.runner.close()
