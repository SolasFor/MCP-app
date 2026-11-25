"""Unified ProcessRunner: controlled Job Objects, independent lifecycle, bounded I/O, SSH cancellation."""
from __future__ import annotations

import asyncio
import os
import secrets
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.core.redaction import SecretRedactor, sanitize_child_env
from app.platform import ProcessIdentity, ProcessJobHandle, get_platform
from backend.output_stream import (
    DEFAULT_MAX_MEMORY_BYTES,
    BoundedOutputBuffer,
    OutputSpoolManager,
    drain_stream_to_buffer,
)

ProcessLifecycle = Literal["controlled", "independent"]


def _clamped_env_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(low, min(high, int(raw)))
    except ValueError:
        return default


@dataclass(frozen=True)
class CommandResult:
    """Bounded result of a synchronous or cancelled subprocess execution."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cancelled: bool
    truncated: bool
    stdout_bytes: int
    stderr_bytes: int
    run_id: str
    duration_ms: int
    spool_id: str | None = None


@dataclass
class ControlledProcessInfo:
    """Metadata for a process tree owned and terminable by MCP-app."""

    run_id: str
    client_id: str
    kind: str
    name: str
    identity: ProcessIdentity | None
    job: ProcessJobHandle | None
    started_at: float
    process: Any = None
    controllable: bool = True
    cancel_requested: bool = False


@dataclass
class IndependentProcessInfo:
    """Metadata for a detached/independent GUI process not owned for kill-on-close."""

    run_id: str
    client_id: str
    name: str
    identity: ProcessIdentity | None
    started_at: float
    reason: str = "Explicitly started in independent lifecycle mode"
    process: Any = None
    controllable: bool = False


@dataclass
class ActiveSSHHandle:
    """Tracks an active SSH session for immediate non-blocking cancellation."""

    run_id: str
    client_id: str
    cancel_event: threading.Event
    started_at: float
    client_ref: Any = None
    channel_ref: Any = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def register_transport(self, client: Any, channel: Any) -> None:
        with self.lock:
            self.client_ref = client
            self.channel_ref = channel
            if self.cancel_event.is_set():
                self._close_unlocked()

    def cancel(self) -> None:
        with self.lock:
            self.cancel_event.set()
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        for obj in (self.channel_ref, self.client_ref):
            if obj is not None:
                try:
                    obj.close()
                except Exception:  # noqa: BLE001
                    pass


@dataclass(frozen=True)
class EmergencyStopReport:
    """Honest report of stopped vs unstoppable processes after emergency stop."""

    stopped_processes: list[dict[str, Any]]
    stopped_ssh_sessions: int
    unstoppable_processes: list[dict[str, Any]]
    reason: str


@dataclass
class ManagedHandle:
    """Handle returned to ManagedServers for a long-running local process."""

    run_id: str
    client_id: str
    name: str
    lifecycle: ProcessLifecycle
    process: Any
    identity: ProcessIdentity | None
    job: ProcessJobHandle | None
    stdout_buffer: BoundedOutputBuffer
    stderr_buffer: BoundedOutputBuffer
    started_at: float
    _reader_threads: list[threading.Thread] = field(default_factory=list)


class _LoopConcurrency:
    def __init__(self, max_in_flight: int, max_cmd: int, max_ssh: int) -> None:
        self.request_sem = asyncio.Semaphore(max_in_flight)
        self.cmd_sem = asyncio.Semaphore(max_cmd)
        self.ssh_sem = asyncio.Semaphore(max_ssh)


class ProcessRunner:
    """Centralized process, SSH, bounded I/O, and emergency-stop manager."""

    def __init__(
        self,
        *,
        spool_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
        max_concurrent_commands: int | None = None,
        max_concurrent_ssh: int | None = None,
        max_in_flight_requests: int | None = None,
        max_managed_processes: int = 32,
    ) -> None:
        self.platform = get_platform()
        self.redactor = redactor or SecretRedactor()
        base_spool = spool_dir or (Path.cwd() / "spool")
        self.spool = OutputSpoolManager(base_spool)

        self.max_concurrent_commands = (
            max(1, int(max_concurrent_commands))
            if max_concurrent_commands is not None
            else _clamped_env_int("MCP_MAX_CONCURRENT_COMMANDS", 8, 1, 64)
        )
        self.max_concurrent_ssh = (
            max(1, int(max_concurrent_ssh))
            if max_concurrent_ssh is not None
            else _clamped_env_int("MCP_MAX_CONCURRENT_SSH", 4, 1, 32)
        )
        self.max_in_flight_requests = (
            max(1, int(max_in_flight_requests))
            if max_in_flight_requests is not None
            else _clamped_env_int("MCP_MAX_IN_FLIGHT", 32, 1, 128)
        )
        self.max_managed_processes = max(1, int(max_managed_processes))

        self._ssh_executor = ThreadPoolExecutor(
            max_workers=self.max_concurrent_ssh,
            thread_name_prefix="mcp-ssh",
        )
        self._lock = threading.RLock()
        self._loop_concurrencies: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _LoopConcurrency] = (
            weakref.WeakKeyDictionary()
        )
        self._active_commands: dict[str, ControlledProcessInfo] = {}
        self._active_managed: dict[str, ManagedHandle] = {}
        self._independent_processes: dict[str, IndependentProcessInfo] = {}
        self._active_ssh: dict[str, ActiveSSHHandle] = {}
        self._emergency_stopped = False
        self._emergency_reason = ""

    def _concurrency(self) -> _LoopConcurrency:
        loop = asyncio.get_running_loop()
        with self._lock:
            state = self._loop_concurrencies.get(loop)
            if state is None:
                state = _LoopConcurrency(
                    self.max_in_flight_requests,
                    self.max_concurrent_commands,
                    self.max_concurrent_ssh,
                )
                self._loop_concurrencies[loop] = state
            return state

    @property
    def is_emergency_stopped(self) -> bool:
        with self._lock:
            return self._emergency_stopped

    def clear_emergency_stop(self) -> None:
        with self._lock:
            self._emergency_stopped = False
            self._emergency_reason = ""

    @asynccontextmanager
    async def request_slot(self, *, queue_timeout: float = 5.0):
        """Bound simultaneous in-flight MCP execution requests."""
        if self.is_emergency_stopped:
            raise PermissionError("Emergency stop is active")
        sem = self._concurrency().request_sem
        try:
            await asyncio.wait_for(sem.acquire(), timeout=max(0.1, queue_timeout))
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Too many concurrent execution requests") from exc
        try:
            if self.is_emergency_stopped:
                raise PermissionError("Emergency stop is active")
            yield
        finally:
            sem.release()

    def _terminate_controlled(
        self,
        job: ProcessJobHandle | None,
        identity: ProcessIdentity | None,
        process: Any = None,
        grace_seconds: float = 0.5,
    ) -> list[int]:
        stopped: list[int] = []
        if job is not None:
            try:
                if self.platform.terminate_job(job, exit_code=1):
                    stopped.extend(job.tracked_pids)
            finally:
                self.platform.close_job(job)
        if identity is not None:
            report = self.platform.terminate_process_tree(
                identity, grace_seconds=grace_seconds, include_parent=True
            )
            for pid in report.stopped_pids:
                if pid not in stopped:
                    stopped.append(pid)
        elif process is not None:
            try:
                if getattr(process, "returncode", None) is None:
                    process.kill()
            except ProcessLookupError:
                pass
            except Exception:  # noqa: BLE001
                pass
        return stopped

    async def run_command(
        self,
        argv: list[str],
        *,
        cwd: str | Path,
        timeout: int | float,
        client_id: str = "system",
        kind: str = "windows",
        env: Mapping[str, str] | None = None,
        spawn_fn: Callable[..., Any] | None = None,
        max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
        output_offset: int = 0,
        output_limit: int = 8000,
        use_spool: bool = True,
        pre_dispatch_check: Callable[[], None] | None = None,
        lifecycle: ProcessLifecycle = "controlled",
        queue_timeout: float = 15.0,
        run_id: str | None = None,
        on_started: Callable[[str, int | None], None] | None = None,
    ) -> CommandResult:
        """Execute a command with bounded parallel output streaming and tree cleanup."""
        run_id = run_id or secrets.token_hex(8)
        started = time.monotonic()
        conc = self._concurrency()

        try:
            await asyncio.wait_for(conc.cmd_sem.acquire(), timeout=max(0.1, queue_timeout))
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Command concurrency queue timeout") from exc

        job: ProcessJobHandle | None = None
        identity: ProcessIdentity | None = None
        process: Any = None
        cmd_info: ControlledProcessInfo | None = None
        spool_writer = self.spool.create_spool(run_id) if use_spool else None
        out_buf = BoundedOutputBuffer(
            max_memory_bytes=max_memory_bytes, spool=spool_writer, stream_name="stdout"
        )
        err_buf = BoundedOutputBuffer(
            max_memory_bytes=max_memory_bytes, spool=spool_writer, stream_name="stderr"
        )

        try:
            # Post-queue permission & emergency-stop recheck immediately before spawn.
            if self.is_emergency_stopped:
                raise PermissionError("Emergency stop is active")
            if pre_dispatch_check is not None:
                pre_dispatch_check()

            child_env = sanitize_child_env(extra_env=env)
            flags = self.platform.subprocess_creation_flags(
                detached=(lifecycle == "independent"),
                hide_console=(lifecycle == "controlled"),
                breakaway_from_job=(lifecycle == "independent"),
            )
            launcher = spawn_fn or asyncio.create_subprocess_exec
            try:
                try:
                    process = await launcher(
                        *argv,
                        cwd=str(cwd),
                        env=child_env,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=flags,
                    )
                except TypeError as exc:
                    if os.name == "nt" or "creationflags" not in str(exc):
                        raise
                    process = await launcher(
                        *argv,
                        cwd=str(cwd),
                        env=child_env,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=True,
                    )
            except PermissionError:
                if lifecycle != "independent":
                    raise
                # Parent host job (e.g. CI runner) may forbid CREATE_BREAKAWAY_FROM_JOB.
                fallback_flags = self.platform.subprocess_creation_flags(
                    detached=True, hide_console=False, breakaway_from_job=False
                )
                process = await launcher(
                    *argv,
                    cwd=str(cwd),
                    env=child_env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=fallback_flags,
                )

            pid = getattr(process, "pid", None)
            if isinstance(pid, int) and pid > 0:
                identity = self.platform.capture_process_identity(pid)
                if lifecycle == "controlled":
                    job = self.platform.create_job(name=f"MCPApp-Cmd-{run_id}", kill_on_close=True)
                    if job is not None:
                        self.platform.assign_process_to_job(job, pid)
                    cmd_info = ControlledProcessInfo(
                        run_id=run_id,
                        client_id=client_id,
                        kind=kind,
                        name=Path(argv[0]).name if argv else kind,
                        identity=identity,
                        job=job,
                        started_at=time.time(),
                        process=process,
                        controllable=True,
                    )
                    with self._lock:
                        self._active_commands[run_id] = cmd_info
                else:
                    with self._lock:
                        self._independent_processes[run_id] = IndependentProcessInfo(
                            run_id=run_id,
                            client_id=client_id,
                            name=Path(argv[0]).name if argv else kind,
                            identity=identity,
                            started_at=time.time(),
                            process=process,
                        )
            if on_started is not None:
                on_started(run_id, pid if isinstance(pid, int) and pid > 0 else None)

            is_real_streams = isinstance(
                getattr(process, "stdout", None), asyncio.StreamReader
            ) and isinstance(getattr(process, "stderr", None), asyncio.StreamReader)

            timed_out = False
            try:
                if is_real_streams:
                    await asyncio.wait_for(
                        asyncio.gather(
                            drain_stream_to_buffer(process.stdout, out_buf),
                            drain_stream_to_buffer(process.stderr, err_buf),
                            process.wait(),
                        ),
                        timeout=timeout,
                    )
                else:
                    # Compatibility path for unit-test AsyncMock subprocesses.
                    raw_out, raw_err = await asyncio.wait_for(process.communicate(), timeout=timeout)
                    out_buf.append(raw_out or b"")
                    err_buf.append(raw_err or b"")
            except asyncio.TimeoutError:
                timed_out = True
                if lifecycle == "controlled":
                    self._terminate_controlled(job, identity, process, grace_seconds=0.3)
                try:
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    pass
            except asyncio.CancelledError:
                if lifecycle == "controlled":
                    self._terminate_controlled(job, identity, process, grace_seconds=0.2)
                try:
                    await asyncio.wait_for(process.wait(), timeout=1.0)
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    pass
                raise

            duration_ms = int((time.monotonic() - started) * 1000)
            stdout_text = out_buf.render(
                limit=output_limit,
                offset=output_offset,
                redactor=self.redactor,
                spool_manager=self.spool,
            )
            stderr_text = err_buf.render(
                limit=output_limit,
                offset=output_offset,
                redactor=self.redactor,
                spool_manager=self.spool,
            )
            truncated = (
                out_buf.dropped_memory_bytes > 0
                or err_buf.dropped_memory_bytes > 0
                or len(stdout_text) >= output_limit
                or len(stderr_text) >= output_limit
            )
            was_cancelled = bool(cmd_info.cancel_requested) if cmd_info is not None else False
            return CommandResult(
                exit_code=None if (timed_out or was_cancelled) else getattr(process, "returncode", None),
                stdout=stdout_text,
                stderr=stderr_text,
                timed_out=timed_out and not was_cancelled,
                cancelled=was_cancelled,
                truncated=truncated,
                stdout_bytes=out_buf.total_bytes,
                stderr_bytes=err_buf.total_bytes,
                run_id=run_id,
                duration_ms=duration_ms,
                spool_id=spool_writer.run_id if spool_writer is not None else None,
            )
        finally:
            with self._lock:
                self._active_commands.pop(run_id, None)
            if job is not None:
                self.platform.close_job(job)
            conc.cmd_sem.release()

    def spawn_managed(
        self,
        argv: list[str],
        *,
        cwd: Path,
        client_id: str,
        name: str,
        lifecycle: ProcessLifecycle = "controlled",
        env: Mapping[str, str] | None = None,
    ) -> ManagedHandle:
        """Spawn a long-running managed process with bounded I/O and explicit lifecycle."""
        import subprocess

        if self.is_emergency_stopped:
            raise PermissionError("Emergency stop is active")

        with self._lock:
            active_count = sum(
                1 for h in self._active_managed.values() if h.process.poll() is None
            )
            if active_count >= self.max_managed_processes:
                raise ValueError("Managed process limit reached")

        run_id = secrets.token_hex(8)
        child_env = sanitize_child_env(extra_env=env)
        flags = self.platform.subprocess_creation_flags(
            detached=(lifecycle == "independent"),
            hide_console=(lifecycle == "controlled"),
            breakaway_from_job=(lifecycle == "independent"),
        )
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                env=child_env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=flags,
            )
        except PermissionError:
            if lifecycle != "independent":
                raise
            # Parent host job (e.g. CI runner) may forbid CREATE_BREAKAWAY_FROM_JOB.
            fallback_flags = self.platform.subprocess_creation_flags(
                detached=True, hide_console=False, breakaway_from_job=False
            )
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                env=child_env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=fallback_flags,
            )
        identity = self.platform.capture_process_identity(proc.pid)
        job: ProcessJobHandle | None = None
        if lifecycle == "controlled":
            job = self.platform.create_job(name=f"MCPApp-Svc-{run_id}", kill_on_close=True)
            if job is not None:
                self.platform.assign_process_to_job(job, proc.pid)

        spool_writer = self.spool.create_spool(run_id)
        out_buf = BoundedOutputBuffer(spool=spool_writer, stream_name="stdout")
        err_buf = BoundedOutputBuffer(spool=spool_writer, stream_name="stderr")

        def pump(pipe, buf: BoundedOutputBuffer) -> None:
            if pipe is None:
                return
            try:
                while True:
                    chunk = pipe.read(16384)
                    if not chunk:
                        break
                    buf.append(chunk)
            except OSError:
                pass
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        t_out = threading.Thread(target=pump, args=(proc.stdout, out_buf), daemon=True)
        t_err = threading.Thread(target=pump, args=(proc.stderr, err_buf), daemon=True)
        t_out.start()
        t_err.start()

        handle = ManagedHandle(
            run_id=run_id,
            client_id=client_id,
            name=name,
            lifecycle=lifecycle,
            process=proc,
            identity=identity,
            job=job,
            stdout_buffer=out_buf,
            stderr_buffer=err_buf,
            started_at=time.time(),
            _reader_threads=[t_out, t_err],
        )
        with self._lock:
            self._active_managed[run_id] = handle
            if lifecycle == "independent":
                self._independent_processes[run_id] = IndependentProcessInfo(
                    run_id=run_id,
                    client_id=client_id,
                    name=name,
                    identity=identity,
                    started_at=handle.started_at,
                    process=proc,
                )
        return handle

    def stop_managed(self, handle: ManagedHandle, *, grace_seconds: float = 2.0) -> bool:
        """Stop a controlled managed process tree after identity verification."""
        if handle.lifecycle == "independent":
            return False
        try:
            if handle.process.poll() is None:
                if handle.identity is not None:
                    self.platform.terminate_process_tree(
                        handle.identity, grace_seconds=grace_seconds, include_parent=True
                    )
                if handle.job is not None:
                    self.platform.terminate_job(handle.job, exit_code=1)
                if handle.process.poll() is None:
                    handle.process.kill()
                    handle.process.wait(timeout=2)
            return True
        finally:
            if handle.job is not None:
                self.platform.close_job(handle.job)
            with self._lock:
                self._active_managed.pop(handle.run_id, None)

    def cancel_run(self, run_id: str) -> bool:
        """Terminate an active controlled command process tree or SSH session by run_id."""
        with self._lock:
            cmd = self._active_commands.get(run_id)
            ssh = self._active_ssh.get(run_id)
        if ssh is not None:
            ssh.cancel()
            return True
        if cmd is not None:
            cmd.cancel_requested = True
            self._terminate_controlled(cmd.job, cmd.identity, cmd.process, grace_seconds=0.3)
            return True
        return False

    async def run_ssh(
        self,
        ssh_fn: Callable[[threading.Event, Callable[[Any, Any], None]], str],
        *,
        client_id: str = "system",
        pre_dispatch_check: Callable[[], None] | None = None,
        queue_timeout: float = 15.0,
        run_id: str | None = None,
    ) -> str:
        """Execute an SSH call on the dedicated executor with non-blocking cancellation."""
        run_id = run_id or secrets.token_hex(8)
        conc = self._concurrency()
        try:
            await asyncio.wait_for(conc.ssh_sem.acquire(), timeout=max(0.1, queue_timeout))
        except asyncio.TimeoutError as exc:
            raise RuntimeError("SSH concurrency queue timeout") from exc

        handle = ActiveSSHHandle(
            run_id=run_id,
            client_id=client_id,
            cancel_event=threading.Event(),
            started_at=time.time(),
        )
        try:
            if self.is_emergency_stopped:
                raise PermissionError("Emergency stop is active")
            if pre_dispatch_check is not None:
                pre_dispatch_check()

            with self._lock:
                self._active_ssh[run_id] = handle

            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(
                self._ssh_executor, ssh_fn, handle.cancel_event, handle.register_transport
            )
            try:
                return await future
            except asyncio.CancelledError:
                handle.cancel()
                raise
        finally:
            with self._lock:
                self._active_ssh.pop(run_id, None)
            conc.ssh_sem.release()

    def emergency_stop(self, reason: str = "Owner emergency stop") -> EmergencyStopReport:
        """Stop all controlled processes and SSH sessions; report any unstoppable ones honestly."""
        stopped: list[dict[str, Any]] = []
        unstoppable: list[dict[str, Any]] = []
        ssh_count = 0

        with self._lock:
            self._emergency_stopped = True
            self._emergency_reason = reason
            commands = list(self._active_commands.values())
            managed = list(self._active_managed.values())
            independents = list(self._independent_processes.values())
            ssh_handles = list(self._active_ssh.values())

        for ssh in ssh_handles:
            ssh.cancel()
            ssh_count += 1

        for cmd in commands:
            pids = self._terminate_controlled(cmd.job, cmd.identity, cmd.process, grace_seconds=0.3)
            still_alive = (
                cmd.identity is not None and self.platform.verify_process_identity(cmd.identity)
            )
            entry = {
                "run_id": cmd.run_id,
                "name": cmd.name,
                "kind": cmd.kind,
                "pid": cmd.identity.pid if cmd.identity else None,
                "stopped_pids": pids,
            }
            if still_alive:
                unstoppable.append({**entry, "reason": "Process survived termination"})
            else:
                stopped.append(entry)
                with self._lock:
                    self._active_commands.pop(cmd.run_id, None)

        for mh in managed:
            if mh.lifecycle == "independent":
                continue
            self.stop_managed(mh, grace_seconds=0.5)
            still_alive = mh.process.poll() is None
            entry = {
                "run_id": mh.run_id,
                "name": mh.name,
                "kind": "managed_server",
                "pid": mh.identity.pid if mh.identity else None,
            }
            if still_alive:
                unstoppable.append({**entry, "reason": "Managed server survived termination"})
            else:
                stopped.append(entry)

        for ind in independents:
            alive = ind.identity is not None and self.platform.verify_process_identity(ind.identity)
            if alive:
                unstoppable.append({
                    "run_id": ind.run_id,
                    "name": ind.name,
                    "kind": "independent",
                    "pid": ind.identity.pid if ind.identity else None,
                    "reason": ind.reason,
                })

        return EmergencyStopReport(
            stopped_processes=stopped,
            stopped_ssh_sessions=ssh_count,
            unstoppable_processes=unstoppable,
            reason=reason,
        )

    def close(self) -> None:
        """Stop controlled processes and shut down background pools cleanly."""
        with self._lock:
            managed = list(self._active_managed.values())
            ssh_handles = list(self._active_ssh.values())
        for ssh in ssh_handles:
            ssh.cancel()
        for mh in managed:
            if mh.lifecycle == "controlled":
                try:
                    self.stop_managed(mh, grace_seconds=0.5)
                except Exception:  # noqa: BLE001
                    pass
        self._ssh_executor.shutdown(wait=False, cancel_futures=True)
