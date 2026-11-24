"""POSIX platform adapter used on Linux/macOS CI and non-Windows environments."""
from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import psutil

from app.platform.base import (
    PlatformAdapter,
    ProcessIdentity,
    ProcessJobHandle,
    TerminationReport,
)


class PosixPlatformAdapter(PlatformAdapter):
    """POSIX fallback adapter implementing process groups and 0700/0600 permissions."""

    def create_job(
        self, name: str = "", kill_on_close: bool = True, allow_breakaway: bool = False
    ) -> ProcessJobHandle | None:
        return ProcessJobHandle(handle=object(), name=name or "posix-group", kill_on_close=kill_on_close)

    def assign_process_to_job(
        self, job: ProcessJobHandle, pid: int, process_handle: int | None = None
    ) -> bool:
        if not job.active or pid <= 0:
            return False
        if pid not in job.tracked_pids:
            job.tracked_pids.append(pid)
        return True

    def terminate_job(self, job: ProcessJobHandle, exit_code: int = 1) -> bool:
        if not job.active:
            return False
        for pid in list(job.tracked_pids):
            ident = self.capture_process_identity(pid)
            if ident is not None:
                self.terminate_process_tree(ident, grace_seconds=0.5, include_parent=True)
            else:
                try:
                    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except OSError:
                    pass
        return True

    def close_job(self, job: ProcessJobHandle) -> None:
        job.active = False
        job.handle = None

    def capture_process_identity(self, pid: int) -> ProcessIdentity | None:
        if pid <= 0:
            return None
        try:
            proc = psutil.Process(pid)
            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = ""
            return ProcessIdentity(
                pid=pid,
                create_time=float(proc.create_time()),
                executable=exe,
                captured_at=time.time(),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return None

    def verify_process_identity(self, identity: ProcessIdentity, tolerance_s: float = 0.5) -> bool:
        if identity.pid <= 0:
            return False
        try:
            proc = psutil.Process(identity.pid)
            if not proc.is_running():
                return False
            return abs(float(proc.create_time()) - identity.create_time) <= tolerance_s
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return False

    def terminate_process_tree(
        self, identity: ProcessIdentity, grace_seconds: float = 2.0, include_parent: bool = True
    ) -> TerminationReport:
        if not self.verify_process_identity(identity):
            return TerminationReport([], [], [identity.pid], "identity_mismatch")

        try:
            parent = psutil.Process(identity.pid)
            victims = parent.children(recursive=True)
        except psutil.Error:
            return TerminationReport([], [], [identity.pid], "psutil_tree")

        if include_parent:
            victims.append(parent)

        stopped: list[int] = []
        failed: list[int] = []
        if grace_seconds > 0 and victims:
            for proc in victims:
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    stopped.append(proc.pid)
                except psutil.Error:
                    pass
            gone, alive = psutil.wait_procs(victims, timeout=max(0.0, grace_seconds))
            stopped.extend(p.pid for p in gone if p.pid not in stopped)
        else:
            alive = list(victims)

        if alive:
            for proc in alive:
                try:
                    proc.kill()
                except psutil.NoSuchProcess:
                    if proc.pid not in stopped:
                        stopped.append(proc.pid)
                except psutil.Error:
                    pass
            gone2, still_alive = psutil.wait_procs(alive, timeout=1.0)
            for proc in gone2:
                if proc.pid not in stopped:
                    stopped.append(proc.pid)
            for proc in still_alive:
                if proc.pid not in failed:
                    failed.append(proc.pid)

        return TerminationReport(
            stopped_pids=sorted(set(stopped)),
            failed_pids=sorted(set(failed)),
            skipped_foreign_pids=[],
            method="psutil_tree",
        )

    def subprocess_creation_flags(
        self, detached: bool = False, hide_console: bool = True, breakaway_from_job: bool = False
    ) -> int:
        return 0

    def dpapi_protect(self, data: bytes, description: str = "MCPApp Secret") -> bytes:
        raise NotImplementedError("Windows DPAPI is not available on POSIX")

    def dpapi_unprotect(self, blob: bytes) -> bytes:
        raise NotImplementedError("Windows DPAPI is not available on POSIX")

    def credman_write(self, target: str, secret: bytes, username: str = "MCPApp") -> bool:
        return False

    def credman_read(self, target: str) -> bytes | None:
        return None

    def credman_delete(self, target: str) -> bool:
        return False

    def restrict_path_acl(self, path: Path, is_dir: bool = False) -> bool:
        try:
            os.chmod(path, 0o700 if is_dir else 0o600)
            return True
        except OSError:
            return False

    def default_oem_encoding(self) -> str:
        return "utf-8"

    def default_ansi_encoding(self) -> str:
        return "utf-8"

    def capabilities(self) -> dict[str, bool]:
        return {
            "job_objects": False,
            "dpapi": False,
            "credman": False,
            "acl_icacls": False,
            "posix_perms": True,
        }
