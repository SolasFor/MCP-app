"""Windows platform adapter: Job Objects, verified process trees, DPAPI, CredMan, ACLs."""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import psutil

from app.platform.base import (
    PlatformAdapter,
    ProcessIdentity,
    ProcessJobHandle,
    TerminationReport,
)

_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_CRED_MAX_BLOB_BYTES = 2560
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
_CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
_CREATE_BREAKAWAY_FROM_JOB = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class _CredentialW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class WindowsPlatformAdapter(PlatformAdapter):
    """Windows 10/11 implementation using Win32 APIs and psutil."""

    def create_job(
        self, name: str = "", kill_on_close: bool = True, allow_breakaway: bool = False
    ) -> ProcessJobHandle | None:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, name or None)
        if not handle:
            return None
        flags = 0
        if kill_on_close:
            flags |= _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if allow_breakaway:
            flags |= _JOB_OBJECT_LIMIT_BREAKAWAY_OK
        if flags:
            info = _JobObjectExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = flags
            ok = kernel32.SetInformationJobObject(
                wintypes.HANDLE(handle),
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok:
                kernel32.CloseHandle(wintypes.HANDLE(handle))
                return None
        return ProcessJobHandle(handle=int(handle), name=name or "job", kill_on_close=kill_on_close)

    def assign_process_to_job(
        self, job: ProcessJobHandle, pid: int, process_handle: int | None = None
    ) -> bool:
        if not job.active or not job.handle or pid <= 0:
            return False
        kernel32 = ctypes.windll.kernel32
        opened = None
        target_handle = process_handle
        if target_handle is None:
            kernel32.OpenProcess.restype = wintypes.HANDLE
            opened = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, int(pid))
            if not opened:
                return False
            target_handle = int(opened)
        try:
            ok = bool(
                kernel32.AssignProcessToJobObject(
                    wintypes.HANDLE(job.handle), wintypes.HANDLE(target_handle)
                )
            )
            if ok and pid not in job.tracked_pids:
                job.tracked_pids.append(pid)
            return ok
        finally:
            if opened:
                kernel32.CloseHandle(wintypes.HANDLE(opened))

    def terminate_job(self, job: ProcessJobHandle, exit_code: int = 1) -> bool:
        if not job.active or not job.handle:
            return False
        kernel32 = ctypes.windll.kernel32
        ok = bool(kernel32.TerminateJobObject(wintypes.HANDLE(job.handle), wintypes.UINT(exit_code)))
        return ok

    def close_job(self, job: ProcessJobHandle) -> None:
        if not job.active or not job.handle:
            return
        ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(job.handle))
        job.active = False
        job.handle = None

    def capture_process_identity(self, pid: int) -> ProcessIdentity | None:
        if pid <= 0:
            return None
        try:
            proc = psutil.Process(pid)
            create_time = float(proc.create_time())
            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = ""
            return ProcessIdentity(
                pid=pid,
                create_time=create_time,
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
            if abs(float(proc.create_time()) - identity.create_time) > tolerance_s:
                return False
            if identity.executable:
                try:
                    current_exe = proc.exe() or ""
                    if current_exe and os.path.normcase(current_exe) != os.path.normcase(
                        identity.executable
                    ):
                        return False
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    pass
            return True
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

        # Verify descendants were not spawned before the captured parent.
        verified_victims: list[psutil.Process] = []
        skipped: list[int] = []
        for proc in victims:
            try:
                if proc.create_time() + 1.0 < identity.create_time:
                    skipped.append(proc.pid)
                    continue
                verified_victims.append(proc)
            except psutil.Error:
                continue

        stopped: list[int] = []
        failed: list[int] = []

        if grace_seconds > 0 and verified_victims:
            for proc in verified_victims:
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    stopped.append(proc.pid)
                except psutil.Error:
                    pass
            gone, alive = psutil.wait_procs(verified_victims, timeout=max(0.0, grace_seconds))
            stopped.extend(p.pid for p in gone if p.pid not in stopped)
        else:
            alive = list(verified_victims)

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
            skipped_foreign_pids=sorted(set(skipped)),
            method="psutil_tree",
        )

    def subprocess_creation_flags(
        self, detached: bool = False, hide_console: bool = True, breakaway_from_job: bool = False
    ) -> int:
        flags = 0
        if detached:
            flags |= _CREATE_NEW_PROCESS_GROUP
        elif hide_console:
            flags |= _CREATE_NO_WINDOW
        if breakaway_from_job:
            flags |= _CREATE_BREAKAWAY_FROM_JOB
        return flags

    def dpapi_protect(self, data: bytes, description: str = "MCPApp Secret") -> bytes:
        buf = ctypes.create_string_buffer(data)
        source = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
        output = _DataBlob()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source),
            description,
            None,
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output.pbData)

    def dpapi_unprotect(self, blob: bytes) -> bytes:
        buf = ctypes.create_string_buffer(blob)
        source = _DataBlob(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
        output = _DataBlob()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source),
            None,
            None,
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output),
        )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output.pbData)

    def credman_write(self, target: str, secret: bytes, username: str = "MCPApp") -> bool:
        if not target or len(secret) > _CRED_MAX_BLOB_BYTES:
            return False
        advapi32 = ctypes.windll.advapi32
        buf = ctypes.create_string_buffer(secret)
        cred = _CredentialW()
        cred.Flags = 0
        cred.Type = _CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.Comment = "MCP app secret"
        cred.CredentialBlobSize = len(secret)
        cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.TargetAlias = None
        cred.UserName = username
        return bool(advapi32.CredWriteW(ctypes.byref(cred), 0))

    def credman_read(self, target: str) -> bytes | None:
        if not target:
            return None
        advapi32 = ctypes.windll.advapi32
        p_cred = ctypes.POINTER(_CredentialW)()
        ok = advapi32.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(p_cred))
        if not ok or not p_cred:
            return None
        try:
            cred = p_cred.contents
            if not cred.CredentialBlobSize or not cred.CredentialBlob:
                return b""
            return ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        finally:
            advapi32.CredFree(p_cred)

    def credman_delete(self, target: str) -> bool:
        if not target:
            return False
        return bool(ctypes.windll.advapi32.CredDeleteW(target, _CRED_TYPE_GENERIC, 0))

    def restrict_path_acl(self, path: Path, is_dir: bool = False) -> bool:
        user = os.environ.get("USERNAME")
        if not user:
            return False
        grant = f"{user}:(OI)(CI)(F)" if is_dir else f"{user}:(F)"
        try:
            res = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
                capture_output=True,
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
                check=False,
            )
            return res.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def default_oem_encoding(self) -> str:
        try:
            cp = int(ctypes.windll.kernel32.GetOEMCP())
            if cp > 0:
                return f"cp{cp}"
        except (AttributeError, OSError):
            pass
        return "cp866"

    def default_ansi_encoding(self) -> str:
        try:
            cp = int(ctypes.windll.kernel32.GetACP())
            if cp > 0:
                return f"cp{cp}"
        except (AttributeError, OSError):
            pass
        return "cp1251"

    def capabilities(self) -> dict[str, bool]:
        return {
            "job_objects": True,
            "dpapi": True,
            "credman": True,
            "acl_icacls": True,
            "posix_perms": False,
        }
