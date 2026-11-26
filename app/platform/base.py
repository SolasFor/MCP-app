"""Platform-independent interfaces for process trees, secrets, ACLs, and encodings."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProcessIdentity:
    """Verified OS process identity to prevent PID-reuse mistakes."""

    pid: int
    create_time: float
    executable: str = ""
    captured_at: float = 0.0


@dataclass
class ProcessJobHandle:
    """OS job or process-group handle managing a controlled process tree."""

    handle: Any
    name: str
    kill_on_close: bool
    active: bool = True
    tracked_pids: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class TerminationReport:
    """Structured outcome of an attempted process-tree termination."""

    stopped_pids: list[int]
    failed_pids: list[int]
    skipped_foreign_pids: list[int]
    method: str


class PlatformAdapter(ABC):
    """Abstract OS adapter isolating Windows-specific APIs from core logic."""

    @abstractmethod
    def create_job(
        self, name: str = "", kill_on_close: bool = True, allow_breakaway: bool = False
    ) -> ProcessJobHandle | None:
        """Create an OS job/group container for controlled child processes."""

    @abstractmethod
    def assign_process_to_job(
        self, job: ProcessJobHandle, pid: int, process_handle: int | None = None
    ) -> bool:
        """Assign an active process to the given job container."""

    @abstractmethod
    def terminate_job(self, job: ProcessJobHandle, exit_code: int = 1) -> bool:
        """Terminate all processes inside the job container."""

    @abstractmethod
    def close_job(self, job: ProcessJobHandle) -> None:
        """Release the OS handle for a job container."""

    @abstractmethod
    def capture_process_identity(self, pid: int) -> ProcessIdentity | None:
        """Capture PID + creation timestamp for ownership verification."""

    @abstractmethod
    def verify_process_identity(self, identity: ProcessIdentity, tolerance_s: float = 0.5) -> bool:
        """Verify that `identity.pid` still refers to the same process instance."""

    @abstractmethod
    def terminate_process_tree(
        self, identity: ProcessIdentity, grace_seconds: float = 2.0, include_parent: bool = True
    ) -> TerminationReport:
        """Verify ownership and terminate the process tree without touching foreign PIDs."""

    @abstractmethod
    def subprocess_creation_flags(
        self, detached: bool = False, hide_console: bool = True, breakaway_from_job: bool = False
    ) -> int:
        """Return OS-specific subprocess creation flags."""

    @abstractmethod
    def dpapi_protect(self, data: bytes, description: str = "MCPApp Secret") -> bytes:
        """Protect bytes using the current OS user keystore/DPAPI."""

    @abstractmethod
    def dpapi_unprotect(self, blob: bytes) -> bytes:
        """Unprotect bytes previously wrapped by `dpapi_protect`."""

    @abstractmethod
    def credman_write(self, target: str, secret: bytes, username: str = "MCPApp") -> bool:
        """Write a secret to the OS credential manager."""

    @abstractmethod
    def credman_read(self, target: str) -> bytes | None:
        """Read a secret from the OS credential manager."""

    @abstractmethod
    def credman_delete(self, target: str) -> bool:
        """Delete a secret from the OS credential manager."""

    @abstractmethod
    def restrict_path_acl(self, path: Path, is_dir: bool = False) -> bool:
        """Restrict filesystem access to the current user only."""

    @abstractmethod
    def default_oem_encoding(self) -> str:
        """Return default console OEM encoding for decoding child output."""

    @abstractmethod
    def default_ansi_encoding(self) -> str:
        """Return default system ANSI encoding for decoding child output."""

    @abstractmethod
    def capabilities(self) -> dict[str, bool]:
        """Report supported platform security/process capabilities."""
