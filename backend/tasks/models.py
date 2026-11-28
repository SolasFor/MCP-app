"""Data models and MCP protocol compatibility helpers for durable background tasks."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from app.core.redaction import SecretRedactor

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_INTERRUPTED = "interrupted"

ALL_STATUSES = frozenset({
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
})
TERMINAL_STATUSES = frozenset({
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
})

_MCP_TASK_STATUS_MAP = {
    STATUS_QUEUED: "working",
    STATUS_RUNNING: "working",
    STATUS_SUCCEEDED: "completed",
    STATUS_FAILED: "failed",
    STATUS_CANCELLED: "cancelled",
    STATUS_INTERRUPTED: "failed",
}


def _iso_utc(ts: float | None) -> str:
    val = time.time() if ts is None else ts
    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()


def summarize_spec_title(kind: str, command: str, host: str = "", redactor: SecretRedactor | None = None) -> str:
    """Create a short redacted human label without persisting sensitive arguments in metadata."""
    head = (command or "").strip().splitlines()[0] if (command or "").strip() else ""
    tokens = head.split()
    summary = tokens[0] if tokens else kind
    if len(tokens) > 1 and not tokens[1].startswith("-") and len(tokens[1]) <= 32:
        summary = f"{summary} {tokens[1]}"
    if len(summary) > 48:
        summary = summary[:47] + "…"
    prefix = f"ssh({host}): " if kind == "ssh" and host else f"{kind}: "
    raw = prefix + summary
    return redactor.redact_text(raw) if redactor is not None else raw


@dataclass(frozen=True)
class TaskSpec:
    kind: Literal["windows", "ssh"]
    command: str
    shell: Literal["cmd", "powershell"] = "cmd"
    timeout: int = 60
    host: str = ""
    user: str = ""
    port: int = 22
    workspace_id: str = ""
    workspace_command: str = ""
    effective_host: str = ""
    effective_user: str = ""
    effective_port: int = 0
    effective_key_path: str = ""
    via_ssh_config: bool = False
    config_alias: str = ""
    effective_host_key_sha256: str = ""
    effective_known_hosts_path: str = ""

    def _validate_ssh(self) -> None:
        if not (self.host or "").strip():
            raise ValueError("SSH task requires target host.")
        if not (1 <= int(self.port) <= 65535):
            raise ValueError("SSH port must be within 1..65535.")
        if self.effective_port and not (1 <= int(self.effective_port) <= 65535):
            raise ValueError("Effective SSH port must be within 1..65535.")

    def validate(self) -> None:
        if self.kind not in ("windows", "ssh"):
            raise ValueError(f"Unsupported task kind: {self.kind!r}")
        if not (self.command or "").strip():
            raise ValueError("Task command is required.")
        if len(self.command) > 32000:
            raise ValueError("Task command exceeds 32000 characters.")
        if self.shell not in ("cmd", "powershell"):
            raise ValueError(f"Unsupported shell: {self.shell!r}")
        if not (1 <= int(self.timeout) <= 3600):
            raise ValueError("Task timeout must be between 1 and 3600 seconds.")
        if self.kind == "ssh":
            self._validate_ssh()

    def _populate_ssh_payload(self, payload: dict[str, Any]) -> None:
        if self.kind != "ssh" or not self.effective_host:
            return
        payload["effective_host"] = self.effective_host
        payload["effective_user"] = self.effective_user
        payload["effective_port"] = int(self.effective_port or self.port)
        optional_fields = (
            ("effective_key_path", self.effective_key_path),
            ("effective_host_key_sha256", self.effective_host_key_sha256),
            ("effective_known_hosts_path", self.effective_known_hosts_path),
        )
        for key, value in optional_fields:
            if value:
                payload[key] = value
        if self.via_ssh_config:
            payload["via_ssh_config"] = True
            if self.config_alias:
                payload["config_alias"] = self.config_alias

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "command": self.command,
            "shell": self.shell,
            "timeout": int(self.timeout),
            "host": self.host,
            "user": self.user,
            "port": int(self.port),
        }
        if self.workspace_id:
            payload["workspace_id"] = self.workspace_id
        if self.workspace_command:
            payload["workspace_command"] = self.workspace_command
        self._populate_ssh_payload(payload)
        return json.dumps(payload, ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> "TaskSpec":
        data = json.loads(raw)
        kind_val: Literal["windows", "ssh"] = "ssh" if data.get("kind") == "ssh" else "windows"
        shell_val: Literal["cmd", "powershell"] = (
            "powershell" if data.get("shell") == "powershell" else "cmd"
        )
        return cls(
            kind=kind_val,
            command=str(data.get("command") or ""),
            shell=shell_val,
            timeout=int(data.get("timeout", 60)),
            host=str(data.get("host") or ""),
            user=str(data.get("user") or ""),
            port=int(data.get("port", 22)),
            workspace_id=str(data.get("workspace_id") or ""),
            workspace_command=str(data.get("workspace_command") or ""),
            effective_host=str(data.get("effective_host") or ""),
            effective_user=str(data.get("effective_user") or ""),
            effective_port=int(data.get("effective_port", 0)),
            effective_key_path=str(data.get("effective_key_path") or ""),
            via_ssh_config=bool(data.get("via_ssh_config", False)),
            config_alias=str(data.get("config_alias") or ""),
            effective_host_key_sha256=str(data.get("effective_host_key_sha256") or ""),
            effective_known_hosts_path=str(data.get("effective_known_hosts_path") or ""),
        )


@dataclass
class TaskRecord:
    task_id: str
    owner_client_id: str
    profile: str
    kind: str
    title: str
    status: str
    priority: int
    idempotency_key: str
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    timeout_seconds: int = 60
    exit_code: int | None = None
    error: str = ""
    progress_percent: int | None = None  # Reported only when actually known, never fabricated
    spool_run_id: str | None = None
    artifact_refs: list[dict[str, Any]] = field(default_factory=list)
    parent_task_id: str | None = None
    cancel_requested: bool = False

    def elapsed_seconds(self, now: float | None = None) -> float:
        cur = time.time() if now is None else now
        ref_start = self.started_at or self.created_at
        end = self.finished_at if self.finished_at is not None else cur
        if self.status == STATUS_QUEUED:
            return max(0.0, cur - self.created_at)
        return max(0.0, end - ref_start)

    def to_public_dict(self, redactor: SecretRedactor | None = None) -> dict[str, Any]:
        clean_title = redactor.redact_text(self.title) if redactor else self.title
        clean_error = redactor.redact_text(self.error) if redactor and self.error else self.error
        return {
            "task_id": self.task_id,
            "owner_client_id": self.owner_client_id,
            "profile": self.profile,
            "kind": self.kind,
            "title": clean_title,
            "status": self.status,
            "priority": self.priority,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.elapsed_seconds(), 2),
            "timeout_seconds": self.timeout_seconds,
            "exit_code": self.exit_code,
            "error": clean_error,
            "progress_percent": self.progress_percent,
            "spool_run_id": self.spool_run_id,
            "artifact_refs": list(self.artifact_refs),
            "parent_task_id": self.parent_task_id,
            "cancel_requested": self.cancel_requested,
        }

    def to_mcp_task_dict(self, redactor: SecretRedactor | None = None) -> dict[str, Any]:
        """Map TaskRecord to MCP SDK `mcp.types.Task` compatible JSON shape."""
        clean_err = redactor.redact_text(self.error) if redactor and self.error else self.error
        return {
            "taskId": self.task_id,
            "status": _MCP_TASK_STATUS_MAP.get(self.status, "failed"),
            "ttl": None,
            "createdAt": _iso_utc(self.created_at),
            "lastUpdatedAt": _iso_utc(self.finished_at or self.started_at or self.created_at),
            "pollInterval": 1000 if self.status in (STATUS_QUEUED, STATUS_RUNNING) else None,
            "statusMessage": clean_err or self.status,
        }
