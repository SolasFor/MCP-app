"""Privacy-safe, durable audit trail for OAuth Windows/SSH command execution.

A separate rotating JSONL file records who requested an action, when, which
profile applied, and its outcome. Command text, arguments, stdout/stderr,
OAuth tokens, SSH usernames, and hostnames are NEVER written to this file.
The SHA-256 fingerprints facilitate correlation without logging plaintext.
"""
from __future__ import annotations

import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
from datetime import datetime, timezone

_ALLOWED_KINDS = frozenset(("windows", "ssh"))
_ALLOWED_EVENTS = frozenset(("denied", "started", "completed", "failed"))
_ALLOWED_PROFILES = frozenset(("safe", "allowlist", "full"))
_EXIT_CODE = re.compile(r"^Exit code: (-?\d+)", re.ASCII)
_MAX_LOG_BYTES = 2 * 1024 * 1024


def classify_command_output(output: str) -> tuple[str, int | None]:
    """Extract status without ever including tool output in an audit record."""
    match = _EXIT_CODE.match(output)
    if match:
        code = int(match.group(1))
        return ("completed" if code == 0 else "failed", code)
    return "failed", None


class ExecutionAudit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("MCPApp.ExecutionAudit." + hashlib.sha256(
            str(self.path.resolve()).encode("utf-8")
        ).hexdigest())
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                self.path, maxBytes=_MAX_LOG_BYTES, backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def record(
        self, *, client_id: str, kind: str, profile: str,
        event: str, command: str, host: str = "", port: int | None = None,
        exit_code: int | None = None, duration_ms: int | None = None,
        action_id: str | None = None,
    ) -> None:
        if kind not in _ALLOWED_KINDS or event not in _ALLOWED_EVENTS:
            raise ValueError("Unsupported execution audit event")
        if profile not in _ALLOWED_PROFILES:
            raise ValueError("Unsupported execution profile")
        # Audit must not contain anything taken directly from the command line.
        payload = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "client_id": str(client_id)[:128],
            "kind": kind,
            "profile": profile,
            "event": event,
            "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
        }
        if action_id is not None:
            if not re.fullmatch(r"[0-9a-f]{16}", action_id):
                raise ValueError("Invalid execution action id")
            payload["action_id"] = action_id
        if host:
            payload["host_sha256"] = hashlib.sha256(host.encode("utf-8")).hexdigest()
        if port is not None:
            payload["port"] = int(port)
        if exit_code is not None:
            payload["exit_code"] = int(exit_code)
        if duration_ms is not None:
            payload["duration_ms"] = max(0, int(duration_ms))
        self._logger.info(json.dumps(payload, ensure_ascii=True, sort_keys=True))
