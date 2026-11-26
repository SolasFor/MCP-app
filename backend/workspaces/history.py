"""Bounded local workspace edit history & rollback snapshots (per-workspace ACLs)."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from app.platform import get_platform
from backend.workspaces.models import MAX_HISTORY_SNAPSHOTS, validate_workspace_id
from backend.workspaces.path_security import sha256_bytes

MAX_WORKSPACE_HISTORY_BYTES = 10 * 1024 * 1024


class WorkspaceHistory:
    """Stores pre-edit file snapshots so owner or client can inspect and revert workspace changes."""

    def __init__(self, history_dir: Path) -> None:
        self.history_dir = Path(history_dir)
        self._lock = threading.RLock()
        self._platform = get_platform()
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._platform.restrict_path_acl(self.history_dir, is_dir=True)

    def _ws_dir(self, workspace_id: str) -> Path:
        clean = validate_workspace_id(workspace_id)
        d = self.history_dir / clean
        d.mkdir(parents=True, exist_ok=True)
        self._platform.restrict_path_acl(d, is_dir=True)
        return d

    def _read_index(self, ws_dir: Path) -> list[dict[str, Any]]:
        idx_path = ws_dir / "index.json"
        if not idx_path.is_file():
            return []
        try:
            data = json.loads(idx_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _write_index(self, ws_dir: Path, entries: list[dict[str, Any]]) -> None:
        idx_path = ws_dir / "index.json"
        tmp = ws_dir / "index.json.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, idx_path)
        self._platform.restrict_path_acl(idx_path, is_dir=False)

    def record_snapshot(
        self,
        *,
        workspace_id: str,
        relative_path: str,
        operation: str,
        before_bytes: bytes | None,
        after_sha256: str,
        client_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            ws_dir = self._ws_dir(workspace_id)
            entries = self._read_index(ws_dir)
            snap_id = secrets.token_hex(8)
            before_sha = ""
            blob_name = ""
            before_size = 0
            if before_bytes is not None:
                before_sha = sha256_bytes(before_bytes)
                before_size = len(before_bytes)
                blob_name = f"{snap_id}.blob"
                blob_path = ws_dir / blob_name
                fd = os.open(blob_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(before_bytes)
                self._platform.restrict_path_acl(blob_path, is_dir=False)

            entry: dict[str, Any] = {
                "snapshot_id": snap_id,
                "ts": time.time(),
                "path": relative_path,
                "operation": operation,
                "client_id": client_id,
                "existed_before": before_bytes is not None,
                "before_sha256": before_sha,
                "after_sha256": after_sha256,
                "before_bytes": before_size,
                "blob": blob_name,
            }
            entries.insert(0, entry)
            self._enforce_quotas(ws_dir, entries)
            self._write_index(ws_dir, entries)
            return {k: v for k, v in entry.items() if k != "blob"}

    @staticmethod
    def _enforce_quotas(ws_dir: Path, entries: list[dict[str, Any]]) -> None:
        # Keep at most MAX_HISTORY_SNAPSHOTS per path and MAX_WORKSPACE_HISTORY_BYTES total
        per_file_counts: dict[str, int] = {}
        kept: list[dict[str, Any]] = []
        total_bytes = 0
        for item in entries:
            p = str(item.get("path") or "")
            count = per_file_counts.get(p, 0) + 1
            size = int(item.get("before_bytes") or 0)
            if count <= MAX_HISTORY_SNAPSHOTS and (total_bytes + size) <= MAX_WORKSPACE_HISTORY_BYTES:
                per_file_counts[p] = count
                total_bytes += size
                kept.append(item)
            else:
                blob = str(item.get("blob") or "")
                if blob:
                    (ws_dir / blob).unlink(missing_ok=True)
        entries[:] = kept

    def list_snapshots(
        self,
        workspace_id: str,
        *,
        relative_path: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        with self._lock:
            ws_dir = self._ws_dir(workspace_id)
            entries = self._read_index(ws_dir)
            out: list[dict[str, Any]] = []
            for item in entries:
                if relative_path and item.get("path") != relative_path:
                    continue
                out.append({k: v for k, v in item.items() if k != "blob"})
                if len(out) >= max(1, min(int(limit), 100)):
                    break
            return out

    def load_snapshot(self, workspace_id: str, snapshot_id: str) -> tuple[dict[str, Any], bytes | None]:
        with self._lock:
            ws_dir = self._ws_dir(workspace_id)
            entries = self._read_index(ws_dir)
            for item in entries:
                if item.get("snapshot_id") == snapshot_id:
                    if not item.get("existed_before"):
                        return {k: v for k, v in item.items() if k != "blob"}, None
                    blob = str(item.get("blob") or "")
                    blob_path = ws_dir / blob
                    if not blob or not blob_path.is_file():
                        raise FileNotFoundError(f"Snapshot payload missing for {snapshot_id!r}")
                    return {k: v for k, v in item.items() if k != "blob"}, blob_path.read_bytes()
            raise KeyError(f"Unknown snapshot_id: {snapshot_id!r}")
