"""Persistent WorkspaceStore: auto-detection, DPAPI SecretStore refs, redacted import/export."""
from __future__ import annotations

import json
import os
import shutil
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dataclasses import replace
from app.core.atomic_io import atomic_write_json, cross_process_lock
from app.core.secret_store import SecretStore
from app.platform import get_platform
from backend.workspaces.models import (
    ENV_KEY_RE,
    MAX_CONFIG_BYTES,
    MAX_WORKSPACES,
    SCHEMA_VERSION,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.path_security import canonical_workspace_root

SECRETS_NAMESPACE = "workspaces"


def detect_workspace_metadata(root_path: str | Path) -> dict[str, Any]:
    """Inspect a local directory (read-only) to suggest language, Git root, venv/Node, and commands."""
    root = canonical_workspace_root(root_path)
    language = "generic"
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file() or any(root.glob("*.py")):
        language = "python"
    elif (root / "package.json").is_file():
        language = "typescript" if (root / "tsconfig.json").is_file() else "javascript"
    elif (root / "Cargo.toml").is_file():
        language = "rust"
    elif (root / "go.mod").is_file():
        language = "go"

    git_root = ""
    cur: Path | None = root
    while cur is not None:
        if (cur / ".git").exists():
            git_root = str(cur)
            break
        if cur.parent == cur:
            break
        cur = cur.parent

    python_venv = ""
    for venv_name in (".venv", "venv", ".venv-build"):
        candidate = root / venv_name
        if candidate.is_dir():
            py_bin = candidate / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if py_bin.is_file():
                python_venv = str(candidate)
                break

    node_path = shutil.which("node") or ""

    commands: dict[str, str] = {}
    if language == "python":
        py_cmd = "python"
        if (root / "tests").is_dir():
            commands["test"] = f"{py_cmd} -m unittest discover -s tests -p \"test_*.py\" -v"
        elif (root / "pyproject.toml").is_file():
            commands["test"] = f"{py_cmd} -m pytest"
    elif language in ("javascript", "typescript") and (root / "package.json").is_file():
        commands["test"] = "node --test"

    return {
        "root_path": str(root),
        "name": root.name or "workspace",
        "language": language,
        "git_root": git_root,
        "python_venv": python_venv,
        "node_path": node_path,
        "commands": commands,
    }


class WorkspaceStore:
    """Thread-safe JSON persistence + DPAPI SecretStore refs for WorkspaceProfile items."""

    def __init__(self, path: Path, secret_store: SecretStore | None = None) -> None:
        self.path = Path(path)
        self.secret_store = secret_store or SecretStore(self.path.parent / "secrets")
        self._lock = threading.RLock()
        self._platform = get_platform()

    def lock(self, timeout: float = 10.0):
        """Return a thread-reentrant cross-process lock covering this workspace store."""
        return cross_process_lock(self.path.with_name(".workspaces.lock"), timeout=timeout)

    def _read_raw_document(self) -> tuple[int, dict[str, Any]]:
        if not self.path.exists():
            return SCHEMA_VERSION, {}
        with self.path.open(encoding="utf-8-sig") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("Workspace configuration exceeds size limit")
        if not raw.strip():
            return SCHEMA_VERSION, {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid workspace configuration format")
        if "workspaces" in parsed:
            ws_map = parsed.get("workspaces")
            version = int(parsed.get("schema_version") or 1)
        else:
            ws_map = parsed
            version = 1
        if not isinstance(ws_map, dict) or len(ws_map) > MAX_WORKSPACES:
            raise ValueError("Invalid workspaces dictionary")
        return version, ws_map

    def _read_raw(self) -> dict[str, Any]:
        _, ws_map = self._read_raw_document()
        return ws_map

    def detect_schema_version(self) -> int:
        with self._lock:
            version, _ = self._read_raw_document()
            return version

    def load_workspaces(self) -> dict[str, WorkspaceProfile]:
        with self._lock:
            raw_map = self._read_raw()
            out: dict[str, WorkspaceProfile] = {}
            for wid, entry in raw_map.items():
                if not isinstance(wid, str) or not isinstance(entry, dict):
                    raise ValueError("Invalid workspace profile entry")
                out[wid] = WorkspaceProfile.from_dict(wid, entry)
            return out

    def get_workspace(self, workspace_id: str) -> WorkspaceProfile | None:
        clean = validate_workspace_id(workspace_id)
        return self.load_workspaces().get(clean)

    def save_workspaces(self, profiles: Mapping[str, WorkspaceProfile]) -> None:
        with self._lock, self.lock():
            if len(profiles) > MAX_WORKSPACES:
                raise ValueError(f"Workspace count exceeds limit ({MAX_WORKSPACES})")
            for wid, prof in profiles.items():
                if prof.workspace_id != wid:
                    raise ValueError("Workspace key mismatch")
                prof.validate()

            payload = {
                "schema_version": SCHEMA_VERSION,
                "workspaces": {
                    wid: profiles[wid].to_dict()
                    for wid in sorted(profiles)
                },
            }
            atomic_write_json(self.path, payload, indent=2, restrict_acl=True)

    def upsert_workspace(self, profile: WorkspaceProfile) -> None:
        profile.validate()
        canonical_workspace_root(profile.root_path)
        with self._lock, self.lock():
            profiles = self.load_workspaces()
            profiles[profile.workspace_id] = profile
            self.save_workspaces(profiles)

    def delete_workspace(self, workspace_id: str, *, delete_secrets: bool = True) -> bool:
        clean = validate_workspace_id(workspace_id)
        with self._lock, self.lock():
            profiles = self.load_workspaces()
            removed = profiles.pop(clean, None)
            if removed is None:
                return False
            self.save_workspaces(profiles)
            if delete_secrets:
                for ref in removed.env_secret_refs.values():
                    try:
                        ns, key = self.secret_store.parse_ref(ref)
                        if ns == SECRETS_NAMESPACE:
                            self.secret_store.delete_secret(ns, key)
                    except Exception:  # noqa: BLE001
                        pass
            return True

    def append_linked_task(
        self,
        workspace_id: str,
        task_id: str,
        *,
        max_items: int = 50,
    ) -> WorkspaceProfile | None:
        """Append a recorded TaskManager task_id to a workspace's linked_tasks cleanly."""
        clean_wid = validate_workspace_id(workspace_id)
        clean_tid = (task_id or "").strip()
        if not clean_tid:
            return None
        with self._lock, self.lock():
            profiles = self.load_workspaces()
            prof = profiles.get(clean_wid)
            if prof is None:
                return None
            existing = [t for t in prof.linked_tasks if t != clean_tid]
            existing.append(clean_tid)
            updated = replace(prof, linked_tasks=tuple(existing[-max(1, int(max_items)):]))
            profiles[clean_wid] = updated
            self.save_workspaces(profiles)
            return updated

    def set_env_secret(self, workspace_id: str, env_key: str, value: str) -> str:
        clean = validate_workspace_id(workspace_id)
        if not ENV_KEY_RE.fullmatch(env_key):
            raise ValueError(f"Invalid secret env key: {env_key!r}")
        key = f"{clean}__{env_key}"
        self.secret_store.set_secret(SECRETS_NAMESPACE, key, value)
        return self.secret_store.secret_ref(SECRETS_NAMESPACE, key)

    def resolve_workspace_env(self, profile: WorkspaceProfile) -> tuple[dict[str, str], list[str]]:
        merged = dict(profile.env)
        secret_values: list[str] = []
        for k, ref in profile.env_secret_refs.items():
            val = self.secret_store.resolve_ref(ref)
            if val is None:
                raise ValueError(f"Missing secret for workspace {profile.workspace_id!r} key {k!r}")
            merged[k] = val
            if val:
                secret_values.append(val)
        return merged, secret_values

    def collect_secret_values(self) -> list[str]:
        values: list[str] = []
        with self._lock:
            try:
                profiles = self.load_workspaces()
            except Exception:  # noqa: BLE001
                return values
            for prof in profiles.values():
                for ref in prof.env_secret_refs.values():
                    try:
                        val = self.secret_store.resolve_ref(ref)
                        if val:
                            values.append(val)
                    except Exception:  # noqa: BLE001
                        pass
        return values

    def export_redacted(self) -> dict[str, Any]:
        """Export all workspace profiles without plaintext secrets (refs retained as metadata)."""
        profiles = self.load_workspaces()
        return {
            "schema_version": SCHEMA_VERSION,
            "workspaces": {
                wid: profiles[wid].to_dict()
                for wid in sorted(profiles)
            },
        }

    def import_redacted(self, payload: dict[str, Any], *, overwrite: bool = False) -> dict[str, Any]:
        """Import workspace profiles from redacted export without importing plaintext secrets."""
        if not isinstance(payload, dict) or not isinstance(payload.get("workspaces"), dict):
            raise ValueError("Invalid workspace export payload")
        with self._lock, self.lock():
            existing = self.load_workspaces()
            imported: list[str] = []
            skipped: list[str] = []
            for wid, entry in payload["workspaces"].items():
                if not isinstance(wid, str) or not isinstance(entry, dict):
                    continue
                prof = WorkspaceProfile.from_dict(wid, entry)
                if wid in existing and not overwrite:
                    skipped.append(wid)
                    continue
                existing[wid] = prof
                imported.append(wid)
            self.save_workspaces(existing)
            return {"imported": sorted(imported), "skipped": sorted(skipped), "total": len(existing)}
