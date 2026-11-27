"""Guarded Workspace & Git manager enforcing per-client permissions, canonical paths, history, and redaction."""
from __future__ import annotations

import asyncio
import difflib
import os
import re
import shlex
import shutil
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.atomic_io import atomic_write_json, try_init_private_dir
from app.core.redaction import SecretRedactor
from backend.output_stream import decode_process_bytes
from backend.process_runner import ProcessRunner
from backend.workspaces import git_ops
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.models import (
    MAX_READ_BYTES,
    MAX_SEARCH_MATCHES,
    MAX_TREE_ENTRIES,
    MAX_WRITE_BYTES,
    WorkspaceProfile,
    validate_workspace_id,
)
from backend.workspaces.path_security import (
    FileVersionConflictError,
    GitIgnoreMatcher,
    PathSecurityError,
    atomic_write_verified,
    canonical_workspace_root,
    is_reparse_or_link,
    read_verified_bytes,
    resolve_workspace_path,
)
from backend.workspaces.store import WorkspaceStore

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _apply_unified_diff(original: str, diff_text: str) -> str:
    orig_lines = original.splitlines(keepends=True)
    diff_lines = diff_text.splitlines(keepends=True)
    idx = 0
    while idx < len(diff_lines) and (
        diff_lines[idx].startswith("--- ") or diff_lines[idx].startswith("+++ ")
    ):
        idx += 1
    out: list[str] = []
    orig_pos = 0
    found_hunk = False
    while idx < len(diff_lines):
        m = _HUNK_HEADER_RE.match(diff_lines[idx])
        if not m:
            idx += 1
            continue
        found_hunk = True
        start_old = max(0, int(m.group(1)) - 1)
        if start_old < orig_pos or start_old > len(orig_lines):
            raise ValueError("Patch hunk offset out of bounds")
        out.extend(orig_lines[orig_pos:start_old])
        orig_pos = start_old
        idx += 1
        while idx < len(diff_lines) and not diff_lines[idx].startswith("@@ "):
            line = diff_lines[idx]
            if line.startswith("\\"):
                idx += 1
                continue
            tag = line[:1]
            body = line[1:]
            if tag == " ":
                if orig_pos >= len(orig_lines) or orig_lines[orig_pos].rstrip("\r\n") != body.rstrip("\r\n"):
                    raise ValueError("Patch context line mismatch")
                out.append(orig_lines[orig_pos])
                orig_pos += 1
            elif tag == "-":
                if orig_pos >= len(orig_lines) or orig_lines[orig_pos].rstrip("\r\n") != body.rstrip("\r\n"):
                    raise ValueError("Patch deletion line mismatch")
                orig_pos += 1
            elif tag == "+":
                out.append(body)
            else:
                raise ValueError(f"Unsupported diff line prefix: {tag!r}")
            idx += 1
    if not found_hunk:
        raise ValueError("Unified diff contains no valid @@ hunk headers")
    out.extend(orig_lines[orig_pos:])
    return "".join(out)


class WorkspaceManager:
    """Orchestrates workspace file, search, patch, history, task execution, and Git operations."""

    def __init__(
        self,
        store: WorkspaceStore,
        history: WorkspaceHistory,
        runner: ProcessRunner | None = None,
        *,
        redactor: SecretRedactor | None = None,
        task_store: Any = None,
        spool_dir: Path | None = None,
        artifacts_dir: Path | None = None,
        coordinator: Any = None,
        server_manager: Any = None,
        live_client_authorizer: Callable[[str | None, str], str] | None = None,
    ) -> None:
        self.store = store
        self.history = history
        self._owns_runner = runner is None
        task_db = getattr(task_store, "path", None) or getattr(task_store, "db_path", None) if task_store is not None else None
        default_base = Path(task_db).parent if task_db is not None else store.path.parent
        resolved_spool = (
            Path(spool_dir).expanduser().resolve()
            if spool_dir is not None
            else (default_base / "spool")
        )
        self.runner = runner or ProcessRunner(
            spool_dir=resolved_spool,
            redactor=redactor,
        )
        self.redactor = redactor or self.runner.redactor
        self.task_store = task_store
        self.artifacts_dir = (
            Path(artifacts_dir).expanduser().resolve()
            if artifacts_dir is not None
            else (default_base / "artifacts" if task_store is not None else store.path.parent / "task_artifacts")
        )
        self.coordinator = coordinator
        self.server_manager = server_manager
        self.live_client_authorizer = live_client_authorizer
        self._nohooks_dir = store.path.parent / "nohooks"
        self._active_task_ids: set[str] = set()
        self._active_tasks_lock = threading.Lock()

    @staticmethod
    def _is_owner(client_id: str | None) -> bool:
        return client_id in (None, "", "owner")

    def _authorize(
        self,
        workspace_id: str,
        *,
        client_id: str | None,
        client_profile: str,
        required: tuple[str, ...],
    ) -> WorkspaceProfile:
        clean = validate_workspace_id(workspace_id)
        prof = self.store.get_workspace(clean)
        if prof is None:
            raise KeyError(f"Unknown workspace: {clean!r}")
        if self._is_owner(client_id):
            return prof
        assert isinstance(client_id, str)
        if not prof.enabled:
            raise PermissionError(f"Workspace {clean!r} is disabled")
        if _PROFILE_RANK.get(client_profile, 0) < _PROFILE_RANK.get(prof.min_profile, 1):
            raise PermissionError(
                f"Workspace {clean!r} requires at least {prof.min_profile} access profile"
            )
        if prof.allowed_clients and client_id not in prof.allowed_clients:
            raise PermissionError(f"Client {client_id!r} is not permitted in workspace {clean!r}")
        perms = prof.permissions_for(client_id)
        if not perms.allows(required):
            raise PermissionError(
                f"Client {client_id!r} lacks workspace permissions: {', '.join(required)}"
            )
        return prof

    def _redact_payload_secrets(self, profile: WorkspaceProfile) -> dict[str, str]:
        env, secrets = self.store.resolve_workspace_env(profile)
        for s in secrets:
            self.redactor.register(s)
        return env

    def list_workspaces(
        self,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> list[dict[str, Any]]:
        profiles = self.store.load_workspaces()
        items: list[dict[str, Any]] = []
        for wid in sorted(profiles):
            prof = profiles[wid]
            if not self._is_owner(client_id):
                try:
                    self._authorize(
                        wid,
                        client_id=client_id,
                        client_profile=client_profile,
                        required=("read",),
                    )
                except PermissionError:
                    continue
            perms = prof.permissions if self._is_owner(client_id) else prof.permissions_for(str(client_id))
            items.append({
                "workspace_id": prof.workspace_id,
                "name": prof.name,
                "root_path": prof.root_path,
                "language": prof.language,
                "has_git": bool(prof.git_root),
                "has_python_venv": bool(prof.python_venv),
                "commands": sorted(prof.commands),
                "permissions": perms.to_dict(),
                "enabled": prof.enabled,
            })
        return items

    def workspace_info(
        self,
        workspace_id: str,
        *,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        perms = prof.permissions if self._is_owner(client_id) else prof.permissions_for(str(client_id))
        linked_statuses: list[dict[str, Any]] = []
        missing_servers: list[str] = []
        if self.server_manager is not None:
            try:
                visible = {
                    s["name"]: s
                    for s in self.server_manager.list_servers(
                        client_id=client_id,
                        client_profile=client_profile,
                        workspace_id=prof.workspace_id,
                    )
                }
            except Exception:  # noqa: BLE001
                visible = {}
            all_profiles = self.server_manager.store.load_profiles(strict=False)
            for sname in prof.linked_servers:
                if sname not in all_profiles:
                    missing_servers.append(sname)
                elif sname in visible:
                    linked_statuses.append(visible[sname])
        elif self.coordinator is not None:
            snap = self.coordinator.partition_servers()
            missing_servers = list(snap.missing_by_workspace.get(prof.workspace_id, ()))

        return {
            "workspace_id": prof.workspace_id,
            "name": prof.name,
            "root_path": prof.root_path,
            "language": prof.language,
            "git_root": prof.git_root,
            "python_venv": prof.python_venv,
            "node_path": prof.node_path,
            "commands": dict(prof.commands),
            "env_keys": sorted(prof.env),
            "env_secret_refs": sorted(prof.env_secret_refs.values()),
            "linked_servers": list(prof.linked_servers),
            "linked_servers_status": linked_statuses,
            "missing_linked_servers": missing_servers,
            "linked_tasks": list(prof.linked_tasks),
            "linked_extensions": list(prof.linked_extensions),
            "exclude_patterns": list(prof.exclude_patterns),
            "permissions": perms.to_dict(),
            "trust_git_hooks": prof.trust_git_hooks,
            "description": prof.description,
        }

    def workspace_tree(
        self,
        workspace_id: str,
        *,
        relative_path: str = "",
        max_depth: int = 3,
        include_ignored: bool = False,
        max_entries: int = MAX_TREE_ENTRIES,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        root = canonical_workspace_root(prof.root_path)
        start = resolve_workspace_path(
            root,
            relative_path,
            allow_missing=False,
            allow_root=True,
            exclude_patterns=prof.exclude_patterns,
        )
        if not start.is_dir():
            raise NotADirectoryError("Tree root must be a directory")
        matcher = GitIgnoreMatcher(root, prof.exclude_patterns)
        limit = max(1, min(int(max_entries), MAX_TREE_ENTRIES))
        depth_limit = max(1, min(int(max_depth), 12))

        entries: list[dict[str, Any]] = []
        truncated = False

        def walk(cur: Path, depth: int) -> None:
            nonlocal truncated
            if truncated or depth > depth_limit:
                return
            try:
                children = sorted(cur.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold()))
            except OSError:
                return
            for child in children:
                if len(entries) >= limit:
                    truncated = True
                    return
                if is_reparse_or_link(child):
                    continue
                rel_posix = child.relative_to(root).as_posix()
                is_dir = child.is_dir()
                if not include_ignored and matcher.is_ignored(rel_posix, is_dir=is_dir):
                    continue
                if include_ignored and matcher.is_ignored(rel_posix, is_dir=False) and (
                    any(seg in rel_posix.split("/") for seg in (".git", ".env"))
                ):
                    continue
                size = 0 if is_dir else child.stat().st_size
                entries.append({"path": rel_posix, "type": "dir" if is_dir else "file", "size": size})
                if is_dir and depth < depth_limit:
                    walk(child, depth + 1)

        walk(start, 1)
        return {
            "workspace_id": prof.workspace_id,
            "entries": entries,
            "truncated": truncated,
        }

    def read_file(
        self,
        workspace_id: str,
        relative_path: str,
        *,
        offset_line: int = 1,
        max_lines: int = 400,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        self._redact_payload_secrets(prof)
        root = canonical_workspace_root(prof.root_path)
        target = resolve_workspace_path(root, relative_path, exclude_patterns=prof.exclude_patterns)
        raw_bytes, sha = read_verified_bytes(root, target, max_bytes=MAX_READ_BYTES)
        text = self.redactor.redact_text(decode_process_bytes(raw_bytes))
        lines = text.splitlines()
        start_idx = max(0, int(offset_line) - 1)
        limit = max(1, min(int(max_lines), 2000))
        sliced = lines[start_idx : start_idx + limit]
        return {
            "workspace_id": prof.workspace_id,
            "path": target.relative_to(root).as_posix(),
            "sha256": sha,
            "size_bytes": len(raw_bytes),
            "total_lines": len(lines),
            "offset_line": start_idx + 1,
            "content": "\n".join(sliced),
            "has_more": (start_idx + limit) < len(lines),
        }

    def write_file(
        self,
        workspace_id: str,
        relative_path: str,
        content: str,
        *,
        expected_sha256: str = "",
        create_only: bool = False,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("write",)
        )
        root = canonical_workspace_root(prof.root_path)
        target = resolve_workspace_path(
            root, relative_path, allow_missing=True, exclude_patterns=prof.exclude_patterns
        )
        payload = content.encode("utf-8")
        new_sha, prev_bytes = atomic_write_verified(
            root,
            target,
            payload,
            max_bytes=MAX_WRITE_BYTES,
            expected_sha256=expected_sha256,
            create_only=create_only,
        )
        rel_posix = target.relative_to(root).as_posix()
        snap = self.history.record_snapshot(
            workspace_id=prof.workspace_id,
            relative_path=rel_posix,
            operation="write",
            before_bytes=prev_bytes,
            after_sha256=new_sha,
            client_id=client_id or "owner",
        )
        return {
            "workspace_id": prof.workspace_id,
            "path": rel_posix,
            "sha256": new_sha,
            "size_bytes": len(payload),
            "snapshot_id": snap["snapshot_id"],
        }

    def search_files(
        self,
        workspace_id: str,
        query: str,
        *,
        relative_path: str = "",
        regex: bool = False,
        case_sensitive: bool = False,
        max_matches: int = 100,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        self._redact_payload_secrets(prof)
        if not isinstance(query, str) or not query:
            raise ValueError("Search query is required")
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query if regex else re.escape(query), flags)
        root = canonical_workspace_root(prof.root_path)
        start = resolve_workspace_path(
            root, relative_path, allow_root=True, exclude_patterns=prof.exclude_patterns
        )
        matcher = GitIgnoreMatcher(root, prof.exclude_patterns)
        limit = max(1, min(int(max_matches), MAX_SEARCH_MATCHES))
        matches: list[dict[str, Any]] = []
        truncated = False

        def scan_file(fpath: Path) -> None:
            nonlocal truncated
            if truncated:
                return
            try:
                raw, _ = read_verified_bytes(root, fpath, max_bytes=MAX_READ_BYTES)
            except (OSError, ValueError, PathSecurityError):
                return
            if b"\x00" in raw[:4096]:
                return
            rel_posix = fpath.relative_to(root).as_posix()
            text = decode_process_bytes(raw)
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    matches.append({
                        "path": rel_posix,
                        "line": lineno,
                        "text": self.redactor.redact_text(line[:300]),
                    })
                    if len(matches) >= limit:
                        truncated = True
                        return

        if start.is_file():
            scan_file(start)
        else:
            for dirpath, dirnames, filenames in os.walk(start):
                if truncated:
                    break
                cur_dir = Path(dirpath)
                kept_dirs: list[str] = []
                for d in sorted(dirnames):
                    sub = cur_dir / d
                    if is_reparse_or_link(sub):
                        continue
                    rel_d = sub.relative_to(root).as_posix()
                    if not matcher.is_ignored(rel_d, is_dir=True):
                        kept_dirs.append(d)
                dirnames[:] = kept_dirs
                for fname in sorted(filenames):
                    f = cur_dir / fname
                    if is_reparse_or_link(f):
                        continue
                    rel_f = f.relative_to(root).as_posix()
                    if matcher.is_ignored(rel_f, is_dir=False):
                        continue
                    scan_file(f)
                    if truncated:
                        break

        return {"workspace_id": prof.workspace_id, "matches": matches, "truncated": truncated}

    def apply_patch(
        self,
        workspace_id: str,
        relative_path: str,
        *,
        expected_sha256: str,
        edits: list[dict[str, Any]] | None = None,
        unified_diff: str = "",
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("write",)
        )
        root = canonical_workspace_root(prof.root_path)
        target = resolve_workspace_path(root, relative_path, exclude_patterns=prof.exclude_patterns)
        raw, current_sha = read_verified_bytes(root, target, max_bytes=MAX_WRITE_BYTES)
        if not expected_sha256 or expected_sha256.lower() != current_sha.lower():
            raise FileVersionConflictError(
                "File changed on disk before apply_patch; expected_sha256 mismatch",
                current_sha256=current_sha,
                expected_sha256=expected_sha256,
            )
        original = raw.decode("utf-8", errors="strict")
        updated = original
        if unified_diff.strip():
            updated = _apply_unified_diff(updated, unified_diff)
        elif edits:
            for item in edits:
                if not isinstance(item, dict) or "old_text" not in item or "new_text" not in item:
                    raise ValueError("Each edit must specify old_text and new_text")
                old_t = str(item["old_text"])
                new_t = str(item["new_text"])
                if not old_t or old_t not in updated:
                    raise ValueError("Patch edit old_text was not found in target file")
                if item.get("all_occurrences"):
                    updated = updated.replace(old_t, new_t)
                else:
                    if updated.count(old_t) > 1:
                        raise ValueError("Patch edit old_text matched multiple times without all_occurrences=True")
                    updated = updated.replace(old_t, new_t, 1)
        else:
            raise ValueError("Provide either edits or unified_diff")

        new_sha, prev_bytes = atomic_write_verified(
            root,
            target,
            updated.encode("utf-8"),
            max_bytes=MAX_WRITE_BYTES,
            expected_sha256=current_sha,
        )
        rel_posix = target.relative_to(root).as_posix()
        snap = self.history.record_snapshot(
            workspace_id=prof.workspace_id,
            relative_path=rel_posix,
            operation="patch",
            before_bytes=prev_bytes,
            after_sha256=new_sha,
            client_id=client_id or "owner",
        )
        diff_preview = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{rel_posix}",
                tofile=f"b/{rel_posix}",
            )
        )
        return {
            "workspace_id": prof.workspace_id,
            "path": rel_posix,
            "sha256": new_sha,
            "snapshot_id": snap["snapshot_id"],
            "diff": diff_preview[:MAX_READ_BYTES],
        }

    def move_file(
        self,
        workspace_id: str,
        src_path: str,
        dst_path: str,
        *,
        expected_sha256: str = "",
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id,
            client_id=client_id,
            client_profile=client_profile,
            required=("write", "delete"),
        )
        root = canonical_workspace_root(prof.root_path)
        src = resolve_workspace_path(root, src_path, exclude_patterns=prof.exclude_patterns)
        dst = resolve_workspace_path(root, dst_path, allow_missing=True, exclude_patterns=prof.exclude_patterns)
        if dst.exists() or is_reparse_or_link(dst):
            raise FileExistsError("Destination path already exists")
        src_bytes, src_sha = read_verified_bytes(root, src, max_bytes=MAX_WRITE_BYTES)
        if expected_sha256 and expected_sha256.lower() != src_sha.lower():
            raise FileVersionConflictError(
                "Source file changed before move",
                current_sha256=src_sha,
                expected_sha256=expected_sha256,
            )
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(src, dst)
        rel_src = src.relative_to(root).as_posix()
        rel_dst = dst.relative_to(root).as_posix()
        self.history.record_snapshot(
            workspace_id=prof.workspace_id,
            relative_path=rel_src,
            operation=f"move->{rel_dst}",
            before_bytes=src_bytes,
            after_sha256="",
            client_id=client_id or "owner",
        )
        return {"workspace_id": prof.workspace_id, "src_path": rel_src, "dst_path": rel_dst, "sha256": src_sha}

    def delete_file(
        self,
        workspace_id: str,
        relative_path: str,
        *,
        expected_sha256: str,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("delete",)
        )
        root = canonical_workspace_root(prof.root_path)
        target = resolve_workspace_path(root, relative_path, exclude_patterns=prof.exclude_patterns)
        prev_bytes, current_sha = read_verified_bytes(root, target, max_bytes=MAX_WRITE_BYTES)
        if not expected_sha256 or expected_sha256.lower() != current_sha.lower():
            raise FileVersionConflictError(
                "File changed on disk before delete_file; expected_sha256 mismatch",
                current_sha256=current_sha,
                expected_sha256=expected_sha256,
            )
        rel_posix = target.relative_to(root).as_posix()
        target.unlink()
        snap = self.history.record_snapshot(
            workspace_id=prof.workspace_id,
            relative_path=rel_posix,
            operation="delete",
            before_bytes=prev_bytes,
            after_sha256="",
            client_id=client_id or "owner",
        )
        return {
            "workspace_id": prof.workspace_id,
            "path": rel_posix,
            "deleted": True,
            "snapshot_id": snap["snapshot_id"],
        }

    def workspace_diff(
        self,
        workspace_id: str,
        *,
        relative_path: str = "",
        snapshot_id: str = "",
        staged: bool = False,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        self._redact_payload_secrets(prof)
        if snapshot_id:
            meta, before_bytes = self.history.load_snapshot(prof.workspace_id, snapshot_id)
            root = canonical_workspace_root(prof.root_path)
            target = resolve_workspace_path(root, str(meta["path"]), allow_missing=True, exclude_patterns=prof.exclude_patterns)
            after_bytes = b""
            if target.is_file():
                after_bytes, _ = read_verified_bytes(root, target, max_bytes=MAX_READ_BYTES)
            before_text = decode_process_bytes(before_bytes or b"").splitlines(keepends=True)
            after_text = decode_process_bytes(after_bytes).splitlines(keepends=True)
            diff_text = "".join(
                difflib.unified_diff(before_text, after_text, fromfile=f"snap/{meta['path']}", tofile=f"work/{meta['path']}")
            )
            return {
                "workspace_id": prof.workspace_id,
                "snapshot_id": snapshot_id,
                "path": meta["path"],
                "diff": self.redactor.redact_text(diff_text[:MAX_READ_BYTES]),
            }
        return git_ops.git_diff(
            prof,
            nohooks_dir=self._nohooks_dir,
            staged=staged,
            relative_path=relative_path,
            redactor=self.redactor,
        )

    def workspace_history(
        self,
        workspace_id: str,
        *,
        relative_path: str = "",
        limit: int = 20,
        rollback_snapshot_id: str = "",
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        if rollback_snapshot_id:
            prof = self._authorize(
                workspace_id,
                client_id=client_id,
                client_profile=client_profile,
                required=("write",),
            )
            meta, before_bytes = self.history.load_snapshot(prof.workspace_id, rollback_snapshot_id)
            root = canonical_workspace_root(prof.root_path)
            rel_path = str(meta["path"])
            target = resolve_workspace_path(root, rel_path, allow_missing=True, exclude_patterns=prof.exclude_patterns)
            if before_bytes is None:
                if target.exists():
                    cur_bytes, cur_sha = read_verified_bytes(root, target, max_bytes=MAX_WRITE_BYTES)
                    target.unlink()
                    self.history.record_snapshot(
                        workspace_id=prof.workspace_id,
                        relative_path=rel_path,
                        operation=f"rollback:{rollback_snapshot_id}",
                        before_bytes=cur_bytes,
                        after_sha256="",
                        client_id=client_id or "owner",
                    )
                return {"workspace_id": prof.workspace_id, "rolled_back": True, "path": rel_path, "deleted": True}

            cur_sha = ""
            if target.exists():
                _, cur_sha = read_verified_bytes(root, target, max_bytes=MAX_WRITE_BYTES)
            new_sha, prev_bytes = atomic_write_verified(
                root,
                target,
                before_bytes,
                max_bytes=MAX_WRITE_BYTES,
                expected_sha256=cur_sha,
            )
            self.history.record_snapshot(
                workspace_id=prof.workspace_id,
                relative_path=rel_path,
                operation=f"rollback:{rollback_snapshot_id}",
                before_bytes=prev_bytes,
                after_sha256=new_sha,
                client_id=client_id or "owner",
            )
            return {"workspace_id": prof.workspace_id, "rolled_back": True, "path": rel_path, "sha256": new_sha}

        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("read",)
        )
        return {
            "workspace_id": prof.workspace_id,
            "snapshots": self.history.list_snapshots(
                prof.workspace_id, relative_path=relative_path, limit=limit
            ),
        }

    def _authorize_live(
        self,
        workspace_id: str,
        *,
        client_id: str | None,
        fallback_profile: str,
        required: tuple[str, ...],
        tool_name: str = "workspace_run_task",
    ) -> tuple[WorkspaceProfile, str]:
        live_profile = (
            str(self.live_client_authorizer(client_id, tool_name))
            if self.live_client_authorizer is not None
            else fallback_profile
        )
        prof = self._authorize(
            workspace_id,
            client_id=client_id,
            client_profile=live_profile,
            required=required,
        )
        return prof, live_profile

    def _record_task_start(
        self,
        workspace_id: str,
        command_name: str,
        raw_cmd: str,
        *,
        timeout_val: int,
        client_id: str | None,
        client_profile: str,
    ) -> str | None:
        if self.task_store is None:
            return None
        from backend.tasks.models import TaskSpec

        safe_cmd = self.redactor.redact_text(raw_cmd)
        spec = TaskSpec(
            kind="windows",
            command=safe_cmd,
            timeout=timeout_val,
            workspace_id=workspace_id,
            workspace_command=command_name,
        )
        rec = self.task_store.create_running_task(
            owner_client_id=client_id or "owner",
            profile=client_profile,
            title=self.redactor.redact_text(f"workspace({workspace_id}): {command_name}"),
            spec=spec,
        )
        tid = str(rec.task_id)
        with self._active_tasks_lock:
            self._active_task_ids.add(tid)
        return tid

    def _write_task_result_artifact(
        self,
        workspace_id: str,
        task_id: str,
        *,
        status: str,
        exit_code: int | None,
        error: str,
        stdout_bytes: int,
        stderr_bytes: int,
        summary: str,
    ) -> list[dict[str, Any]]:
        art_dir = self.artifacts_dir / task_id
        try_init_private_dir(art_dir)
        res_file = art_dir / "result.json"
        atomic_write_json(
            res_file,
            {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "status": status,
                "exit_code": exit_code,
                "error": self.redactor.redact_text(error),
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
                "output_preview": summary[:16384],
                "recorded_at": time.time(),
            },
            indent=2,
            restrict_acl=True,
        )
        return [
            {
                "name": "result.json",
                "size_bytes": res_file.stat().st_size,
                "content_type": "application/json",
            }
        ]

    def _record_task_finish(
        self,
        workspace_id: str,
        task_id: str | None,
        res: Any,
        *,
        timeout_val: int,
    ) -> None:
        if self.task_store is None or not task_id:
            return
        from backend.tasks.models import STATUS_CANCELLED, STATUS_FAILED, STATUS_SUCCEEDED

        current_rec = self.task_store.get_task(task_id)
        was_cancel_flagged = bool(current_rec and current_rec.cancel_requested)
        if res.cancelled or was_cancel_flagged:
            status, err = STATUS_CANCELLED, "Task cancelled"
        elif res.timed_out:
            status, err = STATUS_FAILED, f"Timed out after {timeout_val}s"
        elif res.exit_code in (0, None):
            status, err = STATUS_SUCCEEDED, ""
        else:
            status, err = STATUS_FAILED, f"Exited with code {res.exit_code}"

        summary = self.redactor.redact_text(f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}".strip())
        refs = self._write_task_result_artifact(
            workspace_id,
            task_id,
            status=status,
            exit_code=res.exit_code,
            error=err,
            stdout_bytes=res.stdout_bytes,
            stderr_bytes=res.stderr_bytes,
            summary=summary,
        )
        self.task_store.mark_finished(
            task_id,
            status=status,
            exit_code=res.exit_code,
            error=self.redactor.redact_text(err),
            artifact_refs=refs,
        )
        self.task_store.enforce_retention(
            max_tasks=200,
            ttl_seconds=7 * 86400,
            spool_manager=self.runner.spool,
            artifacts_dir=self.artifacts_dir,
        )
        self.store.append_linked_task(workspace_id, task_id)

    def _abort_task_audit_record(
        self,
        workspace_id: str,
        task_id: str | None,
        *,
        cancelled: bool,
        reason: str,
    ) -> None:
        if self.task_store is None or not task_id:
            return
        from backend.tasks.models import STATUS_CANCELLED, STATUS_FAILED

        current_rec = self.task_store.get_task(task_id)
        is_cancelled = cancelled or bool(current_rec and current_rec.cancel_requested)
        status = STATUS_CANCELLED if is_cancelled else STATUS_FAILED
        clean_err = "Task cancelled" if is_cancelled else self.redactor.redact_text(reason)
        refs = self._write_task_result_artifact(
            workspace_id,
            task_id,
            status=status,
            exit_code=-1 if is_cancelled else None,
            error=clean_err,
            stdout_bytes=0,
            stderr_bytes=0,
            summary="",
        )
        self.task_store.mark_finished(
            task_id,
            status=status,
            exit_code=-1 if is_cancelled else None,
            error=clean_err,
            artifact_refs=refs,
        )
        self.task_store.enforce_retention(
            max_tasks=200,
            ttl_seconds=7 * 86400,
            spool_manager=self.runner.spool,
            artifacts_dir=self.artifacts_dir,
        )
        self.store.append_linked_task(workspace_id, task_id)

    async def _watch_cancel_requests(self, task_id: str, stop_ev: asyncio.Event) -> None:
        if self.task_store is None:
            return
        while not stop_ev.is_set():
            try:
                rec = self.task_store.get_task(task_id)
                if rec is not None and rec.cancel_requested:
                    self.runner.cancel_run(task_id)
                    return
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.05)

    async def execute_restarted_task(self, rec: Any, spec: Any) -> Any:
        """Execute a restarted TaskManager task referencing a registered workspace command."""
        wid = validate_workspace_id(str(getattr(spec, "workspace_id", "") or ""))
        cname = str(getattr(spec, "workspace_command", "") or "").strip()
        if not cname:
            raise ValueError("Missing workspace_command in TaskSpec")
        prof, _live_prof = self._authorize_live(
            wid,
            client_id=rec.owner_client_id,
            fallback_profile=rec.profile,
            required=("read", "execute"),
        )
        root = canonical_workspace_root(prof.root_path)
        env = self._redact_payload_secrets(prof)
        _raw_cmd, argv = self._prepare_workspace_command(prof, cname, env)

        def recheck() -> None:
            self._authorize_live(
                wid,
                client_id=rec.owner_client_id,
                fallback_profile=rec.profile,
                required=("read", "execute"),
            )

        return await self.runner.run_command(
            argv,
            cwd=root,
            timeout=max(1, min(int(spec.timeout), 600)),
            client_id=rec.owner_client_id or "owner",
            kind="workspace",
            env=env,
            spawn_fn=asyncio.create_subprocess_exec,
            pre_dispatch_check=recheck,
            run_id=rec.spool_run_id or rec.task_id,
        )

    @staticmethod
    def _build_workspace_path(prof: WorkspaceProfile, env: dict[str, str]) -> str:
        path_parts: list[str] = []
        if prof.python_venv:
            venv_bin = Path(prof.python_venv) / ("Scripts" if os.name == "nt" else "bin")
            if venv_bin.is_dir():
                path_parts.append(str(venv_bin))
            env["VIRTUAL_ENV"] = prof.python_venv
        if prof.node_path:
            np = Path(prof.node_path)
            node_dir = np if np.is_dir() else np.parent
            if node_dir.is_dir():
                path_parts.append(str(node_dir))
        if os.environ.get("PATH"):
            path_parts.append(os.environ["PATH"])
        effective_path = os.pathsep.join(path_parts)
        env["PATH"] = effective_path
        return effective_path

    def _prepare_workspace_command(
        self,
        prof: WorkspaceProfile,
        command_name: str,
        env: dict[str, str],
    ) -> tuple[str, list[str]]:
        raw_cmd = prof.commands.get(command_name)
        if not raw_cmd:
            raise ValueError(f"Unknown workspace command: {command_name!r}")
        effective_path = self._build_workspace_path(prof, env)
        argv = shlex.split(raw_cmd, posix=os.name != "nt")
        if os.name == "nt":
            argv = [p[1:-1] if len(p) >= 2 and p[0] == '"' and p[-1] == '"' else p for p in argv]
        if not argv:
            raise ValueError("Empty workspace command")
        resolved_exe = shutil.which(argv[0], path=effective_path)
        if not resolved_exe:
            raise ValueError(f"Command executable {argv[0]!r} not found in workspace toolchain PATH")
        argv[0] = resolved_exe
        return raw_cmd, argv

    @staticmethod
    async def _stop_cancel_watcher(watcher: asyncio.Task[None] | None, stop_watch: asyncio.Event) -> None:
        stop_watch.set()
        if watcher is None:
            return
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)

    async def run_workspace_task(
        self,
        workspace_id: str,
        command_name: str,
        *,
        timeout: int = 120,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof, live_profile = self._authorize_live(
            workspace_id,
            client_id=client_id,
            fallback_profile=client_profile,
            required=("read", "execute"),
        )
        root = canonical_workspace_root(prof.root_path)
        env = self._redact_payload_secrets(prof)
        raw_cmd, argv = self._prepare_workspace_command(prof, command_name, env)

        def recheck() -> None:
            self._authorize_live(
                workspace_id,
                client_id=client_id,
                fallback_profile=client_profile,
                required=("read", "execute"),
            )

        bounded_timeout = max(1, min(int(timeout), 600))
        task_id = self._record_task_start(
            prof.workspace_id,
            command_name,
            raw_cmd,
            timeout_val=bounded_timeout,
            client_id=client_id,
            client_profile=live_profile,
        )
        stop_watch = asyncio.Event()
        watcher = (
            asyncio.create_task(self._watch_cancel_requests(task_id, stop_watch))
            if task_id and self.task_store is not None
            else None
        )
        try:
            res = await self.runner.run_command(
                argv,
                cwd=root,
                timeout=bounded_timeout,
                client_id=client_id or "owner",
                kind="workspace",
                env=env,
                spawn_fn=asyncio.create_subprocess_exec,
                pre_dispatch_check=recheck,
                run_id=task_id,
            )
        except asyncio.CancelledError:
            if task_id:
                self.runner.cancel_run(task_id)
            self._abort_task_audit_record(
                prof.workspace_id, task_id, cancelled=True, reason="Task cancelled"
            )
            raise
        except Exception as exc:
            self._abort_task_audit_record(
                prof.workspace_id, task_id, cancelled=False, reason=str(exc)
            )
            raise
        finally:
            await self._stop_cancel_watcher(watcher, stop_watch)
            if task_id:
                with self._active_tasks_lock:
                    self._active_task_ids.discard(task_id)

        self._record_task_finish(prof.workspace_id, task_id, res, timeout_val=bounded_timeout)
        payload: dict[str, Any] = {
            "workspace_id": prof.workspace_id,
            "command_name": command_name,
            "exit_code": res.exit_code,
            "timed_out": res.timed_out,
            "stdout": self.redactor.redact_text(res.stdout),
            "stderr": self.redactor.redact_text(res.stderr),
            "duration_ms": res.duration_ms,
        }
        if task_id:
            payload["task_id"] = task_id
        return payload

    # ------------------------------ Git wrappers with per-client authorization ------------------------------
    def git_status(self, workspace_id: str, *, client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("read", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_status(prof, nohooks_dir=self._nohooks_dir, redactor=self.redactor)

    def git_diff(self, workspace_id: str, *, staged: bool = False, relative_path: str = "", client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("read", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_diff(prof, nohooks_dir=self._nohooks_dir, staged=staged, relative_path=relative_path, redactor=self.redactor)

    def git_log(self, workspace_id: str, *, limit: int = 20, client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("read", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_log(prof, nohooks_dir=self._nohooks_dir, limit=limit, redactor=self.redactor)

    def git_branches(self, workspace_id: str, *, client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("read", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_branches(prof, nohooks_dir=self._nohooks_dir, redactor=self.redactor)

    def git_checkout(self, workspace_id: str, branch: str, *, create: bool = False, client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("write", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_checkout(prof, branch, create=create, nohooks_dir=self._nohooks_dir, redactor=self.redactor)

    def git_commit(self, workspace_id: str, message: str, *, paths: list[str] | tuple[str, ...] = (), client_id: str | None = "owner", client_profile: str = "full") -> dict[str, Any]:
        prof = self._authorize(workspace_id, client_id=client_id, client_profile=client_profile, required=("write", "git"))
        self._redact_payload_secrets(prof)
        return git_ops.git_commit(prof, message, paths=paths, nohooks_dir=self._nohooks_dir, redactor=self.redactor)

    def _interrupt_active_task(self, tid: str) -> None:
        try:
            self.runner.cancel_run(tid)
        except Exception:  # noqa: BLE001
            pass
        if self.task_store is None:
            return
        try:
            from backend.tasks.models import STATUS_INTERRUPTED, TERMINAL_STATUSES

            rec = self.task_store.get_task(tid)
            if rec is not None and rec.status not in TERMINAL_STATUSES:
                self.task_store.mark_finished(
                    tid,
                    status=STATUS_INTERRUPTED,
                    exit_code=None,
                    error="Interrupted by WorkspaceManager shutdown.",
                )
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        with self._active_tasks_lock:
            active_ids = list(self._active_task_ids)
        for tid in active_ids:
            self._interrupt_active_task(tid)
        if self._owns_runner:
            self.runner.close()
