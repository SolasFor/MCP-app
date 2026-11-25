"""Guarded Workspace & Git manager enforcing per-client permissions, canonical paths, history, and redaction."""
from __future__ import annotations

import asyncio
import difflib
import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Any

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
    ) -> None:
        self.store = store
        self.history = history
        self._owns_runner = runner is None
        self.runner = runner or ProcessRunner(
            spool_dir=store.path.parent / "spool",
            redactor=redactor,
        )
        self.redactor = redactor or self.runner.redactor
        self._nohooks_dir = store.path.parent / "nohooks"

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

    async def run_workspace_task(
        self,
        workspace_id: str,
        command_name: str,
        *,
        timeout: int = 120,
        client_id: str | None = "owner",
        client_profile: str = "full",
    ) -> dict[str, Any]:
        prof = self._authorize(
            workspace_id, client_id=client_id, client_profile=client_profile, required=("execute",)
        )
        raw_cmd = prof.commands.get(command_name)
        if not raw_cmd:
            raise ValueError(f"Unknown workspace command: {command_name!r}")
        root = canonical_workspace_root(prof.root_path)
        env = self._redact_payload_secrets(prof)

        path_parts: list[str] = []
        if prof.python_venv:
            venv_bin = Path(prof.python_venv) / ("Scripts" if os.name == "nt" else "bin")
            if venv_bin.is_dir():
                path_parts.append(str(venv_bin))
        if prof.node_path:
            np = Path(prof.node_path)
            node_dir = np if np.is_dir() else np.parent
            if node_dir.is_dir():
                path_parts.append(str(node_dir))
        if os.environ.get("PATH"):
            path_parts.append(os.environ["PATH"])
        effective_path = os.pathsep.join(path_parts)
        env["PATH"] = effective_path
        if prof.python_venv:
            env["VIRTUAL_ENV"] = prof.python_venv

        argv = shlex.split(raw_cmd, posix=os.name != "nt")
        if os.name == "nt":
            argv = [p[1:-1] if len(p) >= 2 and p[0] == '"' and p[-1] == '"' else p for p in argv]
        if not argv:
            raise ValueError("Empty workspace command")

        resolved_exe = shutil.which(argv[0], path=effective_path)
        if not resolved_exe:
            raise ValueError(f"Command executable {argv[0]!r} not found in workspace toolchain PATH")
        argv[0] = resolved_exe

        def recheck() -> None:
            self._authorize(
                workspace_id,
                client_id=client_id,
                client_profile=client_profile,
                required=("execute",),
            )

        res = await self.runner.run_command(
            argv,
            cwd=root,
            timeout=max(1, min(int(timeout), 600)),
            client_id=client_id or "owner",
            kind="workspace",
            env=env,
            spawn_fn=asyncio.create_subprocess_exec,
            pre_dispatch_check=recheck,
        )
        return {
            "workspace_id": prof.workspace_id,
            "command_name": command_name,
            "exit_code": res.exit_code,
            "timed_out": res.timed_out,
            "stdout": self.redactor.redact_text(res.stdout),
            "stderr": self.redactor.redact_text(res.stderr),
            "duration_ms": res.duration_ms,
        }

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

    def close(self) -> None:
        if self._owns_runner:
            self.runner.close()
