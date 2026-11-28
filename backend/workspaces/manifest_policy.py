"""Bounded significant-manifest policy, safe regular-file verification, and re-approval models (Stage N04)."""
from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from backend.workspaces.models import validate_manifest_digests
from backend.workspaces.path_security import (
    PathSecurityError,
    canonical_workspace_root,
    is_reparse_or_link,
    resolve_workspace_path,
    verify_opened_fd,
)

if TYPE_CHECKING:
    from backend.workspaces.discovery import DiagnosticItem, WizardPlanSnapshot

_MAX_VERIFY_MANIFEST_BYTES = 8 * 1024 * 1024

SIGNIFICANT_MANIFEST_BY_STACK: dict[str, tuple[str, ...]] = {
    "node": (
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        ".npmrc",
        ".yarnrc",
        ".yarnrc.yml",
        "pnpm-workspace.yaml",
        "bunfig.toml",
        "tsconfig.json",
        "next.config.js",
        "next.config.mjs",
        "next.config.cjs",
        "next.config.ts",
        "vite.config.js",
        "vite.config.mjs",
        "vite.config.cjs",
        "vite.config.ts",
    ),
    "python": (
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "poetry.toml",
        "uv.lock",
        "uv.toml",
        "pdm.lock",
        "pip.conf",
        "pip.ini",
        "pytest.ini",
        "tox.ini",
        "conftest.py",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.lock",
    ),
    "docker_compose": (
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
        "compose.override.yaml",
        "compose.override.yml",
        "docker-compose.override.yaml",
        "docker-compose.override.yml",
    ),
    "rust_go": (
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
    ),
}

SIGNIFICANT_MANIFEST_FILES: tuple[str, ...] = tuple(
    dict.fromkeys(
        fname
        for files in SIGNIFICANT_MANIFEST_BY_STACK.values()
        for fname in files
    )
)


class ManifestDriftError(ValueError):
    """Raised when approved manifest set changed, disappeared, grew unsafe, or had additions on disk."""


class ManifestLimitError(ValueError):
    """Raised when reading or hashing a manifest would exceed bounded file or total byte limits."""


@dataclass(frozen=True)
class ManifestChangeItem:
    rel_path: str
    status: Literal["added", "modified", "removed", "unsafe"]
    old_sha256: str = ""
    new_sha256: str = ""
    detail: str = ""


@dataclass(frozen=True)
class ManifestReapprovalPreview:
    workspace_id: str
    workspace_name: str
    root_path: str
    manifest_changes: tuple[ManifestChangeItem, ...]
    new_digests: dict[str, str]
    added_commands: dict[str, str]
    changed_commands: dict[str, tuple[str, str]]
    unmatched_existing_commands: tuple[str, ...]
    proposed_commands: dict[str, str]
    runtime_changes: dict[str, tuple[str, str]]
    proposed_language: str
    proposed_python_venv: str
    proposed_node_path: str
    proposed_git_root: str
    updatable_servers: tuple[str, ...]
    skipped_servers: tuple[str, ...]
    server_param_changes: dict[str, dict[str, Any]]
    lifecycle_warnings: tuple[str, ...]
    effective_permissions: dict[str, Any]
    diagnostics: tuple[DiagnosticItem, ...] = ()
    blocking_errors: tuple[str, ...] = ()
    snapshot: WizardPlanSnapshot | None = None
    has_changes: bool = False


def is_safe_regular_file(root: Path, rel_path: str) -> bool:
    """Return True if `rel_path` inside `root` resolves to a non-reparse regular file without opening it."""
    try:
        target = resolve_workspace_path(root, rel_path, allow_missing=False)
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode) or is_reparse_or_link(target):
            return False
        if not stat.S_ISREG(st.st_mode):
            return False
        return not bool(getattr(st, "st_file_attributes", 0) & 0x0040)
    except (OSError, PathSecurityError, FileNotFoundError):
        return False


def open_verified_regular_fd(root: Path, rel_path: str) -> tuple[int, os.stat_result]:
    """Safely open a bounded regular file with pre-open lstat, O_NOFOLLOW|O_NONBLOCK, and handle verification."""
    target = resolve_workspace_path(root, rel_path, allow_missing=False)
    pre_st = os.lstat(target)
    if stat.S_ISLNK(pre_st.st_mode) or is_reparse_or_link(target):
        raise PathSecurityError(f"Refusing symlink/reparse file {rel_path!r}")
    if not stat.S_ISREG(pre_st.st_mode):
        raise PathSecurityError(f"Refusing non-regular special file {rel_path!r}")
    if getattr(pre_st, "st_file_attributes", 0) & 0x0040:
        raise PathSecurityError(f"Refusing device file {rel_path!r}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(target, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PathSecurityError(f"Opened descriptor for {rel_path!r} is not a regular file")
        if os.name != "nt" and (st.st_dev != pre_st.st_dev or st.st_ino != pre_st.st_ino):
            raise PathSecurityError(f"File {rel_path!r} changed during open (race detected)")
        verify_opened_fd(root, fd, target)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _next_bounded_chunk_size(
    file_read: int,
    used_before: int,
    rel_path: str,
    max_file_bytes: int,
    max_total_bytes: int | None,
) -> int:
    rem_file = (max_file_bytes + 1) - file_read
    if max_total_bytes is None:
        return min(65536, rem_file)
    rem_total = max_total_bytes - (used_before + file_read)
    if rem_total <= 0:
        raise ManifestLimitError(f"Total discovery read limit exceeded at {rel_path}")
    return min(65536, rem_file, rem_total)


def _preflight_fd_budget(
    st: os.stat_result,
    rel_path: str,
    *,
    max_file_bytes: int,
    bytes_used: list[int] | None,
    max_total_bytes: int | None,
) -> int:
    used_before = bytes_used[0] if bytes_used is not None else 0
    if st.st_size > max_file_bytes:
        raise ManifestLimitError(
            f"{rel_path} exceeds manifest size limit ({st.st_size} > {max_file_bytes} bytes)"
        )
    if max_total_bytes is not None and used_before + st.st_size > max_total_bytes:
        raise ManifestLimitError(f"Total discovery read limit exceeded at {rel_path}")
    return used_before


def _record_bytes_used(bytes_used: list[int] | None, total_used: int) -> None:
    if bytes_used is not None:
        bytes_used[0] = total_used


def _read_bounded_fd_impl(
    fd: int,
    st: os.stat_result,
    rel_path: str,
    *,
    max_file_bytes: int,
    bytes_used: list[int] | None,
    max_total_bytes: int | None,
    check_cancel: Callable[[], None] | None,
    collect_bytes: bool,
) -> tuple[bytes, str]:
    used_before = _preflight_fd_budget(
        st, rel_path, max_file_bytes=max_file_bytes, bytes_used=bytes_used, max_total_bytes=max_total_bytes
    )
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    file_read = 0
    while True:
        if check_cancel is not None:
            check_cancel()
        to_read = _next_bounded_chunk_size(file_read, used_before, rel_path, max_file_bytes, max_total_bytes)
        chunk = os.read(fd, to_read)
        if not chunk:
            break
        file_read += len(chunk)
        if file_read > max_file_bytes:
            _record_bytes_used(bytes_used, used_before + file_read)
            raise ManifestLimitError(f"{rel_path} exceeded manifest size limit")
        hasher.update(chunk)
        if collect_bytes:
            chunks.append(chunk)
    _record_bytes_used(bytes_used, used_before + file_read)
    return (b"".join(chunks) if collect_bytes else b""), hasher.hexdigest()


def read_regular_file_bounded(
    root: Path,
    rel_path: str,
    *,
    max_file_bytes: int,
    bytes_used: list[int] | None = None,
    max_total_bytes: int | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> tuple[bytes, str]:
    """Read bounded bytes + SHA-256 of a verified regular file strictly within remaining budgets."""
    fd, st = open_verified_regular_fd(root, rel_path)
    try:
        return _read_bounded_fd_impl(
            fd,
            st,
            rel_path,
            max_file_bytes=max_file_bytes,
            bytes_used=bytes_used,
            max_total_bytes=max_total_bytes,
            check_cancel=check_cancel,
            collect_bytes=True,
        )
    finally:
        os.close(fd)


def hash_regular_file_bounded(
    root: Path,
    rel_path: str,
    *,
    max_file_bytes: int = _MAX_VERIFY_MANIFEST_BYTES,
    bytes_used: list[int] | None = None,
    max_total_bytes: int | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> str:
    """Compute SHA-256 of a verified regular file cleanly via bounded non-blocking reads."""
    fd, st = open_verified_regular_fd(root, rel_path)
    try:
        _, digest = _read_bounded_fd_impl(
            fd,
            st,
            rel_path,
            max_file_bytes=max_file_bytes,
            bytes_used=bytes_used,
            max_total_bytes=max_total_bytes,
            check_cancel=check_cancel,
            collect_bytes=False,
        )
        return digest
    finally:
        os.close(fd)


def collect_significant_manifest_digests(
    root: Path,
    *,
    existing_digests: Mapping[str, str] | None = None,
    extra_paths: Iterable[str] = (),
    max_file_bytes: int = _MAX_VERIFY_MANIFEST_BYTES,
    bytes_used: list[int] | None = None,
    max_total_bytes: int | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Hash all present root-level significant manifests within bounded size/byte/cancel budgets."""
    canon_root = canonical_workspace_root(root)
    digests: dict[str, str] = dict(existing_digests or {})
    issues: list[tuple[str, str]] = []
    candidates = tuple(dict.fromkeys([*SIGNIFICANT_MANIFEST_FILES, *extra_paths]))

    for rel in candidates:
        if rel in digests:
            continue
        if check_cancel is not None:
            check_cancel()
        if not os.path.lexists(canon_root / rel):
            continue
        try:
            digests[rel] = hash_regular_file_bounded(
                canon_root,
                rel,
                max_file_bytes=max_file_bytes,
                bytes_used=bytes_used,
                max_total_bytes=max_total_bytes,
                check_cancel=check_cancel,
            )
        except (OSError, PathSecurityError, ManifestLimitError) as exc:
            issues.append((rel, str(exc)))
    return digests, issues


def verify_manifest_digests(
    root: Path,
    expected_digests: Mapping[str, str],
    *,
    check_unexpected_significant: bool = True,
) -> None:
    """Fail closed if any approved manifest drifted, disappeared, or any unapproved significant manifest appeared."""
    canon_root = canonical_workspace_root(root)
    clean_expected = validate_manifest_digests(dict(expected_digests))
    for rel, expected_sha in clean_expected.items():
        try:
            actual_sha = hash_regular_file_bounded(canon_root, rel, max_file_bytes=_MAX_VERIFY_MANIFEST_BYTES)
        except (FileNotFoundError, OSError, PathSecurityError, ManifestLimitError) as exc:
            raise ManifestDriftError(
                f"Approved manifest {rel!r} is missing or unreadable ({exc}); re-approve workspace before running"
            ) from exc
        if actual_sha != expected_sha:
            raise ManifestDriftError(
                f"Approved manifest {rel!r} changed on disk since approval; re-approve workspace before running"
            )

    if not check_unexpected_significant:
        return
    for rel in SIGNIFICANT_MANIFEST_FILES:
        if rel not in clean_expected and os.path.lexists(canon_root / rel):
            raise ManifestDriftError(
                f"Unapproved significant manifest {rel!r} appeared on disk; review and re-approve workspace before running"
            )


def build_manifest_change_items(
    old_digests: Mapping[str, str],
    new_digests: Mapping[str, str],
    issues: Iterable[tuple[str, str]] = (),
) -> tuple[ManifestChangeItem, ...]:
    """Compute a secret-free diff of added, modified, removed, and unsafe manifests."""
    issue_map = {rel: msg for rel, msg in issues}
    all_keys = sorted(set(old_digests) | set(new_digests) | set(issue_map))
    items: list[ManifestChangeItem] = []
    for rel in all_keys:
        if rel in issue_map:
            items.append(
                ManifestChangeItem(
                    rel_path=rel,
                    status="unsafe",
                    old_sha256=old_digests.get(rel, ""),
                    detail=issue_map[rel],
                )
            )
            continue
        old_sha = old_digests.get(rel, "")
        new_sha = new_digests.get(rel, "")
        if not old_sha and new_sha:
            items.append(ManifestChangeItem(rel_path=rel, status="added", new_sha256=new_sha))
        elif old_sha and not new_sha:
            items.append(ManifestChangeItem(rel_path=rel, status="removed", old_sha256=old_sha))
        elif old_sha.lower() != new_sha.lower():
            items.append(ManifestChangeItem(rel_path=rel, status="modified", old_sha256=old_sha, new_sha256=new_sha))
    return tuple(items)
