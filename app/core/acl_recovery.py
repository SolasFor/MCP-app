"""Non-destructive Windows ACL diagnostics and owner-verified recovery for ``%APPDATA%\\MCPApp``.

Pre-v1.0.1 builds used ``icacls %USERNAME% /inheritance:r``, which could resolve to the
local computer account SID (e.g. ``SOLAS$``) when ``USERNAME == COMPUTERNAME`` or leave
protected directories/files without write/read ACEs for the interactive user's token SID.

Guarantees:
- Never follows symlinks, directory junctions, or NTFS reparse points.
- Never modifies files outside the specified ``data_dir`` or owned by a different OS user.
- Never grants ``Everyone`` or weakens protection: restores ``FILE_ALL_ACCESS`` solely for
  the current process ``TokenUser`` SID with ``PROTECTED_DACL_SECURITY_INFORMATION``.
- Never deletes encrypted vaults, DPAPI keys, OAuth SQLite databases, or tokens.
- Idempotent: healthy paths are untouched, and repeated repairs perform zero extra writes.
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.platform import get_platform

MANAGED_SUBDIRS: tuple[str, ...] = (
    "secrets",
    "oauth",
    "extensions",
    "gateway",
    "servers",
    "workspaces",
    "tasks",
    "remote",
    "desktop",
    "automation",
    "tunnels",
    "logs",
)

_MAX_SCAN_DEPTH = 6
_MAX_SCAN_ENTRIES = 2500
_CRITICAL_KEEP_NAMES = frozenset({
    "secrets.key",
    "secrets.vault.enc",
    "token.json",
    "connections.sqlite3",
    "connections.key",
    "tasks.sqlite3",
    "automation.sqlite3",
})


@dataclass(frozen=True)
class AclIssue:
    """Single filesystem object under ``data_dir`` whose DACL blocks current-user access."""

    path: str
    is_dir: bool
    reason: str
    owned_by_current_user: bool


@dataclass(frozen=True)
class AclDiagnosticReport:
    """Read-only diagnostic scan result for an MCPApp data directory."""

    data_dir: str
    issues: tuple[AclIssue, ...] = ()
    skipped_reparse: tuple[str, ...] = ()

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)

    @property
    def repairable_issues(self) -> tuple[AclIssue, ...]:
        return tuple(item for item in self.issues if item.owned_by_current_user)

    @property
    def foreign_owner_issues(self) -> tuple[AclIssue, ...]:
        return tuple(item for item in self.issues if not item.owned_by_current_user)


@dataclass(frozen=True)
class AclRepairReport:
    """Outcome of an owner-confirmed ACL recovery pass."""

    data_dir: str
    repaired_paths: tuple[str, ...] = ()
    unrecoverable_paths: tuple[tuple[str, str], ...] = ()
    backup_paths: tuple[str, ...] = ()
    skipped_reparse: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return len(self.unrecoverable_paths) == 0


def _is_reparse(path_str: str) -> bool:
    if sys.platform != "win32":
        return os.path.islink(path_str)
    from app.platform.windows import is_reparse_point

    return is_reparse_point(path_str)


def _win32_security_context() -> tuple[Any, Any, Any, Any] | None:
    if sys.platform != "win32":
        return None
    try:
        import ntsecuritycon
        import pywintypes
        import win32api
        import win32con
        import win32security
    except ImportError:
        return None
    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            current_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            token.Close()
        return current_sid, win32security, ntsecuritycon, pywintypes
    except (OSError, pywintypes.error):
        return None


def _is_owned_by_sid(path_str: str, current_sid: Any, win32security: Any, pywintypes: Any) -> bool:
    try:
        sd = win32security.GetNamedSecurityInfo(
            path_str,
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION,
        )
        owner_sid = sd.GetSecurityDescriptorOwner()
        return bool(owner_sid is not None and owner_sid == current_sid)
    except (OSError, pywintypes.error):
        return False


def _probe_io_access(path_str: str, is_dir: bool) -> str | None:
    try:
        if is_dir:
            with os.scandir(path_str) as it:
                next(it, None)
        else:
            with open(path_str, "rb") as fh:
                fh.read(1)
        return None
    except PermissionError as exc:
        winerr = getattr(exc, "winerror", None)
        if winerr is None or winerr == 5:
            return "directory_list_denied" if is_dir else "file_read_denied"
        return None
    except OSError:
        return None


def _inspect_path_acl(
    path_str: str,
    *,
    is_dir: bool,
    current_sid: Any,
    win32security: Any,
    ntsecuritycon: Any,
    pywintypes: Any,
) -> str | None:
    """Return damage reason string if ``path_str`` blocks current-user R/W access, else ``None``."""
    io_problem = _probe_io_access(path_str, is_dir)
    if io_problem is not None:
        return io_problem

    req_mask = (
        ntsecuritycon.FILE_LIST_DIRECTORY
        | ntsecuritycon.FILE_ADD_FILE
        | ntsecuritycon.FILE_ADD_SUBDIRECTORY
        | ntsecuritycon.FILE_TRAVERSE
        if is_dir
        else ntsecuritycon.FILE_READ_DATA | ntsecuritycon.FILE_WRITE_DATA
    )
    try:
        sd = win32security.GetNamedSecurityInfo(
            path_str,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
        )
        control, _rev = sd.GetSecurityDescriptorControl()
        is_protected = bool(control & win32security.SE_DACL_PROTECTED)
        dacl = sd.GetSecurityDescriptorDacl()
    except (OSError, pywintypes.error) as exc:
        if getattr(exc, "winerror", None) == 5:
            return "dacl_read_denied"
        return None

    if dacl is None:
        return None

    everyone_sid = win32security.ConvertStringSidToSid("S-1-1-0")
    granted_mask = 0
    for idx in range(dacl.GetAceCount()):
        ace = dacl.GetAce(idx)
        ace_type = int(ace[0][0])
        ace_flags = int(ace[0][1])
        # Inherit-only ACEs do not apply to this object itself.
        if ace_flags & ntsecuritycon.INHERIT_ONLY_ACE:
            continue
        ace_mask = int(ace[1])
        ace_sid = ace[2]
        if ace_type == ntsecuritycon.ACCESS_DENIED_ACE_TYPE and (
            ace_sid == current_sid or ace_sid == everyone_sid
        ):
            ungranted = req_mask & ~granted_mask
            if ace_mask & ungranted:
                return "explicit_deny_ace"
        elif ace_type == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE and ace_sid == current_sid:
            granted_mask |= ace_mask

    if is_protected and (granted_mask & req_mask) != req_mask:
        return "protected_dacl_missing_user_access"
    return None


def _iter_managed_roots(root_abs: str) -> list[tuple[str, bool]]:
    """Return top-level candidates inside ``data_dir`` without touching external paths."""
    candidates: list[tuple[str, bool]] = [(root_abs, True)]
    seen_norm = {os.path.normcase(root_abs)}

    # Always include known managed subdirectories by explicit name even if root listing is denied!
    for sub in MANAGED_SUBDIRS:
        sub_abs = os.path.join(root_abs, sub)
        norm = os.path.normcase(sub_abs)
        if norm not in seen_norm and (os.path.lexists(sub_abs)):
            seen_norm.add(norm)
            candidates.append((sub_abs, True))

    try:
        with os.scandir(root_abs) as it:
            for entry in it:
                p_abs = os.path.abspath(entry.path)
                norm = os.path.normcase(p_abs)
                if norm in seen_norm:
                    continue
                seen_norm.add(norm)
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                candidates.append((p_abs, is_dir))
    except OSError:
        pass
    return candidates


def diagnose_data_acls(data_dir: Path) -> AclDiagnosticReport:
    """Perform a non-destructive bounded scan of ``data_dir`` for broken Windows ACLs."""
    root_abs = os.path.abspath(os.fspath(data_dir))
    if sys.platform != "win32" or not os.path.lexists(root_abs):
        return AclDiagnosticReport(data_dir=root_abs)

    ctx = _win32_security_context()
    if ctx is None:
        return AclDiagnosticReport(data_dir=root_abs)
    current_sid, win32security, ntsecuritycon, pywintypes = ctx

    if _is_reparse(root_abs):
        return AclDiagnosticReport(data_dir=root_abs, skipped_reparse=(root_abs,))

    issues: list[AclIssue] = []
    skipped_reparse: list[str] = []
    visited = 0

    def _scan(path_abs: str, is_dir: bool, depth: int) -> None:
        nonlocal visited
        if visited >= _MAX_SCAN_ENTRIES or depth > _MAX_SCAN_DEPTH:
            return
        if _is_reparse(path_abs):
            skipped_reparse.append(path_abs)
            return
        visited += 1
        reason = _inspect_path_acl(
            path_abs,
            is_dir=is_dir,
            current_sid=current_sid,
            win32security=win32security,
            ntsecuritycon=ntsecuritycon,
            pywintypes=pywintypes,
        )
        if reason is not None:
            owned = _is_owned_by_sid(path_abs, current_sid, win32security, pywintypes)
            issues.append(
                AclIssue(
                    path=path_abs,
                    is_dir=is_dir,
                    reason=reason,
                    owned_by_current_user=owned,
                )
            )
        if not is_dir or depth >= _MAX_SCAN_DEPTH:
            return
        try:
            with os.scandir(path_abs) as it:
                entries = list(it)
        except OSError:
            return
        for entry in entries:
            if visited >= _MAX_SCAN_ENTRIES:
                break
            child_abs = os.path.abspath(entry.path)
            if _is_reparse(child_abs):
                skipped_reparse.append(child_abs)
                continue
            try:
                child_is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                # Stat on child inside accessible dir could still fail; infer from known names or file.
                child_is_dir = os.path.isdir(child_abs)
            _scan(child_abs, child_is_dir, depth + 1)

    for cand_path, cand_is_dir in _iter_managed_roots(root_abs):
        depth = 0 if os.path.normcase(cand_path) == os.path.normcase(root_abs) else 1
        _scan(cand_path, cand_is_dir, depth)

    # Deduplicate while preserving discovery order (in case root scan + explicit subdir overlapped)
    dedup_issues: list[AclIssue] = []
    seen_issue_paths: set[str] = set()
    for item in issues:
        key = os.path.normcase(item.path)
        if key not in seen_issue_paths:
            seen_issue_paths.add(key)
            dedup_issues.append(item)

    return AclDiagnosticReport(
        data_dir=root_abs,
        issues=tuple(dedup_issues),
        skipped_reparse=tuple(dict.fromkeys(skipped_reparse)),
    )


def repair_data_acls(
    data_dir: Path,
    *,
    isolate_unreadable: bool = False,
) -> AclRepairReport:
    """Repair damaged ACLs top-down inside ``data_dir`` for objects owned by ``TokenUser``."""
    root_abs = os.path.abspath(os.fspath(data_dir))
    if sys.platform != "win32" or not os.path.lexists(root_abs):
        return AclRepairReport(data_dir=root_abs)

    ctx = _win32_security_context()
    if ctx is None:
        return AclRepairReport(
            data_dir=root_abs,
            unrecoverable_paths=((root_abs, "pywin32_unavailable"),),
        )
    current_sid, win32security, ntsecuritycon, pywintypes = ctx

    if _is_reparse(root_abs):
        return AclRepairReport(
            data_dir=root_abs,
            skipped_reparse=(root_abs,),
            unrecoverable_paths=((root_abs, "reparse_point_refused"),),
        )

    adapter = get_platform()
    repaired: list[str] = []
    unrecoverable: list[tuple[str, str]] = []
    backups: list[str] = []
    skipped_reparse: list[str] = []
    seen_visited: set[str] = set()

    def _repair_and_walk(path_abs: str, is_dir: bool, depth: int) -> None:
        if len(seen_visited) >= _MAX_SCAN_ENTRIES or depth > _MAX_SCAN_DEPTH:
            return
        norm = os.path.normcase(path_abs)
        if norm in seen_visited:
            return
        if _is_reparse(path_abs):
            skipped_reparse.append(path_abs)
            return
        seen_visited.add(norm)

        reason = _inspect_path_acl(
            path_abs,
            is_dir=is_dir,
            current_sid=current_sid,
            win32security=win32security,
            ntsecuritycon=ntsecuritycon,
            pywintypes=pywintypes,
        )
        if reason is not None:
            if not _is_owned_by_sid(path_abs, current_sid, win32security, pywintypes):
                unrecoverable.append((path_abs, "not_owned_by_current_user"))
                return
            ok = adapter.restrict_path_acl(Path(path_abs), is_dir=is_dir)
            post_problem = _probe_io_access(path_abs, is_dir) if ok else "set_acl_failed"
            if ok and post_problem is None:
                repaired.append(path_abs)
            else:
                if isolate_unreadable and not is_dir:
                    bak = _try_backup_unreadable_file(path_abs, adapter)
                    if bak:
                        backups.append(bak)
                unrecoverable.append((path_abs, post_problem or "set_acl_failed"))
                return

        if not is_dir or depth >= _MAX_SCAN_DEPTH:
            return

        # Known critical file names inside secrets/oauth/extensions in case directory had partial access
        try:
            with os.scandir(path_abs) as it:
                entries = list(it)
        except OSError as exc:
            unrecoverable.append((path_abs, f"scandir_failed:{type(exc).__name__}"))
            return

        for entry in entries:
            if len(seen_visited) >= _MAX_SCAN_ENTRIES:
                break
            child_abs = os.path.abspath(entry.path)
            if _is_reparse(child_abs):
                skipped_reparse.append(child_abs)
                continue
            try:
                child_is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                child_is_dir = os.path.isdir(child_abs)
            _repair_and_walk(child_abs, child_is_dir, depth + 1)

    # First repair root_abs so _iter_managed_roots can enumerate children if root_abs was locked!
    _repair_and_walk(root_abs, True, 0)
    for cand_path, cand_is_dir in _iter_managed_roots(root_abs):
        if os.path.normcase(cand_path) == os.path.normcase(root_abs):
            continue
        _repair_and_walk(cand_path, cand_is_dir, 1)

    return AclRepairReport(
        data_dir=root_abs,
        repaired_paths=tuple(repaired),
        unrecoverable_paths=tuple(unrecoverable),
        backup_paths=tuple(backups),
        skipped_reparse=tuple(dict.fromkeys(skipped_reparse)),
    )


def _try_backup_unreadable_file(path_abs: str, adapter: Any) -> str:
    """Create a restricted backup copy if possible without ever deleting critical vaults/DBs."""
    p = Path(path_abs)
    if p.name.lower() in _CRITICAL_KEEP_NAMES:
        return ""
    stamp = int(time.time())
    bak = p.with_name(f"{p.name}.corrupted-{stamp}.bak")
    try:
        shutil.copy2(p, bak)
        adapter.restrict_path_acl(bak, is_dir=False)
        return str(bak)
    except OSError:
        return ""
