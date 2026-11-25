"""Canonical path security, Windows junction/reparse/ADS/UNC guards, atomic writes, and .gitignore matching."""
from __future__ import annotations

import ctypes
import fnmatch
import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

SENSITIVE_EXACT_NAMES = frozenset({
    ".git",
    ".env",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    "token.json",
    "settings.json",
    "credentials.json",
    "secrets.json",
    "secrets.key",
    "secrets.vault.enc",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
})
SENSITIVE_SUFFIXES = frozenset({".pem", ".key", ".pfx", ".p12", ".ppk", ".kdbx"})
RESERVED_WIN_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})
DEFAULT_SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".mypy_cache", ".ruff_cache"})


class PathSecurityError(PermissionError):
    """Raised when a path escapes the workspace or hits symlinks/junctions/ADS/UNC/sensitive files."""


class FileVersionConflictError(RuntimeError):
    """Raised when expected file SHA-256 fails to match current disk content."""

    def __init__(self, message: str, *, current_sha256: str, expected_sha256: str) -> None:
        super().__init__(message)
        self.current_sha256 = current_sha256
        self.expected_sha256 = expected_sha256


def is_sensitive_segment(segment: str) -> bool:
    low = segment.casefold()
    if low in SENSITIVE_EXACT_NAMES or low.startswith(".env."):
        return True
    suffix = Path(low).suffix
    return suffix in SENSITIVE_SUFFIXES


def _is_reserved_win_name(segment: str) -> bool:
    stem = segment.split(".", 1)[0].casefold()
    return stem in RESERVED_WIN_NAMES


def is_reparse_or_link(path: Path) -> bool:
    """Return True if `path` is a symlink, Windows junction, or NTFS reparse point."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and bool(is_junction()):
            return True
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return True
        attrs = getattr(st, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
        return bool(attrs & reparse_flag)
    except OSError:
        return False


def _is_unc_or_device(raw: str) -> bool:
    if raw.startswith("\\\\") or raw.startswith("//"):
        return True
    return raw.startswith("\\??\\") or raw.startswith("\\\\?\\") or raw.startswith("\\\\.\\")


def canonical_workspace_root(root_path: str | Path) -> Path:
    """Validate and resolve a local directory root, rejecting UNC, device, and symlink/junction roots."""
    raw = str(root_path or "").strip()
    if not raw or "\x00" in raw or _is_unc_or_device(raw):
        raise PathSecurityError("Invalid or UNC/device workspace root path")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise PathSecurityError("Workspace root must be an absolute path")
    if is_reparse_or_link(candidate):
        raise PathSecurityError("Workspace root must not be a symlink or junction")
    resolved = Path(os.path.realpath(str(candidate), strict=True))
    if _is_unc_or_device(str(resolved)) or is_reparse_or_link(resolved):
        raise PathSecurityError("Canonical workspace root resolved to UNC or reparse target")
    if not resolved.is_dir():
        raise PathSecurityError("Workspace root does not exist or is not a directory")
    return resolved


def matches_user_exclusion(rel_posix: str, exclude_patterns: tuple[str, ...]) -> bool:
    if not exclude_patterns or not rel_posix:
        return False
    parts = PurePosixPath(rel_posix).parts
    for pat in exclude_patterns:
        norm = pat.replace("\\", "/").strip()
        if not norm:
            continue
        if fnmatch.fnmatch(rel_posix, norm):
            return True
        if "/" not in norm and any(fnmatch.fnmatch(seg, norm) for seg in parts):
            return True
    return False


def _normalize_relative_segments(relative_path: str, *, allow_root: bool) -> list[str]:
    if not isinstance(relative_path, str):
        raise PathSecurityError("Relative path must be a string")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in relative_path):
        raise PathSecurityError("Control characters are forbidden in paths")
    if _is_unc_or_device(relative_path):
        raise PathSecurityError("UNC or device paths are forbidden")
    if ":" in relative_path:
        raise PathSecurityError("Drive letters and NTFS Alternate Data Streams (:) are forbidden")
    cleaned = relative_path.strip()
    if cleaned in ("", "."):
        if allow_root:
            return []
        raise PathSecurityError("A non-empty relative path is required")
    if "\\" in cleaned and os.name != "nt":
        raise PathSecurityError("Backslashes are not supported on POSIX paths")
    p_in = Path(cleaned)
    p_win = PureWindowsPath(cleaned)
    if p_in.is_absolute() or p_win.is_absolute() or bool(p_win.drive):
        raise PathSecurityError("Absolute paths are forbidden")

    norm = cleaned.replace("\\", "/")
    raw_parts = [seg for seg in norm.split("/") if seg != ""]
    if not raw_parts:
        if allow_root:
            return []
        raise PathSecurityError("A non-empty relative path is required")
    for seg in raw_parts:
        if seg in (".", ".."):
            raise PathSecurityError("Path traversal segments are forbidden")
        if is_sensitive_segment(seg):
            raise PathSecurityError(f"Access to protected file/directory {seg!r} is forbidden")
        if _is_reserved_win_name(seg):
            raise PathSecurityError(f"Windows reserved device name {seg!r} is forbidden")
    return raw_parts


def resolve_workspace_path(
    root: Path,
    relative_path: str,
    *,
    allow_missing: bool = False,
    allow_root: bool = False,
    exclude_patterns: tuple[str, ...] = (),
) -> Path:
    """Resolve `relative_path` inside `root` while rejecting junctions/symlinks/ADS/sensitive paths."""
    canonical_root = canonical_workspace_root(root)
    parts = _normalize_relative_segments(relative_path, allow_root=allow_root)
    rel_posix = "/".join(parts)
    if matches_user_exclusion(rel_posix, exclude_patterns):
        raise PathSecurityError(f"Path {rel_posix!r} is excluded by workspace policy")

    cur = canonical_root
    for idx, seg in enumerate(parts):
        cur = cur / seg
        is_last = idx == len(parts) - 1
        if cur.exists() or is_reparse_or_link(cur):
            if is_reparse_or_link(cur):
                raise PathSecurityError(f"Symlink/junction/reparse component forbidden: {seg!r}")
        elif not is_last:
            if not allow_missing:
                raise FileNotFoundError(f"Missing parent directory: {seg!r}")
        elif not allow_missing:
            raise FileNotFoundError(f"Target path does not exist: {rel_posix!r}")

    resolved = Path(os.path.realpath(str(cur), strict=False))
    if not resolved.is_relative_to(canonical_root):
        raise PathSecurityError("Resolved path escapes workspace root")
    rel_resolved = resolved.relative_to(canonical_root)
    for seg in rel_resolved.parts:
        if is_sensitive_segment(seg) or _is_reserved_win_name(seg):
            raise PathSecurityError("Resolved path touches protected target")
    if matches_user_exclusion(rel_resolved.as_posix(), exclude_patterns):
        raise PathSecurityError("Resolved path matches workspace exclusion pattern")
    return resolved


def _win32_final_path_from_fd(fd: int) -> Path:
    import msvcrt

    kernel32 = getattr(ctypes, "windll", None)
    get_osf = getattr(msvcrt, "get_osfhandle", None)
    if kernel32 is None or get_osf is None:
        raise PathSecurityError("Win32 kernel32/msvcrt unavailable")
    handle = get_osf(fd)
    buf_len = 32768
    buf = ctypes.create_unicode_buffer(buf_len)
    chars = int(kernel32.kernel32.GetFinalPathNameByHandleW(handle, buf, buf_len, 0))
    if chars <= 0 or chars >= buf_len:
        raise PathSecurityError("Failed to query canonical handle path")
    raw = buf.value
    if raw.upper().startswith("\\\\?\\UNC\\"):
        raise PathSecurityError("UNC final handle target is forbidden")
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    return Path(raw)


def verify_opened_fd(root: Path, fd: int, expected_path: Path) -> None:
    """Verify the actually opened file descriptor resolves strictly inside `root` without TOCTOU."""
    canonical_root = canonical_workspace_root(root)
    if sys.platform == "win32":
        actual = _win32_final_path_from_fd(fd)
        if not actual.is_relative_to(canonical_root):
            raise PathSecurityError("Opened handle escaped workspace root")
        if os.path.normcase(str(actual)) != os.path.normcase(str(expected_path)):
            raise PathSecurityError("Opened handle does not match verified workspace target")
        for seg in actual.relative_to(canonical_root).parts:
            if is_sensitive_segment(seg) or _is_reserved_win_name(seg):
                raise PathSecurityError("Opened handle points to sensitive file")
        return

    fd_stat = os.fstat(fd)
    path_stat = os.lstat(expected_path)
    if stat.S_ISLNK(path_stat.st_mode):
        raise PathSecurityError("Opened target is a symlink")
    if fd_stat.st_dev != path_stat.st_dev or fd_stat.st_ino != path_stat.st_ino:
        raise PathSecurityError("Opened descriptor inode mismatch (possible race)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_verified_bytes(root: Path, target: Path, *, max_bytes: int) -> tuple[bytes, str]:
    """Open `target` safely, verify the opened OS handle inside `root`, and read bounded bytes."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags)
    try:
        verify_opened_fd(root, fd, target)
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise IsADirectoryError("Target path is a directory")
        if st.st_size > max_bytes:
            raise ValueError(f"File exceeds size limit ({st.st_size} > {max_bytes} bytes)")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"File exceeds size limit ({total} > {max_bytes} bytes)")
            chunks.append(chunk)
        data = b"".join(chunks)
        return data, sha256_bytes(data)
    finally:
        os.close(fd)


def atomic_write_verified(
    root: Path,
    target: Path,
    data: bytes,
    *,
    max_bytes: int,
    expected_sha256: str = "",
    create_only: bool = False,
) -> tuple[str, bytes | None]:
    """Atomically write `data` to `target` with version precondition and handle verification."""
    if len(data) > max_bytes:
        raise ValueError(f"Write payload exceeds limit ({len(data)} > {max_bytes} bytes)")

    canonical_root = canonical_workspace_root(root)
    if not target.is_relative_to(canonical_root):
        raise PathSecurityError("Write target escapes workspace")

    target.parent.mkdir(parents=True, exist_ok=True)
    # Re-verify parent chain after mkdir
    rel = target.relative_to(canonical_root)
    resolve_workspace_path(canonical_root, rel.as_posix(), allow_missing=True)

    previous_bytes: bytes | None = None
    if target.exists() or is_reparse_or_link(target):
        if is_reparse_or_link(target):
            raise PathSecurityError("Refusing overwrite of symlink/junction target")
        if create_only:
            raise FileVersionConflictError(
                "Target file already exists (create_only=True)",
                current_sha256="exists",
                expected_sha256="",
            )
        previous_bytes, current_sha = read_verified_bytes(canonical_root, target, max_bytes=max_bytes)
        if not expected_sha256 or expected_sha256.lower() != current_sha.lower():
            raise FileVersionConflictError(
                "File changed on disk since last read; supply matching expected_sha256 to avoid overwriting user edits",
                current_sha256=current_sha,
                expected_sha256=expected_sha256,
            )

    tmp_path = target.parent / f".{target.name}.{secrets.token_hex(6)}.mcp_tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp_path, flags, 0o600)
    try:
        verify_opened_fd(canonical_root, fd, tmp_path)
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(tmp_path, target)
    return sha256_bytes(data), previous_bytes


class GitIgnoreMatcher:
    """Lightweight matcher for workspace `.gitignore` + user exclusion rules."""

    def __init__(self, root: Path, exclude_patterns: tuple[str, ...] = ()) -> None:
        self.root = root
        self.exclude_patterns = exclude_patterns
        self._rules: list[tuple[bool, str, bool]] = []  # (negated, pattern, dir_only)
        gitignore = root / ".gitignore"
        if gitignore.is_file() and not is_reparse_or_link(gitignore):
            try:
                raw = gitignore.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                raw = ""
            for line in raw.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                neg = s.startswith("!")
                if neg:
                    s = s[1:].strip()
                if not s:
                    continue
                dir_only = s.endswith("/")
                s = s.rstrip("/")
                if s.startswith("/"):
                    s = s[1:]
                self._rules.append((neg, s, dir_only))

    def is_ignored(self, rel_posix: str, *, is_dir: bool = False) -> bool:
        parts = PurePosixPath(rel_posix).parts
        if any(is_sensitive_segment(seg) for seg in parts):
            return True
        if matches_user_exclusion(rel_posix, self.exclude_patterns):
            return True
        if any(seg in DEFAULT_SKIP_DIRS for seg in parts):
            return True
        ignored = False
        for neg, pat, dir_only in self._rules:
            if dir_only and not is_dir and not any(fnmatch.fnmatch(p, pat) for p in parts[:-1]):
                continue
            matched = (
                fnmatch.fnmatch(rel_posix, pat)
                or fnmatch.fnmatch(parts[-1], pat)
                or any(fnmatch.fnmatch(p, pat) for p in parts)
            )
            if matched:
                ignored = not neg
        return ignored
