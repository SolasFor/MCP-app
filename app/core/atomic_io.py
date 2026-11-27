"""Collision-safe atomic file writes with fsync, transient Win32 retry, and user-only ACLs."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.platform import get_platform

_TRANSIENT_REPLACE_WINERRORS = frozenset({5, 32})  # ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION
_REPLACE_DELAYS_S = (0.015, 0.03, 0.06, 0.12, 0.25, 0.5)
_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, list[Any]] = {}
_CROSS_LOCKS_GUARD = threading.Lock()
_CROSS_LOCKS: dict[str, threading.RLock] = {}
_CROSS_LOCK_DEPTH: dict[tuple[str, int], int] = {}


def _canonical_lock_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _get_cross_thread_lock(key: str) -> threading.RLock:
    with _CROSS_LOCKS_GUARD:
        lock = _CROSS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _CROSS_LOCKS[key] = lock
        return lock


if sys.platform == "win32":
    import msvcrt

    def _acquire_os_lock(fd: int, timeout: float, lock_path: Path) -> None:
        deadline = time.monotonic() + max(0.5, timeout)
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out waiting for lock: {lock_path}") from None
                time.sleep(0.01)

    def _release_os_lock(fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _acquire_os_lock(fd: int, timeout: float, lock_path: Path) -> None:
        del timeout, lock_path
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _release_os_lock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


@contextmanager
def cross_process_lock(lock_path: Path, timeout: float = 10.0) -> Iterator[None]:
    """Thread-reentrant cross-process exclusive file lock for atomic config updates."""
    target = Path(lock_path)
    key = _canonical_lock_key(target)
    tlock = _get_cross_thread_lock(key)
    tid = threading.get_ident()
    with tlock:
        depth_key = (key, tid)
        depth = _CROSS_LOCK_DEPTH.get(depth_key, 0)
        if depth > 0:
            _CROSS_LOCK_DEPTH[depth_key] = depth + 1
            try:
                yield
            finally:
                _CROSS_LOCK_DEPTH[depth_key] = depth
            return

        if not target.parent.exists():
            ensure_private_dir(target.parent, restrict_acl=True)
        fd = os.open(os.fspath(target), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            _acquire_os_lock(fd, timeout, target)
            get_platform().restrict_path_acl(target, is_dir=False)
            _CROSS_LOCK_DEPTH[depth_key] = 1
            try:
                yield
            finally:
                _CROSS_LOCK_DEPTH.pop(depth_key, None)
                _release_os_lock(fd)
        finally:
            os.close(fd)


@contextmanager
def _path_lock(target: Path):
    """Serialize in-process atomic writes to the same target path."""
    key = os.path.normcase(os.path.abspath(os.fspath(target)))
    with _PATH_LOCKS_GUARD:
        entry = _PATH_LOCKS.get(key)
        if entry is None:
            entry = [threading.Lock(), 0]
            _PATH_LOCKS[key] = entry
        entry[1] += 1
        lock = entry[0]
    try:
        with lock:
            yield
    finally:
        with _PATH_LOCKS_GUARD:
            cur = _PATH_LOCKS.get(key)
            if cur is not None:
                cur[1] -= 1
                if cur[1] <= 0:
                    _PATH_LOCKS.pop(key, None)


def ensure_private_dir(path: Path, *, restrict_acl: bool = True) -> None:
    """Create ``path`` if missing and restrict its ACL to the current user when requested."""
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    if restrict_acl:
        get_platform().restrict_path_acl(target, is_dir=True)


def try_init_private_dir(path: Path) -> bool:
    """Best-effort directory setup for store constructors so UI construction never crashes."""
    try:
        ensure_private_dir(path, restrict_acl=True)
        return True
    except OSError:
        return False


def _replace_with_retry(src: Path, dst: Path) -> None:
    for idx, delay_s in enumerate(_REPLACE_DELAYS_S):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            winerr = getattr(exc, "winerror", None)
            if winerr not in _TRANSIENT_REPLACE_WINERRORS or idx == len(_REPLACE_DELAYS_S) - 1:
                raise
            time.sleep(delay_s)
    os.replace(src, dst)


def atomic_write_bytes(path: Path, data: bytes, *, restrict_acl: bool = True) -> None:
    """Write ``data`` to a unique sibling temp file, fsync, atomically replace, and apply ACL.

    Cleans up the temporary file on any failure (including disk-full ``ENOSPC`` or ``PermissionError``)
    so the existing target file remains intact and no orphan ``.tmp`` files accumulate.
    """
    target = Path(path)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with _path_lock(target):
        if not target.parent.exists():
            ensure_private_dir(target.parent, restrict_acl=restrict_acl)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    # Some virtual/ramdisk filesystems do not support fsync on file descriptors.
                    pass
            acl_applied = True
            if restrict_acl:
                # Restrict temp file ACL before publishing it under the target name.
                acl_applied = bool(get_platform().restrict_path_acl(tmp, is_dir=False))
            _replace_with_retry(tmp, target)
            if restrict_acl and not acl_applied:
                get_platform().restrict_path_acl(target, is_dir=False)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise


def atomic_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    restrict_acl: bool = True,
) -> None:
    """Atomically write UTF-8 (or custom-encoded) text to ``path``."""
    atomic_write_bytes(path, text.encode(encoding), restrict_acl=restrict_acl)


def atomic_write_json(
    path: Path,
    payload: Any,
    *,
    indent: int | None = 2,
    restrict_acl: bool = True,
) -> None:
    """Serialize ``payload`` as UTF-8 JSON and atomically replace ``path``."""
    text = json.dumps(payload, indent=indent, ensure_ascii=False)
    atomic_write_text(path, text, encoding="utf-8", restrict_acl=restrict_acl)
