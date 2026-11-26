"""Collision-safe atomic file writes with fsync, transient Win32 retry, and user-only ACLs."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from app.platform import get_platform

_TRANSIENT_REPLACE_WINERRORS = frozenset({5, 32})  # ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION
_REPLACE_DELAYS_S = (0.015, 0.04, 0.08)


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
    ensure_private_dir(target.parent, restrict_acl=restrict_acl)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
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
        if restrict_acl:
            # Restrict temp file ACL before publishing it under the target name.
            get_platform().restrict_path_acl(tmp, is_dir=False)
        _replace_with_retry(tmp, target)
        if restrict_acl:
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
