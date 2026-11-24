"""OS platform adapters (zero-Qt)."""
from __future__ import annotations

import sys

from app.platform.base import (
    PlatformAdapter,
    ProcessIdentity,
    ProcessJobHandle,
    TerminationReport,
)

_ADAPTER: PlatformAdapter | None = None


def get_platform() -> PlatformAdapter:
    """Return the singleton platform adapter for the current OS."""
    global _ADAPTER
    if _ADAPTER is None:
        if sys.platform == "win32":
            from app.platform.windows import WindowsPlatformAdapter

            _ADAPTER = WindowsPlatformAdapter()
        else:
            from app.platform.posix import PosixPlatformAdapter

            _ADAPTER = PosixPlatformAdapter()
    return _ADAPTER


__all__ = [
    "PlatformAdapter",
    "ProcessIdentity",
    "ProcessJobHandle",
    "TerminationReport",
    "get_platform",
]
