"""MCP-app Computer Use package (v0.9.6)."""
from __future__ import annotations

from backend.desktop.backend_base import DesktopBackend, UnavailableDesktopBackend
from backend.desktop.manager import DesktopManager
from backend.desktop.models import (
    DEFAULT_MAX_IMAGE_WIDTH,
    DESKTOP_MIN_PROFILES,
    MAX_SCREENSHOT_BYTES,
    MAX_UI_TREE_DEPTH,
    MAX_UI_TREE_NODES,
    MAX_WAIT_TIMEOUT_S,
    SCHEMA_VERSION,
    SENSITIVE_TITLE_KEYWORDS,
    DesktopPolicy,
    DesktopPolicyStore,
    MonitorInfo,
    ScreenshotResult,
    SessionState,
    UIElementNode,
    WindowInfo,
)
from backend.desktop.png_codec import encode_bgra_to_png
from backend.desktop.win32_backend import Win32DesktopBackend, normalize_virtual_coords

__all__ = [
    "DEFAULT_MAX_IMAGE_WIDTH",
    "DESKTOP_MIN_PROFILES",
    "MAX_SCREENSHOT_BYTES",
    "MAX_UI_TREE_DEPTH",
    "MAX_UI_TREE_NODES",
    "MAX_WAIT_TIMEOUT_S",
    "SCHEMA_VERSION",
    "SENSITIVE_TITLE_KEYWORDS",
    "DesktopBackend",
    "DesktopManager",
    "DesktopPolicy",
    "DesktopPolicyStore",
    "MonitorInfo",
    "ScreenshotResult",
    "SessionState",
    "UIElementNode",
    "UnavailableDesktopBackend",
    "Win32DesktopBackend",
    "WindowInfo",
    "encode_bgra_to_png",
    "normalize_virtual_coords",
]
