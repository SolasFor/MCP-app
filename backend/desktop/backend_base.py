"""Abstract DesktopBackend interface and honest non-Windows/headless fallback."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from backend.desktop.models import MonitorInfo, ScreenshotResult, SessionState, WindowInfo


class DesktopBackend(ABC):
    """OS automation interface for interactive Windows sessions."""

    @abstractmethod
    def check_session_state(self) -> SessionState:
        """Return whether the interactive desktop is unlocked and not on secure desktop."""

    @abstractmethod
    def is_window_elevated(self, hwnd: int) -> bool:
        """Fail-closed check whether `hwnd` belongs to an elevated process relative to MCP-app."""

    @abstractmethod
    def list_monitors(self) -> list[MonitorInfo]:
        """Enumerate connected monitors with virtual bounds and per-monitor DPI."""

    @abstractmethod
    def list_windows(self, *, include_minimized: bool = False) -> list[WindowInfo]:
        """List visible top-level windows with bounds, PID, process name, and elevation status."""

    @abstractmethod
    def capture_screenshot(
        self,
        *,
        monitor_index: int | None = None,
        hwnd: int | None = None,
        max_width: int = 1280,
        max_bytes: int = 1_500_000,
    ) -> ScreenshotResult:
        """Capture an in-memory PNG screenshot without writing image files to disk."""

    @abstractmethod
    def open_app(
        self,
        executable: str,
        args: tuple[str, ...] = (),
        cwd: str = "",
    ) -> dict[str, Any]:
        """Launch a local application without shell interpolation."""

    @abstractmethod
    def close_window(self, hwnd: int) -> bool:
        """Request window closure cleanly via WM_CLOSE."""

    @abstractmethod
    def focus_window(
        self,
        hwnd: int,
        *,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> WindowInfo:
        """Restore/focus a window and optionally reposition/resize it."""

    @abstractmethod
    def get_ui_tree(
        self,
        *,
        hwnd: int | None = None,
        max_depth: int = 4,
        max_nodes: int = 200,
    ) -> dict[str, Any]:
        """Extract bounded Windows UI Automation element tree with password redaction."""

    @abstractmethod
    def find_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> dict[str, Any] | None:
        """Locate the first matching UIA element inside `hwnd` or desktop root."""

    @abstractmethod
    def invoke_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        """Try UIA InvokePattern; return (invoked, matched_element_dict)."""

    @abstractmethod
    def set_element_value(
        self,
        *,
        text: str,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        """Try focusing and setting value via UIA ValuePattern; return (set_ok, element_dict)."""

    @abstractmethod
    def mouse_click(
        self,
        x: int,
        y: int,
        *,
        button: str = "left",
        double: bool = False,
    ) -> None:
        """Perform a mouse click at virtual screen coordinates `(x, y)`."""

    @abstractmethod
    def type_text(self, text: str) -> None:
        """Type Unicode characters cleanly using keyboard input events."""

    @abstractmethod
    def send_keypress(self, keys: str) -> None:
        """Send a named key or key combination (e.g. 'Enter', 'Ctrl+A')."""

    @abstractmethod
    def mouse_scroll(
        self,
        delta: int,
        *,
        x: int | None = None,
        y: int | None = None,
        horizontal: bool = False,
    ) -> None:
        """Scroll mouse wheel vertically or horizontally."""

    @abstractmethod
    def mouse_drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        button: str = "left",
        steps: int = 10,
    ) -> None:
        """Drag pointer smoothly between two virtual screen coordinates."""


class UnavailableDesktopBackend(DesktopBackend):
    """Honest fallback on non-Windows platforms where Windows interactive desktop does not exist."""

    _MSG = "Interactive Windows desktop automation is unavailable on this platform"

    def check_session_state(self) -> SessionState:
        return SessionState(
            interactive=False,
            locked=False,
            secure_desktop=False,
            desktop_name="",
            reason=self._MSG,
        )

    def is_window_elevated(self, hwnd: int) -> bool:
        return True

    def list_monitors(self) -> list[MonitorInfo]:
        raise RuntimeError(self._MSG)

    def list_windows(self, *, include_minimized: bool = False) -> list[WindowInfo]:
        raise RuntimeError(self._MSG)

    def capture_screenshot(
        self,
        *,
        monitor_index: int | None = None,
        hwnd: int | None = None,
        max_width: int = 1280,
        max_bytes: int = 1_500_000,
    ) -> ScreenshotResult:
        raise RuntimeError(self._MSG)

    def open_app(
        self,
        executable: str,
        args: tuple[str, ...] = (),
        cwd: str = "",
    ) -> dict[str, Any]:
        raise RuntimeError(self._MSG)

    def close_window(self, hwnd: int) -> bool:
        raise RuntimeError(self._MSG)

    def focus_window(
        self,
        hwnd: int,
        *,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> WindowInfo:
        raise RuntimeError(self._MSG)

    def get_ui_tree(
        self,
        *,
        hwnd: int | None = None,
        max_depth: int = 4,
        max_nodes: int = 200,
    ) -> dict[str, Any]:
        raise RuntimeError(self._MSG)

    def find_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> dict[str, Any] | None:
        raise RuntimeError(self._MSG)

    def invoke_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        raise RuntimeError(self._MSG)

    def set_element_value(
        self,
        *,
        text: str,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        raise RuntimeError(self._MSG)

    def mouse_click(
        self,
        x: int,
        y: int,
        *,
        button: str = "left",
        double: bool = False,
    ) -> None:
        raise RuntimeError(self._MSG)

    def type_text(self, text: str) -> None:
        raise RuntimeError(self._MSG)

    def send_keypress(self, keys: str) -> None:
        raise RuntimeError(self._MSG)

    def mouse_scroll(
        self,
        delta: int,
        *,
        x: int | None = None,
        y: int | None = None,
        horizontal: bool = False,
    ) -> None:
        raise RuntimeError(self._MSG)

    def mouse_drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        button: str = "left",
        steps: int = 10,
    ) -> None:
        raise RuntimeError(self._MSG)
