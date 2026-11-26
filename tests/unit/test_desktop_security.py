"""Unit security tests for Stage 8 Computer Use: fail-closed locks, UIPI, secrets, PNG bounds, DPI coords."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from backend.desktop.backend_base import DesktopBackend
from backend.desktop.manager import DesktopManager
from backend.desktop.models import (
    DesktopPolicy,
    DesktopPolicyStore,
    MonitorInfo,
    ScreenshotResult,
    SessionState,
    WindowInfo,
)
from backend.desktop.png_codec import encode_bgra_to_png
from backend.desktop.win32_backend import normalize_virtual_coords


class _FakeBackend(DesktopBackend):
    def __init__(self) -> None:
        self.session = SessionState(interactive=True, locked=False, secure_desktop=False, desktop_name="Default")
        self.elevated_hwnds: set[int] = {999}
        self.active_ops = 0
        self.max_concurrent_ops = 0
        self.lock = threading.Lock()
        self.calls: list[tuple[str, Any]] = []
        self.windows = [
            WindowInfo(
                hwnd=101, title="Test Notepad", class_name="Notepad", pid=1001,
                process_name="notepad.exe", x=10, y=20, width=800, height=600,
                minimized=False, active=True, elevated=False,
            ),
            WindowInfo(
                hwnd=999, title="Administrator Prompt", class_name="Console", pid=9999,
                process_name="cmd.exe", x=0, y=0, width=400, height=300,
                minimized=False, active=False, elevated=True,
            ),
            WindowInfo(
                hwnd=777, title="KeePass Password Vault", class_name="KeePass", pid=7777,
                process_name="keepass.exe", x=50, y=50, width=500, height=400,
                minimized=False, active=False, elevated=False,
            ),
        ]

    def _enter_op(self) -> None:
        with self.lock:
            self.active_ops += 1
            self.max_concurrent_ops = max(self.max_concurrent_ops, self.active_ops)

    def _exit_op(self) -> None:
        with self.lock:
            self.active_ops -= 1

    def check_session_state(self) -> SessionState:
        return self.session

    def is_window_elevated(self, hwnd: int) -> bool:
        return hwnd in self.elevated_hwnds

    def list_monitors(self) -> list[MonitorInfo]:
        return [
            MonitorInfo(0, "DISPLAY1", True, 0, 0, 1920, 1080, 0, 0, 1920, 1040, 144, 144),
            MonitorInfo(1, "DISPLAY2", False, 1920, -120, 1920, 1080, 1920, -120, 1920, 1040, 96, 96),
        ]

    def list_windows(self, *, include_minimized: bool = False) -> list[WindowInfo]:
        return list(self.windows)

    def capture_screenshot(self, *, monitor_index=None, hwnd=None, max_width=1280, max_bytes=1_500_000) -> ScreenshotResult:
        self._enter_op()
        try:
            time.sleep(0.03)
            png, w, h = encode_bgra_to_png(b"\x10\x20\x30\xff" * (64 * 48), 64, 48, max_width=max_width, max_bytes=max_bytes)
            return ScreenshotResult(png_bytes=png, width=w, height=h, scale_percent=150, source="mock")
        finally:
            self._exit_op()

    def open_app(self, executable: str, args=(), cwd="") -> dict[str, Any]:
        return {"pid": 4321, "executable": executable}

    def close_window(self, hwnd: int) -> bool:
        self.calls.append(("close", hwnd))
        return True

    def focus_window(self, hwnd: int, *, x=None, y=None, width=None, height=None) -> WindowInfo:
        self.calls.append(("focus", hwnd))
        return self.windows[0]

    def get_ui_tree(self, *, hwnd=None, max_depth=4, max_nodes=200) -> dict[str, Any]:
        return {"hwnd": hwnd, "nodes_captured": 2, "truncated": False, "root": {"control_type": "Window", "name": "Test Notepad", "children": []}}

    def find_element(self, *, hwnd=None, name="", automation_id="", control_type="") -> dict[str, Any] | None:
        if automation_id == "pwd_box":
            return {"control_type": "Edit", "name": "[REDACTED PASSWORD FIELD]", "automation_id": "pwd_box", "bounds": {"x": 50, "y": 50, "width": 100, "height": 24}, "enabled": True, "is_password": True}
        if automation_id == "ok_btn" or name == "OK":
            return {"control_type": "Button", "name": "OK", "automation_id": "ok_btn", "bounds": {"x": 100, "y": 100, "width": 80, "height": 30}, "enabled": True, "is_password": False}
        return None

    def invoke_element(self, *, hwnd=None, name="", automation_id="", control_type=""):
        elem = self.find_element(hwnd=hwnd, name=name, automation_id=automation_id, control_type=control_type)
        if elem:
            self.calls.append(("invoke", automation_id or name))
            return True, elem
        return False, None

    def set_element_value(self, *, text: str, hwnd=None, name="", automation_id=""):
        elem = self.find_element(hwnd=hwnd, name=name, automation_id=automation_id)
        if elem and not elem.get("is_password"):
            self.calls.append(("set_value", text))
            return True, elem
        return False, elem

    def mouse_click(self, x: int, y: int, *, button="left", double=False) -> None:
        self.calls.append(("click", x, y, button, double))

    def type_text(self, text: str) -> None:
        self.calls.append(("type", text))

    def send_keypress(self, keys: str) -> None:
        self.calls.append(("keypress", keys))

    def mouse_scroll(self, delta: int, *, x=None, y=None, horizontal=False) -> None:
        self.calls.append(("scroll", delta))

    def mouse_drag(self, start_x: int, start_y: int, end_x: int, end_y: int, *, button="left", steps=10) -> None:
        self.calls.append(("drag", start_x, start_y, end_x, end_y))


class DesktopSecurityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DesktopPolicyStore(Path(self.tmp.name) / "policy.json")
        self.backend = _FakeBackend()
        self.redactor = SecretRedactor(["top-secret-token-123"])
        self.global_stopped = False
        self.manager = DesktopManager(
            self.store,
            self.backend,
            redactor=self.redactor,
            emergency_stop_checker=lambda: self.global_stopped,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_disabled_by_default_and_client_profile_isolation(self) -> None:
        with self.assertRaises(PermissionError):
            self.manager.list_windows(client_id="client-a", client_profile="full")

        # Enable view-only for client-a only
        self.store.save(
            DesktopPolicy(
                enabled=True,
                allow_screen_capture=True,
                allow_input_control=False,
                allowed_clients=("client-a",),
            )
        )
        # Unlisted client, safe client, and control actions must fail closed
        with self.assertRaises(PermissionError):
            self.manager.list_windows(client_id="stranger", client_profile="full")
        with self.assertRaises(PermissionError):
            self.manager.list_windows(client_id="client-a", client_profile="safe")
        with self.assertRaises(PermissionError):
            self.manager.click(x=10, y=10, client_id="client-a", client_profile="allowlist")

        wins = self.manager.list_windows(client_id="client-a", client_profile="allowlist")["windows"]
        # Elevated and sensitive windows must be masked
        self.assertEqual(wins[0]["title"], "Test Notepad")
        self.assertEqual(wins[1]["title"], "[PROTECTED WINDOW]")
        self.assertEqual(wins[2]["title"], "[PROTECTED WINDOW]")

    def test_locked_session_uac_uipi_secrets_and_emergency_stop_fail_closed(self) -> None:
        self.store.save(
            DesktopPolicy(
                enabled=True,
                allow_screen_capture=True,
                allow_input_control=True,
                allow_secret_typing=False,
            )
        )
        # Locked session -> fail closed
        self.backend.session = SessionState(interactive=False, locked=True, secure_desktop=True, desktop_name="Winlogon", reason="Locked")
        with self.assertRaises(PermissionError):
            self.manager.screenshot(client_id="c1", client_profile="allowlist")

        # Restore unlocked session
        self.backend.session = SessionState(interactive=True, locked=False, secure_desktop=False, desktop_name="Default")

        # Elevated HWND (999) and KeePass HWND (777) -> fail closed
        with self.assertRaises(PermissionError):
            self.manager.focus_window(999, client_id="c1", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.manager.close_window(777, client_id="c1", client_profile="allowlist")

        # Password field and registered secret blocked
        with self.assertRaises(PermissionError):
            self.manager.type_text("my-pass", hwnd=101, automation_id="pwd_box", client_id="c1", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.manager.type_text("token is top-secret-token-123", hwnd=101, client_id="c1", client_profile="allowlist")

        # Global emergency stop & local emergency stop both block calls
        self.global_stopped = True
        with self.assertRaises(PermissionError):
            self.manager.list_monitors(client_id="c1", client_profile="allowlist")
        self.global_stopped = False

        self.store.set_emergency_stop(True, "owner clicked stop")
        with self.assertRaises(PermissionError):
            self.manager.list_monitors(client_id="c1", client_profile="allowlist")

    def test_serialization_uia_preference_png_codec_and_multimonitor_coords(self) -> None:
        self.store.save(
            DesktopPolicy(enabled=True, allow_screen_capture=True, allow_input_control=True)
        )
        # Concurrent calls must serialize strictly (max_concurrent_ops == 1)
        errors: list[Exception] = []

        def run_shot() -> None:
            try:
                self.manager.screenshot(client_id="c1", client_profile="allowlist")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=run_shot) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.backend.max_concurrent_ops, 1)

        # Click prefers UIA InvokePattern when selector is present
        res = self.manager.click(hwnd=101, automation_id="ok_btn", x=5, y=5, client_id="c1", client_profile="allowlist")
        self.assertEqual(res["method"], "uia_invoke")

        # PNG codec bounds width and size in memory
        large_bgra = bytes((i % 256 for i in range(1600 * 100 * 4)))
        png, w, h = encode_bgra_to_png(large_bgra, 1600, 100, max_width=800, max_bytes=120_000)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertLessEqual(w, 800)
        self.assertGreater(h, 0)
        self.assertLessEqual(len(png), 120_000)

        # Virtual desktop coordinate normalization (including negative secondary monitor offset)
        nx0, ny0 = normalize_virtual_coords(0, -120, 0, -120, 3840, 1200)
        self.assertEqual((nx0, ny0), (0, 0))
        nx1, ny1 = normalize_virtual_coords(3839, 1079, 0, -120, 3840, 1200)
        self.assertEqual((nx1, ny1), (65535, 65535))


if __name__ == "__main__":
    unittest.main()
