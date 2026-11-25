"""Serialized, fail-closed DesktopManager for interactive Windows Computer Use (v0.9.6)."""
from __future__ import annotations

import fnmatch
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from backend.desktop.backend_base import DesktopBackend
from backend.desktop.models import (
    MAX_WAIT_TIMEOUT_S,
    SENSITIVE_TITLE_KEYWORDS,
    DesktopPolicy,
    DesktopPolicyStore,
    ScreenshotResult,
)

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}


class DesktopManager:
    """Enforces opt-in policy, locked-session/UIPI/title guards, serialization, and secret protection."""

    def __init__(
        self,
        policy_store: DesktopPolicyStore,
        backend: DesktopBackend,
        *,
        redactor: SecretRedactor | None = None,
        emergency_stop_checker: Callable[[], bool] | None = None,
    ) -> None:
        self.policy_store = policy_store
        self.backend = backend
        self.redactor = redactor or SecretRedactor()
        self.emergency_stop_checker = emergency_stop_checker
        self._op_lock = threading.Lock()

    @staticmethod
    def _is_sensitive_title(title: str, policy: DesktopPolicy) -> bool:
        low = (title or "").casefold()
        if any(kw in low for kw in SENSITIVE_TITLE_KEYWORDS):
            return True
        for pat in policy.blocked_title_patterns:
            if fnmatch.fnmatch(low, pat.casefold()):
                return True
        return False

    def _authorize(
        self,
        client_id: str | None,
        client_profile: str,
        *,
        require_screen: bool = False,
        require_control: bool = False,
        target_hwnd: int | None = None,
    ) -> DesktopPolicy:
        if self.emergency_stop_checker is not None and self.emergency_stop_checker():
            raise PermissionError("Global emergency stop is active")
        policy = self.policy_store.load()
        if policy.emergency_stop:
            raise PermissionError("Computer Use emergency stop is active")
        if not policy.enabled:
            raise PermissionError("Computer Use is disabled by owner")
        if require_screen and not policy.allow_screen_capture:
            raise PermissionError("Screen capture and UI tree inspection are not enabled by owner")
        if require_control and not policy.allow_input_control:
            raise PermissionError("Desktop window and input control are not enabled by owner")

        if client_id not in (None, "", "owner"):
            if _PROFILE_RANK.get(client_profile, 0) < _PROFILE_RANK.get(policy.min_profile, 1):
                raise PermissionError("OAuth client profile does not permit Computer Use")
            if policy.allowed_clients and client_id not in policy.allowed_clients:
                raise PermissionError(f"Client {client_id!r} is not in Computer Use allowed_clients")

        session = self.backend.check_session_state()
        if not session.interactive or session.locked or session.secure_desktop:
            raise PermissionError(
                f"Fail closed: interactive desktop unavailable ({session.reason or 'locked/secure desktop'})"
            )

        if target_hwnd is not None:
            if self.backend.is_window_elevated(target_hwnd):
                raise PermissionError("Refusing to inspect or control an elevated window (UIPI boundary)")
            for win in self.backend.list_windows(include_minimized=True):
                if win.hwnd == target_hwnd and self._is_sensitive_title(win.title, policy):
                    raise PermissionError("Refusing access to protected credential/security window")

        return policy

    def _run_serialized(
        self,
        tool_name: str,
        client_id: str | None,
        fn: Callable[[], Any],
    ) -> Any:
        with self._op_lock:
            self.policy_store.set_activity(True, client_id=str(client_id or "owner"), tool=tool_name)
            try:
                return fn()
            finally:
                self.policy_store.set_activity(False)

    def _redact_window_list(self, policy: DesktopPolicy, windows: list[Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for win in windows:
            d = win.to_dict()
            if self._is_sensitive_title(win.title, policy) or win.elevated:
                d["title"] = "[PROTECTED WINDOW]"
                d["protected"] = True
            else:
                d["title"] = self.redactor.redact_text(win.title)
                d["protected"] = False
            out.append(d)
        return out

    def screenshot(
        self,
        *,
        client_id: str | None,
        client_profile: str,
        monitor_index: int | None = None,
        hwnd: int | None = None,
        max_width: int | None = None,
    ) -> ScreenshotResult:
        def work() -> ScreenshotResult:
            pol = self._authorize(
                client_id, client_profile, require_screen=True, target_hwnd=hwnd
            )
            eff_width = min(pol.max_image_width, int(max_width)) if max_width else pol.max_image_width
            return self.backend.capture_screenshot(
                monitor_index=monitor_index,
                hwnd=hwnd,
                max_width=eff_width,
                max_bytes=pol.max_image_bytes,
            )

        return self._run_serialized("desktop_screenshot", client_id, work)

    def list_monitors(self, *, client_id: str | None, client_profile: str) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_screen=True)
            mons = self.backend.list_monitors()
            return {"monitors": [m.to_dict() for m in mons]}

        return self._run_serialized("desktop_list_monitors", client_id, work)

    def list_windows(
        self,
        *,
        client_id: str | None,
        client_profile: str,
        include_minimized: bool = False,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            pol = self._authorize(client_id, client_profile, require_screen=True)
            wins = self.backend.list_windows(include_minimized=include_minimized)
            return {"windows": self._redact_window_list(pol, wins)}

        return self._run_serialized("desktop_list_windows", client_id, work)

    def open_app(
        self,
        executable: str,
        *,
        args: tuple[str, ...] = (),
        cwd: str = "",
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            pol = self._authorize(client_id, client_profile, require_control=True)
            if pol.allowed_apps:
                exe_name = Path(executable).name.casefold()
                allowed = {a.casefold() for a in pol.allowed_apps}
                if exe_name not in allowed and executable.casefold() not in allowed:
                    raise PermissionError(f"Application {exe_name!r} is not in allowed_apps")
            return self.backend.open_app(executable, args=args, cwd=cwd)

        return self._run_serialized("desktop_open_app", client_id, work)

    def close_window(self, hwnd: int, *, client_id: str | None, client_profile: str) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            ok = self.backend.close_window(hwnd)
            return {"hwnd": hwnd, "close_requested": ok}

        return self._run_serialized("desktop_close_window", client_id, work)

    def focus_window(
        self,
        hwnd: int,
        *,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            win = self.backend.focus_window(hwnd, x=x, y=y, width=width, height=height)
            return win.to_dict()

        return self._run_serialized("desktop_focus_window", client_id, work)

    def get_ui_tree(
        self,
        *,
        hwnd: int | None = None,
        max_depth: int = 4,
        max_nodes: int = 200,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_screen=True, target_hwnd=hwnd)
            return self.backend.get_ui_tree(hwnd=hwnd, max_depth=max_depth, max_nodes=max_nodes)

        return self._run_serialized("desktop_get_ui_tree", client_id, work)

    def click(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
        x: int | None = None,
        y: int | None = None,
        button: str = "left",
        double: bool = False,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            if automation_id or name or control_type:
                invoked, elem = self.backend.invoke_element(
                    hwnd=hwnd, name=name, automation_id=automation_id, control_type=control_type
                )
                if invoked and button.lower() == "left" and not double:
                    return {"method": "uia_invoke", "element": elem}
                if elem is not None:
                    b = elem.get("bounds") or {}
                    bw, bh = int(b.get("width") or 0), int(b.get("height") or 0)
                    if bw > 0 and bh > 0:
                        cx = int(b["x"]) + bw // 2
                        cy = int(b["y"]) + bh // 2
                        self.backend.mouse_click(cx, cy, button=button, double=double)
                        return {"method": "uia_bounds_click", "x": cx, "y": cy, "element": elem}
                if x is None or y is None:
                    raise LookupError("UIA element was not found and no fallback coordinates were supplied")
            if x is None or y is None:
                raise ValueError("Provide UIA selector (automation_id/name) or explicit (x, y) coordinates")
            self.backend.mouse_click(int(x), int(y), button=button, double=double)
            return {"method": "coordinate_click", "x": int(x), "y": int(y)}

        return self._run_serialized("desktop_click", client_id, work)

    def type_text(
        self,
        text: str,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            pol = self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            if not isinstance(text, str) or not text or "\x00" in text:
                raise ValueError("Non-empty text without NUL bytes is required")
            if not pol.allow_secret_typing and self.redactor.redact_text(text) != text:
                raise PermissionError("Typing registered secret values is blocked unless allow_secret_typing=True")
            if automation_id or name:
                elem = self.backend.find_element(hwnd=hwnd, name=name, automation_id=automation_id)
                if elem is None:
                    raise LookupError("Target UIA input element was not found")
                if elem.get("is_password") and not pol.allow_secret_typing:
                    raise PermissionError("Typing into password fields is blocked unless allow_secret_typing=True")
                ok, used = self.backend.set_element_value(
                    text=text, hwnd=hwnd, name=name, automation_id=automation_id
                )
                if ok:
                    return {"method": "uia_value", "typed_chars": len(text), "element": used}
                b = (used or elem).get("bounds") or {}
                if int(b.get("width") or 0) > 0 and int(b.get("height") or 0) > 0:
                    self.backend.mouse_click(
                        int(b["x"]) + int(b["width"]) // 2,
                        int(b["y"]) + int(b["height"]) // 2,
                    )
            self.backend.type_text(text)
            return {"method": "keyboard_sendinput", "typed_chars": len(text)}

        return self._run_serialized("desktop_type", client_id, work)

    def keypress(
        self,
        keys: str,
        *,
        hwnd: int | None = None,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            if hwnd is not None:
                self.backend.focus_window(hwnd)
            self.backend.send_keypress(keys)
            return {"keys": keys, "sent": True}

        return self._run_serialized("desktop_keypress", client_id, work)

    def scroll(
        self,
        delta: int,
        *,
        x: int | None = None,
        y: int | None = None,
        horizontal: bool = False,
        hwnd: int | None = None,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            self.backend.mouse_scroll(int(delta), x=x, y=y, horizontal=horizontal)
            return {"delta": int(delta), "horizontal": bool(horizontal)}

        return self._run_serialized("desktop_scroll", client_id, work)

    def drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        button: str = "left",
        steps: int = 10,
        hwnd: int | None = None,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        def work() -> dict[str, Any]:
            self._authorize(client_id, client_profile, require_control=True, target_hwnd=hwnd)
            self.backend.mouse_drag(
                int(start_x), int(start_y), int(end_x), int(end_y), button=button, steps=steps
            )
            return {
                "start": [int(start_x), int(start_y)],
                "end": [int(end_x), int(end_y)],
                "button": button,
            }

        return self._run_serialized("desktop_drag", client_id, work)

    def wait_for_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
        timeout_seconds: float = 5.0,
        poll_interval: float = 0.25,
        client_id: str | None,
        client_profile: str,
    ) -> dict[str, Any]:
        if not (automation_id or name or control_type):
            raise ValueError("Specify at least one selector (automation_id, name, or control_type)")
        cap = max(0.1, min(float(timeout_seconds), MAX_WAIT_TIMEOUT_S))
        interval = max(0.05, min(float(poll_interval), 2.0))
        deadline = time.monotonic() + cap
        while True:
            with self._op_lock:
                self._authorize(client_id, client_profile, require_screen=True, target_hwnd=hwnd)
                found = self.backend.find_element(
                    hwnd=hwnd, name=name, automation_id=automation_id, control_type=control_type
                )
            if found is not None:
                return {"found": True, "element": found}
            if time.monotonic() >= deadline:
                return {"found": False, "element": None}
            time.sleep(interval)
