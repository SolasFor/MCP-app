"""Live interactive Windows desktop smoke test for Stage 8 Computer Use.

Spawns a real visible PyQt6 test window in the active Windows desktop session,
runs Win32DesktopBackend through DesktopManager (monitors, DPI, window focus,
PNG in-memory screenshot, native UIAutomation tree, UIA button click, typing
into normal QLineEdit, password field refusal, and clean window close).
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QMetaObject, Qt, QTimer
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.redaction import SecretRedactor  # noqa: E402
from backend.desktop import (  # noqa: E402
    DesktopManager,
    DesktopPolicy,
    DesktopPolicyStore,
    Win32DesktopBackend,
)


def main() -> int:
    if sys.platform != "win32":
        print("LIVE DESKTOP SMOKE SKIPPED: Windows only")
        return 0
    if os.environ.get("QT_QPA_PLATFORM", "").lower() == "offscreen":
        print("FAIL: Cannot run live desktop smoke with QT_QPA_PLATFORM=offscreen")
        return 2

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    win = QWidget()
    title = f"MCPApp-Live-ComputerUse-Smoke-{os.getpid()}"
    win.setWindowTitle(title)
    win.resize(420, 260)
    win.move(120, 120)

    layout = QVBoxLayout(win)
    count = [0]
    click_event = threading.Event()
    text_event = threading.Event()
    captured_text: list[str] = [""]
    status_lbl = QLabel("Clicks: 0")
    btn = QPushButton("Smoke Action Button")
    btn.setObjectName("smoke_btn")
    btn.setAccessibleName("Smoke Action Button")

    def _on_clicked() -> None:
        count[0] += 1
        status_lbl.setText(f"Clicks: {count[0]}")
        click_event.set()

    btn.clicked.connect(_on_clicked)

    text_edit = QLineEdit()
    text_edit.setObjectName("smoke_text")
    text_edit.setAccessibleName("Smoke Text Input")

    def _on_text_changed(value: str) -> None:
        captured_text[0] = value
        if "hello-live-123" in value:
            text_event.set()

    text_edit.textChanged.connect(_on_text_changed)

    pwd_edit = QLineEdit()
    pwd_edit.setObjectName("smoke_pwd")
    pwd_edit.setAccessibleName("Smoke Password Field")
    pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)

    layout.addWidget(status_lbl)
    layout.addWidget(btn)
    layout.addWidget(text_edit)
    layout.addWidget(pwd_edit)
    win.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    win.show()
    win.raise_()
    win.activateWindow()

    results: dict[str, object] = {}

    def run_checks(hwnd: int) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = DesktopPolicyStore(Path(tmp) / "policy.json")
            store.save(
                DesktopPolicy(
                    enabled=True,
                    allow_screen_capture=True,
                    allow_input_control=True,
                    allow_secret_typing=False,
                )
            )
            backend = Win32DesktopBackend()
            mgr = DesktopManager(store, backend, redactor=SecretRedactor())
            try:
                sess = backend.check_session_state()
                assert sess.interactive and not sess.locked, f"Session not interactive: {sess}"
                mons = mgr.list_monitors(client_id="owner", client_profile="full")["monitors"]
                assert len(mons) >= 1, "No monitors detected"
                wins = mgr.list_windows(client_id="owner", client_profile="full")["windows"]
                assert any(w["hwnd"] == hwnd for w in wins), "Test window not visible in EnumWindows"

                focused = mgr.focus_window(
                    hwnd, x=140, y=140, width=440, height=280, client_id="owner", client_profile="full"
                )
                assert focused["hwnd"] == hwnd

                shot = mgr.screenshot(hwnd=hwnd, client_id="owner", client_profile="full")
                assert shot.png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                assert 0 < len(shot.png_bytes) <= 1_500_000

                tree = mgr.get_ui_tree(hwnd=hwnd, max_depth=4, max_nodes=100, client_id="owner", client_profile="full")
                assert tree["nodes_captured"] >= 2

                click_res = mgr.click(
                    hwnd=hwnd,
                    name="Smoke Action Button",
                    control_type="Button",
                    client_id="owner",
                    client_profile="full",
                )
                assert click_event.wait(2.0) and count[0] >= 1, f"Button click failed ({click_res}, count={count[0]})"

                mgr.type_text(
                    "hello-live-123",
                    hwnd=hwnd,
                    name="Smoke Text Input",
                    client_id="owner",
                    client_profile="full",
                )
                assert text_event.wait(2.0), f"Typed text missing: {captured_text[0]!r}"

                pwd_blocked = False
                try:
                    mgr.type_text(
                        "secret-value",
                        hwnd=hwnd,
                        name="Smoke Password Field",
                        client_id="owner",
                        client_profile="full",
                    )
                except PermissionError:
                    pwd_blocked = True
                assert pwd_blocked, "Password field was not blocked"

                closed = mgr.close_window(hwnd, client_id="owner", client_profile="full")
                time.sleep(0.1)
                assert closed and not win.isVisible(), "Window did not close cleanly"

                results.update({
                    "monitors": len(mons),
                    "dpi_primary": mons[0]["scale_percent"],
                    "screenshot_bytes": len(shot.png_bytes),
                    "screenshot_size": [shot.width, shot.height],
                    "ui_nodes": tree["nodes_captured"],
                    "click_method": click_res["method"],
                    "typed_text": captured_text[0],
                    "password_blocked": pwd_blocked,
                    "window_closed": closed,
                })
            except Exception as exc:
                results["error"] = repr(exc)
            finally:
                QMetaObject.invokeMethod(app, "quit", Qt.ConnectionType.QueuedConnection)

    workers: list[threading.Thread] = []

    def _start_worker() -> None:
        hwnd = int(win.winId())
        t = threading.Thread(target=run_checks, args=(hwnd,), daemon=True)
        workers.append(t)
        t.start()

    QTimer.singleShot(250, _start_worker)
    QTimer.singleShot(20000, app.quit)
    app.exec()
    for t in workers:
        t.join(timeout=5)

    if "error" in results:
        print("LIVE DESKTOP SMOKE FAIL:", results["error"])
        return 1
    if "monitors" not in results or not results.get("password_blocked"):
        print("LIVE DESKTOP SMOKE FAIL: Incomplete results:", results)
        return 1
    print("LIVE DESKTOP SMOKE PASS:", results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
