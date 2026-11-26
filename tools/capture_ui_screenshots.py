"""Render real Windows screenshots (Dark & Light) and verify DPI/viewport geometry."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QGuiApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from app.config import Settings  # noqa: E402
from app.core.service_manager import ServiceManager  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.i18n import LANG_EN, LANG_RU, i18n  # noqa: E402
from app.ui.main_window import PAGE_IDS, MainWindow  # noqa: E402


def verify_layout_geometry(scale: str = "1.0") -> dict[str, str]:
    """Instantiate MainWindow under the active Qt scale factor and validate widget rects."""
    os.environ["QT_SCALE_FACTOR"] = scale
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        with patch("app.paths.user_data_dir", return_value=data_dir), patch(
            "app.core.service_manager.user_data_dir", return_value=data_dir
        ), patch("app.core.domain_state.user_data_dir", return_value=data_dir), patch(
            "app.config.user_data_dir", return_value=data_dir
        ), patch("app.ui.theme.user_data_dir", return_value=data_dir, create=True), patch(
            "app.ui.main_window.default_store_path", return_value=data_dir / "oauth" / "state.sqlite3"
        ):
            i18n.set_language(LANG_RU)
            settings = Settings()
            theme.apply(app, theme.THEME_DARK)
            mgr = ServiceManager(settings)
            win = MainWindow(mgr, settings, tray_available=False)
            for width, height in ((800, 540), (960, 640), (1440, 900)):
                win.resize(width, height)
                win.show()
                app.processEvents()
                for pid in PAGE_IDS:
                    win.show_page(pid)
                    app.processEvents()
                    assert win.sidebar.width() > 0, f"sidebar width invalid on {pid}"
                    assert win._stack.width() > 300, f"stack clipped on {pid} at {width}x{height} scale={scale}"
                    assert win.home_page.toggle_btn.sizeHint().width() > 0
            win.allow_close()
            win.close()
    return {"scale": scale, "status": "OK"}


def capture_screenshots(out_dir: Path) -> list[Path]:
    """Capture Dark & Light screenshots in docs/screenshots using an isolated temp dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication([])
    saved: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        with patch("app.paths.user_data_dir", return_value=data_dir), patch(
            "app.core.service_manager.user_data_dir", return_value=data_dir
        ), patch("app.core.domain_state.user_data_dir", return_value=data_dir), patch(
            "app.config.user_data_dir", return_value=data_dir
        ), patch("app.ui.main_window.default_store_path", return_value=data_dir / "oauth" / "state.sqlite3"):
            i18n.set_language(LANG_RU)
            settings = Settings()
            theme.apply(app, theme.THEME_DARK)
            mgr = ServiceManager(settings)
            mgr._quick_url = "https://mcp-preview.trycloudflare.com/mcp"
            win = MainWindow(mgr, settings, tray_available=False)
            win.resize(960, 640)
            win.show()
            app.processEvents()

            # Sample redacted logs for logs screenshot
            win.logs_page.viewer.log_view.append_line("app", "✔ MCP-app v1.0.0 UI initialized")
            win.logs_page.viewer.log_view.append_line("server", "Uvicorn running on http://127.0.0.1:8000")
            win.logs_page.viewer.log_view.append_line("tunnel", f"Connected token={mgr.token}")
            win.logs_page.viewer.log_view.append_line("tunnel", "WRN edge reconnect in 2s")
            win.logs_page.viewer.log_view.flush_now()

            # 1. Home Dark (RU)
            win.set_theme_mode(theme.THEME_DARK)
            win.set_language(LANG_RU)
            win.show_page("home")
            win.toasts.clear_all()
            app.processEvents()
            p1 = out_dir / "home-dark.png"
            win.grab().save(str(p1))
            saved.append(p1)

            # 2. Home Light (RU)
            win.set_theme_mode(theme.THEME_LIGHT)
            win.show_page("home")
            win.toasts.clear_all()
            app.processEvents()
            p2 = out_dir / "home-light.png"
            win.grab().save(str(p2))
            saved.append(p2)

            # 3. Connections Dark (EN)
            win.set_theme_mode(theme.THEME_DARK)
            win.set_language(LANG_EN)
            win.show_page("connections")
            win.toasts.clear_all()
            app.processEvents()
            p3 = out_dir / "connections-dark.png"
            win.grab().save(str(p3))
            saved.append(p3)

            # 4. Logs Light (RU)
            win.set_theme_mode(theme.THEME_LIGHT)
            win.set_language(LANG_RU)
            win.show_page("logs")
            win.toasts.clear_all()
            app.processEvents()
            p4 = out_dir / "logs-light.png"
            win.grab().save(str(p4))
            saved.append(p4)

            # 5. Security Dark (RU) - Default access profile & Computer Use ToggleSwitches
            win.set_theme_mode(theme.THEME_DARK)
            win.set_language(LANG_RU)
            win.show_page("security")
            win.toasts.clear_all()
            app.processEvents()
            p5 = out_dir / "security-dark.png"
            win.grab().save(str(p5))
            saved.append(p5)

            # 6. Security Light (RU) - Light theme verification of disabled toggles
            win.set_theme_mode(theme.THEME_LIGHT)
            win.show_page("security")
            win.toasts.clear_all()
            app.processEvents()
            p5_light = out_dir / "security-light.png"
            win.grab().save(str(p5_light))
            saved.append(p5_light)

            # 7. Settings Dark (RU) - Persistent Logging & Appearance
            win.set_theme_mode(theme.THEME_DARK)
            win.show_page("settings")
            win.toasts.clear_all()
            app.processEvents()
            p6 = out_dir / "settings-dark.png"
            win.grab().save(str(p6))
            saved.append(p6)

            win.allow_close()
            win.close()
    return saved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dpi-worker", default="", help="Internal worker scale factor")
    parser.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    args = parser.parse_args()

    if args.dpi_worker:
        res = verify_layout_geometry(args.dpi_worker)
        print(f"DPI check scale={res['scale']}: {res['status']}")
        return 0

    for scale in ("1.0", "1.25", "1.5", "1.75", "2.0"):
        env = dict(os.environ)
        env["QT_SCALE_FACTOR"] = scale
        subprocess.run(
            [sys.executable, str(__file__), "--dpi-worker", scale],
            check=True,
            env=env,
        )

    files = capture_screenshots(Path(args.out))
    for path in files:
        print(f"Saved {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
