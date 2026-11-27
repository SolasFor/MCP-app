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
        ), patch("app.ui.main_window.default_store_path", return_value=data_dir / "oauth" / "state.sqlite3"), patch(
            "backend.oauth_store.default_store_path", return_value=data_dir / "oauth" / "state.sqlite3"
        ), patch(
            "app.ui.pages.clients_page.default_store_path", return_value=data_dir / "oauth" / "state.sqlite3"
        ):
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
            win.logs_page.viewer.log_view.append_line("app", "✔ MCP-app v1.0.2 UI initialized")
            win.logs_page.viewer.log_view.append_line("server", "Uvicorn running on http://127.0.0.1:8000")
            win.logs_page.viewer.log_view.append_line("tunnel", f"Connected token={mgr.token}")
            win.logs_page.viewer.log_view.append_line("tunnel", "WRN edge reconnect in 2s")
            win.logs_page.viewer.log_view.flush_now()

            # Seed a sample OAuth client in isolated temp dir for ClientsPage screenshot
            try:
                from mcp.shared.auth import OAuthClientInformationFull

                win.clients_page.set_public_url(mgr.public_url or "https://mcp-preview.trycloudflare.com/mcp")
                if win.clients_page._store is not None and win.clients_page._execution is not None:
                    win.clients_page._store.save_client(
                        OAuthClientInformationFull(
                            client_id="demo-claude-client",
                            client_secret="s" * 24,
                            client_name="Claude Code",
                            redirect_uris=["http://127.0.0.1/cb"],
                            grant_types=["authorization_code", "refresh_token"],
                            response_types=["code"],
                        )
                    )
                    win.clients_page._store.mark_approved("demo-claude-client")
                    win.clients_page._execution.set_client_profile("demo-claude-client", "allowlist")
                    win.clients_page._store.save_client(
                        OAuthClientInformationFull(
                            client_id="demo-chatgpt-client",
                            client_secret="s" * 24,
                            client_name="ChatGPT",
                            redirect_uris=["https://chatgpt.com/aip/callback"],
                            grant_types=["authorization_code", "refresh_token"],
                            response_types=["code"],
                        )
                    )
                    win.clients_page._store.mark_approved("demo-chatgpt-client")
                    win.clients_page._execution.set_client_profile("demo-chatgpt-client", "safe")
            except Exception:
                pass

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

            # 8. AI Clients Dark & Light (RU) - inline scenario combo & context menu button
            win.set_theme_mode(theme.THEME_DARK)
            win.set_language(LANG_RU)
            win.show_page("clients")
            win.clients_page.reload()
            win.toasts.clear_all()
            app.processEvents()
            p7 = out_dir / "clients-dark.png"
            win.grab().save(str(p7))
            saved.append(p7)

            win.set_theme_mode(theme.THEME_LIGHT)
            win.show_page("clients")
            win.clients_page.reload()
            win.toasts.clear_all()
            app.processEvents()
            p8 = out_dir / "clients-light.png"
            win.grab().save(str(p8))
            saved.append(p8)

            # 9. Tasks Dark (RU)
            win.set_theme_mode(theme.THEME_DARK)
            win.show_page("tasks")
            win.toasts.clear_all()
            app.processEvents()
            p9 = out_dir / "tasks-dark.png"
            win.grab().save(str(p9))
            saved.append(p9)

            # 10. Gateway Add Wizard Dark (RU)
            from app.ui.gateway_add_wizard import AddMcpServerWizard

            wiz = AddMcpServerWizard(win.gateway_page.store, parent=win)
            wiz.resize(760, 560)
            wiz.show()
            app.processEvents()
            p10 = out_dir / "gateway-wizard-dark.png"
            wiz.grab().save(str(p10))
            saved.append(p10)
            wiz.close()

            # 11. Workspaces (with integrated linked & unlinked servers) Dark & Light at 1366x768
            try:
                from backend.servers.models import ReadinessConfig, ServerProfile
                from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile

                sample_dir = data_dir / "sample_repo"
                (sample_dir / "src").mkdir(parents=True, exist_ok=True)
                (sample_dir / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
                win.workspaces_page.server_store.upsert_profile(
                    ServerProfile(
                        name="sample_api",
                        display_name="Sample API",
                        template="python_fastapi",
                        argv=(sys.executable, "-m", "http.server", "8081"),
                        cwd=str(sample_dir),
                        host="127.0.0.1",
                        port=8081,
                        readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=8081),
                    )
                )
                win.workspaces_page.server_store.upsert_profile(
                    ServerProfile(
                        name="standalone_redis",
                        display_name="Standalone Worker",
                        argv=(sys.executable, "-m", "http.server", "8082"),
                        cwd=str(data_dir),
                        host="127.0.0.1",
                        port=8082,
                    )
                )
                win.workspaces_page.store.upsert_workspace(
                    WorkspaceProfile(
                        workspace_id="mcp_demo",
                        name="MCP Demo Project",
                        root_path=str(sample_dir),
                        language="python",
                        commands={"test": f'"{sys.executable}" -m unittest'},
                        linked_servers=("sample_api",),
                        permissions=WorkspacePermissions(read=True, write=True, delete=False, execute=True, git=True),
                    )
                )
            except Exception:
                pass
            win.resize(1366, 768)
            win.set_theme_mode(theme.THEME_DARK)
            win.set_language(LANG_RU)
            win.show_page("workspaces")
            win.workspaces_page.detail_tabs.setCurrentIndex(2)
            win.toasts.clear_all()
            app.processEvents()
            p11 = out_dir / "workspaces-dark.png"
            win.grab().save(str(p11))
            saved.append(p11)

            win.set_theme_mode(theme.THEME_LIGHT)
            win.show_page("workspaces")
            win.toasts.clear_all()
            app.processEvents()
            p12 = out_dir / "workspaces-light.png"
            win.grab().save(str(p12))
            saved.append(p12)

            win.allow_close()
            win.close()

    # 11. OAuth Consent browser pages (Dark RU + Light EN) rendered via Playwright if available
    try:
        import time

        from mcp.server.auth.provider import AuthorizationParams
        from mcp.shared.auth import OAuthClientInformationFull
        from playwright.sync_api import sync_playwright

        from backend.oauth_provider import LocalConsentOAuthProvider, PendingConsent

        prov_ru = LocalConsentOAuthProvider(
            "https://mcp.example.com",
            "https://mcp.example.com/mcp",
            "preview-secret",
            default_profile="allowlist",
        )
        pending_ru = PendingConsent(
            client=OAuthClientInformationFull(
                client_id="cid-1",
                client_name="ChatGPT",
                redirect_uris=["https://chatgpt.com/aip/callback"],
            ),
            params=AuthorizationParams(
                state="st-1",
                scopes=["mcp:read", "mcp:exec"],
                code_challenge="cc",
                redirect_uri="https://chatgpt.com/aip/callback",
                redirect_uri_provided_explicitly=True,
            ),
            expires_at=time.time() + 300,
        )
        html_ru = prov_ru._consent_form_html(pending_ru, "preview-req-1", lang="ru")

        prov_en = LocalConsentOAuthProvider(
            "https://mcp.example.com",
            "https://mcp.example.com/mcp",
            "preview-secret",
            default_profile="full",
        )
        pending_en = PendingConsent(
            client=OAuthClientInformationFull(
                client_id="cid-2",
                client_name="Claude Code",
                redirect_uris=["http://127.0.0.1:4567/callback"],
            ),
            params=AuthorizationParams(
                state="st-2",
                scopes=["mcp:read", "mcp:exec"],
                code_challenge="cc",
                redirect_uri="http://127.0.0.1:4567/callback",
                redirect_uri_provided_explicitly=True,
            ),
            expires_at=time.time() + 300,
        )
        html_en = prov_en._consent_form_html(pending_en, "preview-req-2", lang="en")

        with sync_playwright() as pw:
            br = pw.chromium.launch(headless=True)
            try:
                for scheme, html_doc, fname in (
                    ("dark", html_ru, "oauth-consent-dark-ru.png"),
                    ("light", html_en, "oauth-consent-light-en.png"),
                ):
                    ctx = br.new_context(viewport={"width": 640, "height": 820}, color_scheme=scheme)
                    pg = ctx.new_page()
                    pg.set_content(html_doc, wait_until="load")
                    out_p = out_dir / fname
                    pg.screenshot(path=str(out_p), full_page=True)
                    saved.append(out_p)
                    ctx.close()
            finally:
                br.close()
    except Exception as exc:
        print(f"Skipping OAuth Playwright screenshots: {exc}")

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
