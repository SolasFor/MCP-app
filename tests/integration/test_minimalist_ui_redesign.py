"""Comprehensive tests for the minimalist compact UI redesign, break-ui stress cases & accessibility."""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QShortcut  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLineEdit  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import PROVIDER_CF_NAMED, Settings  # noqa: E402
from app.core.service_manager import Overall, ServiceManager  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.components.table import DataTable  # noqa: E402
from app.ui.connection_diagnostics_dialog import ConnectionDiagnosticsDialog  # noqa: E402
from app.ui.i18n import LANG_RU, i18n  # noqa: E402
from app.ui.main_window import ACTIVE_PAGE_IDS, PAGE_IDS, MainWindow  # noqa: E402
from app.ui.oauth_clients_dialog import OAuthClientsDialog  # noqa: E402
from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog  # noqa: E402
from backend.oauth_execution import ExecutionApprovals  # noqa: E402
from backend.oauth_store import OAuthStore  # noqa: E402


class MinimalistUiRedesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name)
        self.store_path = self.data_dir / "oauth" / "state.sqlite3"
        self._patches = [
            patch("app.paths.user_data_dir", return_value=self.data_dir),
            patch("app.core.service_manager.user_data_dir", return_value=self.data_dir),
            patch("app.core.domain_state.user_data_dir", return_value=self.data_dir),
            patch("app.config.user_data_dir", return_value=self.data_dir),
            patch("app.ui.main_window.user_data_dir", return_value=self.data_dir),
            patch("app.ui.main_window.default_store_path", return_value=self.store_path),
            patch("app.ui.oauth_clients_dialog.default_store_path", return_value=self.store_path),
            patch("app.ui.connection_diagnostics_dialog.user_data_dir", return_value=self.data_dir),
        ]
        for p in self._patches:
            p.start()
        i18n.set_language(LANG_RU)
        self.settings = Settings()
        theme.apply(self.app, theme.THEME_DARK)
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=False)
        self.window.show()
        self.app.processEvents()

    def tearDown(self) -> None:
        self.window.allow_close()
        self.window.close()
        self.app.processEvents()
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def test_responsive_window_sizes_across_all_pages(self) -> None:
        self.assertEqual(len(ACTIVE_PAGE_IDS), 13)
        sizes = (
            (800, 540),
            (960, 640),
            (1024, 680),
            (1120, 760),
            (1280, 800),
            (1440, 900),
        )
        for width, height in sizes:
            self.window.resize(width, height)
            self.app.processEvents()
            for pid in PAGE_IDS:
                self.window.show_page(pid)
                self.app.processEvents()
                self.assertGreater(self.window.sidebar.width(), 0)
                self.assertGreater(self.window._stack.width(), 300)
                if pid == "home":
                    self.assertTrue(self.window.home_page.toggle_btn.isVisible())
                    self.assertGreater(self.window.home_page.copy_field.width(), 200)

    def test_break_ui_oauth_clients_empty_one_hundred_and_long_name(self) -> None:
        public_url = "https://mcp.example.com/mcp"
        store = OAuthStore(self.store_path, "https://mcp.example.com", public_url)

        # 0 clients
        dlg_empty = OAuthClientsDialog(public_url, self.window)
        self.assertEqual(dlg_empty.table.rowCount(), 0)
        self.assertFalse(dlg_empty.table.isVisibleTo(dlg_empty))
        self.assertTrue(dlg_empty.empty_state.isVisibleTo(dlg_empty))
        dlg_empty.close()

        # 1 client with 100-char name
        long_name = "Enterprise-MCP-Integration-Client-" + ("X" * 66)
        store.save_client(
            OAuthClientInformationFull(
                client_id="client-long-001",
                client_name=long_name,
                redirect_uris=["http://127.0.0.1:9001/cb"],  # type: ignore[arg-type]
            )
        )
        dlg_one = OAuthClientsDialog(public_url, self.window)
        self.assertEqual(dlg_one.table.rowCount(), 1)
        self.assertTrue(dlg_one.table.isVisibleTo(dlg_one))
        self.assertEqual(dlg_one.table.textElideMode(), Qt.TextElideMode.ElideRight)
        self.assertLessEqual(dlg_one.table.columnWidth(0), 300)
        dlg_one.close()

        # 100 clients
        for idx in range(2, 101):
            store.save_client(
                OAuthClientInformationFull(
                    client_id=f"client-{idx:03d}",
                    client_name=f"Client #{idx}",
                    redirect_uris=["http://127.0.0.1:9002/cb"],  # type: ignore[arg-type]
                )
            )
        dlg_many = OAuthClientsDialog(public_url, self.window)
        self.assertEqual(dlg_many.table.rowCount(), 100)
        dlg_many.close()

    def test_break_ui_allowlist_empty_and_large(self) -> None:
        store = OAuthStore(self.store_path, "https://mcp.example.com", "https://mcp.example.com/mcp")
        approvals = ExecutionApprovals(store)

        approvals.set_policy(windows="", hosts="", ssh_commands="")
        dlg_empty = ExecutionPolicyDialog(approvals, self.window)
        self.assertEqual(dlg_empty.windows.toPlainText(), "")
        dlg_empty.save()
        dlg_empty.close()

        many_cmds = "\n".join(f"cmd_{i}" for i in range(24))
        approvals.set_policy(windows=many_cmds, hosts="host-a\nhost-b", ssh_commands=many_cmds)
        dlg_many = ExecutionPolicyDialog(approvals, self.window)
        self.assertEqual(len(dlg_many.windows.toPlainText().splitlines()), 24)
        dlg_many.save()
        self.assertEqual(len(approvals.policy()["windows"]), 24)
        dlg_many.close()

    def test_break_ui_states_unconfigured_domain_long_url_paths_and_logs(self) -> None:
        hp = self.window.home_page
        # State sync across all 5 Overall states
        for state in (
            Overall.STOPPED,
            Overall.STARTING,
            Overall.RUNNING,
            Overall.DEGRADED,
            Overall.ERROR,
        ):
            want = state in (Overall.STARTING, Overall.RUNNING, Overall.DEGRADED)
            self.manager._want_running = want
            self.manager._overall = state
            self.window._on_overall(state)
            self.app.processEvents()
            self.assertEqual(hp.error_banner.isVisible(), state == Overall.ERROR)
            self.assertEqual(hp.emergency_btn.isVisible(), want)

        # Unconfigured named domain keeps copy button disabled when URL empty
        self.manager.set_active_provider(PROVIDER_CF_NAMED)
        self.manager._overall = Overall.STOPPED
        self.window._on_overall(Overall.STOPPED)
        self.window._refresh_address()
        self.app.processEvents()
        self.assertEqual(hp.copy_field.full_text(), "")
        self.assertFalse(hp.copy_field.copy_button.isEnabled())

        # 180-char URL preserves exact verbatim text and stays within stack width
        long_url = "https://" + ("subdomain-segment-" * 9) + "example.com/mcp"
        self.assertGreaterEqual(len(long_url), 180)
        hp.set_endpoint(long_url)
        self.app.processEvents()
        self.assertEqual(hp.copy_field.full_text(), long_url)
        self.assertTrue(hp.copy_field.copy_button.isEnabled())
        self.assertLessEqual(hp.copy_field.width(), self.window._stack.width())

        # 220-char path fits elided in DataTable
        long_path = "C:\\Workspaces\\" + ("nested_directory_name\\" * 10) + "repo"
        self.assertGreaterEqual(len(long_path), 220)
        tbl = DataTable(["Name", "Path"])
        tbl.setRowCount(1)
        from PyQt6.QtWidgets import QTableWidgetItem

        tbl.setItem(0, 0, QTableWidgetItem("ws1"))
        tbl.setItem(0, 1, QTableWidgetItem(long_path))
        self.assertEqual(tbl.textElideMode(), Qt.TextElideMode.ElideRight)

        # Empty & 500-line logs + secret redaction
        lv = self.window.logs_page.viewer.log_view
        lv.clear_log()
        self.assertEqual(lv.records_count(), (0, 0))
        secret = self.manager.token
        for i in range(500):
            lv.append_line("server", f"line {i} secret={secret}")
        lv.flush_now()
        self.assertEqual(lv.records_count(), (500, 500))
        self.assertNotIn(secret, lv.plain_text())

        # Token field masked by default
        self.window.show_page("connections")
        self.assertEqual(self.window.connections_page.token_edit.echoMode(), QLineEdit.EchoMode.Password)

    def test_shortcuts_accessibility_and_diagnostics_dialog_hook(self) -> None:
        keys = {sc.key().toString() for sc in self.window.findChildren(QShortcut)}
        self.assertIn("Ctrl+K", keys)
        self.assertIn("Ctrl+B", keys)
        for n in range(1, 10):
            self.assertIn(f"Ctrl+{n}", keys)

        self.assertTrue(self.window.sidebar._collapse_btn.accessibleName())
        self.assertTrue(self.window._palette_top_btn.accessibleName())
        for pid in PAGE_IDS:
            self.assertTrue(self.window.sidebar.button(pid).accessibleName())

        opened: list[tuple[str, int, str]] = []

        def fake_exec(dlg_self: ConnectionDiagnosticsDialog) -> int:
            opened.append(dlg_self._params)
            for _ in range(50):
                self.app.processEvents()
                if dlg_self._worker is None:
                    break
            return int(ConnectionDiagnosticsDialog.DialogCode.Accepted)

        with patch("app.ui.connection_diagnostics_dialog.probe_connection", return_value=[]), patch.object(
            ConnectionDiagnosticsDialog, "exec", fake_exec
        ):
            self.window.home_page.connection_diagnostics_btn.click()

        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0][2], self.settings.server_health_path)

    def test_remove_animations_static_guard(self) -> None:
        ui_root = ROOT / "app" / "ui"
        for py in ui_root.rglob("*.py"):
            src = py.read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(r"\b(QPropertyAnimation|QGraphicsOpacityEffect)\b", src),
                f"Forbidden animation found in {py}",
            )
            if "QVariantAnimation" in src:
                self.assertEqual(
                    py.resolve(),
                    (ui_root / "components" / "toggle_switch.py").resolve(),
                    f"QVariantAnimation is only allowed in toggle_switch.py, found in {py}",
                )


if __name__ == "__main__":
    unittest.main()
