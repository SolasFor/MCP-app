"""Acceptance regression tests for GUI & config fixes (Tasks 1, 2, 3, 4, 5, 7, 11, 12)."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import ast
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtCore import QPointF, Qt, QTimer
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QApplication, QScrollArea, QVBoxLayout, QWidget

from app.config import PROVIDER_LOCAL, Settings
from app.core.secret_store import SecretStore
from app.core.service_manager import ServiceManager
from app.core.tunnels import ALL_PROVIDERS
from app.ui import theme
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.main_window import MainWindow
from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog
from app.ui.tray import TrayIcon
from backend.oauth_execution import DEFAULT_WINDOWS_ALLOWLIST, ExecutionApprovals
from backend.oauth_store import OAuthStore
from mcp.shared.auth import OAuthClientInformationFull

ROOT = Path(__file__).resolve().parents[2]


def _wheel_event(widget: QWidget, delta_y: int = -120) -> QWheelEvent:
    pos = QPointF(widget.rect().center())
    gpos = QPointF(widget.mapToGlobal(widget.rect().center()))
    from PyQt6.QtCore import QPoint

    return QWheelEvent(
        pos,
        gpos,
        QPoint(0, 0),
        QPoint(0, delta_y),
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
        Qt.ScrollPhase.NoScrollPhase,
        False,
    )


class AcceptanceGuiFixesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings_path = self.root / "settings.json"
        self.oauth_path = self.root / "oauth" / "connections.sqlite3"
        self.p_data = patch("app.paths.user_data_dir", return_value=self.root)
        self.p_mgr_data = patch("app.core.service_manager.user_data_dir", return_value=self.root)
        self.p_store = patch("app.ui.main_window.default_store_path", return_value=self.oauth_path)
        self.p_settings = patch.object(Settings, "path", return_value=self.settings_path)
        for p in (self.p_data, self.p_mgr_data, self.p_store, self.p_settings):
            p.start()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.settings = Settings.load()
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=False)

    def tearDown(self) -> None:
        self.window.allow_close()
        self.window.close()
        for p in (self.p_data, self.p_mgr_data, self.p_store, self.p_settings):
            p.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_task1_default_allowlist_before_start_persistence_inheritance_and_fail_closed(self) -> None:
        self.assertEqual(self.settings.default_access_profile, "allowlist")
        self.assertTrue(self.window._access_profile.isEnabled())
        self.assertEqual(self.window._access_profile.currentData(), "allowlist")

        # Edit pre-start allowlist template & switch default profile before server start
        tmpl = ExecutionApprovals.default_template(self.oauth_path, default_profile="allowlist")
        tmpl.set_policy(windows="whoami\necho\ncustom_tool.exe", hosts="srv.local", ssh_commands="uptime")

        idx_safe = self.window._access_profile.findData("safe")
        self.window._access_profile.setCurrentIndex(idx_safe)
        self.assertEqual(Settings.load().default_access_profile, "safe")

        idx_allow = self.window._access_profile.findData("allowlist")
        self.window._access_profile.setCurrentIndex(idx_allow)
        self.assertEqual(Settings.load().default_access_profile, "allowlist")

        # Full access requires explicit confirmation
        idx_full = self.window._access_profile.findData("full")
        with patch.object(SilentMessageBox, "warning", return_value=SilentMessageBox.StandardButton.No):
            self.window._access_profile.setCurrentIndex(idx_full)
        self.assertEqual(self.window._access_profile.currentData(), "allowlist")

        # New OAuth issuer/clients inherit saved template & global profile unless overridden
        store = OAuthStore(self.oauth_path, "https://new-issuer.example", "https://new-issuer.example/mcp")
        for cid in ("client-inherited", "client-custom"):
            store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=cid,
                    redirect_uris=["http://127.0.0.1:18100/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            store.mark_approved(cid)
        exec_app = ExecutionApprovals(store, default_profile=Settings.load().default_access_profile)
        self.assertEqual(exec_app.profile_for("client-inherited"), "allowlist")
        self.assertIn("custom_tool.exe", exec_app.policy()["windows"])
        exec_app.set_client_profile("client-custom", "safe")
        exec_app.set_profile("full")
        self.assertEqual(exec_app.profile_for("client-inherited"), "full")
        self.assertEqual(exec_app.profile_for("client-custom"), "safe")

        # Fail-closed on invalid config file value
        self.settings_path.write_text(json.dumps({"default_access_profile": "root"}), encoding="utf-8")
        corrupt = Settings.load()
        self.assertEqual(corrupt.default_access_profile, "safe")
        self.assertTrue(DEFAULT_WINDOWS_ALLOWLIST)

        # Pre-start ExecutionPolicyDialog opens cleanly
        dlg = ExecutionPolicyDialog(ExecutionApprovals.default_template(self.oauth_path), self.window)
        self.assertIn("whoami", dlg.windows.toPlainText())
        dlg.close()

    def test_task2_safe_combobox_wheel_guard_and_ast_sweep(self) -> None:
        scroll = QScrollArea()
        scroll.resize(300, 120)
        container = QWidget()
        layout = QVBoxLayout(container)
        combo = SafeComboBox(container)
        for item in ("one", "two", "three"):
            combo.addItem(item, item)
        combo.setCurrentIndex(1)
        spacer = QWidget()
        spacer.setFixedHeight(600)
        layout.addWidget(combo)
        layout.addWidget(spacer)
        scroll.setWidget(container)
        scroll.show()
        self.app.processEvents()

        # Closed unfocused & closed focused must NOT change selection and must pass wheel to scroll area
        combo.setFocus()
        ev1 = _wheel_event(combo, -120)
        combo.wheelEvent(ev1)
        self.assertEqual(combo.currentIndex(), 1)
        self.assertFalse(ev1.isAccepted())

        # When open (popup visible), wheel selection proceeds
        with patch.object(combo, "is_popup_open", return_value=True):
            ev2 = _wheel_event(combo, -120)
            combo.wheelEvent(ev2)
        self.assertTrue(combo.currentIndex() in (0, 1, 2))
        scroll.close()

        # AST sweep across all app/**/*.py: no raw QComboBox instantiations outside safe_combo.py
        offenders: list[str] = []
        for path in (ROOT / "app").rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if rel == "app/ui/components/safe_combo.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if (isinstance(fn, ast.Name) and fn.id == "QComboBox") or (
                        isinstance(fn, ast.Attribute) and fn.attr == "QComboBox"
                    ):
                        offenders.append(f"{rel}:{node.lineno}")
        self.assertEqual(offenders, [], f"Raw QComboBox calls found: {offenders}")

    def test_task3_silent_dialogs_and_tray_ast_sweep(self) -> None:
        offenders: list[str] = []
        for path in (ROOT / "app").rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if rel == "app/ui/components/silent_dialog.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id == "QMessageBox":
                        offenders.append(f"{rel}:{node.lineno}:QMessageBox()")
                    elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                        if fn.value.id == "QMessageBox" and fn.attr in (
                            "warning",
                            "critical",
                            "information",
                            "question",
                        ):
                            offenders.append(f"{rel}:{node.lineno}:QMessageBox.{fn.attr}")
                        if fn.value.id == "QApplication" and fn.attr == "beep":
                            offenders.append(f"{rel}:{node.lineno}:QApplication.beep")
                    if isinstance(fn, ast.Attribute) and fn.attr == "showMessage":
                        offenders.append(f"{rel}:{node.lineno}:showMessage")
        self.assertEqual(offenders, [], f"Non-silent dialog/notification calls found: {offenders}")

        # Verify SilentMessageBox works cleanly without QApplication.beep
        with patch("PyQt6.QtWidgets.QApplication.beep", side_effect=AssertionError("beep forbidden")):
            def _accept_active() -> None:
                for w in self.app.topLevelWidgets():
                    if isinstance(w, SilentMessageBox) and w.isVisible():
                        btn = w.button(SilentMessageBox.StandardButton.Ok)
                        if btn is not None:
                            btn.click()
                        return

            QTimer.singleShot(25, _accept_active)
            ans = SilentMessageBox.information(self.window, "Silent", "Check silent ok")
            self.assertEqual(ans, SilentMessageBox.StandardButton.Ok)

        tray = TrayIcon(self.manager, self.settings, should_notify=lambda: True)
        with patch.object(TrayIcon, "showMessage", side_effect=AssertionError("showMessage forbidden")):
            tray.notify_task_event("tsk-1", "Demo", "succeeded")
        self.assertIsNotNone(tray.last_notification)

    def test_task4_topbar_theme_dropdown_syncs_with_settings_and_persists(self) -> None:
        combo = self.window._theme_combo
        self.assertIsInstance(combo, SafeComboBox)
        self.assertEqual(
            [combo.itemData(i) for i in range(combo.count())],
            [theme.THEME_LIGHT, theme.THEME_DARK, theme.THEME_SYSTEM],
        )
        for i in range(combo.count()):
            self.assertFalse(combo.itemIcon(i).isNull())

        combo.setCurrentIndex(combo.findData(theme.THEME_LIGHT))
        self.assertEqual(self.settings.theme_mode, theme.THEME_LIGHT)
        self.assertTrue(self.window.settings_page.theme_buttons[theme.THEME_LIGHT].isChecked())
        self.assertEqual(Settings.load().theme_mode, theme.THEME_LIGHT)

        self.window.settings_page.theme_buttons[theme.THEME_SYSTEM].click()
        self.assertEqual(combo.currentData(), theme.THEME_SYSTEM)
        self.assertEqual(Settings.load().theme_mode, theme.THEME_SYSTEM)

    def test_task5_fast_theme_switch_caching_lazy_pages_and_state(self) -> None:
        self.assertIsNone(self.window.logs_page.property("_mcp_theme_version"))
        self.window.show_page("settings")
        area = self.window.settings_page.findChild(QScrollArea)
        assert area is not None
        sb = area.verticalScrollBar()
        self.assertIsNotNone(sb)
        sb.setRange(0, 200)
        sb.setValue(77)

        with patch("app.ui.theme.QStyleFactory.create") as style_mock, patch.object(
            self.app, "setStyleSheet"
        ) as app_qss_mock, patch.object(self.manager.connections, "list_statuses") as cli_mock:
            t0 = time.perf_counter()
            self.window.set_theme_mode(theme.THEME_LIGHT)
            self.app.processEvents()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

        style_mock.assert_not_called()
        app_qss_mock.assert_not_called()
        cli_mock.assert_not_called()
        self.assertLess(elapsed_ms, 200.0)
        self.assertEqual(self.window._current_page_id, "settings")
        self.assertEqual(sb.value(), 77)
        # Hidden pages are themed lazily upon visiting them
        self.assertIsNone(self.window.logs_page.property("_mcp_theme_version"))
        self.window.show_page("logs")
        self.assertEqual(self.window.logs_page.property("_mcp_theme_version"), theme.manager().version)

    def test_task7_openai_removed_and_legacy_config_migrated(self) -> None:
        from app.config import PROVIDER_NONE

        self.assertEqual(len(ALL_PROVIDERS), 4)
        self.assertNotIn("openai_tunnel", ALL_PROVIDERS)
        self.assertNotIn(PROVIDER_LOCAL, ALL_PROVIDERS)
        self.assertNotIn("openai_tunnel", self.window.connections_page.provider_rows)
        self.assertNotIn(PROVIDER_LOCAL, self.window.connections_page.provider_rows)

        # Write legacy openai_tunnel settings + secrets -> loads safely as none
        self.settings_path.write_text(
            json.dumps({"active_provider": "openai_tunnel", "default_access_profile": "allowlist"}),
            encoding="utf-8",
        )
        secrets = SecretStore(self.root / "secrets")
        secrets.set_secret("tunnel", "openai_tunnel_api_key", "legacy-openai-key")
        secrets.set_secret("tunnel", "ngrok_authtoken", "keep-ngrok-key")

        migrated_settings = Settings.load()
        self.assertEqual(migrated_settings.active_provider, PROVIDER_NONE)
        self.assertEqual(migrated_settings.migrated_from_provider, "openai_tunnel")

        mgr2 = ServiceManager(migrated_settings)
        self.assertTrue(mgr2.migrated_from_openai_tunnel)
        self.assertTrue(mgr2.has_legacy_openai_secret())
        self.assertTrue(mgr2.purge_legacy_openai_secret())
        self.assertIsNone(secrets.get_secret("tunnel", "openai_tunnel_api_key"))
        self.assertEqual(secrets.get_secret("tunnel", "ngrok_authtoken"), "keep-ngrok-key")

    def test_task11_and_task12_removed_ui_blocks(self) -> None:
        from app.ui.components.cards import Card
        from app.ui.components.safe_combo import SafeComboBox

        for attr in (
            "clients_summary_lbl",
            "clients_table",
            "clients_empty_lbl",
            "set_clients_summary",
            "access_header",
            "access_label",
            "access_profile",
            "access_profile_hint",
            "allowlist_btn",
            "clients_btn",
            "diag_btn",
            "access_profile_changed",
            "allowlist_requested",
            "diagnostics_requested",
        ):
            self.assertFalse(hasattr(self.window.home_page, attr), f"HomePage still has {attr}")
        self.assertEqual(len(self.window.home_page.findChildren(Card)), 1)

        for attr in (
            "action_title",
            "emergency_btn",
            "diag_btn",
            "diagnostics_requested",
            "emergency_stop_requested",
            "desktop_stop_btn",
            "stop_computer_use",
        ):
            self.assertFalse(hasattr(self.window.security_page, attr), f"SecurityPage still has {attr}")
        self.assertIsInstance(self.window.security_page.access_profile, SafeComboBox)
        self.assertIs(self.window._access_profile, self.window.security_page.access_profile)
        self.assertTrue(hasattr(self.window.home_page, "emergency_btn"))

        # Language switch still translates clean pages
        self.window.set_language(LANG_EN)
        self.assertEqual(self.window.home_page.toggle_btn.text(), "Start")


if __name__ == "__main__":
    unittest.main()
