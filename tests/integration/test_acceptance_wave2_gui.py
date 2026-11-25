"""Integration tests for Wave 2 GUI Acceptance requirements."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.config import (
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_NONE,
    PROVIDER_TAILSCALE,
    Settings,
)
from app.core import proxy as px
from app.core.logging_manager import LOG_COMPONENTS, LogConfig, configure_logging
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.components.toggle_switch import ToggleSwitch
from app.ui.i18n import LANG_RU, i18n
from app.ui.main_window import MainWindow


class AcceptanceWave2GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings_path = self.root / "settings.json"
        self.oauth_path = self.root / "oauth" / "connections.sqlite3"
        self.policy_path = self.root / "desktop" / "policy.json"
        self.logs_dir = self.root / "logs"

        self.lm = configure_logging(
            base_dir=self.logs_dir,
            config=LogConfig(enabled=True, level="INFO"),
            data_root=self.root,
        )

        self.patches = [
            patch("app.core.service_manager.user_data_dir", return_value=self.root),
            patch("app.paths.user_data_dir", return_value=self.root),
            patch("app.core.token_store.user_data_dir", return_value=self.root),
            patch("app.core.domain_state.user_data_dir", return_value=self.root),
            patch("app.ui.main_window.default_store_path", return_value=self.oauth_path),
            patch.object(Settings, "path", return_value=self.settings_path),
            patch.object(MainWindow, "_oauth_store_path", return_value=self.oauth_path),
        ]
        for p in self.patches:
            p.start()

        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.settings = Settings(default_access_profile="allowlist")
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=True)

    def tearDown(self) -> None:
        self.window.allow_close()
        self.window.close()
        self.lm.shutdown(timeout=2.0)
        for p in reversed(self.patches):
            p.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_unnecessary_notifications_removed_on_theme_and_tray(self) -> None:
        self.assertFalse(hasattr(self.window, "hidden_to_tray"))
        with patch.object(self.window.toasts, "show_toast") as toast_mock:
            t0 = time.perf_counter()
            self.window.set_theme_mode(theme.THEME_LIGHT)
            self.app.processEvents()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.window.set_theme_mode(theme.THEME_DARK)
            self.app.processEvents()
            toast_mock.assert_not_called()
        self.assertLess(elapsed_ms, 200.0)

        # Close when minimize_to_tray_on_close is enabled -> hides window without emitting notifications
        self.window.settings.minimize_to_tray_on_close = True
        self.window.show()
        self.window.close()
        self.assertFalse(self.window.isVisible())

    def test_connections_page_minimal_four_providers_and_paste_token(self) -> None:
        c = self.window.connections_page
        self.assertEqual(
            list(c.provider_rows.keys()),
            [PROVIDER_CF_QUICK, "cloudflare_named", PROVIDER_NGROK, PROVIDER_TAILSCALE],
        )
        self.assertNotIn(PROVIDER_LOCAL, c.provider_rows)
        self.assertNotIn("openai_tunnel", c.provider_rows)

        # Zero detection/version/Loopback badges
        forbidden = ("не найден", "установлен", "доступен", "loopback")
        for pid, (_key, name_lbl, active_badge, _sel, _cfg, _diag) in c.provider_rows.items():
            txt = (name_lbl.text() + " " + active_badge.text()).lower()
            for marker in forbidden:
                self.assertNotIn(marker, txt)
            if pid == PROVIDER_CF_QUICK:
                self.assertFalse(active_badge.isHidden())
            else:
                self.assertTrue(active_badge.isHidden())

        # Legacy local_only migrates to none + banner without auto-enabling tunnel
        c.set_legacy_openai_migration(migrated=True, has_secret=False, migrated_from="local_only")
        self.assertFalse(c.migration_banner.isHidden())
        self.assertIn("Loopback", c.migration_banner.message_label.text())

        # Owner token paste + manual entry
        QApplication.clipboard().setText("  custom-pasted-owner-token-987654  ")
        c.token_paste.click()
        self.assertEqual(c.token_edit.text(), "custom-pasted-owner-token-987654")
        self.assertFalse(c.token_save.isHidden())

    def test_security_page_toggle_switches_autosave_and_rollback(self) -> None:
        sec = self.window.security_page
        self.window.show_page("security")
        self.assertFalse(hasattr(sec, "desktop_save_btn"))
        for attr in ("desktop_enabled_sw", "desktop_screen_sw", "desktop_control_sw", "desktop_secrets_sw"):
            self.assertIsInstance(getattr(sec, attr), ToggleSwitch)

        with patch.object(self.window.toasts, "show_toast") as toast_mock:
            sec.desktop_enabled_sw.click()
            sec.desktop_screen_sw.click()
            self.app.processEvents()
            toast_mock.assert_not_called()

        loaded = sec._desktop_store.load()
        self.assertTrue(loaded.enabled)
        self.assertTrue(loaded.allow_screen_capture)

        sec.desktop_clients_edit.setText("client-a, client-b, client-a")
        sec.desktop_clients_edit.editingFinished.emit()
        self.assertEqual(sec._desktop_store.load().allowed_clients, ("client-a", "client-b"))

        audit_jsonl = self.policy_path.with_name("desktop_policy_audit.jsonl")
        self.assertTrue(audit_jsonl.is_file())
        self.assertIn('"enabled"', audit_jsonl.read_text(encoding="utf-8"))

        # Rollback + silent warning when atomic save fails
        with patch.object(sec._desktop_store, "update", side_effect=OSError("disk full")), patch(
            "app.ui.pages.security_page.SilentMessageBox.warning"
        ) as warn_mock:
            sec.desktop_control_sw.click()
            self.assertTrue(warn_mock.called)
        self.assertFalse(sec.desktop_control_sw.isChecked())

    def test_settings_and_logs_page_persistent_logs_and_zip_export(self) -> None:
        st = self.window.settings_page
        idx = st.logging_level_combo.findData("DEBUG")
        self.assertGreaterEqual(idx, 0)
        st.logging_level_combo.setCurrentIndex(idx)
        st.logging_max_file_spin.setValue(25)
        self.assertEqual(self.settings.logging_level, "DEBUG")
        self.assertEqual(self.settings.logging_max_file_mb, 25)
        self.assertEqual(self.lm.config.level, "DEBUG")

        # Protected security audit must survive log clearing
        audit_file = self.logs_dir / "mcp_execution_audit.jsonl"
        audit_file.write_text('{"event":"keep_me"}\n', encoding="utf-8")
        self.lm.error("oauth", "Redacted sample Bearer super-secret-xyz", event_code="test_err", sync=True)

        viewer = self.window.logs_page.viewer
        self.assertEqual(viewer.component_combo.count(), 1 + len(LOG_COMPONENTS))

        zip_out = self.root / "bundle.zip"
        with patch("app.ui.components.log_viewer.QFileDialog.getSaveFileName", return_value=(str(zip_out), "")):
            viewer.export_log()
        self.assertTrue(zip_out.is_file())
        with zipfile.ZipFile(zip_out, "r") as zf:
            raw_oauth = zf.read("logs/oauth.log").decode("utf-8")
            self.assertNotIn("super-secret-xyz", raw_oauth)

        viewer.clear_logs()
        self.assertEqual(audit_file.read_text(encoding="utf-8"), '{"event":"keep_me"}\n')

    def test_proxy_page_wave2_modes_and_save(self) -> None:
        pp = self.window.connections_page.proxy_page
        cur = pp.current()
        self.assertEqual(cur.mode, px.PROXY_MODE_NONE)
        self.assertEqual(pp.host_edit.text(), "")

        idx_manual = pp.mode_combo.findData(px.PROXY_MODE_MANUAL)
        pp.mode_combo.setCurrentIndex(idx_manual)
        pp.scheme_combo.setCurrentIndex(pp.scheme_combo.findData("http"))
        pp.host_edit.setText("127.0.0.1")
        pp.port_spin.setValue(8080)
        pp._save()
        loaded = px.load()
        self.assertEqual(loaded.mode, px.PROXY_MODE_MANUAL)
        self.assertEqual(loaded.scheme, "http")
        self.assertEqual(loaded.port, 8080)
        self.assertNotEqual(PROVIDER_NONE, "")


if __name__ == "__main__":
    unittest.main()
