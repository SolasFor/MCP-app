"""Headless Qt regression tests for Stage 2 UI redesign (themes, RU/EN, sidebar, Ctrl+K, logs, tray)."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from app.config import Settings
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.components.command_palette import CommandPaletteDialog
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.main_window import ACTIVE_PAGE_IDS, PAGE_IDS, PLANNED_PAGE_IDS, MainWindow
from app.ui.tray import TrayIcon


class UiRedesignGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.oauth_path = Path(self.tmp.name) / "oauth" / "state.sqlite3"
        self.settings_path = Path(self.tmp.name) / "settings.json"
        self.store_patch = patch("app.ui.main_window.default_store_path", return_value=self.oauth_path)
        self.settings_patch = patch.object(Settings, "path", return_value=self.settings_path)
        self.store_patch.start()
        self.settings_patch.start()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.settings = Settings()
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=False)

    def tearDown(self) -> None:
        self.window.allow_close()
        self.window.close()
        self.store_patch.stop()
        self.settings_patch.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_all_active_and_planned_pages_are_navigable_and_honest(self) -> None:
        self.assertEqual(len(PAGE_IDS), 13)
        self.assertEqual(len(ACTIVE_PAGE_IDS), 7)
        self.assertEqual(len(PLANNED_PAGE_IDS), 6)
        for idx, pid in enumerate(PAGE_IDS):
            self.window.show_page(pid)
            self.assertEqual(self.window._stack.currentIndex(), idx)
        for pid in PLANNED_PAGE_IDS:
            planned = self.window._planned_pages[pid]
            self.assertTrue(planned.badge.text())
            self.assertIn("v0.9.", planned.badge.text())

    def test_live_theme_and_language_switch_without_restart(self) -> None:
        self.window.set_theme_mode(theme.THEME_LIGHT)
        self.assertEqual(theme.manager().resolved, theme.THEME_LIGHT)
        self.assertEqual(self.settings.theme_mode, theme.THEME_LIGHT)
        self.assertIn("#F8F9FC", self.app.styleSheet())

        self.window.set_language(LANG_EN)
        self.assertEqual(self.settings.language, LANG_EN)
        self.assertEqual(self.window.sidebar.button("home").text(), "Home")
        self.assertEqual(self.window.home_page.toggle_btn.text(), "Start")

        self.window.set_theme_mode(theme.THEME_DARK)
        self.window.set_language(LANG_RU)
        self.assertEqual(self.window.sidebar.button("home").text(), "Главная")
        self.assertIn("#14151A", self.app.styleSheet())

    def test_sidebar_collapse_and_window_geometry_persist(self) -> None:
        self.window.sidebar.set_collapsed(True, emit=True)
        self.assertTrue(self.window.sidebar.is_collapsed)
        self.assertEqual(self.window.sidebar.width(), self.window.sidebar.COLLAPSED_WIDTH)
        self.assertTrue(Settings.load().sidebar_collapsed)

        for w, h in ((860, 600), (1120, 760), (1440, 900)):
            self.window.resize(w, h)
            self.app.processEvents()
            self.assertGreaterEqual(self.window.width(), 860)
            self.assertGreaterEqual(self.window.height(), 600)

    def test_command_palette_filters_and_navigates(self) -> None:
        def drive_dialog() -> None:
            for w in self.app.topLevelWidgets():
                if isinstance(w, CommandPaletteDialog):
                    w.search_input.setText("security")
                    self.app.processEvents()
                    w._run_selected()
                    return

        QTimer.singleShot(25, drive_dialog)
        self.window.open_command_palette()
        self.assertEqual(self.window._current_page_id, "security")

    def test_log_viewer_filters_and_redacts_secrets(self) -> None:
        token = self.manager.token
        lv = self.window.logs_page.viewer.log_view
        lv.append_line("server", f"listening with secret {token}")
        lv.append_line("tunnel", "ERR origin connection failed")
        lv.flush_now()
        self.assertNotIn(token, lv.plain_text())
        lv.set_filters(source="tunnel", level="err")
        shown, total = lv.records_count()
        self.assertEqual(total, 2)
        self.assertEqual(shown, 1)

    def test_tray_icon_updates_language_and_theme_live(self) -> None:
        tray = TrayIcon(self.manager, self.settings, should_notify=lambda: False)
        self.window.set_language(LANG_EN)
        self.assertEqual(tray._act_open.text(), "Show Window")
        self.window.set_theme_mode(theme.THEME_LIGHT)
        self.assertFalse(tray.icon().isNull())


if __name__ == "__main__":
    unittest.main()
