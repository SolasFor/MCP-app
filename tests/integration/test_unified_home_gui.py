"""Qt smoke test for merged Overview/Connection and three global modes."""
from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication, QMessageBox
from app.config import Settings
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.i18n import LANG_RU, i18n
from app.ui.main_window import MainWindow, NAV_TITLES, PAGE_IDS
from backend.oauth_store import OAuthStore
from backend.oauth_execution import ExecutionApprovals

URL = "https://gui-profile.example/mcp"
ISSUER = "https://gui-profile.example"


class UnifiedHomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth" / "state.sqlite3"
        self.store_patch = patch("app.ui.main_window.default_store_path", return_value=self.path)
        self.store_patch.start()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.settings = Settings()
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=False)

    def tearDown(self):
        self.window.allow_close()
        self.window.close()
        self.store_patch.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_only_one_main_page_contains_server_connection_and_profile(self):
        self.assertEqual(
            NAV_TITLES,
            (
                "Главная",
                "Подключения",
                "AI-клиенты",
                "Gateway",
                "Задачи",
                "Серверы",
                "Workspaces",
                "Расширения",
                "Устройства",
                "Безопасность",
                "Журналы",
                "Настройки",
                "Автоматизация",
            ),
        )
        self.assertEqual(self.window._stack.count(), len(PAGE_IDS))
        self.assertTrue(hasattr(self.window, "_toggle"))
        self.assertTrue(hasattr(self.window, "_mode_buttons"))
        self.assertTrue(hasattr(self.window, "_url_copy"))
        self.assertTrue(hasattr(self.window, "_access_profile"))
        self.assertFalse(self.window._access_profile.isEnabled())
        self.assertFalse(hasattr(self.window, "_query_check"))
        self.assertFalse(hasattr(self.window, "_ov_copy_full"))

    def test_gui_profile_selection_is_persistent_and_full_requires_warning(self):
        self.manager._quick_url = URL
        self.window._refresh_access_profile()
        self.assertTrue(self.window._access_profile.isEnabled())
        self.assertEqual(self.window._access_profile.currentData(), "safe")
        backend = ExecutionApprovals(OAuthStore(self.path, ISSUER, URL))

        index = self.window._access_profile.findData("allowlist")
        self.window._access_profile.setCurrentIndex(index)
        self.assertEqual(backend.profile(), "allowlist")

        index = self.window._access_profile.findData("full")
        with patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.No):
            self.window._access_profile.setCurrentIndex(index)
        self.assertEqual(backend.profile(), "allowlist")
        self.assertEqual(self.window._access_profile.currentData(), "allowlist")

        with patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes):
            self.window._access_profile.setCurrentIndex(index)
        self.assertEqual(backend.profile(), "full")
        self.window._access_profile.setCurrentIndex(self.window._access_profile.findData("safe"))
        self.assertEqual(backend.profile(), "safe")


if __name__ == "__main__":
    unittest.main()
