"""Headless CI integration tests for Stage 8 Computer Use: 13 tools, ImageContent, GUI opt-in & indicator."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication
from mcp.types import ImageContent, TextContent

from app.config import Settings
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.main_window import MainWindow
from backend.desktop.models import DesktopPolicy
from backend.tool_registry import DESKTOP_TOOLS
from tests.unit.test_desktop_security import _FakeBackend


class DesktopComputerUseIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.oauth_path = self.root / "oauth" / "state.sqlite3"
        self.policy_path = self.root / "desktop" / "policy.json"
        self.settings_path = self.root / "settings.json"
        self.store_patch = patch("app.ui.main_window.default_store_path", return_value=self.oauth_path)
        self.settings_patch = patch.object(Settings, "path", return_value=self.settings_path)
        self.policy_patch = patch.object(ServiceManager, "desktop_policy_path", return_value=self.policy_path)
        self.store_patch.start()
        self.settings_patch.start()
        self.policy_patch.start()
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
        self.policy_patch.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_gui_opt_in_visible_topbar_indicator_and_master_toggle(self) -> None:
        from app.ui.components.toggle_switch import ToggleSwitch

        sec = self.window.security_page
        self.window.show_page("security")
        self.assertIsInstance(sec.desktop_enabled_sw, ToggleSwitch)
        self.assertFalse(hasattr(sec, "desktop_save_btn"))
        self.assertFalse(hasattr(sec, "desktop_stop_btn"))
        self.assertFalse(hasattr(sec, "stop_computer_use"))
        self.assertFalse(sec.desktop_enabled_sw.isChecked())
        self.assertFalse(sec.desktop_screen_sw.isEnabled())
        self.assertFalse(sec.desktop_control_sw.isEnabled())
        self.assertFalse(sec.desktop_secrets_sw.isEnabled())
        self.assertTrue(self.window._desktop_indicator_btn.isHidden())

        # Enable view-only opt-in via ToggleSwitch immediate auto-save (no Save button)
        sec.desktop_clients_edit.setText("c-view")
        sec.desktop_clients_edit.editingFinished.emit()
        sec.desktop_enabled_sw.click()
        self.assertTrue(sec.desktop_screen_sw.isEnabled())
        self.assertTrue(sec.desktop_control_sw.isEnabled())
        self.assertFalse(sec.desktop_secrets_sw.isEnabled())
        sec.desktop_screen_sw.click()
        self.assertFalse(self.window._desktop_indicator_btn.isHidden())
        self.assertIn("Просмотр", self.window._desktop_indicator_btn.text())

        # Enable input control -> indicator updates immediately & unlocks secret typing toggle
        sec.desktop_control_sw.click()
        self.assertTrue(sec.desktop_secrets_sw.isEnabled())
        sec.desktop_secrets_sw.click()
        self.assertIn("Контроль", self.window._desktop_indicator_btn.text())
        self.window.set_language(LANG_EN)
        self.assertIn("Control", self.window._desktop_indicator_btn.text())
        self.window.set_language(LANG_RU)

        # Turn master switch OFF -> dependent toggles become disabled/greyed while preserving saved values
        sec.desktop_enabled_sw.click()
        self.assertFalse(sec.desktop_enabled_sw.isChecked())
        self.assertFalse(sec.desktop_screen_sw.isEnabled())
        self.assertFalse(sec.desktop_control_sw.isEnabled())
        self.assertFalse(sec.desktop_secrets_sw.isEnabled())
        self.assertTrue(sec.desktop_screen_sw.isChecked())
        self.assertTrue(sec.desktop_control_sw.isChecked())
        self.assertTrue(sec.desktop_secrets_sw.isChecked())
        self.assertTrue(self.window._desktop_indicator_btn.isHidden())
        pol_off = sec._desktop_store.load()
        self.assertFalse(pol_off.enabled)
        self.assertTrue(pol_off.allow_screen_capture)
        self.assertTrue(pol_off.allow_input_control)
        self.assertTrue(pol_off.allow_secret_typing)
        self.assertFalse(pol_off.effective_screen_capture)
        self.assertFalse(pol_off.effective_input_control)
        self.assertFalse(pol_off.effective_secret_typing)

        # Turn master switch back ON -> saved choices restore cleanly and become enabled
        sec.desktop_enabled_sw.click()
        self.assertTrue(sec.desktop_screen_sw.isEnabled())
        self.assertTrue(sec.desktop_control_sw.isEnabled())
        self.assertTrue(sec.desktop_secrets_sw.isEnabled())
        self.assertTrue(sec.desktop_screen_sw.isChecked())
        self.assertTrue(sec.desktop_control_sw.isChecked())
        self.assertTrue(sec.desktop_secrets_sw.isChecked())

        # Internal emergency stop mechanism remains functional
        sec._desktop_store.set_emergency_stop(True, "Internal emergency stop")
        sec.reload_desktop_policy()
        self.window._refresh_desktop_indicator()
        loaded = sec._desktop_store.load()
        self.assertTrue(loaded.emergency_stop)
        self.assertFalse(loaded.enabled)
        self.assertTrue(self.window._desktop_indicator_btn.isHidden())
        self.assertFalse(sec.desktop_clear_stop_btn.isHidden())

    def test_mcp_desktop_tools_pipeline_and_image_content(self) -> None:
        import asyncio
        from backend import server
        from mcp.server.auth.provider import AccessToken
        from mcp.shared.auth import OAuthClientInformationFull

        self.assertEqual(len(DESKTOP_TOOLS), 13)
        fake = _FakeBackend()
        server.DESKTOP_POLICY_STORE = server.DesktopPolicyStore(self.policy_path)
        server.DESKTOP_MANAGER = server.DesktopManager(
            server.DESKTOP_POLICY_STORE, fake, redactor=server.REDACTOR
        )
        assert server.oauth_provider is not None and server.oauth_execution is not None
        server.oauth_provider.store.save_client(
            OAuthClientInformationFull(
                client_id="dt-client",
                client_name="DT Client",
                redirect_uris=["http://127.0.0.1:19991/cb"],
                token_endpoint_auth_method="none",
            )
        )
        server.oauth_provider.store.mark_approved("dt-client")
        server.oauth_execution.set_client_profile("dt-client", "allowlist")
        server.DESKTOP_POLICY_STORE.save(
            DesktopPolicy(
                enabled=True,
                allow_screen_capture=True,
                allow_input_control=True,
                allowed_clients=("dt-client",),
            )
        )
        tok = AccessToken(
            token="t",
            client_id="dt-client",
            scopes=["mcp:read"],
            resource=server.RESOURCE_URL,
        )
        with patch("backend.tool_permissions.get_access_token", return_value=tok):
            shot_res = asyncio.run(server.desktop_screenshot())
            self.assertIsInstance(shot_res.content[0], TextContent)
            self.assertIsInstance(shot_res.content[1], ImageContent)
            meta = json.loads(shot_res.content[0].text)
            self.assertFalse(meta["saved_to_disk"])
            self.assertGreater(meta["size_bytes"], 0)

            mons = asyncio.run(server.desktop_list_monitors())
            self.assertEqual(mons["monitors"][0]["scale_percent"], 150)

            tree = asyncio.run(server.desktop_get_ui_tree(hwnd=101))
            self.assertEqual(tree["root"]["name"], "Test Notepad")

            clicked = asyncio.run(server.desktop_click(hwnd=101, automation_id="ok_btn"))
            self.assertEqual(clicked["method"], "uia_invoke")

            wait_res = asyncio.run(server.desktop_wait_for_element(hwnd=101, name="OK", timeout_seconds=0.5))
            self.assertTrue(wait_res["found"])

            asyncio.run(server.desktop_scroll(delta=-2, x=100, y=100))
            asyncio.run(server.desktop_drag(10, 10, 50, 50))
            asyncio.run(server.desktop_keypress("Enter", hwnd=101))
            self.assertTrue(any(c[0] == "keypress" for c in fake.calls))


if __name__ == "__main__":
    unittest.main()
