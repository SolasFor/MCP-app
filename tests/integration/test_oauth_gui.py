"""Headless Qt test for local OAuth client management and immediate revocation."""
from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication, QMessageBox

from app.ui.oauth_clients_dialog import OAuthClientsDialog
from backend.oauth_store import OAuthStore
from mcp.shared.auth import OAuthClientInformationFull

BASE = "https://stable.example.com"
RESOURCE = BASE + "/mcp"


class OAuthGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth" / "connections.sqlite3"
        self.store = OAuthStore(self.path, BASE, RESOURCE)
        self.store.bind_owner("local-owner-token")
        self.store.save_client(OAuthClientInformationFull(
            client_id="gui-client-1",
            client_name="Test connection",
            redirect_uris=["http://127.0.0.1:3105/callback"],
            token_endpoint_auth_method="none",
        ))
        self.store.mark_approved("gui-client-1")
        self.path_patch = patch("app.ui.oauth_clients_dialog.default_store_path", return_value=self.path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.tmp.cleanup()

    def test_gui_shows_client_but_not_secrets(self):
        dialog = OAuthClientsDialog(RESOURCE)
        self.assertEqual(dialog.table.rowCount(), 1)
        self.assertEqual(dialog.table.item(0, 0).text(), "Test connection")
        self.assertEqual(dialog.table.item(0, 1).text(), "Разрешён")
        dialog.close()

    def test_rights_column_has_per_client_scenario_dropdown(self):
        from backend.oauth_execution import ExecutionApprovals
        dialog = OAuthClientsDialog(RESOURCE)
        select = dialog.table.cellWidget(0, 2)
        self.assertIsNotNone(select)
        self.assertFalse(hasattr(dialog, "policy_button"))
        self.assertEqual(
            [select.itemData(i) for i in range(select.count())],
            ["safe", "allowlist", "full"],
        )
        self.assertEqual(select.currentData(), "safe")
        select.setCurrentIndex(select.findData("allowlist"))
        state = ExecutionApprovals(self.store)
        self.assertEqual(state.profile_for("gui-client-1"), "allowlist")
        self.assertEqual(state.profile(), "safe")
        dialog.reload()
        self.assertEqual(dialog.table.cellWidget(0, 2).currentData(), "allowlist")
        dialog.close()

    def test_full_access_requires_explicit_confirmation_and_can_be_revoked(self):
        from backend.oauth_execution import ExecutionApprovals
        dialog = OAuthClientsDialog(RESOURCE)
        combo = dialog.table.cellWidget(0, 2)
        full = combo.findData("full")
        with patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.No):
            combo.setCurrentIndex(full)
        self.assertEqual(combo.currentData(), "safe")
        self.assertEqual(ExecutionApprovals(self.store).profile_for("gui-client-1"), "safe")
        with patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes):
            combo.setCurrentIndex(full)
        self.assertEqual(ExecutionApprovals(self.store).profile_for("gui-client-1"), "full")
        combo.setCurrentIndex(combo.findData("safe"))
        self.assertEqual(ExecutionApprovals(self.store).profile_for("gui-client-1"), "safe")
        dialog.close()

    def test_restore_basic_commands_preserves_ssh_policy(self):
        from backend.oauth_execution import ExecutionApprovals, DEFAULT_WINDOWS_ALLOWLIST
        from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog
        settings = ExecutionApprovals(self.store)
        settings.set_policy(windows="", hosts="trusted.example", ssh_commands="uptime")
        dialog = ExecutionPolicyDialog(settings)
        self.assertEqual(dialog.windows.toPlainText(), "")
        dialog.reset_windows.click()
        self.assertEqual(
            dialog.windows.toPlainText(), "\n".join(DEFAULT_WINDOWS_ALLOWLIST)
        )
        # The reset is a proposed UI change until the user saves.
        self.assertEqual(settings.policy()["windows"], ())
        dialog.save()
        self.assertEqual(settings.policy()["windows"], DEFAULT_WINDOWS_ALLOWLIST)
        self.assertEqual(settings.policy()["hosts"], ("trusted.example",))
        self.assertEqual(settings.policy()["ssh_commands"], ("uptime",))

    def test_revoke_button_revokes_in_live_backend_store(self):
        dialog = OAuthClientsDialog(RESOURCE)
        dialog.table.selectRow(0)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            dialog.revoke_selected()
        self.assertEqual(dialog.table.rowCount(), 0)
        self.assertIsNone(self.store.get_client("gui-client-1"))
        dialog.close()


if __name__ == "__main__":
    unittest.main()
