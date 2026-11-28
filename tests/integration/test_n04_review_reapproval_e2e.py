"""GUI E2E integration tests for N04-02 & N04-04 unified manifest re-approval workflow."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.ui import theme
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.manifest_reapproval_dialog import ManifestReapprovalDialog
from app.ui.pages.workspaces_page import WorkspacesPage
from app.ui.workspace_wizard import WorkspaceWizardDialog
from backend.workspaces.discovery import ManifestDriftError


class N04ReviewReapprovalE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.data_dir = self.root / "appdata"
        self.data_dir.mkdir(parents=True)
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.page = WorkspacesPage(
            config_path=self.data_dir / "workspaces" / "workspaces.json",
            history_dir=self.data_dir / "workspaces" / "history",
            secrets_dir=self.data_dir / "workspaces" / "secrets",
            servers_config_path=self.data_dir / "servers" / "managed_servers.json",
            servers_secrets_dir=self.data_dir / "servers" / "secrets",
            tasks_db_path=self.data_dir / "tasks" / "tasks.sqlite3",
            tasks_spool_dir=self.data_dir / "tasks" / "spool",
            tasks_artifacts_dir=self.data_dir / "tasks" / "artifacts",
        )

    def tearDown(self) -> None:
        self.page.shutdown()
        self.page.deleteLater()
        self.app.processEvents()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self._tmp.cleanup()

    def _pump_until(self, predicate, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if predicate():
                return
            time.sleep(0.02)
        self.app.processEvents()
        self.assertTrue(predicate(), "Timed out waiting for wizard or UI operation")

    def test_full_wizard_server_drift_reapproval_cancel_and_relaunch(self) -> None:
        proj = self.root / "py_srv_app"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "py-srv"\ndependencies = ["fastapi"]\n',
            encoding="utf-8",
        )
        (proj / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")

        # 1) Create Workspace + suggested server via Wizard
        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        wiz.show()
        wiz.path_edit.setText(str(proj))
        wiz.start_analysis()
        self._pump_until(lambda: not wiz.is_analyzing())
        wiz.go_next()
        self.assertGreaterEqual(len(wiz._srv_rows), 1)
        wiz._srv_rows[0].enable_cb.setChecked(True)
        wiz.add_manual_command("ping", f'"{sys.executable}" -c "print(\'E2E_PING_OK\')"')
        wiz.go_next()
        wiz.commit()
        wid = wiz.committed_workspace_id or ""
        self.assertEqual(wid, "py_srv_app")
        self.assertEqual(len(wiz.committed_server_names), 1)
        srv_name = wiz.committed_server_names[0]
        wiz.deleteLater()
        self.app.processEvents()

        # Point wizard server to a benign sleep script so start_server actually runs cleanly in E2E
        srv_prof = self.page.server_store.get_profile(srv_name)
        assert srv_prof is not None
        from dataclasses import replace

        self.page.server_store.upsert_profile(
            replace(
                srv_prof,
                argv=(sys.executable, "-c", "import time; time.sleep(1.5)"),
                readiness=replace(srv_prof.readiness, kind="none"),
            )
        )
        self.page.reload()
        self.assertTrue(self.page.select_workspace(wid))

        # First-time execute approval from owner
        idx = self.page.cmd_combo.findData("ping")
        self.assertGreaterEqual(idx, 0)
        self.page.cmd_combo.setCurrentIndex(idx)
        with patch.object(SilentMessageBox, "question", return_value=SilentMessageBox.StandardButton.Yes):
            self.page.run_selected_task()
            self.page.wait_for_pending_ops(timeout=5.0)
        self.assertIn("E2E_PING_OK", self.page.details_view.toPlainText())

        # 2) Modify manifest & add significant lockfile/npm config on disk
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "py-srv"\ndependencies = ["fastapi", "pytest"]\n',
            encoding="utf-8",
        )
        (proj / "package.json").write_text(
            json.dumps({"name": "py-srv", "scripts": {"build": "echo ok", "prebuild": "echo pre"}}),
            encoding="utf-8",
        )
        (proj / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

        # 3) Backend start_server fails closed with ManifestDriftError
        with self.assertRaises(ManifestDriftError):
            self.page.server_manager.start_server(srv_name, client_id="owner", wait_readiness=False, workspace_id=wid)

        # 4) Cancel inside ManifestReapprovalDialog leaves data unchanged and blocks both task and server
        ws_before = self.page.store.path.read_text(encoding="utf-8")
        srv_before = self.page.server_store.path.read_text(encoding="utf-8")
        with patch.object(ManifestReapprovalDialog, "exec", return_value=int(ManifestReapprovalDialog.DialogCode.Rejected)):
            self.page.run_selected_task()
            self.page.wait_for_pending_ops(timeout=2.0)
            self.page._run_server_op("start", srv_name)
            self.page.wait_for_pending_ops(timeout=2.0)
        self.assertEqual(self.page.store.path.read_text(encoding="utf-8"), ws_before)
        self.assertEqual(self.page.server_store.path.read_text(encoding="utf-8"), srv_before)
        self.assertFalse(self.page.server_manager.status_server(srv_name, workspace_id=wid)["running"])

        # 5) Inspect & approve via real ManifestReapprovalDialog across RU/EN & Dark/Light themes
        dlg = ManifestReapprovalDialog(self.page.coordinator, wid, parent=self.page)
        try:
            for lang in (LANG_RU, LANG_EN):
                i18n.set_language(lang)
                for mode in (theme.THEME_DARK, theme.THEME_LIGHT):
                    theme.apply(self.app, mode)
                    dlg.retranslate()
                    dlg.show()
                    self.app.processEvents()
            txt = dlg.preview_view.toPlainText()
            self.assertIn("pyproject.toml", txt)
            self.assertIn("pnpm-lock.yaml", txt)
            self.assertIn(srv_name, txt)
            self.assertIn("hook", txt.lower())
            self.assertFalse(dlg.apply_commands_check.isChecked())
            self.assertFalse(dlg.apply_runtime_check.isChecked())
            dlg.approve()
            self.assertIsNotNone(dlg.commit_result)
        finally:
            dlg.close()
            dlg.deleteLater()
            self.app.processEvents()

        # 6) Both task (with zero extra confirmation prompts!) and wizard server now run cleanly
        self.page.reload()
        self.page.select_workspace(wid)
        idx = self.page.cmd_combo.findData("ping")
        self.page.cmd_combo.setCurrentIndex(idx)
        with patch.object(SilentMessageBox, "question", side_effect=AssertionError("Unexpected prompt after approval")):
            self.page.run_selected_task()
            self.page.wait_for_pending_ops(timeout=5.0)
        self.assertIn("E2E_PING_OK", self.page.details_view.toPlainText())

        self.page._run_server_op("start", srv_name)
        self.page.wait_for_pending_ops(timeout=5.0)
        self.assertTrue(self.page.server_manager.status_server(srv_name, workspace_id=wid)["running"])
        self.page.server_manager.stop_server(srv_name, client_id="owner", workspace_id=wid)

    def test_wizard_rejects_unseen_venv_drift_between_step4_and_commit(self) -> None:
        py_rel = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
        proj = self.root / "wiz_drift_py"
        proj.mkdir()
        (proj / "pyproject.toml").write_text('[project]\nname = "wiz-drift"\ndependencies = ["pytest"]\n', encoding="utf-8")
        v1 = proj / "venv" / py_rel
        v1.parent.mkdir(parents=True)
        v1.write_bytes(b"stub-v1")

        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        try:
            wiz.show()
            wiz.path_edit.setText(str(proj))
            wiz.start_analysis()
            self._pump_until(lambda: not wiz.is_analyzing())
            wiz.go_next()
            self.assertEqual(Path(wiz.venv_edit.text()).name, "venv")
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 3)

            # While Step 4 preview is displayed, `.venv` appears on disk without touching manifests
            v2 = proj / ".venv" / py_rel
            v2.parent.mkdir(parents=True)
            v2.write_bytes(b"stub-v2")

            with patch.object(SilentMessageBox, "warning") as m_warn:
                wiz.commit()
                self.assertEqual(m_warn.call_count, 1)
            self.assertIsNone(wiz.committed_workspace_id)
            self.assertEqual(self.page.store.load_workspaces(), {})

            # Re-analyze so the owner sees `.venv`, then commit succeeds cleanly
            wiz.start_analysis()
            self._pump_until(lambda: not wiz.is_analyzing())
            wiz.go_next()
            self.assertEqual(Path(wiz.venv_edit.text()).name, ".venv")
            wiz.go_next()
            wiz.commit()
            self.assertEqual(wiz.committed_workspace_id, "wiz_drift_py")
            saved = self.page.store.get_workspace("wiz_drift_py")
            assert saved is not None
            self.assertEqual(Path(saved.python_venv).name, ".venv")
        finally:
            wiz.close()
            wiz.deleteLater()
            self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
