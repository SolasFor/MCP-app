"""E2E GUI integration tests for Stage N04: Workspaces addition wizard."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.ui import theme
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.workspaces_page import WorkspacesPage
from app.ui.workspace_wizard import WorkspaceWizardDialog
from backend.servers.models import ServerProfile
from backend.workspaces.discovery import CommandProposal, ServerProposal, WorkspaceDiscoveryResult


class N04WorkspaceWizardE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
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
        self.assertTrue(predicate(), "Timed out waiting for wizard background operation")

    def test_wizard_four_steps_cancel_zero_writes_and_commit_without_autostart(self) -> None:
        proj = self.root / "web_next"
        (proj / "tests").mkdir(parents=True)
        (proj / "package.json").write_text(
            json.dumps(
                {
                    "name": "web-next",
                    "dependencies": {"next": "15.0.0"},
                    "scripts": {"dev": "next dev -p 3000", "build": "next build"},
                }
            ),
            encoding="utf-8",
        )
        (proj / "tsconfig.json").write_text("{}", encoding="utf-8")

        existing_srv = ServerProfile(
            name="unrelated_srv",
            argv=(sys.executable, "-c", "import time; time.sleep(1)"),
            cwd=str(proj),
            workspace_scoped=False,
            autostart=False,
        )
        self.page.server_store.upsert_profile(existing_srv)
        self.page.reload()

        # 1) Cancel before commit leaves zero workspaces and existing server untouched
        wiz_cancel = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        wiz_cancel.show()
        wiz_cancel.path_edit.setText(str(proj))
        wiz_cancel.start_analysis()
        self._pump_until(lambda: not wiz_cancel.is_analyzing())
        wiz_cancel.reject()
        wiz_cancel.deleteLater()
        self.app.processEvents()
        self.assertEqual(self.page.store.load_workspaces(), {})
        self.assertEqual(self.page.server_store.get_profile("unrelated_srv"), existing_srv)

        # 2) Full 4-step flow with editable commands, read-only default, and no autostart
        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        wiz.resize(760, 520)
        wiz.show()
        wiz.path_edit.setText(str(proj))
        wiz.start_analysis()
        self._pump_until(lambda: not wiz.is_analyzing())

        self.assertEqual(wiz.stack.currentIndex(), 1)
        wiz.go_next()
        self.assertEqual(wiz.stack.currentIndex(), 2)
        self.assertEqual(wiz.lang_edit.text(), "typescript")
        # Edit command manually and add an explicit command
        wiz.add_manual_command("check", f'"{sys.executable}" -c "print(\'WIZ_RUN_OK\')"')

        wiz.go_next()
        self.assertEqual(wiz.stack.currentIndex(), 3)
        self.assertFalse(wiz.allow_oauth_check.isChecked())
        self.assertFalse(wiz.perm_execute.isChecked())
        self.assertIn("deny_all", wiz.preview_view.toPlainText().lower())

        with patch.object(self.page.runtime_proxy, "start_server") as m_start:
            wiz.commit()
            self.assertEqual(m_start.call_count, 0)
        self.assertEqual(wiz.committed_workspace_id, "web_next")
        wiz.deleteLater()
        self.app.processEvents()

        self.page.reload()
        self.assertEqual(self.page.table.rowCount(), 1)
        self.assertTrue(self.page.select_workspace("web_next"))
        saved = self.page.store.get_workspace("web_next")
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertFalse(saved.allow_oauth_clients)
        self.assertFalse(saved.permissions.execute)
        self.assertEqual(self.page.server_store.get_profile("unrelated_srv"), existing_srv)

        # 3) Running a task on newly added read-only workspace asks owner confirmation first
        idx = self.page.cmd_combo.findData("check")
        self.assertGreaterEqual(idx, 0)
        self.page.cmd_combo.setCurrentIndex(idx)
        with patch.object(SilentMessageBox, "question", return_value=SilentMessageBox.StandardButton.No):
            self.page.run_selected_task()
            self.page.wait_for_pending_ops(timeout=3.0)
        self.assertFalse(self.page.store.get_workspace("web_next").permissions.execute)  # type: ignore[union-attr]

        with patch.object(SilentMessageBox, "question", return_value=SilentMessageBox.StandardButton.Yes):
            self.page.run_selected_task()
            self.page.wait_for_pending_ops(timeout=5.0)
        self.assertTrue(self.page.store.get_workspace("web_next").permissions.execute)  # type: ignore[union-attr]
        self.assertIn("WIZ_RUN_OK", self.page.details_view.toPlainText())

    def test_wizard_ignores_stale_background_result_when_root_changes(self) -> None:
        proj_a = self.root / "proj_a"
        proj_b = self.root / "proj_b"
        proj_a.mkdir()
        proj_b.mkdir()
        (proj_b / "pyproject.toml").write_text('[project]\nname="proj_b"\n', encoding="utf-8")

        gate = threading.Event()

        def _slow_or_fast(path, **_kw):
            if Path(path).name == "proj_a":
                gate.wait(timeout=2.0)
                return WorkspaceDiscoveryResult(
                    root_path=str(proj_a),
                    name="proj_a",
                    suggested_id="proj_a",
                    language="javascript",
                    stacks=("javascript",),
                    confidence="medium",
                    commands=(CommandProposal(name="stale_cmd", command="echo stale", source="package.json"),),
                )
            return WorkspaceDiscoveryResult(
                root_path=str(proj_b),
                name="proj_b",
                suggested_id="proj_b",
                language="python",
                stacks=("python",),
                confidence="high",
                commands=(CommandProposal(name="fresh_cmd", command="python -m unittest", source="pyproject.toml"),),
            )

        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        wiz.show()
        try:
            with patch("app.ui.workspace_wizard.analyze_workspace_directory", side_effect=_slow_or_fast):
                wiz.path_edit.setText(str(proj_a))
                wiz.start_analysis()
                wiz.path_edit.setText(str(proj_b))
                wiz.start_analysis()
                gate.set()
                self._pump_until(lambda: not wiz.is_analyzing())
            self.assertEqual(wiz.id_edit.text(), "proj_b")
            self.assertEqual(wiz.lang_edit.text(), "python")
        finally:
            gate.set()
            wiz.close()
            wiz.deleteLater()
            self.app.processEvents()

    def test_wizard_responsive_ru_en_themes_and_break_ui_worst_case(self) -> None:
        long_proj = self.root / ("very_long_monorepo_project_directory_" + "x" * 60)
        long_proj.mkdir()
        worst = WorkspaceDiscoveryResult(
            root_path=str(long_proj),
            name="Aleksandra Wiśniewska-Kowalczyk — 🚀 Проект №1",
            suggested_id="long_ws_id_" + "a" * 50,
            language="typescript",
            stacks=("nextjs", "docker_compose", "python"),
            confidence="medium",
            commands=tuple(
                CommandProposal(name=f"script_{i}", command=f"echo step_{i}_" + ("x" * 80), source="package.json")
                for i in range(16)
            ),
            server_proposals=(
                ServerProposal(
                    name="srv_" + "n" * 40,
                    display_name="VeryLongServerProfileTitle_" + "S" * 50,
                    template="vite_next",
                    cwd=str(long_proj),
                    executable="node",
                    entrypoint="next",
                    port=3000,
                    port_verified=False,
                    source="package.json",
                ),
            ),
        )
        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        try:
            for lang in (LANG_RU, LANG_EN):
                i18n.set_language(lang)
                for mode in (theme.THEME_DARK, theme.THEME_LIGHT):
                    theme.apply(self.app, mode)
                    wiz.retranslate()
                    wiz._apply_discovery_result(worst)
                    wiz.resize(680, 480)
                    wiz.show()
                    self.app.processEvents()
                    self.assertLessEqual(wiz.width(), 800)
                    self.assertGreater(wiz.next_btn.width(), 0)
        finally:
            wiz.close()
            wiz.deleteLater()
            self.app.processEvents()

    def test_wizard_parent_scan_and_manual_fallback(self) -> None:
        parent_dir = self.root / "projects_hub"
        (parent_dir / "py_service").mkdir(parents=True)
        (parent_dir / "py_service" / "pyproject.toml").write_text('[project]\nname="py_service"\n', encoding="utf-8")
        (parent_dir / "unknown_empty").mkdir(parents=True)

        wiz = WorkspaceWizardDialog(
            self.page.store,
            self.page.server_store,
            self.page.coordinator,
            parent=self.page,
        )
        try:
            wiz.show()
            wiz._set_mode("scan")
            wiz.path_edit.setText(str(parent_dir))
            wiz.start_analysis()
            self._pump_until(lambda: not wiz.is_analyzing())
            self.assertEqual(wiz.candidates_list.count(), 1)
            wiz._analyze_selected_candidate()
            self._pump_until(lambda: not wiz.is_analyzing())
            self.assertEqual(wiz.lang_edit.text(), "python")
            wiz._request_manual_form()
            self.assertTrue(wiz.manual_requested)
        finally:
            wiz.close()
            wiz.deleteLater()
            self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
