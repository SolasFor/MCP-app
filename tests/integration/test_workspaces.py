"""Integration tests for Stage 7 Workspaces: real project + venv task, patch/diff, Git, isolation, GUI."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shutil
import subprocess
import tempfile
import unittest
import venv
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.workspaces_page import WorkspaceProfileDialog, WorkspacesPage
from backend.process_runner import ProcessRunner
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.store import WorkspaceStore


class WorkspacesIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.proj = self.base / "sample_project"
        (self.proj / "tests").mkdir(parents=True)
        (self.proj / "calc.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8"
        )
        (self.proj / "tests" / "test_calc.py").write_text(
            "import os, unittest\n"
            "from calc import add\n"
            "class CalcTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        print('SECRET_CHECK=' + os.environ.get('WS_TOKEN', ''))\n"
            "        self.assertEqual(add(2, 3), 5)\n"
            "if __name__ == '__main__': unittest.main()\n",
            encoding="utf-8",
        )
        # Create a real minimal Python venv (stdlib only, no pip needed)
        venv_dir = self.proj / ".venv"
        venv.create(venv_dir, with_pip=False)

        self.has_git = bool(shutil.which("git"))
        if self.has_git:
            subprocess.run(["git", "init"], cwd=self.proj, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "CI"], cwd=self.proj, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=self.proj, check=True, capture_output=True)
            subprocess.run(["git", "add", "calc.py", "tests/test_calc.py"], cwd=self.proj, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=self.proj, check=True, capture_output=True)

        self.redactor = SecretRedactor()
        self.store = WorkspaceStore(
            self.base / "workspaces.json",
            secret_store=SecretStore(self.base / "secrets"),
        )
        self.history = WorkspaceHistory(self.base / "history")
        self.runner = ProcessRunner(spool_dir=self.base / "spool", redactor=self.redactor)
        self.manager = WorkspaceManager(
            self.store, self.history, runner=self.runner, redactor=self.redactor
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.runner.close()
        self.tmp.cleanup()

    def test_search_patch_diff_venv_tests_git_and_client_isolation(self) -> None:
        secret_ref = self.store.set_env_secret("sample", "WS_TOKEN", "workspace-top-secret-888")
        prof = WorkspaceProfile(
            workspace_id="sample",
            name="Sample Project",
            root_path=str(self.proj),
            language="python",
            git_root=str(self.proj) if self.has_git else "",
            python_venv=str(self.proj / ".venv"),
            commands={"test": "python -m unittest discover -s tests -p test_*.py -v"},
            env_secret_refs={"WS_TOKEN": secret_ref},
            permissions=WorkspacePermissions(read=True, write=False, delete=False, execute=False, git=False),
            client_permissions={
                "dev-client": WorkspacePermissions(read=True, write=True, delete=True, execute=True, git=True),
                "reader-client": WorkspacePermissions(read=True, write=False, delete=False, execute=False, git=True),
            },
            allowed_clients=("dev-client", "reader-client"),
            min_profile="allowlist",
        )
        self.store.upsert_workspace(prof)

        # Unlisted client & safe profile denied
        with self.assertRaises(PermissionError):
            self.manager.workspace_info("sample", client_id="stranger", client_profile="full")
        with self.assertRaises(PermissionError):
            self.manager.read_file("sample", "calc.py", client_id="dev-client", client_profile="safe")

        # Reader cannot write, delete, or run tasks
        read_res = self.manager.read_file("sample", "calc.py", client_id="reader-client", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.manager.apply_patch(
                "sample",
                "calc.py",
                expected_sha256=read_res["sha256"],
                edits=[{"old_text": "a - b", "new_text": "a + b"}],
                client_id="reader-client",
                client_profile="allowlist",
            )
        with self.assertRaises(PermissionError):
            import asyncio
            asyncio.run(self.manager.run_workspace_task("sample", "test", client_id="reader-client", client_profile="allowlist"))

        # Search before fix
        search_res = self.manager.search_files("sample", "a - b", client_id="dev-client", client_profile="allowlist")
        self.assertEqual(len(search_res["matches"]), 1)
        self.assertEqual(search_res["matches"][0]["path"], "calc.py")

        # Patch bug with dev-client
        patched = self.manager.apply_patch(
            "sample",
            "calc.py",
            expected_sha256=read_res["sha256"],
            edits=[{"old_text": "return a - b", "new_text": "return a + b"}],
            client_id="dev-client",
            client_profile="allowlist",
        )
        self.assertIn("+    return a + b", patched["diff"])

        # Snapshot diff shows change
        snap_diff = self.manager.workspace_diff(
            "sample", snapshot_id=patched["snapshot_id"], client_id="dev-client", client_profile="allowlist"
        )
        self.assertIn("+    return a + b", snap_diff["diff"])

        # Run real tests inside workspace python_venv and verify secret redaction in stdout
        import asyncio
        task_res = asyncio.run(
            self.manager.run_workspace_task("sample", "test", client_id="dev-client", client_profile="allowlist")
        )
        self.assertEqual(task_res["exit_code"], 0)
        self.assertIn("SECRET_CHECK=", task_res["stdout"])
        self.assertNotIn("workspace-top-secret-888", task_res["stdout"])

        # Move + Delete
        created = self.manager.write_file(
            "sample", "notes.txt", "temp note\n", create_only=True, client_id="dev-client", client_profile="allowlist"
        )
        moved = self.manager.move_file(
            "sample", "notes.txt", "docs/notes.txt", expected_sha256=created["sha256"], client_id="dev-client", client_profile="allowlist"
        )
        deleted = self.manager.delete_file(
            "sample", "docs/notes.txt", expected_sha256=moved["sha256"], client_id="dev-client", client_profile="allowlist"
        )
        self.assertTrue(deleted["deleted"])

        # Git branch, status, commit, log (when git is available)
        if self.has_git:
            br = self.manager.git_checkout(
                "sample", "feat/fix-add", create=True, client_id="dev-client", client_profile="allowlist"
            )
            self.assertTrue(br["created"])
            st = self.manager.git_status("sample", client_id="reader-client", client_profile="allowlist")
            self.assertIn("feat/fix-add", st["branch"])
            cmt = self.manager.git_commit(
                "sample", "fix add()", paths=["calc.py"], client_id="dev-client", client_profile="allowlist"
            )
            self.assertTrue(cmt["sha"])
            lg = self.manager.git_log("sample", limit=5, client_id="reader-client", client_profile="allowlist")
            self.assertEqual(lg["commits"][0]["subject"], "fix add()")

    def test_headless_workspaces_gui_autodetect_export_and_retranslate(self) -> None:
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        page = WorkspacesPage(
            config_path=self.base / "gui_ws.json",
            history_dir=self.base / "gui_hist",
            secrets_dir=self.base / "gui_sec",
            redactor=self.redactor,
        )
        try:
            dlg = WorkspaceProfileDialog(page.store, is_new=True, parent=page)
            dlg.root_edit.setText(str(self.proj))
            dlg.auto_detect_fields()
            self.assertEqual(dlg.lang_edit.text(), "python")
            self.assertTrue(dlg.venv_edit.text().endswith(".venv"))
            dlg.perm_execute.setChecked(True)
            dlg.secret_env_edit.setPlainText("WS_TOKEN=gui-ws-secret-321")
            dlg._on_accept()
            self.assertIsNotNone(dlg.saved_profile)
            page.save_profile(dlg.saved_profile)  # type: ignore[arg-type]

            self.assertEqual(page.table.rowCount(), 1)
            page.table.selectRow(0)
            page.file_search_edit.setText("CalcTests")
            page.search_in_selected_workspace()
            self.assertIn("test_calc.py", page.details_view.toPlainText())
            self.assertNotIn("gui-ws-secret-321", page.details_view.toPlainText())

            page.export_json()
            cb = QApplication.clipboard()
            if cb is not None:
                self.assertNotIn("gui-ws-secret-321", cb.text())

            i18n.set_language(LANG_EN)
            page.retranslate()
            self.assertEqual(page.add_btn.text(), "Add")
            i18n.set_language(LANG_RU)
            page.retranslate()
        finally:
            page.shutdown()
            i18n.set_language(LANG_RU)
            theme.apply(self.app, theme.THEME_DARK)


if __name__ == "__main__":
    unittest.main()
