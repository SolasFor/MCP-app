"""Integration tests for Stage 5 Task Manager: survives client disconnect + paginated output + TasksPage GUI."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.core.redaction import SecretRedactor
from app.ui.i18n import LANG_RU, i18n
from app.ui.pages.tasks_page import TasksPage
from app.ui.tray import TrayIcon
from backend.process_runner import ProcessRunner
from backend.tasks.manager import TaskManager
from backend.tasks.models import STATUS_QUEUED, STATUS_RUNNING, STATUS_SUCCEEDED, TaskSpec
from backend.tasks.store import TaskStore


class TaskManagerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_background_task_survives_disconnect_and_updates_tasks_gui(self) -> None:
        i18n.set_language(LANG_RU)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            secret = "live-task-secret-xyz"
            redactor = SecretRedactor([secret])
            db_path = root / "tasks" / "tasks.sqlite3"
            spool_dir = root / "tasks" / "spool"
            art_dir = root / "tasks" / "artifacts"

            store = TaskStore(db_path)
            runner = ProcessRunner(spool_dir=spool_dir, redactor=redactor)

            script = (
                "import sys, time; "
                "print('step-1: ' + 'B'*40, flush=True); "
                f"print('leak: {secret}', file=sys.stderr, flush=True); "
                "time.sleep(0.35); "
                "print('step-2: finished-ok', flush=True)"
            )

            async def exec_task(rec, spec):
                return await runner.run_command(
                    [sys.executable, "-c", spec.command],
                    cwd=root,
                    timeout=spec.timeout,
                    client_id=rec.owner_client_id,
                    run_id=rec.spool_run_id or rec.task_id,
                )

            async def run_flow() -> tuple[str, dict, dict]:
                mgr = TaskManager(
                    store,
                    runner,
                    artifacts_dir=art_dir,
                    redactor=redactor,
                    command_executor=exec_task,
                    poll_interval_seconds=0.05,
                )
                try:
                    # 1. Start task & return immediately ("client disconnects" without awaiting completion)
                    rec, dedup = await mgr.submit(
                        owner_client_id="client-reconnect",
                        profile="full",
                        spec=TaskSpec(kind="windows", command=script, timeout=15),
                        title="long-background-job",
                    )
                    self.assertFalse(dedup)
                    task_id = rec.task_id

                    # Open GUI while task is active/queued -> record transition when finished
                    page = TasksPage(
                        db_path=db_path, spool_dir=spool_dir, artifacts_dir=art_dir, redactor=redactor
                    )
                    finished_events: list[tuple[str, str, str]] = []
                    page.task_finished.connect(lambda a, b, c: finished_events.append((a, b, c)))
                    page.reload()
                    self.assertEqual(page.table.rowCount(), 1)
                    # Honest unknown progress shows "—", never fake percent
                    self.assertEqual(page.table.item(0, 5).text(), "—")

                    # Wait in background for task completion (detached from any request context)
                    deadline = time.monotonic() + 8.0
                    while time.monotonic() < deadline:
                        cur = store.get_task(task_id)
                        if cur is not None and cur.status == STATUS_SUCCEEDED:
                            break
                        await asyncio.sleep(0.05)

                    # Reconnect client & verify paginated stdout + redacted stderr + result + artifacts
                    out1 = mgr.read_output(task_id, owner_client_id="client-reconnect", stream="stdout", offset=0, limit=12)
                    self.assertTrue(out1["has_more"])
                    out2 = mgr.read_output(
                        task_id,
                        owner_client_id="client-reconnect",
                        stream="stdout",
                        offset=out1["next_offset"],
                        limit=4096,
                    )
                    combined = out1["text"] + out2["text"]
                    self.assertIn("step-1:", combined)
                    self.assertIn("step-2: finished-ok", combined)

                    err_page = mgr.read_output(task_id, owner_client_id="client-reconnect", stream="stderr")
                    self.assertIn("leak:", err_page["text"])
                    self.assertNotIn(secret, err_page["text"])

                    res = mgr.result_dict(task_id, owner_client_id="client-reconnect")
                    self.assertEqual(res["exit_code"], 0)
                    art = mgr.read_artifacts(
                        task_id, owner_client_id="client-reconnect", artifact_name="result.json"
                    )
                    self.assertNotIn(secret, art["content"])

                    # Poll GUI after completion -> emits task_finished for tray notification
                    page._known_statuses[task_id] = STATUS_RUNNING
                    page.reload()
                    self.assertEqual(finished_events, [(task_id, "long-background-job", STATUS_SUCCEEDED)])
                    self.assertEqual(page.artifact_combo.currentText(), "result.json")
                    self.assertIn("step-2: finished-ok", page.artifact_view.toPlainText())
                    self.assertNotIn(secret, page.artifact_view.toPlainText())

                    # GUI Restart places new queued task into SQLite store
                    page.restart_selected()
                    all_rows = store.list_tasks(limit=10)
                    self.assertEqual(len(all_rows), 2)
                    restarted = next(r for r in all_rows if r.task_id != task_id)
                    self.assertEqual(restarted.parent_task_id, task_id)
                    self.assertEqual(restarted.status, STATUS_QUEUED)

                    # GUI Cancel cancels queued restart cleanly
                    page.table.selectRow(0)
                    page.cancel_selected()

                    return task_id, res, art
                finally:
                    await mgr.close()
                    runner.close()

            tid, res, _art = asyncio.run(run_flow())
            self.assertTrue(tid.startswith("tsk_"))
            self.assertEqual(res["status"], STATUS_SUCCEEDED)

            # Verify TrayIcon.notify_task_event uses silent notification (never QSystemTrayIcon.showMessage)
            with patch.object(TrayIcon, "show_silent_notification") as mock_msg, patch.object(
                TrayIcon, "showMessage"
            ) as mock_audible:
                fake_self = type(
                    "_Dummy",
                    (),
                    {"_should_notify": lambda self: True, "show_silent_notification": mock_msg},
                )()
                TrayIcon.notify_task_event(fake_self, tid, "job", STATUS_SUCCEEDED)
                mock_msg.assert_called_once()
                mock_audible.assert_not_called()


if __name__ == "__main__":
    unittest.main()
