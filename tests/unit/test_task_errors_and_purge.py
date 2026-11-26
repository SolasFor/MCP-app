"""Unit tests for structured MCP task errors, task_start dynamic timeout, and safe inactive purge."""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.types import CallToolResult

from app.core.redaction import SecretRedactor
from backend.process_runner import ProcessRunner
from backend.tasks import (
    TERMINAL_STATUSES,
    TaskManager,
    TaskSpec,
    TaskStore,
)
from backend.tasks.errors import (
    ALL_TASK_ERROR_CODES,
    TASK_ACCESS_DENIED,
    TASK_CANCELLED,
    TASK_COMMAND_NOT_ALLOWED,
    TASK_EXECUTABLE_NOT_FOUND,
    TASK_INTERNAL_ERROR,
    TASK_INVALID_ARGUMENT,
    TASK_INVALID_STATE,
    TASK_INVALID_TIMEOUT,
    TASK_NOT_FOUND,
    TASK_PROCESS_START_FAILED,
    TASK_QUEUE_FULL,
    TASK_STORAGE_ERROR,
    TASK_TIMEOUT,
    TaskToolError,
    build_task_error_result,
    classify_task_exception,
)


class TaskErrorsAndPurgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.db_path = self.root / "tasks.sqlite3"
        self.artifacts_dir = self.root / "artifacts"
        self.spool_dir = self.root / "spool"
        self.redactor = SecretRedactor(["super-secret-token-xyz-999"])
        self.runner = ProcessRunner(spool_dir=self.spool_dir, redactor=self.redactor)
        self.spool = self.runner.spool
        self.store = TaskStore(self.db_path)
        self.manager = TaskManager(
            self.store,
            self.runner,
            artifacts_dir=self.artifacts_dir,
            spool=self.spool,
            redactor=self.redactor,
        )

    def tearDown(self) -> None:
        asyncio.run(self.manager.close())
        self.runner.close()
        self._tmp.cleanup()

    def test_all_13_error_codes_and_structured_call_tool_result(self) -> None:
        self.assertEqual(len(ALL_TASK_ERROR_CODES), 13)
        expected = {
            TASK_NOT_FOUND,
            TASK_ACCESS_DENIED,
            TASK_INVALID_ARGUMENT,
            TASK_INVALID_TIMEOUT,
            TASK_COMMAND_NOT_ALLOWED,
            TASK_INVALID_STATE,
            TASK_QUEUE_FULL,
            TASK_EXECUTABLE_NOT_FOUND,
            TASK_PROCESS_START_FAILED,
            TASK_TIMEOUT,
            TASK_CANCELLED,
            TASK_STORAGE_ERROR,
            TASK_INTERNAL_ERROR,
        }
        self.assertEqual(set(ALL_TASK_ERROR_CODES), expected)

        secret = "super-secret-token-xyz-999"
        err = TaskToolError(
            TASK_PROCESS_START_FAILED,
            f"Process failed using {secret} in C:\\Users\\alice\\secrets.txt",
            details={"task_id": "tsk_1"},
            suggestion="Check stderr log.",
        )
        res = build_task_error_result(err, redactor=self.redactor)
        self.assertIsInstance(res, CallToolResult)
        self.assertTrue(res.is_error)
        sc = res.structured_content
        assert isinstance(sc, dict)
        self.assertFalse(sc["success"])
        self.assertEqual(sc["error"]["code"], TASK_PROCESS_START_FAILED)
        self.assertEqual(sc["error"]["details"]["task_id"], "tsk_1")
        self.assertNotIn(secret, sc["error"]["message"])
        self.assertNotIn("alice\\secrets.txt", sc["error"]["message"])
        payload = json.loads(res.content[0].text)
        self.assertEqual(payload["error"]["code"], TASK_PROCESS_START_FAILED)
        self.assertNotIn(secret, payload["error"]["message"])

    def test_classify_task_exception_hides_cross_client_existence(self) -> None:
        err = classify_task_exception(
            PermissionError("Task 'tsk_secret' does not belong to current client."),
            tool_name="task_status",
            task_id="tsk_secret",
            lookup_operation=True,
        )
        self.assertEqual(err.code, TASK_NOT_FOUND)
        self.assertNotIn("other-client", err.message)

        with self.assertRaises(asyncio.CancelledError):
            classify_task_exception(asyncio.CancelledError(), tool_name="task_start")

    def test_inactive_task_delete_and_purge_preserves_running_and_external_files(self) -> None:
        ids: dict[str, str] = {}
        for label, status, age_offset in (
            ("ok_old", "succeeded", -40 * 86400),
            ("fail_recent", "failed", -3 * 86400),
            ("cancel_mid", "cancelled", -15 * 86400),
            ("intr_old", "interrupted", -95 * 86400),
            ("running", "running", -100 * 86400),
            ("queued", "queued", -100 * 86400),
        ):
            rec, _ = self.store.create_task(
                spec=TaskSpec(kind="windows", command="echo hi"),
                owner_client_id="owner",
                profile="allowlist",
                title=label,
            )
            tid = rec.task_id
            ids[label] = tid
            (self.spool_dir / tid).mkdir(parents=True, exist_ok=True)
            (self.spool_dir / tid / "stdout.log").write_text("out", encoding="utf-8")
            (self.artifacts_dir / tid).mkdir(parents=True, exist_ok=True)
            (self.artifacts_dir / tid / "result.txt").write_text("res", encoding="utf-8")
            ts = time.time() + age_offset
            if status in TERMINAL_STATUSES:
                self.store.mark_finished(tid, status=status)
                with self.store._db() as db:
                    db.execute("UPDATE tasks SET created_at=?, finished_at=? WHERE task_id=?", (ts, ts, tid))
            elif status == "running":
                with self.store._db() as db:
                    db.execute("UPDATE tasks SET status='running', started_at=? WHERE task_id=?", (ts, tid))

        # Outside user export file MUST never be deleted even if inside root
        user_export = self.root / "user_exported_result.txt"
        user_export.write_text("keep-me", encoding="utf-8")

        # Forbidden on running/queued
        with self.assertRaises(ValueError):
            self.manager.delete_inactive_task(ids["running"])
        with self.assertRaises(ValueError):
            self.manager.delete_inactive_task(ids["queued"])

        # Purge >30 days deletes ok_old and intr_old, leaves fail_recent/cancel_mid/running/queued
        self.assertEqual(self.manager.count_purgeable_tasks(older_than_days=30), 2)
        purged_30 = self.manager.purge_inactive_tasks(older_than_days=30)
        self.assertEqual(purged_30["deleted_count"], 2)
        self.assertEqual(set(purged_30["deleted_task_ids"]), {ids["ok_old"], ids["intr_old"]})
        self.assertFalse((self.spool_dir / ids["ok_old"]).exists())
        self.assertFalse((self.artifacts_dir / ids["intr_old"]).exists())
        self.assertTrue(user_export.is_file())

        # Single delete on fail_recent
        one = self.manager.delete_inactive_task(ids["fail_recent"])
        self.assertEqual(one["deleted_task_ids"], [ids["fail_recent"]])
        self.assertIsNone(self.store.get_task(ids["fail_recent"]))

        # Purge all remaining inactive deletes cancel_mid and preserves running & queued
        purged_all = self.manager.purge_inactive_tasks(older_than_days=None)
        self.assertEqual(purged_all["deleted_task_ids"], [ids["cancel_mid"]])
        self.assertIsNotNone(self.store.get_task(ids["running"]))
        self.assertIsNotNone(self.store.get_task(ids["queued"]))

    def test_server_task_start_default_timeout_and_structured_error(self) -> None:
        from unittest.mock import MagicMock

        from backend import server as srv

        mock_prov = MagicMock()
        mock_prov.store = object()
        mock_exec = MagicMock()
        mock_exec.emergency_stopped.return_value = False
        mock_exec.client_approved.return_value = True
        mock_exec.profile_for.return_value = "allowlist"
        mock_exec.can_request.return_value = True

        async def _run_case() -> None:
            local_store = TaskStore(self.root / "srv_tasks.sqlite3")
            local_mgr = TaskManager(
                local_store,
                self.runner,
                artifacts_dir=self.root / "srv_artifacts",
                spool=self.spool,
                redactor=self.redactor,
                command_executor=lambda rec, spec: srv._task_command_executor(rec, spec),
            )
            with patch.object(srv, "TASK_STORE", local_store), patch.object(
                srv, "TASK_MANAGER", local_mgr
            ), patch.object(srv, "oauth_provider", mock_prov), patch.object(
                srv, "oauth_execution", mock_exec
            ), patch(
                "backend.server.require_execution_permission", return_value="client-allow"
            ):
                try:
                    # Omitting timeout in allowlist defaults cleanly to 15s and queues without error
                    res = await srv.task_start(
                        command="echo hello-task",
                        kind="windows",
                        title="Smoke echo",
                    )
                    self.assertNotIsInstance(res, CallToolResult)
                    self.assertEqual(res["timeout_seconds"], 15)
                    tid = res["task_id"]

                    for _ in range(50):
                        st = await srv.task_status(tid)
                        if isinstance(st, dict) and st.get("status") in TERMINAL_STATUSES:
                            break
                        await asyncio.sleep(0.05)

                    # Explicit excessive timeout under allowlist still fails with structured MCP error
                    err_res = await srv.task_start(
                        command="echo too-long",
                        kind="windows",
                        timeout=60,
                    )
                    self.assertIsInstance(err_res, CallToolResult)
                    self.assertTrue(err_res.is_error)
                    self.assertEqual(
                        err_res.structured_content["error"]["code"],  # type: ignore[index]
                        TASK_INVALID_TIMEOUT,
                    )

                    # Missing task returns TASK_NOT_FOUND CallToolResult
                    missing_res = await srv.task_status("tsk_does_not_exist")
                    self.assertIsInstance(missing_res, CallToolResult)
                    self.assertTrue(missing_res.is_error)
                    self.assertEqual(
                        missing_res.structured_content["error"]["code"],  # type: ignore[index]
                        TASK_NOT_FOUND,
                    )
                finally:
                    await local_mgr.close()

        asyncio.run(_run_case())


if __name__ == "__main__":
    unittest.main()
