"""Unit tests for Stage 5 Task Manager: encryption, quotas, priority, cancel tree, retention & isolation."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

import psutil

from app.core.redaction import SecretRedactor
from backend.process_runner import CommandResult, ProcessRunner
from backend.tasks.manager import TaskManager
from backend.tasks.models import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_QUEUED,
    STATUS_SUCCEEDED,
    TaskSpec,
)
from backend.tasks.store import TaskStore


class TaskManagerUnitTests(unittest.TestCase):
    def test_encrypted_spec_idempotency_recovery_and_mcp_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            secret = "top-secret-task-token-999"
            redactor = SecretRedactor([secret])
            store = TaskStore(root / "tasks.sqlite3")

            spec = TaskSpec(kind="windows", command=f"echo {secret}", timeout=30)
            rec1, dedup1 = store.create_task(
                owner_client_id="client-a",
                profile="full",
                title="windows: echo [REDACTED]",
                spec=spec,
                priority=5,
                idempotency_key="idem-1",
            )
            self.assertFalse(dedup1)
            self.assertEqual(rec1.status, STATUS_QUEUED)

            # Same client + same idempotency_key returns existing record
            rec1_dup, dedup2 = store.create_task(
                owner_client_id="client-a",
                profile="full",
                title="ignored",
                spec=spec,
                idempotency_key="idem-1",
            )
            self.assertTrue(dedup2)
            self.assertEqual(rec1_dup.task_id, rec1.task_id)

            # Different client with same key gets its own task
            rec2, dedup3 = store.create_task(
                owner_client_id="client-b",
                profile="full",
                title="other client",
                spec=spec,
                idempotency_key="idem-1",
            )
            self.assertFalse(dedup3)
            self.assertNotEqual(rec2.task_id, rec1.task_id)

            # Encrypted payload keeps secret out of raw SQLite bytes and public dict
            raw_db_bytes = (root / "tasks.sqlite3").read_bytes()
            self.assertNotIn(secret.encode("utf-8"), raw_db_bytes)
            pub = rec1.to_public_dict(redactor)
            self.assertNotIn(secret, json.dumps(pub))
            self.assertIsNone(pub["progress_percent"])
            self.assertEqual(rec1.to_mcp_task_dict(redactor)["status"], "working")

            # Simulate restart: queued/running become interrupted without auto-restart
            claimed = store.pop_next_runnable(max_global=4, max_per_client=2)
            self.assertIsNotNone(claimed)
            interrupted_count = store.recover_interrupted()
            self.assertEqual(interrupted_count, 2)
            after = store.get_task(rec1.task_id)
            assert after is not None
            self.assertEqual(after.status, STATUS_INTERRUPTED)
            self.assertEqual(after.to_mcp_task_dict(redactor)["status"], "failed")

    def test_priority_quotas_revocation_and_cross_client_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = TaskStore(root / "tasks.sqlite3")
            runner = ProcessRunner(spool_dir=root / "spool")
            execution_order: list[str] = []
            revoked_clients: set[str] = set()

            async def fake_exec(rec, spec):
                execution_order.append(rec.title)
                await asyncio.sleep(0.06)
                return CommandResult(
                    exit_code=0,
                    stdout=f"ok:{rec.title}",
                    stderr="",
                    timed_out=False,
                    cancelled=False,
                    truncated=False,
                    stdout_bytes=8,
                    stderr_bytes=0,
                    run_id=rec.spool_run_id or rec.task_id,
                    duration_ms=60,
                )

            def rechecker(rec, _spec):
                if rec.owner_client_id in revoked_clients:
                    raise PermissionError("Client revoked")

            async def scenario() -> None:
                mgr = TaskManager(
                    store,
                    runner,
                    artifacts_dir=root / "artifacts",
                    auth_rechecker=rechecker,
                    command_executor=fake_exec,
                    max_global_concurrent=2,
                    max_per_client_concurrent=1,
                    poll_interval_seconds=0.05,
                )
                try:
                    t_low, _ = await mgr.submit(
                        owner_client_id="client-a",
                        profile="full",
                        spec=TaskSpec(kind="windows", command="low", timeout=10),
                        priority=1,
                        title="low-prio",
                    )
                    t_high, _ = await mgr.submit(
                        owner_client_id="client-a",
                        profile="full",
                        spec=TaskSpec(kind="windows", command="high", timeout=10),
                        priority=50,
                        title="high-prio",
                    )
                    t_rev, _ = await mgr.submit(
                        owner_client_id="client-b",
                        profile="full",
                        spec=TaskSpec(kind="windows", command="revoked", timeout=10),
                        priority=10,
                        title="revoked-task",
                    )
                    revoked_clients.add("client-b")

                    # Cross-client isolation check across all operations
                    with self.assertRaises(PermissionError):
                        mgr.status_dict(t_low.task_id, owner_client_id="client-b")
                    with self.assertRaises(PermissionError):
                        mgr.read_output(t_low.task_id, owner_client_id="client-b")
                    with self.assertRaises(PermissionError):
                        mgr.result_dict(t_low.task_id, owner_client_id="client-b")
                    with self.assertRaises(PermissionError):
                        mgr.cancel(t_low.task_id, owner_client_id="client-b")
                    with self.assertRaises(PermissionError):
                        mgr.read_artifacts(t_low.task_id, owner_client_id="client-b")

                    # Wait for all 3 to reach terminal state
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        s_low = store.get_task(t_low.task_id)
                        s_high = store.get_task(t_high.task_id)
                        s_rev = store.get_task(t_rev.task_id)
                        if (
                            s_low and s_high and s_rev
                            and s_low.status == STATUS_SUCCEEDED
                            and s_high.status == STATUS_SUCCEEDED
                            and s_rev.status == STATUS_FAILED
                        ):
                            break
                        await asyncio.sleep(0.05)

                    self.assertEqual(execution_order[0], "high-prio")
                    self.assertEqual(execution_order[1], "low-prio")
                    self.assertNotIn("revoked-task", execution_order)
                    self.assertIn("revoked", store.get_task(t_rev.task_id).error.lower())  # type: ignore[union-attr]

                    # Explicit restart creates new task linked via parent_task_id
                    restarted = await mgr.restart(t_high.task_id, owner_client_id="client-a")
                    self.assertEqual(restarted["parent_task_id"], t_high.task_id)
                finally:
                    await mgr.close()
                    runner.close()

            asyncio.run(scenario())

    def test_cancel_terminates_process_tree_and_retention_cleans_disk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = TaskStore(root / "tasks.sqlite3")
            runner = ProcessRunner(spool_dir=root / "spool")
            pid_file = root / "child_pid.txt"

            child_script = (
                "import subprocess, sys, time; "
                "from pathlib import Path; "
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                f"Path({str(pid_file)!r}).write_text(str(p.pid), encoding='utf-8'); "
                "print('SPAWNED', flush=True); "
                "time.sleep(30)"
            )

            async def real_exec(rec, spec):
                return await runner.run_command(
                    [sys.executable, "-c", spec.command],
                    cwd=root,
                    timeout=spec.timeout,
                    client_id=rec.owner_client_id,
                    run_id=rec.spool_run_id or rec.task_id,
                )

            async def scenario() -> None:
                mgr = TaskManager(
                    store,
                    runner,
                    artifacts_dir=root / "artifacts",
                    command_executor=real_exec,
                    retention_max_tasks=1,
                    poll_interval_seconds=0.05,
                )
                try:
                    t1, _ = await mgr.submit(
                        owner_client_id="client-x",
                        profile="full",
                        spec=TaskSpec(kind="windows", command=child_script, timeout=30),
                        title="tree-cancel",
                    )

                    deadline = time.monotonic() + 5.0
                    while not pid_file.is_file() and time.monotonic() < deadline:
                        await asyncio.sleep(0.05)
                    self.assertTrue(pid_file.is_file(), "Child PID file was not written in time")
                    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
                    self.assertTrue(psutil.pid_exists(child_pid))

                    mgr.cancel(t1.task_id, owner_client_id="client-x")
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        cur = store.get_task(t1.task_id)
                        if cur is not None and cur.status == STATUS_CANCELLED:
                            break
                        await asyncio.sleep(0.05)
                    self.assertEqual(store.get_task(t1.task_id).status, STATUS_CANCELLED)  # type: ignore[union-attr]

                    # Verify spawned child process tree also terminated
                    await asyncio.sleep(0.2)
                    still_alive = False
                    if psutil.pid_exists(child_pid):
                        try:
                            still_alive = psutil.Process(child_pid).status() != psutil.STATUS_ZOMBIE
                        except psutil.Error:
                            still_alive = False
                    self.assertFalse(still_alive, "Grandchild process survived tree cancellation")

                    # Create 2 short succeeded tasks so retention_max_tasks=1 prunes t1 + spool + artifacts
                    for idx in range(2):
                        rec, _ = store.create_task(
                            owner_client_id="client-x",
                            profile="full",
                            title=f"done-{idx}",
                            spec=TaskSpec(kind="windows", command="echo ok", timeout=10),
                        )
                        mgr._finalize_with_result(
                            rec, status=STATUS_SUCCEEDED, exit_code=0, error="", summary_text="ok"
                        )
                    self.assertIsNone(store.get_task(t1.task_id))
                    self.assertFalse((root / "artifacts" / t1.task_id).exists())
                    self.assertFalse((root / "spool" / (t1.spool_run_id or t1.task_id)).exists())
                finally:
                    await mgr.close()
                    runner.close()

            asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
