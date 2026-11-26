"""Unit tests for ProcessRunner: trees, Job Objects, independent lifecycle, env redaction, large output."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import psutil

from app.core.redaction import SecretRedactor
from app.platform import ProcessIdentity, get_platform
from backend.process_runner import ProcessRunner


class ProcessRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.spool_dir = Path(self.tmp.name) / "spool"
        self.redactor = SecretRedactor(["SECRET_OWNER_TOKEN_XYZ"])
        self.runner = ProcessRunner(
            spool_dir=self.spool_dir,
            redactor=self.redactor,
            max_concurrent_commands=2,
        )

    def tearDown(self) -> None:
        self.runner.close()
        self.tmp.cleanup()

    def test_large_output_flood_keeps_memory_and_disk_bounded(self) -> None:
        # Emit >10 MiB stdout and >10 MiB stderr concurrently.
        script = (
            "import sys; "
            "chunk = 'A' * 65536 + '\\n'; "
            "err_chunk = 'E' * 65536 + '\\n'; "
            "[(sys.stdout.write(chunk), sys.stderr.write(err_chunk)) for _ in range(170)]; "
            "sys.stdout.flush(); sys.stderr.flush()"
        )
        res = asyncio.run(
            self.runner.run_command(
                [sys.executable, "-c", script],
                cwd=self.tmp.name,
                timeout=30,
                max_memory_bytes=64 * 1024,
                output_limit=8000,
            )
        )
        self.assertEqual(res.exit_code, 0)
        self.assertFalse(res.timed_out)
        self.assertGreater(res.stdout_bytes, 10 * 1024 * 1024)
        self.assertGreater(res.stderr_bytes, 10 * 1024 * 1024)
        self.assertTrue(res.truncated)
        self.assertLessEqual(len(res.stdout), 8300)
        self.assertLessEqual(len(res.stderr), 8300)
        self.assertLessEqual(
            self.runner.spool.total_usage_bytes(),
            self.runner.spool.max_total_bytes + self.runner.spool.max_file_bytes,
        )

    def test_timeout_kills_entire_process_tree(self) -> None:
        pid_file = Path(self.tmp.name) / "child.pid"
        script = (
            "import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            f"open({str(pid_file)!r}, 'w').write(str(p.pid)); "
            "time.sleep(60)"
        )
        res = asyncio.run(
            self.runner.run_command(
                [sys.executable, "-c", script],
                cwd=self.tmp.name,
                timeout=1,
            )
        )
        self.assertTrue(res.timed_out)
        self.assertIsNone(res.exit_code)
        child_pid = int(pid_file.read_text(encoding="utf-8").strip())
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if not psutil.pid_exists(child_pid):
                break
            time.sleep(0.05)
        self.assertFalse(psutil.pid_exists(child_pid), "Child process survived timeout!")

    def test_cancellation_kills_process_tree_immediately(self) -> None:
        pid_file = Path(self.tmp.name) / "cancel_child.pid"
        script = (
            "import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            f"open({str(pid_file)!r}, 'w').write(str(p.pid)); "
            "time.sleep(60)"
        )

        async def run_and_cancel():
            task = asyncio.create_task(
                self.runner.run_command(
                    [sys.executable, "-c", script],
                    cwd=self.tmp.name,
                    timeout=30,
                )
            )
            for _ in range(50):
                if pid_file.exists():
                    break
                await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(run_and_cancel())
        child_pid = int(pid_file.read_text(encoding="utf-8").strip())
        time.sleep(0.2)
        self.assertFalse(psutil.pid_exists(child_pid))

    def test_foreign_pid_mismatch_never_killed(self) -> None:
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            platform = get_platform()
            fake_identity = ProcessIdentity(
                pid=proc.pid,
                create_time=1000.0,  # mismatched create_time simulates PID reuse
                executable=sys.executable,
            )
            report = platform.terminate_process_tree(fake_identity, grace_seconds=0.5)
            self.assertIn(proc.pid, report.skipped_foreign_pids)
            self.assertEqual(report.stopped_pids, [])
            self.assertIsNone(proc.poll())
        finally:
            proc.kill()
            proc.wait(timeout=3)

    def test_environment_redaction_strips_internal_secrets(self) -> None:
        old_env = {
            k: os.environ.get(k)
            for k in ("MCP_SECRET_TOKEN", "TUNNEL_TOKEN", "MCP_CUSTOM_SECRET")
        }
        os.environ["MCP_SECRET_TOKEN"] = "SECRET_OWNER_TOKEN_XYZ"
        os.environ["TUNNEL_TOKEN"] = "secret-tunnel-token-999"
        os.environ["MCP_CUSTOM_SECRET"] = "secret-custom-123"
        try:
            res = asyncio.run(
                self.runner.run_command(
                    [sys.executable, "-c", "import json, os; print(json.dumps(sorted(os.environ.keys())))"],
                    cwd=self.tmp.name,
                    timeout=10,
                    output_limit=65536,
                    max_memory_bytes=256 * 1024,
                )
            )
            self.assertEqual(res.exit_code, 0)
            child_keys = set(json.loads(res.stdout))
            self.assertNotIn("MCP_SECRET_TOKEN", child_keys)
            self.assertNotIn("TUNNEL_TOKEN", child_keys)
            self.assertNotIn("MCP_CUSTOM_SECRET", child_keys)
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_emergency_stop_stops_controlled_and_reports_independent(self) -> None:
        controlled = self.runner.spawn_managed(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=Path(self.tmp.name),
            client_id="client-a",
            name="ctrl-svc",
            lifecycle="controlled",
        )
        independent = self.runner.spawn_managed(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=Path(self.tmp.name),
            client_id="client-a",
            name="ind-gui",
            lifecycle="independent",
        )
        try:
            report = self.runner.emergency_stop("test emergency")
            self.assertTrue(self.runner.is_emergency_stopped)
            self.assertTrue(any(p["name"] == "ctrl-svc" for p in report.stopped_processes))
            self.assertTrue(any(p["name"] == "ind-gui" for p in report.unstoppable_processes))
            self.assertIsNotNone(controlled.process.poll())
            self.assertIsNone(independent.process.poll())

            # Subsequent commands fail closed until cleared.
            with self.assertRaises(PermissionError):
                asyncio.run(
                    self.runner.run_command(
                        [sys.executable, "-c", "print('ok')"],
                        cwd=self.tmp.name,
                        timeout=5,
                    )
                )
        finally:
            if independent.process.poll() is None:
                independent.process.kill()
                independent.process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
