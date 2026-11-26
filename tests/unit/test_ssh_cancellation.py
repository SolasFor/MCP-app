"""Unit tests for non-blocking SSH cancellation under ProcessRunner."""
from __future__ import annotations

import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path

from backend.process_runner import ProcessRunner


class _FakeChannel:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()


class _FakeClient:
    def __init__(self) -> None:
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()


class SSHCancellationTests(unittest.TestCase):
    def test_cancelling_one_ssh_does_not_block_other_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = ProcessRunner(spool_dir=Path(tmp) / "spool", max_concurrent_ssh=2)
            fake_client = _FakeClient()
            fake_chan = _FakeChannel()
            started_slow = threading.Event()

            def slow_ssh(cancel_event: threading.Event, reg_cb) -> str:
                reg_cb(fake_client, fake_chan)
                started_slow.set()
                cancel_event.wait(timeout=10.0)
                return "cancelled"

            def fast_ssh(cancel_event: threading.Event, reg_cb) -> str:
                return "Exit code: 0\nSTDOUT:\nfast-ok\nSTDERR:\n"

            async def run_test():
                t_slow = asyncio.create_task(runner.run_ssh(slow_ssh, client_id="c1"))
                while not started_slow.is_set():
                    await asyncio.sleep(0.02)

                t0 = time.monotonic()
                t_slow.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await t_slow
                cancel_elapsed = time.monotonic() - t0
                self.assertLess(cancel_elapsed, 0.5)
                self.assertTrue(fake_chan.closed.is_set())
                self.assertTrue(fake_client.closed.is_set())

                fast_out = await asyncio.wait_for(
                    runner.run_ssh(fast_ssh, client_id="c2"),
                    timeout=2.0,
                )
                self.assertIn("fast-ok", fast_out)

            try:
                asyncio.run(run_test())
            finally:
                runner.close()


if __name__ == "__main__":
    unittest.main()
