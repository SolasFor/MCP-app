"""Regression coverage for console allocation in the desktop MCP server."""
from __future__ import annotations

import asyncio
import os
import subprocess
import unittest
from unittest.mock import AsyncMock, patch


class ConsoleWindowTests(unittest.TestCase):
    def test_oauth_command_retains_output_and_platform_creation_flags(self):
        from backend import server

        for full in (False, True):
            with self.subTest(full=full):
                proc = AsyncMock()
                proc.communicate.return_value = (b"test stdout", b"test stderr")
                proc.returncode = 0
                with patch.object(server, "_restricted_windows_argv", return_value=["whoami"]), \
                     patch.object(server.asyncio, "create_subprocess_exec", return_value=proc) as launch:
                    result = asyncio.run(server._oauth_windows_run("whoami", full=full))
                launch.assert_awaited_once()
                self.assertEqual(
                    launch.call_args.kwargs["creationflags"],
                    subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                self.assertEqual(launch.call_args.kwargs["stdout"], asyncio.subprocess.PIPE)
                self.assertEqual(launch.call_args.kwargs["stderr"], asyncio.subprocess.PIPE)
                self.assertIn("Exit code: 0", result)
                self.assertIn("test stdout", result)
                self.assertIn("test stderr", result)

    def test_legacy_command_retains_output_and_platform_creation_flags(self):
        from backend import server

        proc = AsyncMock()
        proc.communicate.return_value = (b"legacy stdout", b"")
        proc.returncode = 0
        with patch.object(server, "parse_allowed_command", return_value=["whoami"]), \
             patch.object(server.asyncio, "create_subprocess_exec", return_value=proc) as launch:
            result = asyncio.run(server.run_local_command("whoami"))
        launch.assert_awaited_once()
        self.assertEqual(
            launch.call_args.kwargs["creationflags"],
            subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.assertIn("legacy stdout", result)

    def test_allowlist_cannot_choose_powershell_or_extended_timeout(self):
        from backend.server import _oauth_windows_run
        for kwargs in ({"shell": "powershell"}, {"timeout": 120}):
            result = asyncio.run(_oauth_windows_run("whoami", full=False, **kwargs))
            self.assertIn("Full Access", result)

    @unittest.skipUnless(os.name == "nt", "Windows-only PowerShell smoke test")
    def test_powershell_multiline_and_extended_timeout(self):
        from backend.server import _oauth_windows_run
        result = asyncio.run(_oauth_windows_run(
            "Write-Output 'first'\nWrite-Output 'second'",
            full=True, shell="powershell", timeout=60,
        ))
        self.assertIn("Exit code: 0", result)
        self.assertIn("first", result)
        self.assertIn("second", result)

    @unittest.skipUnless(os.name == "nt", "Windows-only process smoke test")
    def test_actual_windows_command_in_both_execution_modes(self):
        from backend.server import _oauth_windows_run

        for full in (False, True):
            with self.subTest(full=full):
                output = asyncio.run(_oauth_windows_run("whoami", full=full))
                self.assertIn("Exit code: 0", output)


if __name__ == "__main__":
    unittest.main()
