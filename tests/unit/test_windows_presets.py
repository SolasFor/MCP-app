"""Regression tests for the standard Windows command presets.

All commands are denied in Safe mode. In allowlist mode, the built-in tools
are implemented as data operations, not executed through cmd.exe. The OS
utilities resolve to Windows System32 binaries on Windows.
"""
from __future__ import annotations

import asyncio
import os
import unittest

from backend.oauth_execution import DEFAULT_WINDOWS_ALLOWLIST, windows_whitelisted


class WindowsPresetTests(unittest.TestCase):
    def test_exact_standard_preset(self):
        self.assertEqual(
            DEFAULT_WINDOWS_ALLOWLIST,
            ("ls", "pwd", "dir", "echo", "whoami", "ipconfig", "systeminfo"),
        )
        for command in DEFAULT_WINDOWS_ALLOWLIST:
            with self.subTest(command=command):
                self.assertTrue(windows_whitelisted(command, DEFAULT_WINDOWS_ALLOWLIST))

    def test_rejects_unlisted_argument_forms_and_shell_chaining(self):
        for command in (
            "whoami /priv", "ipconfig /all", "systeminfo /fo list",
            "dir ..", "ls -R", "pwd && whoami", "powershell -Command Get-Date",
        ):
            with self.subTest(command=command):
                self.assertFalse(windows_whitelisted(command, DEFAULT_WINDOWS_ALLOWLIST))
        # Echo is deliberately literal and handled without cmd.exe.
        self.assertTrue(windows_whitelisted("echo hello", DEFAULT_WINDOWS_ALLOWLIST))

    @unittest.skipUnless(os.name == "nt", "Windows-specific executable test")
    def test_builtin_echo_is_not_a_shell(self):
        from backend.server import _oauth_windows_run
        response = asyncio.run(_oauth_windows_run("echo hello & whoami", full=False))
        self.assertEqual(response, "hello & whoami")

    @unittest.skipUnless(os.name == "nt", "Windows-specific executable test")
    def test_whoami_runs_from_system32_without_shell(self):
        from backend.server import _restricted_windows_argv, _oauth_windows_run
        argv = _restricted_windows_argv("whoami")
        self.assertEqual(len(argv), 1)
        self.assertTrue(argv[0].lower().endswith("system32\\whoami.exe"))
        output = asyncio.run(_oauth_windows_run("whoami", full=False))
        self.assertIn("Exit code: 0", output)


if __name__ == "__main__":
    unittest.main()
