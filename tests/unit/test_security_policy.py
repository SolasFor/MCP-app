"""Safety-policy unit tests (no MCP SDK or external network required)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.security_policy import (
    MAX_WRITE_BYTES,
    allowed_ssh_host,
    enabled,
    exact_allowlist,
    parse_allowed_command,
    workspace_path,
)


class SecurityPolicyTests(unittest.TestCase):
    def test_boolean_opt_in(self) -> None:
        for val in (None, "", "false", "0", "off", " no "):
            self.assertFalse(enabled(val))
        for val in ("1", "true", " YES ", "ON"):
            self.assertTrue(enabled(val))

    def test_host_allowlist_denies_by_default(self) -> None:
        self.assertFalse(allowed_ssh_host("prod.internal", exact_allowlist("")))
        allow = exact_allowlist("prod.internal, 10.0.0.2")
        self.assertTrue(allowed_ssh_host("PROD.INTERNAL", allow))
        self.assertFalse(allowed_ssh_host("prod.internal.evil.com", allow))
        self.assertFalse(allowed_ssh_host("", allow))

    def test_wildcards_rejected(self) -> None:
        for value in ("*", "*.example.org", "prod?"):
            with self.assertRaises(ValueError):
                exact_allowlist(value)

    def test_workspace_file_and_subdirectory(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertEqual(workspace_path(root, "nested/file.txt"), root.resolve() / "nested" / "file.txt")

    def test_workspace_blocks_absolute_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for value in ("../secret", "nested/../../secret", str(root / "file"), "C:\\Windows\\system.ini"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    workspace_path(root, value)

    def test_workspace_blocks_credential_names(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for value in (".env", ".env.production", "nested/token.json", ".ssh/id_rsa", "abc.pem", "config.yml"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    workspace_path(root, value)

    def test_workspace_blocks_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as rootdir, tempfile.TemporaryDirectory() as otherdir:
            root = Path(rootdir)
            try:
                (root / "out").symlink_to(Path(otherdir), target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this system")
            with self.assertRaises(ValueError):
                workspace_path(root, "out/outside.txt")

    def test_workspace_blocks_symlink_to_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "token.json").write_text("secret", encoding="utf-8")
            try:
                (root / "public.txt").symlink_to(root / "token.json")
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this system")
            with self.assertRaises(ValueError):
                workspace_path(root, "public.txt")

    def test_command_requires_allowlist(self) -> None:
        with self.assertRaises(ValueError):
            parse_allowed_command("python -V", exact_allowlist(""))

    def test_command_rejects_shell_paths_and_newlines(self) -> None:
        allow = exact_allowlist("python")
        for command in ("../python -V", "C:\\Windows\\system32\\cmd.exe /c whoami", "python\nwhoami"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                parse_allowed_command(command, allow)

    def test_command_spawns_executable_not_shell(self) -> None:
        executable_name = Path(sys.executable).name
        with patch("backend.security_policy.shutil.which", return_value=sys.executable):
            parsed = parse_allowed_command(
                f'{executable_name} "-V"',
                exact_allowlist(executable_name),
            )
        self.assertEqual(parsed[0], sys.executable)
        self.assertEqual(parsed[1], "-V")

    def test_write_size_bound(self) -> None:
        self.assertGreater(MAX_WRITE_BYTES, 0)
        self.assertLessEqual(MAX_WRITE_BYTES, 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
