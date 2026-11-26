"""Windows ACL, damaged-DACL recovery, reparse-point guard, and atomic I/O regression tests."""
from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.acl_recovery import diagnose_data_acls, repair_data_acls
from app.core.atomic_io import atomic_write_bytes, atomic_write_json
from app.core.secret_store import SecretStore


class AtomicIoTests(unittest.TestCase):
    def test_disk_full_preserves_existing_file_and_cleans_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secrets.vault.enc"
            target.write_bytes(b"original-intact-payload")

            real_fdopen = os.fdopen

            def _failing_fdopen(fd: int, *args, **kwargs):  # noqa: ANN002, ANN003
                fh = real_fdopen(fd, *args, **kwargs)
                fh.close()
                raise OSError(errno.ENOSPC, "No space left on device")

            with patch("app.core.atomic_io.os.fdopen", side_effect=_failing_fdopen):
                with self.assertRaises(OSError) as ctx:
                    atomic_write_bytes(target, b"partial-broken-payload", restrict_acl=False)
                self.assertEqual(ctx.exception.errno, errno.ENOSPC)

            self.assertEqual(target.read_bytes(), b"original-intact-payload")
            leftovers = [p.name for p in Path(tmp).iterdir() if p.name != target.name]
            self.assertEqual(leftovers, [])

    def test_concurrent_atomic_json_writes_and_unicode_parent_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "Профиль пользователя (тест)" / "вложенная папка" / "config.json"
            errors: list[BaseException] = []

            def _worker(worker_id: int) -> None:
                try:
                    for seq in range(12):
                        atomic_write_json(
                            nested,
                            {"worker": worker_id, "seq": seq, "note": "Проверка кириллицы"},
                        )
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=_worker, args=(idx,)) for idx in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)

            self.assertEqual(errors, [])
            parsed = json.loads(nested.read_text(encoding="utf-8"))
            self.assertIn("worker", parsed)
            self.assertEqual(parsed["note"], "Проверка кириллицы")
            leftovers = [p.name for p in nested.parent.iterdir() if p.name != nested.name]
            self.assertEqual(leftovers, [])


@unittest.skipUnless(sys.platform == "win32", "Windows security descriptors")
class WindowsAclTests(unittest.TestCase):
    def _current_sid(self):  # noqa: ANN202
        import win32api
        import win32con
        import win32security as security

        token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            return security.GetTokenInformation(token, security.TokenUser)[0]
        finally:
            token.Close()

    def _lock_out_current_user(self, path: Path, *, is_dir: bool) -> None:
        """Simulate pre-v1.0.1 broken icacls /inheritance:r where current user lacks ACEs."""
        import ntsecuritycon
        import win32con
        import win32security as security

        system_sid = security.ConvertStringSidToSid("S-1-5-18")  # NT AUTHORITY\SYSTEM only
        dacl = security.ACL()
        flags = (win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE) if is_dir else 0
        dacl.AddAccessAllowedAceEx(
            security.ACL_REVISION, flags, ntsecuritycon.FILE_ALL_ACCESS, system_sid
        )
        security.SetNamedSecurityInfo(
            str(path),
            security.SE_FILE_OBJECT,
            security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )

    def test_process_sid_with_ambiguous_environment_and_unicode_paths(self) -> None:
        import win32security as security

        from app.platform.windows import WindowsPlatformAdapter

        expected = self._current_sid()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Данные Профиля (Тест)" / "secrets"
            folder.mkdir(parents=True)
            adapter = WindowsPlatformAdapter()
            with patch.dict(os.environ, {"USERNAME": "SOLAS", "COMPUTERNAME": "SOLAS"}):
                self.assertTrue(adapter.restrict_path_acl(folder, is_dir=True))
                child = folder / "secrets.key.tmp"
                child.write_bytes(b"test")
                self.assertTrue(adapter.restrict_path_acl(child))
                child.write_bytes(b"test again")
            for path in (folder, child):
                sd = security.GetNamedSecurityInfo(
                    str(path), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
                )
                self.assertTrue(sd.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED)
                dacl = sd.GetSecurityDescriptorDacl()
                self.assertEqual(dacl.GetAceCount(), 1)
                self.assertEqual(dacl.GetAce(0)[2], expected)

    def test_failure_does_not_change_existing_acl(self) -> None:
        import pywintypes
        import win32security as security

        from app.platform.windows import WindowsPlatformAdapter

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "data"
            folder.mkdir()

            def descriptor() -> str:
                sd = security.GetNamedSecurityInfo(
                    str(folder), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
                )
                return security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                    sd, security.SDDL_REVISION_1, security.DACL_SECURITY_INFORMATION
                )

            before = descriptor()
            with patch.object(security, "SetNamedSecurityInfo", side_effect=pywintypes.error(5, "test", "denied")):
                self.assertFalse(WindowsPlatformAdapter().restrict_path_acl(folder, is_dir=True))
            self.assertEqual(descriptor(), before)
            (folder / "probe").write_bytes(b"ok")

    def test_damaged_acl_recovery_preserves_dpapi_vault_and_extensions_idempotently(self) -> None:
        import win32security as security

        expected_sid = self._current_sid()
        everyone_sid = security.ConvertStringSidToSid("S-1-1-0")

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "MCPApp"
            store = SecretStore(data_dir / "secrets")
            store.set_secret("owner", "bearer_token", "persistent-owner-secret-token-123456")

            ext_dir = data_dir / "extensions" / "installed" / "demo_ext" / "1.0.0"
            ext_dir.mkdir(parents=True)
            ext_file = ext_dir / "plugin.py"
            ext_file.write_text("print('ok')\n", encoding="utf-8")

            try:
                # Damage child files and parent directories (order: children first so we can lock them, then parents)
                self._lock_out_current_user(data_dir / "secrets" / "secrets.key", is_dir=False)
                self._lock_out_current_user(data_dir / "secrets" / "secrets.vault.enc", is_dir=False)
                self._lock_out_current_user(data_dir / "secrets", is_dir=True)
                self._lock_out_current_user(ext_file, is_dir=False)
                self._lock_out_current_user(data_dir / "extensions" / "installed", is_dir=True)

                # Confirm access is genuinely blocked before recovery
                with self.assertRaises(PermissionError):
                    list((data_dir / "secrets").iterdir())

                diag = diagnose_data_acls(data_dir)
                self.assertTrue(diag.has_issues)
                self.assertGreaterEqual(len(diag.repairable_issues), 2)

                report = repair_data_acls(data_dir, isolate_unreadable=True)
                self.assertTrue(report.ok, f"Unexpected unrecoverable paths: {report.unrecoverable_paths}")
                self.assertGreaterEqual(len(report.repaired_paths), 4)

                # Verify DPAPI vault and extension files survived intact without Everyone ACEs
                reopened = SecretStore(data_dir / "secrets")
                self.assertEqual(
                    reopened.get_secret("owner", "bearer_token"),
                    "persistent-owner-secret-token-123456",
                )
                self.assertEqual(ext_file.read_text(encoding="utf-8"), "print('ok')\n")

                for checked in (
                    data_dir / "secrets",
                    data_dir / "secrets" / "secrets.key",
                    data_dir / "secrets" / "secrets.vault.enc",
                    data_dir / "extensions" / "installed",
                    ext_file,
                ):
                    sd = security.GetNamedSecurityInfo(
                        str(checked), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
                    )
                    dacl = sd.GetSecurityDescriptorDacl()
                    self.assertEqual(dacl.GetAceCount(), 1)
                    self.assertEqual(dacl.GetAce(0)[2], expected_sid)
                    self.assertNotEqual(dacl.GetAce(0)[2], everyone_sid)

                # Second diagnostic & repair pass must be a clean no-op
                diag_after = diagnose_data_acls(data_dir)
                self.assertFalse(diag_after.has_issues)
                report_after = repair_data_acls(data_dir)
                self.assertEqual(report_after.repaired_paths, ())
            finally:
                # Ensure TemporaryDirectory cleanup can always remove everything even if an assertion failed
                repair_data_acls(data_dir)

    def test_reparse_point_junction_is_never_followed_or_modified(self) -> None:
        import win32security as security

        from app.platform.windows import WindowsPlatformAdapter

        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside_target"
            outside.mkdir()
            outside_secret = outside / "keep.txt"
            outside_secret.write_text("outside", encoding="utf-8")

            def _dacl_sddl(p: Path) -> str:
                sd = security.GetNamedSecurityInfo(
                    str(p), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
                )
                return security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                    sd, security.SDDL_REVISION_1, security.DACL_SECURITY_INFORMATION
                )

            before_outside = _dacl_sddl(outside)
            before_file = _dacl_sddl(outside_secret)

            data_dir = Path(tmp) / "MCPApp"
            data_dir.mkdir()
            junction = data_dir / "junction_escape"
            res = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.assertEqual(res.returncode, 0, res.stderr.decode("cp866", errors="replace"))
            try:
                adapter = WindowsPlatformAdapter()
                self.assertFalse(adapter.restrict_path_acl(junction, is_dir=True))

                diag = diagnose_data_acls(data_dir)
                self.assertIn(os.path.abspath(str(junction)), diag.skipped_reparse)

                rep = repair_data_acls(data_dir)
                self.assertIn(os.path.abspath(str(junction)), rep.skipped_reparse)

                self.assertEqual(_dacl_sddl(outside), before_outside)
                self.assertEqual(_dacl_sddl(outside_secret), before_file)
            finally:
                # Remove junction directory entry without touching outside target
                os.rmdir(junction)

    def test_foreign_owned_object_is_reported_unrecoverable_not_modified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "MCPApp"
            secrets_dir = data_dir / "secrets"
            secrets_dir.mkdir(parents=True)
            key_file = secrets_dir / "secrets.key"
            key_file.write_bytes(b"foreign")
            try:
                self._lock_out_current_user(key_file, is_dir=False)
                with patch("app.core.acl_recovery._is_owned_by_sid", return_value=False):
                    rep = repair_data_acls(data_dir)
                self.assertFalse(rep.ok)
                reasons = dict(rep.unrecoverable_paths)
                self.assertEqual(
                    reasons.get(os.path.abspath(str(key_file))),
                    "not_owned_by_current_user",
                )
            finally:
                repair_data_acls(data_dir)

    def test_cli_repair_acl_flag_recovers_isolated_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            appdata = Path(tmp) / "Roaming"
            data_dir = appdata / "MCPApp"
            store = SecretStore(data_dir / "secrets")
            store.set_secret("owner", "bearer_token", "cli-repair-token-value")
            report_file = Path(tmp) / "acl_report.json"
            try:
                self._lock_out_current_user(data_dir / "secrets" / "secrets.key", is_dir=False)
                self._lock_out_current_user(data_dir / "secrets", is_dir=True)

                env = dict(os.environ)
                env["APPDATA"] = str(appdata)
                env["LOCALAPPDATA"] = str(Path(tmp) / "Local")
                proc = subprocess.run(
                    [sys.executable, "main.py", "--repair-acl", str(report_file)],
                    cwd=str(Path(__file__).resolve().parents[2]),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                payload = json.loads(report_file.read_text(encoding="utf-8"))
                self.assertTrue(payload["ok"])
                self.assertGreaterEqual(payload["detected_issues"], 1)
                self.assertGreaterEqual(len(payload["repaired_paths"]), 2)
                self.assertEqual(
                    SecretStore(data_dir / "secrets").get_secret("owner", "bearer_token"),
                    "cli-repair-token-value",
                )
            finally:
                repair_data_acls(data_dir)

    def test_is_owned_by_sid_accepts_elevated_token_owner_tuple_and_rejects_foreign(self) -> None:
        import win32security as security

        from app.core.acl_recovery import _is_owned_by_sid

        user_sid = self._current_sid()
        admins_sid = security.ConvertStringSidToSid("S-1-5-32-544")
        system_sid = security.ConvertStringSidToSid("S-1-5-18")
        mock_sd = type("_SD", (), {"GetSecurityDescriptorOwner": lambda self: admins_sid})()
        with patch.object(security, "GetNamedSecurityInfo", return_value=mock_sd):
            self.assertTrue(_is_owned_by_sid("C:\\dummy\\file", (user_sid, admins_sid), security, object))
            self.assertFalse(_is_owned_by_sid("C:\\dummy\\file", (user_sid,), security, object))
        mock_sys_sd = type("_SD", (), {"GetSecurityDescriptorOwner": lambda self: system_sid})()
        with patch.object(security, "GetNamedSecurityInfo", return_value=mock_sys_sd):
            self.assertFalse(_is_owned_by_sid("C:\\dummy\\file", (user_sid, admins_sid), security, object))

    def test_resolve_report_output_path_sanitizes_cli_destinations(self) -> None:
        from app.core.acl_recovery import _resolve_report_output_path

        with tempfile.TemporaryDirectory() as tmp:
            data_root = Path(tmp) / "MCPApp"
            data_root.mkdir(parents=True)

            ok_temp = _resolve_report_output_path(str(Path(tmp) / "acl-report.json"), data_root)
            self.assertEqual(ok_temp.name, "acl-report.json")

            ok_txt = _resolve_report_output_path(str(data_root / "logs" / "acl.txt"), data_root)
            self.assertEqual(ok_txt.name, "acl.txt")

            for bad in (
                "",
                "--another-flag",
                "report.exe",
                str(data_root / "secrets" / "secrets.key"),
                str(data_root / "token.json"),
                r"C:\Windows\System32\evil.json",
                str(Path(tmp) / "bad\x00.json"),
            ):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    _resolve_report_output_path(bad, data_root)


if __name__ == "__main__":
    unittest.main()
