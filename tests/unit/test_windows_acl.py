"""Windows ACL regressions: process token SID, inheritance and failure safety."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(sys.platform == "win32", "Windows security descriptors")
class WindowsAclTests(unittest.TestCase):
    def test_process_sid_with_ambiguous_environment(self) -> None:
        import win32api
        import win32con
        import win32security as security

        from app.platform.windows import WindowsPlatformAdapter

        token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            expected = security.GetTokenInformation(token, security.TokenUser)[0]
        finally:
            token.Close()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "secrets"
            folder.mkdir()
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


if __name__ == "__main__":
    unittest.main()
