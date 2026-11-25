"""Security unit tests for Stage 10 Remote Management."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from backend.remote.manager import RemoteManager
from backend.remote.models import (
    DevicePermissions,
    DeviceProfile,
    contains_shell_metacharacters,
    validate_remote_posix_path,
    validate_service_name,
)
from backend.remote.store import DeviceStore, import_ssh_config


class RemoteSecurityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secrets = SecretStore(self.root / "secrets")
        self.store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.secrets)
        self.redactor = SecretRedactor()
        self.mgr = RemoteManager(self.store, redactor=self.redactor)

    def tearDown(self) -> None:
        self.mgr.close()
        self.tmp.cleanup()

    def test_strict_host_key_cannot_be_disabled(self) -> None:
        with self.assertRaises(ValueError):
            DeviceProfile(
                device_id="srv1",
                name="Srv 1",
                host="10.0.0.5",
                strict_host_key=False,
            )

    def test_ssh_config_import_skips_wildcards_and_ignores_proxycommand(self) -> None:
        cfg = self.root / "ssh_config"
        cfg.write_text(
            """
Host *
    User wildcard-ignored
    ProxyCommand evil-cmd

Host web-prod
    HostName 192.168.10.20
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    ProxyCommand nc -X connect %h %p

Host db-staging
    HostName 192.168.10.21
    User pg
""",
            encoding="utf-8",
        )
        imported = import_ssh_config(cfg)
        ids = {d.device_id for d in imported}
        self.assertEqual(ids, {"web-prod", "db-staging"})
        web = next(d for d in imported if d.device_id == "web-prod")
        self.assertEqual(web.host, "192.168.10.20")
        self.assertEqual(web.port, 2222)
        self.assertEqual(web.username, "deploy")
        self.assertTrue(web.strict_host_key)
        # Fail closed: all capabilities disabled by default
        self.assertFalse(web.permissions.execute)
        self.assertFalse(web.permissions.sftp_read)
        self.assertFalse(web.permissions.sftp_write)

    def test_sftp_path_validation_and_service_name_guards(self) -> None:
        roots = ("/srv/app", "/var/log/myapp")
        self.assertEqual(validate_remote_posix_path("/srv/app/data/out.txt", roots), "/srv/app/data/out.txt")
        for bad in ("/etc/passwd", "/srv/app/../etc/shadow", "relative/path", "/srv/app\x00x"):
            with self.assertRaises((ValueError, PermissionError), msg=bad):
                validate_remote_posix_path(bad, roots)

        self.assertEqual(validate_service_name("nginx.service"), "nginx.service")
        for bad_svc in ("nginx; rm -rf /", "../svc", "svc && whoami", ""):
            with self.assertRaises(ValueError, msg=bad_svc):
                validate_service_name(bad_svc)

        self.assertTrue(contains_shell_metacharacters("uptime; id"))
        self.assertFalse(contains_shell_metacharacters("uptime"))

    def test_secret_redaction_and_cross_client_profile_isolation(self) -> None:
        pwd_ref = self.store.set_secret("dev1", "password", "super-ssh-password-xyz")
        self.store.upsert(
            DeviceProfile(
                device_id="dev1",
                name="Dev 1",
                host="127.0.0.1",
                port=2222,
                username="ops",
                auth_method="password_ref",
                password_ref=pwd_ref,
                allowed_commands=("uptime",),
                allowed_services=("nginx",),
                allowed_clients=("client-a",),
                min_profile="allowlist",
                permissions=DevicePermissions(execute=True, service_control=True),
            )
        )
        exported = self.store.export_redacted()
        self.assertNotIn("super-ssh-password-xyz", str(exported))

        self.mgr._register_secrets()
        self.assertNotIn("super-ssh-password-xyz", self.redactor.redact_text("pw=super-ssh-password-xyz"))

        # Safe profile, disallowed client, shell injection, unlisted command/service all deny fail-closed
        with self.assertRaises(PermissionError):
            self.mgr.list_devices(client_id="client-a", client_profile="safe")
        with self.assertRaises(PermissionError):
            self.mgr.ssh_execute("dev1", "uptime", client_id="client-b", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.mgr.ssh_execute("dev1", "uptime; id", client_id="client-a", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.mgr.ssh_execute("dev1", "rm -rf /", client_id="client-a", client_profile="allowlist")
        with self.assertRaises(PermissionError):
            self.mgr.remote_service_action("dev1", "postgres", "stop", client_id="client-a", client_profile="allowlist")


if __name__ == "__main__":
    unittest.main()
