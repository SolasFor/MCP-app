"""Integration tests for Stage 10 Remote Management against a real localhost Paramiko SSH/SFTP server."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.devices_page import DevicesPage
from backend.remote.manager import RemoteManager
from backend.remote.models import DevicePermissions, DeviceProfile
from backend.remote.store import DeviceStore
from tests.fixtures.local_ssh_server import LocalSSHServer


class RemoteManagementIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sftp_root = self.root / "sftp_root"
        self.sftp_root.mkdir()
        (self.sftp_root / "hello.txt").write_text("remote-hello-world", encoding="utf-8")

        self.ssh_srv = LocalSSHServer(self.sftp_root, username="ciuser", password="cipass-secret").start()
        self.known_hosts = self.ssh_srv.write_known_hosts(self.root / "known_hosts")

        self.store = DeviceStore(
            self.root / "remote" / "devices.json",
            secret_store=SecretStore(self.root / "secrets"),
        )
        self.redactor = SecretRedactor()
        pwd_ref = self.store.set_secret("box1", "password", "cipass-secret")
        self.store.upsert(
            DeviceProfile(
                device_id="box1",
                name="Local CI Box",
                host=self.ssh_srv.host,
                port=self.ssh_srv.port,
                username="ciuser",
                group="ci",
                auth_method="password_ref",
                password_ref=pwd_ref,
                known_hosts_path=str(self.known_hosts),
                strict_host_key=True,
                allowed_sftp_roots=("/sandbox",),
                sftp_max_bytes=4096,
                allowed_commands=("echo ok", "slow_job", "drop_connection"),
                allowed_services=("nginx",),
                allowed_clients=("rm-allowed",),
                min_profile="allowlist",
                permissions=DevicePermissions(
                    execute=True,
                    sftp_read=True,
                    sftp_write=True,
                    service_control=True,
                    metrics=True,
                ),
            )
        )
        self.mgr = RemoteManager(self.store, redactor=self.redactor)

    def tearDown(self) -> None:
        self.mgr.close()
        self.ssh_srv.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_host_key_verification_and_changed_key_rejection(self) -> None:
        # 1. Trusted host key succeeds
        h = self.mgr.device_health("box1")
        self.assertTrue(h["reachable"])
        self.assertIn("Linux", h["system"])

        # 2. Missing known_hosts fails closed
        empty_kh = self.root / "empty_kh"
        empty_kh.write_text("", encoding="utf-8")
        dev = self.store.get("box1")
        assert dev is not None
        dev.known_hosts_path = str(empty_kh)
        self.store.upsert(dev)
        with self.assertRaises(PermissionError):
            self.mgr.device_health("box1")

        # 3. Restore known_hosts, then rotate server key -> MUST refuse changed host key
        dev.known_hosts_path = str(self.known_hosts)
        self.store.upsert(dev)
        self.ssh_srv.rotate_host_key()
        with self.assertRaises(PermissionError):
            self.mgr.device_health("box1")

    def test_sftp_upload_download_traversal_quota_metrics_services_and_disconnect(self) -> None:
        # SFTP list, upload, download inside allowed root
        listing = self.mgr.sftp_list("box1", "/sandbox")
        self.assertTrue(any(e["name"] == "hello.txt" for e in listing["entries"]))
        up = self.mgr.sftp_upload("box1", "/sandbox/sub/uploaded.txt", "stage10-payload")
        self.assertEqual(up["bytes_written"], len("stage10-payload"))
        dl = self.mgr.sftp_download("box1", "/sandbox/sub/uploaded.txt")
        self.assertEqual(dl["content"], "stage10-payload")

        # Quota & symlink / traversal protection
        with self.assertRaises(PermissionError):
            self.mgr.sftp_upload("box1", "/sandbox/too_big.bin", "x" * 5000)
        with self.assertRaises((ValueError, PermissionError)):
            self.mgr.sftp_download("box1", "/outside/secret.txt")
        with self.assertRaises(PermissionError):
            self.mgr.sftp_download("box1", "/sandbox/sym_secret.txt")
        with self.assertRaises(PermissionError):
            self.mgr.sftp_download("box1", "/sandbox/escape_link/file.txt")

        # Metrics & Services
        m = self.mgr.remote_metrics("box1")
        self.assertIn("MemTotal", m["metrics_text"])
        svc_start = self.mgr.remote_service_action("box1", "nginx", "start")
        self.assertEqual(svc_start["exit_code"], 0)
        svc_list = self.mgr.remote_service_list("box1")
        self.assertIn("active", svc_list["services_output"])
        svc_stop = self.mgr.remote_service_action("box1", "nginx", "stop")
        self.assertIn("stopped", svc_stop["output"])

        # Async remote job completion
        job = self.mgr.ssh_task_start("box1", "slow_job")
        deadline = time.monotonic() + 5.0
        st = job
        while time.monotonic() < deadline and st["state"] == "running":
            time.sleep(0.05)
            st = self.mgr.job_status(job["job_id"])
        self.assertEqual(st["state"], "succeeded")
        self.assertIn("job-done", st["output"])

        # Network disconnect during job -> marks 'disconnected' honestly without blocking engine
        drop_job = self.mgr.ssh_task_start("box1", "drop_connection")
        deadline = time.monotonic() + 5.0
        dst = drop_job
        while time.monotonic() < deadline and dst["state"] == "running":
            time.sleep(0.05)
            dst = self.mgr.job_status(drop_job["job_id"])
        self.assertEqual(dst["state"], "disconnected")
        self.assertIn("cannot be confirmed", dst["disconnect_note"])

    def test_oauth_cross_client_isolation_via_server_tools(self) -> None:
        from backend import server
        from backend.oauth_execution import ExecutionApprovals
        from backend.oauth_store import OAuthStore

        store = OAuthStore(
            self.root / "srv_oauth.sqlite3",
            issuer=server.BASE_URL,
            resource_url=server.RESOURCE_URL,
        )
        exec_app = ExecutionApprovals(store, default_profile="safe")
        for cid in ("rm-allowed", "rm-denied"):
            store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=cid,
                    redirect_uris=["http://127.0.0.1:19996/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            store.mark_approved(cid)
            exec_app.set_client_profile(cid, "allowlist")

        fake_prov = type("_P", (), {"store": store})()
        with patch.object(server, "REMOTE_STORE", self.store), patch.object(
            server, "REMOTE_MANAGER", self.mgr
        ), patch.object(server, "oauth_provider", fake_prov), patch.object(
            server, "oauth_execution", exec_app
        ):
            tok_ok = AccessToken(token="t1", client_id="rm-allowed", scopes=["mcp:read"], resource=server.RESOURCE_URL)
            with patch("backend.tool_permissions.get_access_token", return_value=tok_ok):
                listed = asyncio.run(server.device_list())
                self.assertEqual(len(listed["devices"]), 1)
                res = asyncio.run(server.ssh_execute("box1", "echo ok"))
                self.assertEqual(res["exit_code"], 0)
                self.assertEqual(res["stdout"].strip(), "ok")
                # Cross-check that secret is not present in output or device_info
                info = asyncio.run(server.device_info("box1"))
                self.assertNotIn("cipass-secret", str(info))

            tok_bad = AccessToken(token="t2", client_id="rm-denied", scopes=["mcp:read"], resource=server.RESOURCE_URL)
            with patch("backend.tool_permissions.get_access_token", return_value=tok_bad):
                denied_list = asyncio.run(server.device_list())
                self.assertEqual(denied_list["devices"], [])
                denied_exec = asyncio.run(server.ssh_execute("box1", "echo ok"))
                self.assertIn("denied", denied_exec["error"].lower())

    def test_headless_devices_gui_import_health_and_i18n(self) -> None:
        cfg = self.root / "ssh_config"
        cfg.write_text(f"Host ci-imported\n  HostName {self.ssh_srv.host}\n  User {self.ssh_srv.username}\n  Port {self.ssh_srv.port}\n", encoding="utf-8")
        page = DevicesPage(
            config_path=self.root / "gui_devices.json",
            secrets_dir=self.root / "gui_secrets",
            redactor=self.redactor,
        )
        try:
            cnt = page.import_from_ssh_config(cfg)
            self.assertEqual(cnt, 1)
            self.assertEqual(page.table.rowCount(), 1)
            i18n.set_language(LANG_EN)
            page.retranslate()
            self.assertEqual(page.import_btn.text(), "Import ~/.ssh/config")
        finally:
            page.shutdown()


if __name__ == "__main__":
    unittest.main()
