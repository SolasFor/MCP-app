"""Integration tests for Stage 11 Automation, Monitoring, Playground, Backup, Updater & Headless."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PyQt6.QtWidgets import QApplication
from starlette.testclient import TestClient

from app.core.redaction import SecretRedactor
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.automation_page import AutomationPage
from backend.automation import BackupManager, ScheduleSpec, StagedUpdater, UpdateCandidate


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class AutomationMonitoringIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_server_admin_api_playground_metrics_and_backup_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            env = {
                "MCP_SECRET_TOKEN": "int-owner-secret-token-1234",
                "MCP_ADMIN_TOKEN": "int-admin-write-token-5678",
                "MCP_PUBLIC_URL": "https://stage11.example.com/mcp",
                "MCP_ENABLE_OAUTH": "1",
                "MCP_OAUTH_STORE_PATH": str(tpath / "oauth" / "state.sqlite3"),
                "MCP_GATEWAY_CONFIG_PATH": str(tpath / "gateway" / "servers.json"),
                "MCP_MANAGED_SERVERS_PATH": str(tpath / "servers" / "managed_servers.json"),
                "MCP_WORKSPACES_CONFIG_PATH": str(tpath / "workspaces" / "workspaces.json"),
                "MCP_WORKSPACES_HISTORY_DIR": str(tpath / "workspaces" / "history"),
                "MCP_DESKTOP_POLICY_PATH": str(tpath / "desktop" / "policy.json"),
                "MCP_EXTENSIONS_DIR": str(tpath / "extensions"),
                "MCP_DEVICES_CONFIG_PATH": str(tpath / "remote" / "devices.json"),
                "MCP_AUTOMATION_DIR": str(tpath / "automation"),
                "MCP_SECRETS_DIR": str(tpath / "secrets"),
                "MCP_TASKS_DB_PATH": str(tpath / "tasks" / "tasks.sqlite3"),
                "MCP_TASKS_ARTIFACTS_DIR": str(tpath / "tasks" / "artifacts"),
                "MCP_SPOOL_DIR": str(tpath / "tasks" / "spool"),
            }
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            try:
                with patch.dict(os.environ, env, clear=False):
                    import importlib
                    import backend.server as srv_mod

                    srv = importlib.reload(srv_mod)

                    # 1. Playground allowed & denied calls + metrics + zero leftover SQLite clients
                    before_clients = len(srv.oauth_provider.store.list_clients())
                    allowed_res = asyncio.run(
                        srv.invoke_playground_tool("server_info", {}, profile="safe")
                    )
                    self.assertTrue(allowed_res["allowed"])
                    self.assertFalse(allowed_res["is_error"])

                    denied_res = asyncio.run(
                        srv.invoke_playground_tool(
                            "oauth_windows_command", {"command": "whoami"}, profile="safe"
                        )
                    )
                    self.assertFalse(denied_res["allowed"])

                    allowed_dev = asyncio.run(
                        srv.invoke_playground_tool("device_list", {}, profile="allowlist")
                    )
                    self.assertTrue(allowed_dev["allowed"])
                    self.assertFalse(allowed_dev["is_error"])
                    self.assertEqual(len(srv.oauth_provider.store.list_clients()), before_clients)

                    snap = srv.METRICS_REGISTRY.snapshot()
                    self.assertGreaterEqual(snap["total_requests"], 3)
                    self.assertGreaterEqual(snap["error_requests"], 1)

                    # 2. Live scheduler startup + event + revoke flow
                    srv.AUTOMATION_SCHEDULER.upsert_schedule(
                        ScheduleSpec(
                            schedule_id="evt-check",
                            name="On Tunnel",
                            trigger_type="event",
                            event_name="tunnel.ready",
                            tool_name="server_info",
                        )
                    )
                    ev_runs = srv.AUTOMATION_SCHEDULER.emit_event("tunnel.ready")
                    self.assertEqual(len(ev_runs), 1)
                    self.assertEqual(ev_runs[0]["status"], "succeeded")

                    # 3. Local Admin REST API scoped access & secret redaction
                    admin_app = srv.build_local_admin_app(read_only_token="int-admin-ro-token")
                    tc = TestClient(
                        admin_app, base_url="http://127.0.0.1:8001", client=("127.0.0.1", 52000)
                    )
                    self.assertEqual(tc.get("/api/v1/monitoring").status_code, 401)
                    self.assertEqual(
                        tc.post(
                            "/api/v1/schedules/evt-check/run",
                            headers={"Authorization": "Bearer int-admin-ro-token"},
                        ).status_code,
                        403,
                    )
                    self.assertEqual(
                        tc.get(
                            "/api/v1/monitoring",
                            headers={"Authorization": "Bearer int-admin-ro-token", "Cf-Ray": "abc"},
                        ).status_code,
                        403,
                    )
                    mon_resp = tc.get(
                        "/api/v1/monitoring",
                        headers={"Authorization": "Bearer int-admin-ro-token"},
                    )
                    self.assertEqual(mon_resp.status_code, 200)
                    diag_resp = tc.get(
                        "/api/v1/diagnostics/export",
                        headers={"Authorization": "Bearer int-admin-ro-token"},
                    )
                    self.assertEqual(diag_resp.status_code, 200)
                    self.assertNotIn("int-owner-secret-token-1234", diag_resp.text)
                    self.assertNotIn("int-admin-write-token-5678", diag_resp.text)
            finally:
                import backend as backend_pkg
                import logging

                for h in list(logging.getLogger().handlers):
                    if isinstance(h, logging.FileHandler):
                        h.close()
                        logging.getLogger().removeHandler(h)
                if srv is not None:
                    srv.PROCESS_RUNNER.close()
                    srv.EXEC_AUDIT.close()
                    srv.REMOTE_MANAGER.close()
                    srv.EXTENSION_MANAGER.shutdown_all()
                    srv.MANAGED_SERVERS.close()
                sys.modules.pop("backend.server", None)
                if hasattr(backend_pkg, "server"):
                    delattr(backend_pkg, "server")
                os.chdir(old_cwd)

    def test_backup_restore_and_signed_updater_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cfg"
            root.mkdir()
            (root / "settings.json").write_text('{"v":1}', encoding="utf-8")
            zip_path = Path(tmp) / "bkp.zip"
            BackupManager.create_backup(root, zip_path)
            (root / "settings.json").write_text('{"v":2}', encoding="utf-8")
            res = BackupManager.restore_backup(zip_path, root)
            self.assertEqual((root / "settings.json").read_text(encoding="utf-8"), '{"v":1}')
            self.assertTrue(Path(res["rollback_snapshot"]).is_file())

            # StagedUpdater Ed25519 sign -> stage -> apply -> rollback
            priv = Ed25519PrivateKey.generate()
            pub_b64 = base64.b64encode(
                priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).decode("ascii")
            updater = StagedUpdater(Path(tmp) / "upd", trusted_pubkeys={"rel1": pub_b64})

            install_dir = Path(tmp) / "app_dir"
            install_dir.mkdir()
            (install_dir / "marker.txt").write_text("old-0.9.8", encoding="utf-8")

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("marker.txt", "new-0.9.9")
            payload = buf.getvalue()
            sha = hashlib.sha256(payload).hexdigest()
            sig_b64 = base64.b64encode(priv.sign(sha.encode("ascii"))).decode("ascii")
            cand = UpdateCandidate("0.9.9", "rel", "https://example/a.zip", sha, sig_b64=sig_b64, key_id="rel1")

            staged = updater.stage_bytes(cand, payload)
            updater.apply_staged(cand, staged, install_dir=install_dir, owner_explicit_install=True)
            self.assertEqual((install_dir / "marker.txt").read_text(encoding="utf-8"), "new-0.9.9")
            self.assertTrue(updater.rollback_last("0.9.9", install_dir=install_dir))
            self.assertEqual((install_dir / "marker.txt").read_text(encoding="utf-8"), "old-0.9.8")

    def test_headless_backend_subprocess_serves_health(self) -> None:
        port = _free_port()
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            env = dict(os.environ)
            env.update({
                "MCP_HOST": "127.0.0.1",
                "MCP_PORT": str(port),
                "MCP_SECRET_TOKEN": "headless-smoke-token-987654",
                "MCP_PUBLIC_URL": f"http://127.0.0.1:{port}/mcp",
                "MCP_ENABLE_OAUTH": "1",
                "MCP_OAUTH_STORE_PATH": str(tpath / "oauth" / "state.sqlite3"),
                "MCP_GATEWAY_CONFIG_PATH": str(tpath / "gateway" / "servers.json"),
                "MCP_MANAGED_SERVERS_PATH": str(tpath / "servers" / "managed_servers.json"),
                "MCP_WORKSPACES_CONFIG_PATH": str(tpath / "workspaces" / "workspaces.json"),
                "MCP_WORKSPACES_HISTORY_DIR": str(tpath / "workspaces" / "history"),
                "MCP_DESKTOP_POLICY_PATH": str(tpath / "desktop" / "policy.json"),
                "MCP_EXTENSIONS_DIR": str(tpath / "extensions"),
                "MCP_DEVICES_CONFIG_PATH": str(tpath / "remote" / "devices.json"),
                "MCP_AUTOMATION_DIR": str(tpath / "automation"),
                "MCP_SECRETS_DIR": str(tpath / "secrets"),
                "MCP_TASKS_DB_PATH": str(tpath / "tasks" / "tasks.sqlite3"),
                "MCP_TASKS_ARTIFACTS_DIR": str(tpath / "tasks" / "artifacts"),
                "MCP_SPOOL_DIR": str(tpath / "tasks" / "spool"),
                "PYTHONPATH": str(repo_root),
            })
            proc = subprocess.Popen(
                [sys.executable, str(repo_root / "main.py"), "--headless"],
                cwd=str(tpath),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                ready = False
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.0) as resp:
                            if resp.status == 200 and "ok" in resp.read().decode("utf-8"):
                                ready = True
                                break
                    except Exception:
                        time.sleep(0.25)
                self.assertTrue(ready, "Headless server failed to answer /health=200")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5.0)

    def test_automation_page_gui_workflows_and_i18n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg"
            cfg.mkdir()
            (cfg / "settings.json").write_text('{"ok":true}', encoding="utf-8")
            page = AutomationPage(
                automation_dir=cfg / "automation",
                config_root=cfg,
                redactor=SecretRedactor(["secret-gui-val"]),
            )
            try:
                toasts: list[tuple[str, str]] = []
                page.status_message.connect(lambda msg, lvl: toasts.append((msg, lvl)))
                spec = ScheduleSpec(
                    schedule_id="gui-job",
                    name="GUI Job",
                    trigger_type="interval",
                    tool_name="server_info",
                )
                page.create_schedule(spec)
                self.assertEqual(page.schedules_table.rowCount(), 1)
                page.schedules_table.selectRow(0)
                page.run_selected_schedule()
                self.assertTrue(any(lvl == "error" for _, lvl in toasts), toasts)
                self.assertNotIn("succeeded", page.history_view.toPlainText())

                pg_ok = page.run_playground(tool_name="server_info", arguments={}, profile="safe")
                self.assertTrue(pg_ok["allowed"])
                pg_deny = page.run_playground(
                    tool_name="oauth_windows_command", arguments={"command": "whoami"}, profile="safe"
                )
                self.assertFalse(pg_deny["allowed"])

                diag_text = page.export_diagnostics()
                self.assertIn("mcp_metrics", diag_text)

                bkp = cfg / "ui_bkp.zip"
                res = page.create_backup_to(bkp)
                self.assertEqual(res["file_count"], 2)
                self.assertTrue(bkp.is_file())

                i18n.set_language(LANG_EN)
                page.retranslate()
                self.assertEqual(page.tabs.tabText(0), "Schedules")
                i18n.set_language(LANG_RU)
                page.retranslate()
                self.assertEqual(page.tabs.tabText(0), "Расписание")
            finally:
                i18n.set_language(LANG_RU)
                page.shutdown()
                page.close()


if __name__ == "__main__":
    unittest.main()
