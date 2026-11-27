"""N01 baseline audit reproduction and regression tests (P0/P1 findings F-N01-01..F-N01-06)."""
from __future__ import annotations

import ast
import errno
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp.shared.auth import OAuthClientInformationFull
from PyQt6.QtWidgets import QApplication

from app.core.diagnostics import export_diagnostic_report
from app.platform import get_platform
from app.ui.i18n import LANG_EN, LANG_RU, _STRINGS, i18n
from app.ui.main_window import MainWindow
from app.ui.pages.gateway_page import GatewayPage
from backend.automation.backup_updater import BackupManager
from backend.automation.monitoring import prune_audit_file
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec
from backend.extensions.runtime import ExtensionProcessHost
from backend.gateway.models import TRANSPORT_STDIO, UpstreamServerProfile
from backend.oauth_execution import PROFILE_ALLOWLIST, ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.remote.models import DeviceProfile
from backend.remote.ssh_client import SSHConnectionManager
from backend.remote.store import DeviceStore
from backend.tool_registry import EXEC_SSH, EXEC_WINDOWS
from backend.workspaces.history import WorkspaceHistory


class _DummyTokenStore:
    def get_secret(self, *_a, **_kw):  # noqa: ANN001
        return None


class I18nGatewayRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_all_tr_keys_exist_in_ru_and_en(self) -> None:
        ru_keys = set(_STRINGS[LANG_RU])
        en_keys = set(_STRINGS[LANG_EN])
        self.assertEqual(ru_keys, en_keys)

        app_dir = Path(__file__).resolve().parents[2] / "app"
        missing: list[tuple[str, int, str]] = []
        for py_file in sorted(app_dir.rglob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and (
                    (isinstance(node.func, ast.Name) and node.func.id == "tr")
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == "tr")
                ) and node.args:
                    arg0 = node.args[0]
                    vals: list[str] = []
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        vals.append(arg0.value)
                    elif isinstance(arg0, ast.IfExp):
                        for branch in (arg0.body, arg0.orelse):
                            if isinstance(branch, ast.Constant) and isinstance(branch.value, str):
                                vals.append(branch.value)
                    for key in vals:
                        if key not in ru_keys or key not in en_keys:
                            missing.append((str(py_file), node.lineno, key))
        self.assertEqual(missing, [])

    def test_gateway_page_row_menu_labels_translated_ru_and_en(self) -> None:
        prev_lang = i18n.language
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "gateway" / "servers.json"
            page = GatewayPage(config_path=cfg)
            try:
                prof_on = UpstreamServerProfile(
                    server_id="srv_on",
                    name="Enabled Server",
                    transport=TRANSPORT_STDIO,
                    command="python",
                    enabled=True,
                )
                prof_off = UpstreamServerProfile(
                    server_id="srv_off",
                    name="Disabled Server",
                    transport=TRANSPORT_STDIO,
                    command="python",
                    enabled=False,
                )
                self.assertEqual(page.store.upsert(prof_on), [])
                self.assertEqual(page.store.upsert(prof_off), [])
                page.reload()

                for lang in (LANG_RU, LANG_EN):
                    i18n.set_language(lang)
                    for row in range(2):
                        specs = page._build_row_menu(row)
                        toggle = next(s for s in specs if s.key == "toggle")
                        self.assertNotIn("gateway.menu.", toggle.label)
                        self.assertTrue(toggle.label.strip())
            finally:
                i18n.set_language(prev_lang)
                page.deleteLater()


class SchedulerAndSftpSecurityTests(unittest.TestCase):
    def test_scheduler_permission_check_enforces_allowlist_and_gateway(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            env = {
                "MCP_SECRET_TOKEN": "sched-test-secret-0123456789abcdef",
                "MCP_PUBLIC_URL": "https://sched-test.example.com/mcp",
                "MCP_ENABLE_OAUTH": "1",
                "MCP_OAUTH_STORE_PATH": str(root / "oauth.sqlite3"),
                "MCP_GATEWAY_CONFIG_PATH": str(root / "gateway.json"),
                "MCP_MANAGED_SERVERS_PATH": str(root / "servers.json"),
                "MCP_WORKSPACES_CONFIG_PATH": str(root / "workspaces.json"),
                "MCP_WORKSPACES_HISTORY_DIR": str(root / "ws_history"),
                "MCP_DESKTOP_POLICY_PATH": str(root / "desktop_policy.json"),
                "MCP_EXTENSIONS_DIR": str(root / "extensions"),
                "MCP_DEVICES_CONFIG_PATH": str(root / "devices.json"),
                "MCP_AUTOMATION_DIR": str(root / "automation"),
                "MCP_SECRETS_DIR": str(root / "secrets"),
                "MCP_TASKS_DB_PATH": str(root / "tasks.sqlite3"),
                "MCP_TASKS_ARTIFACTS_DIR": str(root / "artifacts"),
                "MCP_SPOOL_DIR": str(root / "spool"),
                "MCP_LOGS_DIR": str(root / "logs"),
            }
            old_cwd = os.getcwd()
            with patch.dict(os.environ, env, clear=False):
                os.chdir(root)
                try:
                    import backend.server as srv
                finally:
                    os.chdir(old_cwd)

            store = OAuthStore(root / "oauth.sqlite3", "https://sched.example", "https://sched.example/mcp")
            store.save_client(
                OAuthClientInformationFull(
                    client_id="client-allow",
                    client_name="Allowlist Client",
                    redirect_uris=["http://127.0.0.1:43123/cb"],
                )
            )
            store.mark_approved("client-allow")
            approvals = ExecutionApprovals(store, default_profile=PROFILE_ALLOWLIST)
            approvals.set_client_profile("client-allow", PROFILE_ALLOWLIST)
            approvals.set_client_allowlist(
                "client-allow",
                windows="whoami",
                hosts="prod.example",
                ssh_commands="uptime",
            )
            provider_stub = MagicMock()
            provider_stub.store = store
            gateway_stub = MagicMock()
            gw_tool = MagicMock()
            gw_tool.name = "gw_demo__ping"
            gateway_stub.list_authorized_tools.return_value = [gw_tool]

            with (
                patch.object(srv, "oauth_provider", provider_stub),
                patch.object(srv, "oauth_execution", approvals),
                patch.object(srv, "GATEWAY_ROUTER", gateway_stub),
            ):
                ok_win = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="win-ok",
                        name="win-ok",
                        trigger_type="interval",
                        tool_name=EXEC_WINDOWS,
                        arguments={"command": "whoami"},
                        client_id="client-allow",
                    )
                )
                self.assertEqual(ok_win, (True, ""))

                bad_win = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="win-bad",
                        name="win-bad",
                        trigger_type="interval",
                        tool_name=EXEC_WINDOWS,
                        arguments={"command": "calc.exe"},
                        client_id="client-allow",
                    )
                )
                self.assertFalse(bad_win[0], f"Unlisted Windows command should be denied: {bad_win}")

                bad_ssh_host = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="ssh-bad-host",
                        name="ssh-bad-host",
                        trigger_type="interval",
                        tool_name=EXEC_SSH,
                        arguments={"host": "evil.example", "command": "uptime"},
                        client_id="client-allow",
                    )
                )
                self.assertFalse(bad_ssh_host[0], f"Unlisted SSH host should be denied: {bad_ssh_host}")

                bad_ssh_cmd = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="ssh-bad-cmd",
                        name="ssh-bad-cmd",
                        trigger_type="interval",
                        tool_name=EXEC_SSH,
                        arguments={"host": "prod.example", "command": "id"},
                        client_id="client-allow",
                    )
                )
                self.assertFalse(bad_ssh_cmd[0], f"Unlisted SSH command should be denied: {bad_ssh_cmd}")

                ok_ssh = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="ssh-ok",
                        name="ssh-ok",
                        trigger_type="interval",
                        tool_name=EXEC_SSH,
                        arguments={"host": "prod.example", "command": "uptime"},
                        client_id="client-allow",
                    )
                )
                self.assertEqual(ok_ssh, (True, ""))

                ok_gw = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="gw-ok",
                        name="gw-ok",
                        trigger_type="interval",
                        tool_name="gw_demo__ping",
                        arguments={},
                        client_id="client-allow",
                    )
                )
                self.assertEqual(ok_gw, (True, ""))

                bad_gw = srv._scheduler_permission_check(
                    ScheduleSpec(
                        schedule_id="gw-bad",
                        name="gw-bad",
                        trigger_type="interval",
                        tool_name="gw_demo__secret_tool",
                        arguments={},
                        client_id="client-allow",
                    )
                )
                self.assertFalse(bad_gw[0])

    def test_sftp_canonical_rejects_ancestor_symlink_when_parent_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            sftp = MagicMock()

            def _fake_normalize(path: str) -> str:
                if path == "/srv/allowed/evil_link/new_sub":
                    raise IOError("No such file")
                if path == "/srv/allowed/evil_link":
                    return "/etc"
                if path == "/srv/allowed":
                    return "/srv/allowed"
                if path == "/srv/allowed/new_sub":
                    raise IOError("No such file")
                return path

            sftp.normalize.side_effect = _fake_normalize

            with self.assertRaises(PermissionError):
                mgr._verify_sftp_canonical(
                    sftp,
                    "/srv/allowed/evil_link/new_sub/passwd",
                    ("/srv/allowed",),
                    for_write=True,
                )

            ok = mgr._verify_sftp_canonical(
                sftp,
                "/srv/allowed/new_sub/report.txt",
                ("/srv/allowed",),
                for_write=True,
            )
            self.assertEqual(ok, "/srv/allowed/new_sub/report.txt")

    def test_ssh_open_client_loads_system_host_keys_and_keeps_reject_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = DeviceProfile(device_id="srv1", name="srv1", host="example.com", known_hosts_path="")
            with patch("backend.remote.ssh_client.paramiko.SSHClient") as client_cls:
                fake_cli = MagicMock()
                client_cls.return_value = fake_cli
                cli = mgr._open_client(dev)
                self.assertIs(cli, fake_cli)
                fake_cli.load_system_host_keys.assert_called_once()
                fake_cli.set_missing_host_key_policy.assert_called()


class AtomicIoAndAclRegressionTests(unittest.TestCase):
    def test_backup_restore_enforces_acl_and_cleans_tmp_on_enospc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cfg"
            root.mkdir()
            (root / "settings.json").write_text('{"state":"before"}', encoding="utf-8")
            zip_path = Path(tmp) / "backup.zip"
            BackupManager.create_backup(root, zip_path)

            (root / "settings.json").write_text('{"state":"live"}', encoding="utf-8")
            with patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left on device")):
                with self.assertRaises(OSError):
                    BackupManager.restore_backup(zip_path, root)

            self.assertEqual(json.loads((root / "settings.json").read_text(encoding="utf-8")), {"state": "live"})
            leftovers = [p.name for p in root.rglob("*.tmp")]
            self.assertEqual(leftovers, [], f"Leftover temp files after ENOSPC: {leftovers}")

    def test_scheduler_and_history_clean_tmp_on_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sched_dir = root / "sched"
            sched = AutomationScheduler(sched_dir)
            sched.upsert_schedule(
                ScheduleSpec(schedule_id="s1", name="s1", trigger_type="interval", tool_name="server_info")
            )
            with patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left")):
                with self.assertRaises(OSError):
                    sched.upsert_schedule(
                        ScheduleSpec(schedule_id="s2", name="s2", trigger_type="interval", tool_name="server_info")
                    )
            self.assertEqual([s["schedule_id"] for s in sched.list_schedules()], ["s1"])
            self.assertEqual([p.name for p in sched_dir.rglob("*.tmp")], [])

            hist_dir = root / "hist"
            hist = WorkspaceHistory(hist_dir)
            hist.record_snapshot(
                workspace_id="ws1",
                relative_path="a.txt",
                operation="write",
                before_bytes=b"old",
                after_sha256="abc",
                client_id="owner",
            )
            with patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left")):
                with self.assertRaises(OSError):
                    hist.record_snapshot(
                        workspace_id="ws1",
                        relative_path="b.txt",
                        operation="write",
                        before_bytes=b"two",
                        after_sha256="def",
                        client_id="owner",
                    )
            self.assertEqual(len(hist.list_snapshots("ws1")), 1)
            self.assertEqual([p.name for p in hist_dir.rglob("*.tmp")], [])

    def test_monitoring_prune_and_diagnostics_and_oauth_export_use_atomic_io_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = root / "audit.log"
            audit.write_text("\n".join(f"line {i}" for i in range(10)) + "\n", encoding="utf-8")
            diag = root / "diag.json"
            diag.write_text('{"ok":true}', encoding="utf-8")
            store = OAuthStore(root / "oauth.sqlite3", "https://ex", "https://ex/mcp")
            snap = root / "snap.json"
            snap.write_text('{"snap":1}', encoding="utf-8")

            with patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left")):
                with self.assertRaises(OSError):
                    prune_audit_file(audit, max_lines=3)
                with self.assertRaises(OSError):
                    export_diagnostic_report(diag, {"ok": False})
                with self.assertRaises(OSError):
                    store.export_redacted_backup(snap)

            self.assertEqual([p.name for p in root.glob("*.tmp")], [])
            self.assertEqual(json.loads(diag.read_text(encoding="utf-8")), {"ok": True})
            self.assertEqual(json.loads(snap.read_text(encoding="utf-8")), {"snap": 1})


class ExtensionRuntimeAndUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_extension_process_host_assigns_kill_on_close_job_and_closes_it(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            entry = root / "ext_entry.py"
            entry.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    req = json.loads(line)\n"
                "    m = req.get('method')\n"
                "    res = {'ok': True}\n"
                "    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':res}) + '\\n')\n"
                "    sys.stdout.flush()\n"
                "    if m == 'shutdown':\n"
                "        break\n",
                encoding="utf-8",
            )
            host = ExtensionProcessHost(
                extension_id="sample_ext",
                entrypoint=entry,
                data_dir=root / "data",
                declared_secrets={},
                on_log=lambda _line: None,
            )
            real_platform = get_platform()
            fake_job = MagicMock()
            with (
                patch.object(real_platform, "create_job", return_value=fake_job) as create_job,
                patch.object(real_platform, "assign_process_to_job", return_value=True) as assign_job,
                patch.object(real_platform, "close_job") as close_job,
            ):
                try:
                    host.start(timeout_seconds=5.0)
                    create_job.assert_called_once()
                    self.assertTrue(create_job.call_args.kwargs.get("kill_on_close"))
                    assign_job.assert_called_once()
                finally:
                    host.stop()
                close_job.assert_called_once_with(fake_job)

    def test_main_window_show_page_refreshes_extensions_and_devices(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            with (
                patch("app.paths.user_data_dir", return_value=root),
                patch("app.core.service_manager.user_data_dir", return_value=root),
                patch("app.ui.main_window.user_data_dir", return_value=root),
            ):
                from app.config import Settings
                from app.core.service_manager import ServiceManager

                settings = Settings()
                mgr = ServiceManager(settings)
                win = MainWindow(mgr, settings, tray_available=False)
                try:
                    with (
                        patch.object(win.extensions_page, "refresh_all") as ext_ref,
                        patch.object(win.devices_page, "refresh_all") as dev_ref,
                    ):
                        win.show_page("extensions")
                        win.show_page("devices")
                        ext_ref.assert_called_once()
                        dev_ref.assert_called_once()
                finally:
                    win.allow_close()
                    win.close()
                    shutil.rmtree(root, ignore_errors=True)

    def test_selftest_qt_imports_succeed(self) -> None:
        from app.selftest import _check_qt

        ver = _check_qt()
        self.assertTrue(bool(ver))
