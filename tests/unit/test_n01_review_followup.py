"""TDD reproduction and regression tests for N01 independent ChatGPT review follow-up."""
from __future__ import annotations

import errno
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
import psutil
from mcp.shared.auth import OAuthClientInformationFull
from mcp.types import CallToolResult, TextContent
from pydantic import AnyHttpUrl
from PyQt6.QtWidgets import QApplication

from app.core.acl_recovery import diagnose_data_acls
from app.core.atomic_io import atomic_write_json, atomic_write_text
from app.core.secret_store import SecretStore
from app.platform.base import ProcessJobHandle
from app.ui.pages.automation_page import AutomationPage
from backend.automation.backup_updater import BackupManager, StagedUpdater, UpdateCandidate
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec
from backend.extensions.runtime import ExtensionProcessHost
from backend.gateway.models import TRANSPORT_STDIO, UpstreamServerProfile
from backend.gateway.router import UpstreamToolEntry
from backend.oauth_execution import PROFILE_ALLOWLIST, PROFILE_FULL, PROFILE_SAFE
from backend.oauth_store import OAuthStore
from backend.remote.models import DeviceProfile
from backend.remote.ssh_client import SSHConnectionManager
from backend.remote.store import DeviceStore
from backend.tool_registry import EXEC_WINDOWS, TASK_START, WS_WRITE
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile


def _stat_attr(*, mode: int, size: int = 0, ino: int = 0, dev: int = 0) -> paramiko.SFTPAttributes:
    attr = paramiko.SFTPAttributes()
    attr.st_mode = mode
    attr.st_size = size
    attr.st_ino = ino  # type: ignore[attr-defined]
    attr.st_dev = dev  # type: ignore[attr-defined]
    return attr


class _MemSFTPHandle:
    def __init__(self, initial: bytes = b"", *, stat_attr: paramiko.SFTPAttributes | None = None) -> None:
        self._buf = bytearray(initial)
        self._stat_attr = stat_attr or _stat_attr(mode=0o100600, size=len(initial), ino=1001, dev=1)

    def __enter__(self) -> _MemSFTPHandle:
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def read(self, n: int = -1) -> bytes:
        return bytes(self._buf if n < 0 else self._buf[:n])

    def write(self, data: bytes) -> int:
        self._buf.extend(data)
        self._stat_attr.st_size = len(self._buf)
        return len(data)

    def stat(self) -> paramiko.SFTPAttributes:
        return self._stat_attr


class SftpReviewSecurityTests(unittest.TestCase):
    def _device(self) -> DeviceProfile:
        return DeviceProfile(
            device_id="srv1",
            name="srv1",
            host="10.0.0.10",
            allowed_sftp_roots=("/sandbox",),
            sftp_max_bytes=1024 * 64,
        )

    def test_sftp_upload_rejects_existing_target_symlink_and_dangling_target_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = self._device()

            # Case 1: existing symlink at target pointing outside allowed_sftp_roots
            sftp = MagicMock()
            sftp.normalize.side_effect = lambda p: {
                "/sandbox": "/sandbox",
                "/sandbox/sym_out.txt": "/outside/secret.txt",
            }[p]
            sftp.lstat.return_value = _stat_attr(mode=0o120777, size=18)
            fake_cli = MagicMock()
            fake_cli.open_sftp.return_value = sftp
            with patch.object(mgr, "_open_client", return_value=fake_cli):
                with self.assertRaises(PermissionError):
                    mgr.sftp_upload(dev, "/sandbox/sym_out.txt", b"overwrite-pwn")
            sftp.open.assert_not_called()

            # Case 2: dangling target symlink (normalize raises ENOENT, lstat sees S_IFLNK)
            sftp2 = MagicMock()
            sftp2.normalize.side_effect = lambda p: (
                "/sandbox" if p == "/sandbox" else (_ for _ in ()).throw(FileNotFoundError(errno.ENOENT, "No such file"))
            )
            sftp2.lstat.return_value = _stat_attr(mode=0o120777, size=18)
            fake_cli2 = MagicMock()
            fake_cli2.open_sftp.return_value = sftp2
            with patch.object(mgr, "_open_client", return_value=fake_cli2):
                with self.assertRaises(PermissionError):
                    mgr.sftp_upload(dev, "/sandbox/dangling.txt", b"dangling-pwn")
            sftp2.open.assert_not_called()

    def test_sftp_upload_rejects_parent_symlink_escape_and_intermediate_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = self._device()

            # Case 1: parent dir symlink escapes /sandbox
            sftp_escape = MagicMock()
            sftp_escape.normalize.side_effect = lambda p: "/outside" if p == "/sandbox/sym_dir" else p
            fake_cli = MagicMock()
            fake_cli.open_sftp.return_value = sftp_escape
            with patch.object(mgr, "_open_client", return_value=fake_cli):
                with self.assertRaises(PermissionError):
                    mgr.sftp_upload(dev, "/sandbox/sym_dir/new.txt", b"escape")
            sftp_escape.open.assert_not_called()

            # Case 2: intermediate dangling symlink dir (normalize raises ENOENT, lstat shows S_IFLNK)
            sftp_dang = MagicMock()

            def _norm_dang(p: str) -> str:
                if p == "/sandbox":
                    return "/sandbox"
                raise FileNotFoundError(errno.ENOENT, "No such file")

            sftp_dang.normalize.side_effect = _norm_dang
            sftp_dang.lstat.side_effect = lambda p: (
                _stat_attr(mode=0o120777)
                if p == "/sandbox/dang_dir"
                else (_ for _ in ()).throw(FileNotFoundError(errno.ENOENT, "No such file"))
            )
            fake_cli2 = MagicMock()
            fake_cli2.open_sftp.return_value = sftp_dang
            with patch.object(mgr, "_open_client", return_value=fake_cli2):
                with self.assertRaises(PermissionError):
                    mgr.sftp_upload(dev, "/sandbox/dang_dir/new.txt", b"escape")
            sftp_dang.open.assert_not_called()

    def test_sftp_canonical_fails_closed_on_permission_error_and_io_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            for err in (
                PermissionError(errno.EACCES, "Permission denied"),
                OSError(errno.EIO, "I/O error"),
            ):
                sftp = MagicMock()
                sftp.normalize.side_effect = lambda p, e=err: (
                    "/sandbox" if p == "/sandbox" else (_ for _ in ()).throw(e)
                )
                with self.assertRaises(PermissionError):
                    mgr._verify_sftp_canonical(
                        sftp, "/sandbox/locked/out.txt", ("/sandbox",), for_write=True
                    )

    def test_sftp_upload_new_and_overwrite_toctou_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = self._device()

            # New file uses exclusive create ("xb") and rejects concurrent EEXIST race
            sftp_new = MagicMock()
            sftp_new.normalize.side_effect = lambda p: (
                "/sandbox" if p == "/sandbox" else (_ for _ in ()).throw(FileNotFoundError(errno.ENOENT, "No such file"))
            )
            sftp_new.lstat.side_effect = FileNotFoundError(errno.ENOENT, "No such file")
            sftp_new.open.side_effect = OSError(errno.EEXIST, "File exists")
            cli_new = MagicMock()
            cli_new.open_sftp.return_value = sftp_new
            with patch.object(mgr, "_open_client", return_value=cli_new):
                with self.assertRaises(PermissionError):
                    mgr.sftp_upload(dev, "/sandbox/race.txt", b"hello")
            self.assertEqual(sftp_new.open.call_args.args, ("/sandbox/race.txt", "wxb"))

            # Overwrite existing regular file stages to .tmp with "wxb" and uses posix_rename
            sftp_ovr = MagicMock()
            sftp_ovr.normalize.return_value = "/sandbox/report.txt"
            # Wait: for_write calls normalize("/sandbox") and normalize("/sandbox/report.txt")
            sftp_ovr.normalize.side_effect = lambda p: p
            reg = _stat_attr(mode=0o100600, size=3, ino=42, dev=7)
            sftp_ovr.lstat.return_value = reg
            mem_handle = _MemSFTPHandle(stat_attr=_stat_attr(mode=0o100600, size=0, ino=43, dev=7))
            sftp_ovr.open.return_value = mem_handle
            cli_ovr = MagicMock()
            cli_ovr.open_sftp.return_value = sftp_ovr
            with patch.object(mgr, "_open_client", return_value=cli_ovr):
                res = mgr.sftp_upload(dev, "/sandbox/report.txt", b"clean-bytes")
            self.assertEqual(res["bytes_written"], 11)
            open_path, open_mode = sftp_ovr.open.call_args.args
            self.assertEqual(open_mode, "wxb")
            self.assertIn("/sandbox/.report.txt.mcp-", open_path)
            sftp_ovr.posix_rename.assert_called_once_with(open_path, "/sandbox/report.txt")

            # Fallback when posix_rename raises EOPNOTSUPP cleans temp file and verifies fstat/inode on "wb"
            sftp_fb = MagicMock()
            sftp_fb.normalize.side_effect = lambda p: p
            reg_fb = _stat_attr(mode=0o100600, size=5, ino=77, dev=3)
            sftp_fb.lstat.return_value = reg_fb
            stage_h = _MemSFTPHandle(stat_attr=_stat_attr(mode=0o100600, size=0, ino=78, dev=3))
            wb_h = _MemSFTPHandle(stat_attr=_stat_attr(mode=0o100600, size=0, ino=77, dev=3))
            sftp_fb.open.side_effect = [stage_h, wb_h]
            sftp_fb.posix_rename.side_effect = OSError(errno.EOPNOTSUPP, "Operation unsupported")
            cli_fb = MagicMock()
            cli_fb.open_sftp.return_value = sftp_fb
            with patch.object(mgr, "_open_client", return_value=cli_fb):
                res2 = mgr.sftp_upload(dev, "/sandbox/fallback.txt", b"abc")
            self.assertEqual(res2["bytes_written"], 3)
            sftp_fb.remove.assert_called_once()
            self.assertEqual(sftp_fb.open.call_args_list[-1].args, ("/sandbox/fallback.txt", "wb"))

    def test_sftp_download_rejects_fstat_type_or_inode_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = self._device()
            sftp = MagicMock()
            sftp.normalize.return_value = "/sandbox/data.txt"
            sftp.lstat.return_value = _stat_attr(mode=0o100600, size=10, ino=101, dev=1)
            swapped_handle = _MemSFTPHandle(
                b"secret",
                stat_attr=_stat_attr(mode=0o100600, size=10, ino=999, dev=1),
            )
            sftp.open.return_value = swapped_handle
            cli = MagicMock()
            cli.open_sftp.return_value = sftp
            with patch.object(mgr, "_open_client", return_value=cli):
                with self.assertRaises(PermissionError):
                    mgr.sftp_download(dev, "/sandbox/data.txt")

    def test_sftp_positive_operations_and_reject_policy_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = SSHConnectionManager(DeviceStore(Path(tmp) / "devices.json"))
            dev = self._device()
            with patch("backend.remote.ssh_client.paramiko.SSHClient") as cli_cls:
                fake_cli = MagicMock()
                cli_cls.return_value = fake_cli
                mgr._open_client(dev)
                self.assertIsInstance(
                    fake_cli.set_missing_host_key_policy.call_args.args[0],
                    paramiko.RejectPolicy,
                )

            # Positive list + upload + download on a clean regular directory/file
            sftp = MagicMock()
            sftp.normalize.side_effect = lambda p: p
            sftp.lstat.side_effect = [
                _stat_attr(mode=0o040700, size=0, ino=10, dev=1),  # sftp_list dir check
                FileNotFoundError(errno.ENOENT, "missing"),  # upload verify_sftp_canonical target lstat
                FileNotFoundError(errno.ENOENT, "missing"),  # upload _inspect_regular_target
                _stat_attr(mode=0o100600, size=5, ino=11, dev=1),  # download _inspect_regular_target
            ]
            entry = _stat_attr(mode=0o100600, size=5, ino=11, dev=1)
            entry.filename = "ok.txt"
            sftp.listdir_attr.return_value = [entry]
            up_handle = _MemSFTPHandle(stat_attr=_stat_attr(mode=0o100600, size=0, ino=11, dev=1))
            dl_handle = _MemSFTPHandle(b"hello", stat_attr=_stat_attr(mode=0o100600, size=5, ino=11, dev=1))
            sftp.open.side_effect = [up_handle, dl_handle]
            cli = MagicMock()
            cli.open_sftp.return_value = sftp
            with patch.object(mgr, "_open_client", return_value=cli):
                listed = mgr.sftp_list(dev, "/sandbox")
                self.assertEqual([e["name"] for e in listed["entries"]], ["ok.txt"])
                up = mgr.sftp_upload(dev, "/sandbox/ok.txt", b"hello")
                self.assertEqual(up["bytes_written"], 5)
                dl = mgr.sftp_download(dev, "/sandbox/ok.txt")
                self.assertEqual(dl["content"], "hello")


class ExtensionRuntimeFaultInjectionTests(unittest.TestCase):
    def _write_worker(self, root: Path, *, spawn_grandchild: bool = False, fail_init: bool = False) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        ep = root / "worker.py"
        marker = root / "grandchild_pid.txt"
        ep.write_text(
            f"""
import json, subprocess, sys, time
from pathlib import Path

gc_file = Path({str(marker)!r})
if {spawn_grandchild!r}:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    gc_file.write_text(str(child.pid), encoding="utf-8")

for line in sys.stdin:
    req = json.loads(line)
    m = req.get("method")
    rid = req.get("id")
    if m == "initialize":
        if {fail_init!r}:
            time.sleep(30)
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": rid, "result": {{"ok": True}}}}) + "\\n")
        sys.stdout.flush()
    elif m == "ping":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": rid, "result": {{"pong": True}}}}) + "\\n")
        sys.stdout.flush()
    elif m == "shutdown":
        sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": rid, "result": {{"bye": True}}}}) + "\\n")
        sys.stdout.flush()
        break
""",
            encoding="utf-8",
        )
        return ep

    def _host(self, root: Path, ep: Path) -> ExtensionProcessHost:
        logs: list[str] = []
        return ExtensionProcessHost(
            extension_id="fault_ext",
            entrypoint=ep,
            data_dir=root / "data",
            declared_secrets={},
            on_log=logs.append,
        )

    def test_fault_injection_create_and_assign_job_never_leak_and_recover(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ep = self._write_worker(root)
            host = self._host(root, ep)

            # 1. create_job raises OSError
            mock_adapter = MagicMock()
            mock_adapter.create_job.side_effect = OSError("create_job failed")
            try:
                with patch("backend.extensions.runtime.get_platform", return_value=mock_adapter):
                    with self.assertRaises(OSError):
                        host.start(timeout_seconds=2.0)
                self.assertIsNone(host._proc)
                self.assertIsNone(host._job)

                # 2. assign_process_to_job raises OSError -> job MUST be closed (not leaked)
                mock_adapter2 = MagicMock()
                fake_job = ProcessJobHandle(handle=12345, name="ext-fault_ext", kill_on_close=True, active=True)
                mock_adapter2.create_job.return_value = fake_job
                mock_adapter2.assign_process_to_job.side_effect = OSError("assign failed")
                mock_adapter2.capture_process_identity.return_value = None
                with patch("backend.extensions.runtime.get_platform", return_value=mock_adapter2):
                    with self.assertRaises(OSError):
                        host.start(timeout_seconds=2.0)
                mock_adapter2.close_job.assert_called_once_with(fake_job)
                self.assertIsNone(host._proc)
                self.assertIsNone(host._job)

                # 3. assign_process_to_job returns False -> fail closed, close job, clear handles
                mock_adapter3 = MagicMock()
                fake_job3 = ProcessJobHandle(handle=67890, name="ext-fault_ext", kill_on_close=True, active=True)
                mock_adapter3.create_job.return_value = fake_job3
                mock_adapter3.assign_process_to_job.return_value = False
                mock_adapter3.capture_process_identity.return_value = None
                with patch("backend.extensions.runtime.get_platform", return_value=mock_adapter3):
                    with self.assertRaises(RuntimeError):
                        host.start(timeout_seconds=2.0)
                mock_adapter3.close_job.assert_called_once_with(fake_job3)
                self.assertIsNone(host._proc)
                self.assertIsNone(host._job)

                # 4. Subsequent clean start() succeeds
                init_res = host.start(timeout_seconds=5.0)
                self.assertTrue(init_res.get("ok"))
                self.assertEqual(host.request("ping"), {"pong": True})
            finally:
                host.stop()

    def test_partial_startup_and_stop_job_errors_cleanup_descendants_and_allow_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ep_hang = self._write_worker(root / "hang", spawn_grandchild=True, fail_init=True)
            (root / "hang").mkdir(exist_ok=True)
            host = self._host(root / "hang", ep_hang)
            try:
                with self.assertRaises(TimeoutError):
                    host.start(timeout_seconds=0.8)
                self.assertIsNone(host._proc)
                self.assertIsNone(host._job)
                gc_file = root / "hang" / "grandchild_pid.txt"
                if gc_file.is_file():
                    gc_pid = int(gc_file.read_text(encoding="utf-8").strip())
                    # Poll briefly for OS cleanup
                    deadline = time.monotonic() + 2.0
                    while psutil.pid_exists(gc_pid) and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertFalse(psutil.pid_exists(gc_pid), f"Orphan grandchild PID {gc_pid} survived")

                # Reconfigure host to healthy script and verify stop() fault tolerance + restart
                ep_ok = self._write_worker(root)
                host.entrypoint = ep_ok
                host.start(timeout_seconds=5.0)
                worker_pid = host.pid
                assert worker_pid is not None
                fake_job = host._job
                assert fake_job is not None

                from app.platform import get_platform as real_get_platform

                real_adapter = real_get_platform()
                faulty = MagicMock(wraps=real_adapter)
                faulty.terminate_job.side_effect = OSError("terminate_job failed")
                faulty.close_job.side_effect = RuntimeError("close_job failed")
                # Force kill path by making shutdown + terminate appear slow
                with (
                    patch("backend.extensions.runtime.get_platform", return_value=faulty),
                    patch.object(host, "_rpc_locked", side_effect=RuntimeError("shutdown failed")),
                ):
                    try:
                        host.stop()
                    finally:
                        # Ensure underlying OS job handle is actually released even though close_job was faulted
                        real_adapter.close_job(fake_job)
                self.assertIsNone(host._proc)
                self.assertIsNone(host._job)
                self.assertFalse(psutil.pid_exists(worker_pid))

                # Restart again after faulted stop()
                res = host.start(timeout_seconds=5.0)
                self.assertTrue(res.get("ok"))
            finally:
                host.stop()


class AutomationSecurityFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_scheduler_principal_binding_validation_and_fail_closed_checker(self) -> None:
        with self.assertRaises(ValueError):
            ScheduleSpec.from_dict(
                {
                    "schedule_id": "s1",
                    "name": "Empty client",
                    "trigger_type": "interval",
                    "tool_name": "server_info",
                    "client_id": "",
                }
            )
        with self.assertRaises(ValueError):
            ScheduleSpec(
                schedule_id="s1",
                name="Reserved",
                trigger_type="interval",
                tool_name="server_info",
                client_id="mcp-app-user",
            )

        with tempfile.TemporaryDirectory() as tmp:
            def _raising_checker(_spec: ScheduleSpec) -> tuple[bool, str]:
                raise RuntimeError("sqlite unavailable")

            sched = AutomationScheduler(Path(tmp), permission_checker=_raising_checker)

            # Non-owner Full Access client cannot spoof client_id="owner" or another client
            with self.assertRaises(PermissionError):
                sched.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="escalate-owner",
                        name="Escalate",
                        trigger_type="interval",
                        tool_name="server_info",
                        client_id="owner",
                    ),
                    actor_id="client-full",
                    actor_profile="full",
                )
            with self.assertRaises(PermissionError):
                sched.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="escalate-peer",
                        name="Peer",
                        trigger_type="interval",
                        tool_name="server_info",
                        client_id="client-other",
                    ),
                    actor_id="client-full",
                    actor_profile="full",
                )

            # Owner creates an owner schedule; client-full cannot overwrite or remove it
            sched.upsert_schedule(
                ScheduleSpec(
                    schedule_id="owner-job",
                    name="Owner Job",
                    trigger_type="interval",
                    tool_name="server_info",
                    client_id="owner",
                ),
                actor_id="owner",
                actor_profile="full",
            )
            with self.assertRaises(PermissionError):
                sched.remove_schedule("owner-job", actor_id="client-full", actor_profile="full")

            # permission_checker exception must fail closed (paused_revoked)
            run = sched.trigger_now("owner-job", trigger="manual")
            self.assertEqual(run["status"], "paused_revoked")
            self.assertFalse(sched.list_schedules()[0]["enabled"])

    def test_end_to_end_scheduler_execution_profiles_revocation_task_start_gateway_and_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            ws_dir = tpath / "repo_ws"
            ws_dir.mkdir(parents=True)
            (ws_dir / "note.txt").write_text("hello", encoding="utf-8")

            env = {
                "MCP_SECRET_TOKEN": "review-owner-secret-9999",
                "MCP_ADMIN_TOKEN": "review-admin-secret-8888",
                "MCP_PUBLIC_URL": "https://review.example.com/mcp",
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
                    assert srv.oauth_provider is not None
                    assert srv.oauth_execution is not None

                    for cid, prof in (
                        ("client-safe", PROFILE_SAFE),
                        ("client-allow", PROFILE_ALLOWLIST),
                        ("client-full", PROFILE_FULL),
                        ("client-other", PROFILE_FULL),
                    ):
                        srv.oauth_provider.store.save_client(
                            OAuthClientInformationFull(
                                client_id=cid,
                                client_name=cid,
                                redirect_uris=[AnyHttpUrl("http://127.0.0.1/cb")],
                            )
                        )
                        srv.oauth_provider.store.mark_approved(cid)
                        srv.oauth_execution.set_client_profile(cid, prof)

                    srv.oauth_execution.set_policy(
                        windows="whoami",
                        hosts="srv-ok",
                        ssh_commands="uname -a",
                    )

                    # Workspace strictly allowing ONLY client-other (full must NOT escalate to owner!)
                    srv.WORKSPACE_STORE.upsert_workspace(
                        WorkspaceProfile(
                            workspace_id="priv_ws",
                            name="Private WS",
                            root_path=str(ws_dir),
                            allowed_clients=("client-other",),
                            min_profile="allowlist",
                            permissions=WorkspacePermissions(read=True, write=True),
                        )
                    )

                    # 1. Safe client: server_info succeeds, execution/task tools fail check
                    self.assertTrue(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="safe-info",
                                name="Safe Info",
                                trigger_type="interval",
                                tool_name="server_info",
                                client_id="client-safe",
                            )
                        )[0]
                    )
                    self.assertFalse(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="safe-task",
                                name="Safe Task",
                                trigger_type="interval",
                                tool_name=TASK_START,
                                arguments={"kind": "windows", "command": "whoami"},
                                client_id="client-safe",
                            )
                        )[0]
                    )

                    # 2. Allowlist client: task_start validates windows & ssh args + shell/timeout
                    self.assertTrue(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="allow-task-ok",
                                name="Allow Task OK",
                                trigger_type="interval",
                                tool_name=TASK_START,
                                arguments={"kind": "windows", "command": "whoami", "shell": "cmd", "timeout": 10},
                                client_id="client-allow",
                            )
                        )[0]
                    )
                    self.assertFalse(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="allow-task-bad-cmd",
                                name="Allow Task Bad",
                                trigger_type="interval",
                                tool_name=TASK_START,
                                arguments={"kind": "windows", "command": "powershell -c id"},
                                client_id="client-allow",
                            )
                        )[0]
                    )
                    self.assertFalse(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="allow-task-ps",
                                name="Allow Task PS",
                                trigger_type="interval",
                                tool_name=TASK_START,
                                arguments={"kind": "windows", "command": "whoami", "shell": "powershell"},
                                client_id="client-allow",
                            )
                        )[0]
                    )
                    self.assertFalse(
                        srv._scheduler_permission_check(
                            ScheduleSpec(
                                schedule_id="allow-task-ssh-bad",
                                name="Allow Task SSH Bad",
                                trigger_type="interval",
                                tool_name=TASK_START,
                                arguments={"kind": "ssh", "host": "evil-host", "command": "uname -a"},
                                client_id="client-allow",
                            )
                        )[0]
                    )

                    # 3. Real execution for full client (cmd runs) & NO privilege escalation on restricted workspace
                    full_exec_spec = ScheduleSpec(
                        schedule_id="full-echo",
                        name="Full Echo",
                        trigger_type="interval",
                        tool_name=EXEC_WINDOWS,
                        arguments={"command": "echo scheduled-full-ok", "shell": "cmd", "timeout": 10},
                        client_id="client-full",
                    )
                    srv.AUTOMATION_SCHEDULER.upsert_schedule(full_exec_spec, actor_id="client-full", actor_profile="full")
                    res_full = srv.AUTOMATION_SCHEDULER.trigger_now("full-echo", trigger="manual")
                    self.assertEqual(res_full["status"], "succeeded", res_full)
                    self.assertIn("scheduled-full-ok", res_full["result_summary"])

                    # Workspace escape check: client-full cannot write into client-other's workspace!
                    ws_escape_spec = ScheduleSpec(
                        schedule_id="full-ws-escape",
                        name="WS Escape",
                        trigger_type="interval",
                        tool_name=WS_WRITE,
                        arguments={"workspace_id": "priv_ws", "relative_path": "pwn.txt", "content": "nope"},
                        client_id="client-full",
                    )
                    srv.AUTOMATION_SCHEDULER.upsert_schedule(ws_escape_spec, actor_id="client-full", actor_profile="full")
                    res_escape = srv.AUTOMATION_SCHEDULER.trigger_now("full-ws-escape", trigger="manual")
                    self.assertEqual(res_escape["status"], "failed")
                    self.assertFalse((ws_dir / "pwn.txt").exists())

                    # Unattended Desktop control tools are forbidden even for approved owner/full schedules
                    with self.assertRaises(PermissionError):
                        srv.AUTOMATION_SCHEDULER.upsert_schedule(
                            ScheduleSpec(
                                schedule_id="bad-dt",
                                name="Bad Desktop",
                                trigger_type="interval",
                                tool_name="desktop_click",
                                arguments={"x": 10, "y": 10},
                                client_id="client-full",
                            ),
                            actor_id="client-full",
                            actor_profile="full",
                        )

                    # 4. Gateway tool authorization + live revocation / profile downgrade
                    gw_prof = UpstreamServerProfile(
                        server_id="demo_gw",
                        name="Demo GW",
                        transport=TRANSPORT_STDIO,
                        command="python",
                        min_profile="allowlist",
                        allowed_clients=("client-full",),
                        enabled=True,
                        approved_by_owner=True,
                    )
                    srv.GATEWAY_STORE.upsert(gw_prof)
                    srv.GATEWAY_ROUTER._server_tools["demo_gw"] = [
                        UpstreamToolEntry(
                            server_id="demo_gw",
                            raw_name="ping",
                            namespaced_name="gw__demo_gw__ping",
                            description="Ping",
                            input_schema={"type": "object"},
                        )
                    ]
                    srv.GATEWAY_ROUTER._rebuild_catalog()
                    gw_spec = ScheduleSpec(
                        schedule_id="gw-call",
                        name="GW Call",
                        trigger_type="interval",
                        tool_name="gw__demo_gw__ping",
                        arguments={"x": 1},
                        client_id="client-full",
                    )
                    srv.AUTOMATION_SCHEDULER.upsert_schedule(gw_spec, actor_id="client-full", actor_profile="full")
                    fake_gw_handle = MagicMock()

                    async def _fake_call_tool(name: str, args: dict | None) -> CallToolResult:
                        return CallToolResult(content=[TextContent(type="text", text=f"gw-ok:{name}")], isError=False)

                    fake_gw_handle.call_tool = _fake_call_tool
                    with patch.object(srv.GATEWAY_ROUTER, "_get_or_connect", return_value=fake_gw_handle):
                        gw_res = srv.AUTOMATION_SCHEDULER.trigger_now("gw-call", trigger="manual")
                    self.assertEqual(gw_res["status"], "succeeded", gw_res)

                    # Downgrade client-full -> allowlist with denied_tools -> paused_revoked
                    srv.oauth_execution.set_client_tool_policy("client-full", denied_tools=("gw__demo_gw__ping",))
                    gw_denied = srv.AUTOMATION_SCHEDULER.trigger_now("gw-call", trigger="manual")
                    self.assertEqual(gw_denied["status"], "paused_revoked")

                    # 5. Revoke OAuth client after schedule creation -> paused_revoked on next run
                    srv.oauth_provider.store.revoke_client("client-full")
                    revoked_run = srv.AUTOMATION_SCHEDULER.trigger_now("full-echo", trigger="manual")
                    self.assertEqual(revoked_run["status"], "paused_revoked")
            finally:
                import logging

                for h in list(logging.getLogger().handlers):
                    if isinstance(h, logging.FileHandler):
                        h.close()
                        logging.getLogger().removeHandler(h)
                if srv is not None:
                    srv.PROCESS_RUNNER.close()
                    srv.EXEC_AUDIT.close()
                    srv.REMOTE_MANAGER.close()
                os.chdir(old_cwd)


class AtomicIoAndAclFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_automation_export_and_updater_stage_clean_tmp_on_enospc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            page = AutomationPage(automation_dir=root / "auto")
            dest = root / "diag.json"
            dest.write_text('{"preserved":true}', encoding="utf-8")

            updater = StagedUpdater(
                root / "updates",
                trusted_pubkeys={"k1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            )
            payload = b"update-zip-bytes"
            import hashlib
            sha = hashlib.sha256(payload).hexdigest()
            cand = UpdateCandidate(
                version="1.0.3",
                changelog="c",
                asset_url="https://example.com/u.zip",
                sha256=sha,
                sig_b64="AAAA",
                key_id="k1",
            )

            with (
                patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left")),
                patch("backend.automation.backup_updater.Ed25519PublicKey.from_public_bytes") as mock_pub,
            ):
                mock_pub.return_value = MagicMock()
                with self.assertRaises(OSError):
                    page.export_diagnostics(dest_path=dest)
                with self.assertRaises(OSError):
                    updater.stage_bytes(cand, payload)

            self.assertEqual(json.loads(dest.read_text(encoding="utf-8")), {"preserved": True})
            self.assertEqual([p.name for p in root.rglob("*.tmp")], [])

    def test_concurrent_atomic_writes_permission_error_and_oauth_token_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "concurrent.json"
            errors: list[BaseException] = []

            def _writer(wid: int) -> None:
                try:
                    for i in range(25):
                        atomic_write_json(target, {"w": wid, "i": i}, restrict_acl=False)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=_writer, args=(idx,)) for idx in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
            self.assertEqual(errors, [])
            parsed = json.loads(target.read_text(encoding="utf-8"))
            self.assertIn("w", parsed)
            self.assertEqual([p.name for p in root.glob("*.tmp")], [])

            # PermissionError preserves target and cleans tmp; OAuthStore & SecretStore stay intact
            with patch("os.replace", side_effect=PermissionError(errno.EACCES, "Denied")):
                with self.assertRaises(PermissionError):
                    atomic_write_text(target, '{"corrupt":1}', restrict_acl=False)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), parsed)
            self.assertEqual([p.name for p in root.glob("*.tmp")], [])

            sec = SecretStore(root / "secrets", use_credman=False)
            sec.set_secret("owner", "bearer_token", "owner-tok-1234")
            store = OAuthStore(root / "oauth" / "state.sqlite3", "https://ex", "https://ex/mcp")
            store.save_client(
                OAuthClientInformationFull(
                    client_id="keep-me",
                    client_name="Keep",
                    redirect_uris=[AnyHttpUrl("http://127.0.0.1/cb")],
                )
            )
            with patch("os.replace", side_effect=OSError(errno.ENOSPC, "No space left")):
                with self.assertRaises(OSError):
                    BackupManager.create_backup(root, root / "bk.zip")
            self.assertEqual(sec.get_secret("owner", "bearer_token"), "owner-tok-1234")
            self.assertEqual([c["client_id"] for c in store.list_clients()], ["keep-me"])

    @unittest.skipUnless(sys.platform == "win32", "Windows NTFS DACL verification")
    def test_windows_overwrite_enforces_protected_user_only_dacl(self) -> None:
        import win32api
        import win32con
        import win32security as security

        token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            expected_sid = security.GetTokenInformation(token, security.TokenUser)[0]
        finally:
            token.Close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "profile_data"
            root.mkdir()
            target = root / "state.json"
            target.write_text('{"before":1}', encoding="utf-8")
            # Target starts with inherited permissions from Temp dir; atomic overwrite must lock down DACL
            atomic_write_text(target, '{"after":2}', restrict_acl=True)
            report = diagnose_data_acls(root)
            self.assertFalse(report.has_issues, f"ACL diagnostic reported issues: {report.issues}")
            sd = security.GetNamedSecurityInfo(
                str(target), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
            )
            self.assertTrue(sd.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED)
            dacl = sd.GetSecurityDescriptorDacl()
            self.assertEqual(dacl.GetAceCount(), 1)
            self.assertEqual(dacl.GetAce(0)[2], expected_sid)


if __name__ == "__main__":
    unittest.main()
