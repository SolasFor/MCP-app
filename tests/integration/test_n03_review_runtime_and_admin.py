"""Integration tests for N03-01: Single authoritative ServerManager runtime via Admin API & cross-process ledger."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn
from PyQt6.QtWidgets import QApplication

from app.core.admin_client import LocalAdminClient
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.platform import ProcessIdentity, get_platform
from app.ui import theme
from app.ui.i18n import LANG_EN, i18n
from app.ui.pages.workspaces_page import WorkspacesPage
from backend.automation.admin_api import build_admin_app
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.store import TaskStore
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspaceProfile
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _TestAdminServer:
    """In-process loopback uvicorn server hosting Local Admin API against a backend ServerManager."""

    def __init__(
        self,
        server_manager: ServerManager,
        workspace_manager: WorkspaceManager,
        token: str = "test-admin-token-n03",
    ) -> None:
        self.port = _free_port()
        self.token = token
        app = build_admin_app(
            admin_tokens={token: frozenset({"admin:read", "admin:write"})},
            snapshot_provider=lambda: {"status": "ok"},
            scheduler_list_provider=list,
            scheduler_trigger_fn=lambda sid: {},
            diagnostics_export_fn=lambda: "{}",
            server_list_provider=lambda: server_manager.list_servers(client_id="owner"),
            server_status_fn=lambda n: server_manager.status_server(n, client_id="owner"),
            server_start_fn=lambda n, wid, wait_r: server_manager.start_server(
                n, client_id="owner", workspace_id=wid, wait_readiness=wait_r
            ),
            server_stop_fn=lambda n: server_manager.stop_server(n, client_id="owner"),
            server_restart_fn=lambda n, wid, wait_r: server_manager.restart_server(
                n, client_id="owner", workspace_id=wid, wait_readiness=wait_r
            ),
            server_health_fn=lambda n: server_manager.health_server(n, client_id="owner", run_probe=True),
            server_logs_fn=lambda n, st, off, lim: server_manager.logs_server(
                n, client_id="owner", stream=st, offset=off, limit=lim
            ),
            server_metrics_fn=lambda n: server_manager.metrics_server(n, client_id="owner"),
            server_autostart_fn=server_manager.start_autostart_servers,
            workspace_run_task_fn=lambda wid, cname: workspace_manager.run_workspace_task(
                wid, cname, client_id="owner"
            ),
        )
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning", access_log=False)
        self._server = uvicorn.Server(config)
        self._server.install_signal_handlers = lambda: None
        self._thread = threading.Thread(target=lambda: asyncio.run(self._server.serve()), daemon=True)

    def start(self) -> LocalAdminClient:
        self._thread.start()
        client = LocalAdminClient(port=self.port, token=self.token)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                client.list_servers()
                return client
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("Test Admin API server failed to start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=4.0)


class N03ReviewRuntimeAndAdminTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws_root = self.root / "proj"
        self.ws_root.mkdir(parents=True)
        self.secrets = SecretStore(self.root / "secrets")
        self.redactor = SecretRedactor()
        self.ws_path = self.root / "workspaces" / "workspaces.json"
        self.srv_path = self.root / "servers" / "managed_servers.json"
        self.tasks_db = self.root / "tasks" / "tasks.sqlite3"
        self.spool_dir = self.root / "tasks" / "spool"
        self.artifacts_dir = self.root / "tasks" / "artifacts"

        self.ws_store = WorkspaceStore(self.ws_path, secret_store=self.secrets)
        self.srv_store = ServerConfigStore(self.srv_path, secret_store=self.secrets)
        self.coord = WorkspaceServerCoordinator(self.ws_store, self.srv_store)
        self.task_store = TaskStore(self.tasks_db)
        self.platform = get_platform()

        sleep_cmd = "import time; print('SRV_READY', flush=True); time.sleep(30)"
        self.srv_store.upsert_profile(
            ServerProfile(
                name="ctrl_srv",
                argv=(sys.executable, "-c", sleep_cmd),
                cwd=str(self.ws_root),
                lifecycle="controlled",
                autostart=True,
            )
        )
        self.srv_store.upsert_profile(
            ServerProfile(
                name="indep_srv",
                argv=(sys.executable, "-c", sleep_cmd),
                cwd=str(self.ws_root),
                lifecycle="independent",
            )
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws1",
                name="Project One",
                root_path=str(self.ws_root),
                linked_servers=("ctrl_srv", "indep_srv"),
            )
        )
        self._extra_pids: list[ProcessIdentity] = []
        i18n.set_language(LANG_EN)
        theme.apply(self.app, theme.THEME_DARK)

    def tearDown(self) -> None:
        for ident in self._extra_pids:
            try:
                if self.platform.verify_process_identity(ident):
                    self.platform.terminate_process_tree(ident, grace_seconds=0.5, include_parent=True)
            except Exception:
                pass
        self._tmp.cleanup()

    def _track_pid(self, state: dict) -> None:
        pid = state.get("pid")
        ctime = state.get("create_time")
        if isinstance(pid, int) and pid > 0 and ctime is not None:
            self._extra_pids.append(ProcessIdentity(pid=pid, create_time=float(ctime)))

    def test_n03_01_gui_and_mcp_share_authoritative_runtime(self) -> None:
        backend_runner = ProcessRunner(spool_dir=self.spool_dir, redactor=self.redactor)
        backend_mgr = ServerManager(
            self.srv_store,
            runner=backend_runner,
            redactor=self.redactor,
            task_store=self.task_store,
            workspace_authorizer=self.coord.authorize_server_operation,
        )
        ws_mgr = WorkspaceManager(
            self.ws_store,
            WorkspaceHistory(self.root / "workspaces" / "history"),
            runner=backend_runner,
            redactor=self.redactor,
            task_store=self.task_store,
            artifacts_dir=self.artifacts_dir,
            coordinator=self.coord,
            server_manager=backend_mgr,
        )
        admin_srv = _TestAdminServer(backend_mgr, ws_mgr)
        admin_client = admin_srv.start()

        page = WorkspacesPage(
            config_path=self.ws_path,
            history_dir=self.root / "workspaces" / "history",
            secrets_dir=self.root / "secrets",
            servers_config_path=self.srv_path,
            servers_secrets_dir=self.root / "secrets",
            tasks_db_path=self.tasks_db,
            tasks_spool_dir=self.spool_dir,
            tasks_artifacts_dir=self.artifacts_dir,
            redactor=self.redactor,
            admin_client_provider=lambda: admin_client,
            backend_running_checker=lambda: True,
        )
        try:
            # 1) Start in GUI -> visible with same PID in backend (MCP)
            page.select_server("ctrl_srv")
            page.start_selected_server()
            self.assertTrue(page.wait_for_pending_ops(timeout=8.0))
            mcp_st = backend_mgr.status_server("ctrl_srv", client_id="owner")
            self.assertTrue(mcp_st["running"])
            self._track_pid(mcp_st)
            pid1 = mcp_st["pid"]

            # 2) Concurrent start attempt from backend + second manager does not spawn duplicate process
            other_mgr = ServerManager(
                ServerConfigStore(self.srv_path, secret_store=self.secrets),
                redactor=self.redactor,
                task_store=self.task_store,
            )
            try:
                dup_st = other_mgr.start_server("ctrl_srv", client_id="owner", wait_readiness=False)
                self.assertEqual(dup_st["pid"], pid1)
            finally:
                other_mgr.close()

            # 3) Rename / Delete blocked across instances while running
            with self.assertRaises(ValueError):
                self.coord.rename_server("ctrl_srv", "ctrl_srv_2", server_manager=page.server_manager)
            with self.assertRaises(ValueError):
                self.coord.delete_server_and_unlink("ctrl_srv", server_manager=page.server_manager)

            # 4) Close GUI while backend owns controlled + independent -> NEITHER killed
            indep_st = backend_mgr.start_server("indep_srv", client_id="owner", wait_readiness=False)
            self._track_pid(indep_st)
            page.shutdown()
            self.assertTrue(backend_mgr.status_server("ctrl_srv", client_id="owner")["running"])
            self.assertTrue(backend_mgr.status_server("indep_srv", client_id="owner")["running"])

            # 5) Stop from new GUI / Admin API
            admin_client.stop_server("ctrl_srv")
            self.assertFalse(backend_mgr.status_server("ctrl_srv", client_id="owner")["running"])
        finally:
            try:
                page.shutdown()
            except Exception:
                pass
            admin_srv.stop()
            ws_mgr.close()
            backend_mgr.close()
            backend_runner.close()

    def test_n03_01_concurrent_autostart_and_backend_restart_retains_independent(self) -> None:
        mgr1 = ServerManager(
            ServerConfigStore(self.srv_path, secret_store=self.secrets),
            task_store=self.task_store,
            workspace_authorizer=self.coord.authorize_server_operation,
        )
        mgr2 = ServerManager(
            ServerConfigStore(self.srv_path, secret_store=self.secrets),
            task_store=self.task_store,
            workspace_authorizer=self.coord.authorize_server_operation,
        )
        try:
            # Simultaneous autostart across two ServerManager instances -> single PID
            results: list[list[dict]] = []

            def run_auto(m: ServerManager) -> None:
                results.append(m.start_autostart_servers())

            t1 = threading.Thread(target=run_auto, args=(mgr1,))
            t2 = threading.Thread(target=run_auto, args=(mgr2,))
            t1.start()
            t2.start()
            t1.join(timeout=8.0)
            t2.join(timeout=8.0)
            st1 = mgr1.status_server("ctrl_srv", client_id="owner")
            st2 = mgr2.status_server("ctrl_srv", client_id="owner")
            self._track_pid(st1)
            self._track_pid(st2)
            self.assertTrue(st1["running"])
            self.assertTrue(st2["running"])
            self.assertEqual(st1["pid"], st2["pid"])

            # Start independent on mgr1, restart backend (close mgr1 -> mgr3)
            indep = mgr1.start_server("indep_srv", client_id="owner", wait_readiness=False)
            self._track_pid(indep)
            self.assertTrue(indep["running"])
            mgr1.close()
            mgr2.close()

            mgr3 = ServerManager(
                ServerConfigStore(self.srv_path, secret_store=self.secrets),
                task_store=self.task_store,
                workspace_authorizer=self.coord.authorize_server_operation,
            )
            try:
                # Controlled stopped cleanly; independent stays running with verified PID identity!
                self.assertFalse(mgr3.status_server("ctrl_srv", client_id="owner")["running"])
                st_indep = mgr3.status_server("indep_srv", client_id="owner")
                self.assertTrue(st_indep["running"])
                self.assertEqual(st_indep["pid"], indep["pid"])
                self.assertEqual(st_indep["create_time"], indep["create_time"])
            finally:
                mgr3.close()
        finally:
            mgr1.close()
            mgr2.close()


if __name__ == "__main__":
    unittest.main()
