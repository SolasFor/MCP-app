"""Integration tests for N03-01: Single authoritative ServerManager runtime via Admin API & cross-process ledger."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import gc
import socket
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import uvicorn
from PyQt6.QtWidgets import QApplication

from app.core.admin_client import AdminBackendUnavailableError, LocalAdminClient
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.platform import ProcessIdentity, get_platform
from app.ui import theme
from app.ui.i18n import LANG_EN, i18n
from app.ui.pages.workspaces_page import WorkspacesPage
from backend.automation.admin_api import build_admin_app
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import RestartConfig, ServerProfile
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
        self._tracked_runners: list[ProcessRunner] = []
        i18n.set_language(LANG_EN)
        theme.apply(self.app, theme.THEME_DARK)

    def tearDown(self) -> None:
        self._cleanup_tracked_processes()
        self._tmp.cleanup()

    def _track_runner(self, runner: ProcessRunner) -> None:
        if runner not in self._tracked_runners:
            self._tracked_runners.append(runner)

    def _cleanup_tracked_processes(self) -> None:
        for ident in self._extra_pids:
            try:
                if self.platform.verify_process_identity(ident):
                    self.platform.terminate_process_tree(ident, grace_seconds=0.5, include_parent=True)
            except Exception:
                pass
        for runner in self._tracked_runners:
            for info in list(getattr(runner, "_independent_processes", {}).values()):
                proc = getattr(info, "process", None)
                if proc is not None:
                    try:
                        proc.wait(timeout=2.0)
                    except Exception:
                        try:
                            proc.poll()
                        except Exception:
                            pass
            for mh in list(getattr(runner, "_active_managed", {}).values()):
                for th in getattr(mh, "_reader_threads", ()):
                    try:
                        th.join(timeout=1.0)
                    except Exception:
                        pass
            try:
                runner.close()
            except Exception:
                pass
        self._tracked_runners.clear()
        self._extra_pids.clear()

    def _track_pid(self, state: dict) -> None:
        pid = state.get("pid")
        ctime = state.get("create_time")
        if isinstance(pid, int) and pid > 0 and ctime is not None:
            self._extra_pids.append(ProcessIdentity(pid=pid, create_time=float(ctime)))

    def test_n03_01_gui_and_mcp_share_authoritative_runtime(self) -> None:
        backend_runner = ProcessRunner(spool_dir=self.spool_dir, redactor=self.redactor)
        self._track_runner(backend_runner)
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
            self._track_runner(page.server_manager.runner)
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
        self._track_runner(mgr1.runner)
        self._track_runner(mgr2.runner)
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
            self._track_runner(mgr3.runner)
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

    def test_n03_final_01_no_mutating_fallback_on_ambiguous_response_or_live_backend(self) -> None:
        from app.core import admin_client as ac_mod

        ambig_cls = getattr(ac_mod, "AdminRequestAmbiguousError", None)
        self.assertIsNotNone(ambig_cls, "AdminRequestAmbiguousError must exist on app.core.admin_client")

        # Raw TCP listener accepts POST request (marking server_accepted), then drops socket before HTTP response.
        accepted_paths: list[str] = []
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(5)
        drop_port = int(srv_sock.getsockname()[1])
        stop_flag = threading.Event()

        def _accept_and_drop() -> None:
            srv_sock.settimeout(0.1)
            while not stop_flag.is_set():
                try:
                    conn, _ = srv_sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                try:
                    data = conn.recv(4096).decode("utf-8", errors="replace")
                    if data:
                        first_line = data.splitlines()[0]
                        if first_line.startswith("POST "):
                            accepted_paths.append(first_line)
                finally:
                    conn.close()

        t_drop = threading.Thread(target=_accept_and_drop, daemon=True)
        t_drop.start()
        dead_port = _free_port()
        backend_live = True
        use_drop_server = True

        def _client_provider() -> LocalAdminClient | None:
            if not backend_live:
                return None
            return LocalAdminClient(port=drop_port if use_drop_server else dead_port, token="tok")

        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws1",
                name="Project One",
                root_path=str(self.ws_root),
                linked_servers=("ctrl_srv",),
                commands={"ping": f'"{sys.executable}" -c "print(\'LOCAL_RAN\')"'},
            )
        )
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
            admin_client_provider=_client_provider,
            backend_running_checker=lambda: backend_live,
        )
        try:
            # 1) Ambiguous response after request accepted: must raise AdminRequestAmbiguousError & NOT run locally
            with patch.object(page.server_manager, "start_server", wraps=page.server_manager.start_server) as m_start:
                with patch.object(page.server_manager, "restart_server", wraps=page.server_manager.restart_server) as m_rst:
                    with self.assertRaises(ambig_cls):  # type: ignore[arg-type]
                        page.runtime_proxy.start_server("ctrl_srv", wait_readiness=False)
                    with self.assertRaises(ambig_cls):  # type: ignore[arg-type]
                        page.runtime_proxy.restart_server("ctrl_srv", wait_readiness=False)
                    self.assertEqual(m_start.call_count, 0)
                    self.assertEqual(m_rst.call_count, 0)
            self.assertEqual(len(accepted_paths), 2)

            with patch.object(page.manager, "run_workspace_task", wraps=page.manager.run_workspace_task) as m_task:
                with self.assertRaises(ambig_cls):  # type: ignore[arg-type]
                    page._run_workspace_task_via_admin_or_local("ws1", "ping")
                self.assertEqual(m_task.call_count, 0)
            self.assertEqual(len(accepted_paths), 3)

            # 2) Backend live (backend_live=True) while Admin API refuses connection -> mutating calls fail closed!
            use_drop_server = False
            with patch.object(page.server_manager, "start_server", wraps=page.server_manager.start_server) as m_start:
                with self.assertRaises(AdminBackendUnavailableError):
                    page.runtime_proxy.start_server("ctrl_srv", wait_readiness=False)
                with self.assertRaises(AdminBackendUnavailableError):
                    page.runtime_proxy.stop_server("ctrl_srv")
                with self.assertRaises(AdminBackendUnavailableError):
                    page.runtime_proxy.start_autostart_servers()
                with self.assertRaises(AdminBackendUnavailableError):
                    page.runtime_proxy.health_server("ctrl_srv", run_probe=True)
                with self.assertRaises(AdminBackendUnavailableError):
                    page._run_workspace_task_via_admin_or_local("ws1", "ping")
                self.assertEqual(m_start.call_count, 0)

            # Read-only status still succeeds cleanly via ledger when Admin API is momentarily unreachable
            ro = page.runtime_proxy.status_server("ctrl_srv")
            self.assertFalse(ro["running"])

            # 3) Confirmed backend stopped -> local fallback works safely
            backend_live = False
            st_local = page.runtime_proxy.start_server("ctrl_srv", wait_readiness=False)
            self._track_pid(st_local)
            self.assertTrue(st_local["running"])
            st_stopped = page.runtime_proxy.stop_server("ctrl_srv")
            self.assertFalse(st_stopped["running"])
        finally:
            stop_flag.set()
            srv_sock.close()
            t_drop.join(timeout=2.0)
            page.shutdown()
            page.deleteLater()
            self.app.processEvents()

    def test_n03_final_01_ownership_handoff_local_to_backend_stop_and_restart(self) -> None:
        fail_cmd = "import sys, time; print('UP', flush=True); time.sleep(30); sys.exit(1)"
        self.srv_store.upsert_profile(
            ServerProfile(
                name="ctrl_srv",
                argv=(sys.executable, "-c", fail_cmd),
                cwd=str(self.ws_root),
                lifecycle="controlled",
                restart=RestartConfig(
                    policy="on-failure",
                    base_backoff_seconds=0.1,
                    max_backoff_seconds=0.2,
                    max_attempts=3,
                ),
            )
        )
        backend_runner = ProcessRunner(spool_dir=self.spool_dir, redactor=self.redactor)
        self._track_runner(backend_runner)
        backend_mgr = ServerManager(
            self.srv_store,
            runner=backend_runner,
            redactor=self.redactor,
            task_store=self.task_store,
            workspace_authorizer=self.coord.authorize_server_operation,
            supervisor_poll_seconds=0.05,
        )
        admin_srv = _TestAdminServer(
            backend_mgr,
            WorkspaceManager(
                self.ws_store,
                WorkspaceHistory(self.root / "workspaces" / "history"),
                runner=backend_runner,
                redactor=self.redactor,
                task_store=self.task_store,
                artifacts_dir=self.artifacts_dir,
                coordinator=self.coord,
                server_manager=backend_mgr,
            ),
        )
        admin_client = admin_srv.start()
        backend_live = False

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
            admin_client_provider=lambda: admin_client if backend_live else None,
            backend_running_checker=lambda: backend_live,
        )
        local_mgr2 = ServerManager(
            ServerConfigStore(self.srv_path, secret_store=self.secrets),
            redactor=self.redactor,
            task_store=self.task_store,
            supervisor_poll_seconds=0.05,
        )
        self._track_runner(page.server_manager.runner)
        self._track_runner(local_mgr2.runner)
        try:
            # Start controlled + independent locally while backend is OFF
            st1 = page.runtime_proxy.start_server("ctrl_srv", wait_readiness=False)
            ind1 = page.runtime_proxy.start_server("indep_srv", wait_readiness=False)
            self._track_pid(st1)
            self._track_pid(ind1)
            pid1 = st1["pid"]

            # Backend turns ON; GUI restarts ctrl_srv via Admin API -> backend spawns pid2, GUI shutdown preserves pid2!
            backend_live = True
            st2 = page.runtime_proxy.restart_server("ctrl_srv", wait_readiness=False)
            self._track_pid(st2)
            pid2 = st2["pid"]
            self.assertNotEqual(pid2, pid1)
            page.shutdown()
            after_close = backend_mgr.status_server("ctrl_srv", client_id="owner")
            self.assertTrue(after_close["running"])
            self.assertEqual(after_close["pid"], pid2)

            # Local manager starts ctrl_srv, backend stops it -> local supervisor MUST NOT auto-restart it!
            backend_mgr.stop_server("ctrl_srv", client_id="owner")
            st3 = local_mgr2.start_server("ctrl_srv", client_id="owner", wait_readiness=False)
            self._track_pid(st3)
            backend_mgr.stop_server("ctrl_srv", client_id="owner")
            time.sleep(0.45)
            self.assertFalse(local_mgr2.status_server("ctrl_srv", client_id="owner")["running"])
            self.assertFalse(backend_mgr.status_server("ctrl_srv", client_id="owner")["running"])

            # Independent process kept exact identity throughout
            ind_now = backend_mgr.status_server("indep_srv", client_id="owner")
            self.assertTrue(ind_now["running"])
            self.assertEqual((ind_now["pid"], ind_now["create_time"]), (ind1["pid"], ind1["create_time"]))
        finally:
            local_mgr2.close()
            try:
                page.shutdown()
            except Exception:
                pass
            admin_srv.stop()
            backend_mgr.close()
            backend_runner.close()

    def test_n03_final_03_zero_subprocess_resource_warnings_and_controlled_cleanup(self) -> None:
        mgr = ServerManager(
            ServerConfigStore(self.srv_path, secret_store=self.secrets),
            redactor=self.redactor,
            task_store=self.task_store,
            workspace_authorizer=self.coord.authorize_server_operation,
        )
        self._track_runner(mgr.runner)
        ctrl_ident: ProcessIdentity | None = None
        indep_ident: ProcessIdentity | None = None
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                st_c = mgr.start_server("ctrl_srv", client_id="owner", wait_readiness=False)
                st_i = mgr.start_server("indep_srv", client_id="owner", wait_readiness=False)
                self._track_pid(st_c)
                self._track_pid(st_i)
                ctrl_ident = ProcessIdentity(pid=int(st_c["pid"]), create_time=float(st_c["create_time"]))
                indep_ident = ProcessIdentity(pid=int(st_i["pid"]), create_time=float(st_i["create_time"]))

                # Close manager: controlled must be dead, independent intentionally still alive
                mgr.close()
                self.assertFalse(self.platform.verify_process_identity(ctrl_ident))
                self.assertTrue(self.platform.verify_process_identity(indep_ident))

                # Intentional test-owned cleanup for detached independent test process
                self._cleanup_tracked_processes()
                self.assertFalse(self.platform.verify_process_identity(indep_ident))
                del mgr
                gc.collect()

            subproc_warns = [str(w.message) for w in caught if "still running" in str(w.message)]
            self.assertEqual(subproc_warns, [], f"Leaked subprocess ResourceWarnings: {subproc_warns}")
        finally:
            for ident in (ctrl_ident, indep_ident):
                if ident is not None and self.platform.verify_process_identity(ident):
                    self.platform.terminate_process_tree(ident, grace_seconds=0.5, include_parent=True)


if __name__ == "__main__":
    unittest.main()
