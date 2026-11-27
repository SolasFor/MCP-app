"""End-to-end integration tests for Stage N03: Workspaces + Server Manager consolidation."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull
from PyQt6.QtGui import QShortcut
from PyQt6.QtWidgets import QApplication

from app.config import Settings
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.core.service_manager import ServiceManager
from app.ui import theme
from app.ui.components.command_palette import CommandPaletteDialog
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.main_window import ACTIVE_PAGE_IDS, NAV_SPECS, PAGE_IDS, MainWindow
from app.ui.pages.servers_page import RenameServerDialog, TemplateWizardDialog
from app.ui.pages.workspaces_page import WorkspacesPage
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.servers.models import ReadinessConfig, ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.store import TaskStore
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore

FIXTURE_SERVER = str(Path(__file__).resolve().parents[1] / "fixtures" / "dev_http_server.py")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_auth_user(client_id: str, scopes: list[str] | None = None) -> AuthenticatedUser:
    token = AccessToken(
        token=f"tok-{client_id}",
        client_id=client_id,
        scopes=scopes or ["mcp:read", "mcp:tools"],
        expires_at=None,
        resource="https://srv.example.com/mcp",
    )
    return AuthenticatedUser(token)


class N03WorkspaceServersE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.data_dir = self.root / "appdata"
        self.data_dir.mkdir(parents=True)
        self.store_path = self.data_dir / "oauth" / "state.sqlite3"
        self.redactor = SecretRedactor(["base-n03-secret"])
        self._patches = [
            patch("app.paths.user_data_dir", return_value=self.data_dir),
            patch("app.core.service_manager.user_data_dir", return_value=self.data_dir),
            patch("app.core.domain_state.user_data_dir", return_value=self.data_dir),
            patch("app.config.user_data_dir", return_value=self.data_dir),
            patch("app.ui.main_window.user_data_dir", return_value=self.data_dir),
            patch("app.ui.main_window.default_store_path", return_value=self.store_path),
            patch("app.ui.oauth_clients_dialog.default_store_path", return_value=self.store_path),
            patch("app.ui.connection_diagnostics_dialog.user_data_dir", return_value=self.data_dir),
        ]
        for p in self._patches:
            p.start()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)

    def tearDown(self) -> None:
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def test_navigation_removes_servers_and_redirects_safely(self) -> None:
        nav_ids = [spec.page_id for spec in NAV_SPECS]
        self.assertNotIn("servers", nav_ids)
        self.assertNotIn("servers", ACTIVE_PAGE_IDS)
        self.assertNotIn("servers", PAGE_IDS)
        self.assertEqual(len(NAV_SPECS), 12)

        settings = Settings()
        svc = ServiceManager(settings)
        win = MainWindow(svc, settings, tray_available=False)
        try:
            win.resize(1366, 768)
            win.show()
            self.app.processEvents()

            self.assertIsNone(win.sidebar.button_for("servers"))
            self.assertIsNotNone(win.sidebar.button_for("workspaces"))

            for legacy_target in ("servers", "server_manager", "managed_servers"):
                win.show_page(legacy_target)
                self.app.processEvents()
                self.assertEqual(win.current_page_id(), "workspaces")

            # Verify Ctrl+1..Ctrl+9 shortcuts exist and work without error
            shortcut_seqs = {sc.key().toString() for sc in win.findChildren(QShortcut) if sc.key().toString()}
            for n in range(1, 10):
                self.assertIn(f"Ctrl+{n}", shortcut_seqs)

            # Command palette routes legacy server queries to Workspaces
            for query in ("servers", "серверы"):
                palette = CommandPaletteDialog(win.build_palette_actions(), win)
                palette.search_input.setText(query)
                self.app.processEvents()
                self.assertTrue(
                    any(act.action_id == "nav.workspaces" for act in palette._filtered),
                    f"Missing nav.workspaces for query {query!r}",
                )
        finally:
            win.allow_close()
            win.close()
            self.app.processEvents()

    def test_workspaces_page_full_server_parity_nonblocking_lifecycle_and_break_ui(self) -> None:
        ws_alpha = self.root / "ws_alpha"
        ws_beta = self.root / "ws_beta"
        ws_alpha.mkdir()
        ws_beta.mkdir()

        ws_store = WorkspaceStore(self.data_dir / "workspaces.json", secret_store=SecretStore(self.data_dir / "ws_secrets"))
        srv_store = ServerConfigStore(self.data_dir / "managed_servers.json", secret_store=SecretStore(self.data_dir / "srv_secrets"))
        srv_store.set_env_secret("alpha_api", "APP_SECRET", "gui-alpha-secret-991")

        port_alpha = _free_port()
        port_indep = _free_port()
        port_unlinked = _free_port()

        srv_store.upsert_profile(
            ServerProfile(
                name="alpha_api",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_alpha), "--secret-env", "APP_SECRET"),
                cwd=str(ws_alpha),
                env_secret_refs={"APP_SECRET": srv_store.set_env_secret("alpha_api", "APP_SECRET", "gui-alpha-secret-991")},
                host="127.0.0.1",
                port=port_alpha,
                lifecycle="controlled",
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_alpha, http_path="/health", timeout_seconds=8.0),
            )
        )
        srv_store.upsert_profile(
            ServerProfile(
                name="indep_srv",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_indep)),
                cwd=str(ws_alpha),
                host="127.0.0.1",
                port=port_indep,
                lifecycle="independent",
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_indep, http_path="/health", timeout_seconds=8.0),
            )
        )
        srv_store.upsert_profile(
            ServerProfile(
                name="unlinked_srv",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_unlinked)),
                cwd=str(self.root),
                host="127.0.0.1",
                port=port_unlinked,
                lifecycle="controlled",
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_unlinked, http_path="/health", timeout_seconds=8.0),
            )
        )

        ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="alpha",
                name="Alpha Workspace",
                root_path=str(ws_alpha),
                commands={"hello": f'"{sys.executable}" -c "print(\'WS_TASK_OK\')"'},
                linked_servers=("alpha_api", "indep_srv", "missing_ref"),
                permissions=WorkspacePermissions(read=True, write=True, delete=True, execute=True, git=True),
            )
        )
        ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="beta",
                name="Beta Workspace",
                root_path=str(ws_beta),
                linked_servers=("indep_srv",),
                permissions=WorkspacePermissions(read=True, write=True, delete=True, execute=True, git=True),
            )
        )

        page = WorkspacesPage(
            config_path=self.data_dir / "workspaces.json",
            history_dir=self.data_dir / "ws_history",
            secrets_dir=self.data_dir / "ws_secrets",
            servers_config_path=self.data_dir / "managed_servers.json",
            servers_secrets_dir=self.data_dir / "srv_secrets",
            tasks_db_path=self.data_dir / "tasks.sqlite3",
            redactor=self.redactor,
        )
        from app.platform import get_platform

        platform = get_platform()
        indep_ident = None
        try:
            page.resize(1366, 768)
            page.show()
            self.app.processEvents()

            # 5 detail tabs + 2 collection tabs
            self.assertEqual(page.collection_tabs.count(), 2)
            self.assertEqual(page.detail_tabs.count(), 5)

            # Unlinked tab shows unlinked_srv
            self.assertEqual(page.unlinked_table.rowCount(), 1)
            self.assertEqual(page.unlinked_table.item(0, 0).text(), "unlinked_srv")

            # Alpha project shows alpha_api, indep_srv, plus stale/missing indicator for missing_ref
            page.select_workspace("alpha")
            self.app.processEvents()
            row_names = [page.ws_servers_table.item(r, 0).text() for r in range(page.ws_servers_table.rowCount())]
            self.assertIn("alpha_api", row_names)
            self.assertIn("indep_srv", row_names)
            self.assertTrue(any("missing_ref" in name for name in row_names))

            # Non-blocking start of indep_srv & alpha_api
            page.select_server("indep_srv")
            page.start_selected_server()
            page.wait_for_pending_ops(timeout=12.0)
            self.app.processEvents()
            indep_state = page.server_manager.status_server("indep_srv", client_id="owner")
            self.assertTrue(indep_state["healthy"])
            if indep_state.get("pid"):
                indep_ident = platform.capture_process_identity(int(indep_state["pid"]))

            page.select_server("alpha_api")
            page.start_selected_server()
            page.wait_for_pending_ops(timeout=12.0)
            self.app.processEvents()
            self.assertTrue(page.server_manager.status_server("alpha_api", client_id="owner")["healthy"])
            self.assertNotIn("gui-alpha-secret-991", page.logs_view.toPlainText())
            self.assertIn("cpu_percent", page.info_view.toPlainText())

            # Unlink indep_srv from alpha -> stays running and stays linked in beta (still running)
            page.unlink_server_from_workspace("alpha", "indep_srv")
            self.app.processEvents()
            self.assertTrue(page.server_manager.status_server("indep_srv", client_id="owner")["running"])

            # Delete beta workspace -> indep_srv moves to unlinked AND remains running!
            page.delete_workspace_by_id("beta")
            self.app.processEvents()
            self.assertIsNotNone(page.server_store.get_profile("indep_srv"))
            self.assertTrue(page.server_manager.status_server("indep_srv", client_id="owner")["running"])
            unlinked_names = [page.unlinked_table.item(r, 0).text() for r in range(page.unlinked_table.rowCount())]
            self.assertIn("indep_srv", unlinked_names)

            # Rename refused while running; after stopping alpha_api, rename -> alpha_api_v2 updates links cleanly
            page.select_workspace("alpha")
            with self.assertRaises(ValueError):
                page.rename_server_profile("alpha_api", "alpha_api_v2")
            page.select_server("alpha_api")
            page.stop_selected_server()
            page.wait_for_pending_ops(timeout=12.0)
            self.app.processEvents()
            page.rename_server_profile("alpha_api", "alpha_api_v2")
            self.app.processEvents()
            alpha_after = page.store.get_workspace("alpha")
            assert alpha_after is not None
            self.assertIn("alpha_api_v2", alpha_after.linked_servers)
            self.assertNotIn("alpha_api", alpha_after.linked_servers)

            # Template wizard invoked from workspace pre-fills cwd
            tpl = TemplateWizardDialog(page.server_store, default_cwd=str(ws_alpha), parent=page)
            self.assertEqual(tpl.cwd_edit.text(), str(ws_alpha))

            # RenameServerDialog validation
            rdlg = RenameServerDialog("alpha_api_v2", {"alpha_api_v2", "indep_srv"}, parent=page)
            rdlg.new_name_edit.setText("alpha_api_v3")
            rdlg._on_accept()
            self.assertEqual(rdlg.new_name, "alpha_api_v3")

            # Run workspace task non-blockingly and check history + TaskStore record
            page.task_combo.setCurrentIndex(max(0, page.task_combo.findData("hello")))
            page.run_selected_task()
            page.wait_for_pending_ops(timeout=12.0)
            self.app.processEvents()
            self.assertIn("WS_TASK_OK", page.git_view.toPlainText() + page.task_output_view.toPlainText())
            tasks_list = TaskStore(self.data_dir / "tasks.sqlite3").list_tasks(limit=20)
            self.assertTrue(tasks_list)

            # Break-UI stress: long names/paths/Unicode/sizes/themes/languages
            long_ws = self.root / ("в" * 60 + "_" + "a" * 60)
            long_ws.mkdir()
            page.store.upsert_workspace(
                WorkspaceProfile(
                    workspace_id="long_unicode_ws_id_" + "x" * 20,
                    name="🚀 ОченьДлинноеИмяПроекта_" + "Z" * 80,
                    root_path=str(long_ws),
                    linked_servers=("alpha_api_v2",),
                )
            )
            page.reload()
            for size in ((800, 540), (960, 640), (1366, 768)):
                for lang in (LANG_RU, LANG_EN):
                    for mode in (theme.THEME_DARK, theme.THEME_LIGHT):
                        i18n.set_language(lang)
                        theme.apply(self.app, mode)
                        page.resize(*size)
                        page.retranslate()
                        page.apply_theme()
                        self.app.processEvents()
        finally:
            for srv_name in ("alpha_api", "alpha_api_v2", "indep_srv", "unlinked_srv"):
                try:
                    page.server_manager.stop_server(srv_name, client_id="owner")
                except Exception:
                    pass
            if indep_ident is not None:
                platform.terminate_process_tree(indep_ident, grace_seconds=0.5, include_parent=True)
                entry = page.server_manager._entries.get("indep_srv")
                if entry is not None and entry.handle is not None:
                    try:
                        entry.handle.process.wait(timeout=2.0)
                    except Exception:
                        pass
            page.shutdown()

        # Corrupt JSON fails closed with visible warning banner without overwriting disk file
        corrupt_ws = self.root / "corrupt_workspaces.json"
        corrupt_raw = "{broken json"
        corrupt_ws.write_text(corrupt_raw, encoding="utf-8")
        bad_page = WorkspacesPage(
            config_path=corrupt_ws,
            history_dir=self.root / "bad_hist",
            secrets_dir=self.root / "bad_ws_sec",
            servers_config_path=self.root / "bad_srv.json",
            servers_secrets_dir=self.root / "bad_srv_sec",
            tasks_db_path=self.root / "bad_tasks.sqlite3",
            redactor=self.redactor,
        )
        try:
            self.assertFalse(bad_page.corrupt_banner.isHidden())
            self.assertEqual(corrupt_ws.read_text(encoding="utf-8"), corrupt_raw)
        finally:
            bad_page.shutdown()

    def test_mcp_tools_e2e_across_workspace_and_server_layers(self) -> None:
        ws_alpha = self.root / "mcp_ws_alpha"
        ws_beta = self.root / "mcp_ws_beta"
        ws_alpha.mkdir()
        ws_beta.mkdir()

        oauth_store = OAuthStore(
            self.store_path,
            "https://srv.example.com",
            "https://srv.example.com/mcp",
        )
        oauth_store.bind_owner("owner-tok")
        approvals = ExecutionApprovals(oauth_store, default_profile="allowlist")
        oauth_store.save_client(
            OAuthClientInformationFull(
                client_id="client-alpha",
                client_name="Alpha Client",
                redirect_uris=["http://127.0.0.1:9999/cb"],
                token_endpoint_auth_method="none",
            )
        )
        oauth_store.mark_approved("client-alpha")
        approvals.set_client_profile("client-alpha", "allowlist")

        port_solo = _free_port()
        port_alpha = _free_port()
        port_beta = _free_port()

        srv_store = ServerConfigStore(self.data_dir / "managed_servers.json", secret_store=SecretStore(self.data_dir / "srv_secrets"))
        srv_store.upsert_profile(
            ServerProfile(
                name="solo_alpha",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_solo)),
                cwd=str(ws_alpha),
                host="127.0.0.1",
                port=port_solo,
                min_profile="allowlist",
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_solo, timeout_seconds=8.0),
            )
        )
        srv_store.upsert_profile(
            ServerProfile(
                name="db_beta",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_beta)),
                cwd=str(ws_beta),
                host="127.0.0.1",
                port=port_beta,
                min_profile="allowlist",
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_beta, timeout_seconds=8.0),
            )
        )
        srv_store.upsert_profile(
            ServerProfile(
                name="app_alpha",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_alpha)),
                cwd=str(ws_alpha),
                host="127.0.0.1",
                port=port_alpha,
                min_profile="allowlist",
                depends_on=("db_beta",),
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_alpha, timeout_seconds=8.0),
            )
        )

        ws_store = WorkspaceStore(self.data_dir / "workspaces.json", secret_store=SecretStore(self.data_dir / "ws_secrets"))
        ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_alpha",
                name="Alpha",
                root_path=str(ws_alpha),
                commands={"ping": f'"{sys.executable}" -c "print(\'MCP_WS_PING\')"'},
                linked_servers=("solo_alpha", "app_alpha"),
                permissions=WorkspacePermissions(read=True, write=True, delete=False, execute=True, git=True),
                client_permissions={"client-alpha": WorkspacePermissions(read=True, write=True, delete=False, execute=True, git=False)},
            )
        )
        ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_beta",
                name="Beta",
                root_path=str(ws_beta),
                linked_servers=("db_beta",),
                permissions=WorkspacePermissions(read=True, write=False, delete=False, execute=False, git=False),
                client_permissions={"client-alpha": WorkspacePermissions(read=False, write=False, delete=False, execute=False, git=False)},
            )
        )

        import backend.server as srv_mod
        from backend.managed_servers import ManagedServers

        async def _exercise() -> dict[str, object]:
            token = auth_context_var.set(_make_auth_user("client-alpha"))
            try:
                ws_info_call = await srv_mod.mcp.call_tool("workspace_info", {"workspace_id": "ws_alpha"})
                ws_info = json.loads("".join(getattr(c, "text", "") for c in ws_info_call.content))

                run_call = await srv_mod.mcp.call_tool(
                    "workspace_run_task",
                    {"workspace_id": "ws_alpha", "command_name": "ping"},
                )
                run_res = json.loads("".join(getattr(c, "text", "") for c in run_call.content))

                started_solo_call = await srv_mod.mcp.call_tool(
                    "server_start",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                started_solo = json.loads("".join(getattr(c, "text", "") for c in started_solo_call.content))

                status_solo_call = await srv_mod.mcp.call_tool(
                    "server_status",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                status_solo = json.loads("".join(getattr(c, "text", "") for c in status_solo_call.content))

                logs_solo_call = await srv_mod.mcp.call_tool(
                    "server_logs",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                logs_solo = json.loads("".join(getattr(c, "text", "") for c in logs_solo_call.content))

                metrics_solo_call = await srv_mod.mcp.call_tool(
                    "server_metrics",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                metrics_solo = json.loads("".join(getattr(c, "text", "") for c in metrics_solo_call.content))

                health_solo_call = await srv_mod.mcp.call_tool(
                    "server_health",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                health_solo = json.loads("".join(getattr(c, "text", "") for c in health_solo_call.content))

                stopped_solo_call = await srv_mod.mcp.call_tool(
                    "server_stop",
                    {"name": "solo_alpha", "workspace_id": "ws_alpha"},
                )
                stopped_solo = json.loads("".join(getattr(c, "text", "") for c in stopped_solo_call.content))

                confused_res_call = await srv_mod.mcp.call_tool(
                    "server_start",
                    {"name": "app_alpha", "workspace_id": "ws_alpha"},
                )
                confused_res = json.loads("".join(getattr(c, "text", "") for c in confused_res_call.content))

                # Revoke client and confirm fail-closed on subsequent MCP call
                oauth_store.revoke_client("client-alpha")
                revoked_denied = False
                try:
                    revoked_call = await srv_mod.mcp.call_tool(
                        "server_list",
                        {"workspace_id": "ws_alpha"},
                    )
                    revoked_payload = "".join(getattr(c, "text", "") for c in revoked_call.content)
                    revoked_denied = "denied" in revoked_payload.lower() or "error" in revoked_payload.lower()
                except Exception:
                    revoked_denied = True

                return {
                    "ws_info": ws_info,
                    "run_res": run_res,
                    "started_solo": started_solo,
                    "status_solo": status_solo,
                    "logs_solo": logs_solo,
                    "metrics_solo": metrics_solo,
                    "health_solo": health_solo,
                    "stopped_solo": stopped_solo,
                    "confused_res": confused_res,
                    "revoked_denied": revoked_denied,
                }
            finally:
                auth_context_var.reset(token)

        orig_oauth = srv_mod.oauth_provider
        orig_exec = srv_mod.oauth_execution
        orig_managed = srv_mod.MANAGED_SERVERS
        orig_ws_mgr = srv_mod.WORKSPACE_MANAGER
        orig_srv_mgr = srv_mod.SERVER_MANAGER
        orig_coord = srv_mod.WORKSPACE_SERVER_COORDINATOR
        orig_tasks = srv_mod.TASK_STORE
        task_store = TaskStore(self.data_dir / "tasks.sqlite3")
        coord = WorkspaceServerCoordinator(ws_store, srv_store)
        tmp_managed = ManagedServers(srv_store.path, secret_store=srv_store.secret_store)
        try:
            srv_mod.oauth_provider = SimpleNamespace(store=oauth_store)  # type: ignore[assignment]
            srv_mod.oauth_execution = approvals
            srv_mod.TASK_STORE = task_store
            srv_mod.WORKSPACE_SERVER_COORDINATOR = coord
            srv_mod.MANAGED_SERVERS = tmp_managed
            srv_mod.SERVER_MANAGER = orig_srv_mgr.__class__(
                srv_store,
                task_store=task_store,
                workspace_authorizer=coord.authorize_server_operation,
                auth_rechecker=srv_mod._server_auth_rechecker,
            )
            srv_mod.WORKSPACE_MANAGER = orig_ws_mgr.__class__(
                ws_store,
                orig_ws_mgr.history,
                task_store=task_store,
                coordinator=coord,
                server_manager=srv_mod.SERVER_MANAGER,
            )
            res = asyncio.run(_exercise())
            ws_info = res["ws_info"]
            assert isinstance(ws_info, dict)
            self.assertIn("linked_servers_status", ws_info)
            run_res = res["run_res"]
            assert isinstance(run_res, dict)
            self.assertTrue(run_res.get("task_id"))
            self.assertTrue(res["started_solo"]["healthy"])  # type: ignore[index]
            self.assertTrue(res["status_solo"]["running"])  # type: ignore[index]
            self.assertIn("text", res["logs_solo"])  # type: ignore[arg-type]
            self.assertIn("cpu_percent", res["metrics_solo"])  # type: ignore[arg-type]
            self.assertTrue(res["health_solo"]["healthy"])  # type: ignore[index]
            self.assertFalse(res["stopped_solo"]["running"])  # type: ignore[index]
            self.assertIn("error", res["confused_res"])  # type: ignore[arg-type]
            self.assertTrue(res["revoked_denied"])
        finally:
            try:
                srv_mod.SERVER_MANAGER.stop_server("solo_alpha", client_id="owner")
            except Exception:
                pass
            srv_mod.SERVER_MANAGER.close()
            srv_mod.WORKSPACE_MANAGER.close()
            tmp_managed.close()
            srv_mod.oauth_provider = orig_oauth
            srv_mod.oauth_execution = orig_exec
            srv_mod.MANAGED_SERVERS = orig_managed
            srv_mod.WORKSPACE_MANAGER = orig_ws_mgr
            srv_mod.SERVER_MANAGER = orig_srv_mgr
            srv_mod.WORKSPACE_SERVER_COORDINATOR = orig_coord
            srv_mod.TASK_STORE = orig_tasks


if __name__ == "__main__":
    unittest.main()
