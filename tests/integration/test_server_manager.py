"""Integration tests for Stage 6 Server Manager: HTTP readiness, logs, metrics, restarts, trees, GUI."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.platform import get_platform
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.servers_page import ServerProfileDialog, ServersPage, TemplateWizardDialog
from backend.managed_servers import ManagedServers
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ReadinessConfig, RestartConfig, ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.models import TaskSpec
from backend.tasks.store import TaskStore
from backend.tool_registry import DEFAULT_REGISTRY, SERVER_TOOLS
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

FIXTURE_SERVER = str(Path(__file__).resolve().parents[1] / "fixtures" / "dev_http_server.py")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class ServerManagerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.redactor = SecretRedactor(["base-token-xyz"])
        self.store = ServerConfigStore(
            self.root / "managed_servers.json",
            secret_store=SecretStore(self.root / "secrets"),
        )
        self.runner = ProcessRunner(spool_dir=self.root / "spool", redactor=self.redactor)
        self.task_store = TaskStore(self.root / "tasks.sqlite3")
        self.manager = ServerManager(
            self.store,
            runner=self.runner,
            redactor=self.redactor,
            task_store=self.task_store,
            supervisor_poll_seconds=0.1,
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.runner.close()
        self.tmp.cleanup()

    def test_http_server_readiness_metrics_redacted_logs_and_task_link(self) -> None:
        port = _free_port()
        secret_ref = self.store.set_env_secret("api", "DB_PASS", "super-secret-db-pass-987")
        task, _created = self.task_store.create_task(
            owner_client_id="client-a",
            profile="allowlist",
            spec=TaskSpec(kind="windows", command="echo prepare"),
            title="prepare",
        )
        profile = ServerProfile(
            name="api",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port), "--secret-env", "DB_PASS"),
            cwd=str(self.root),
            env_secret_refs={"DB_PASS": secret_ref},
            host="127.0.0.1",
            port=port,
            readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port, http_path="/health", timeout_seconds=8.0),
            min_profile="allowlist",
            allowed_clients=("client-a",),
        )
        self.store.upsert_profile(profile)

        # Safe client or unlisted client must be denied
        with self.assertRaises(PermissionError):
            self.manager.start_server("api", client_id="client-a", client_profile="safe")
        with self.assertRaises(PermissionError):
            self.manager.start_server("api", client_id="client-b", client_profile="full")

        started = self.manager.start_server(
            "api",
            client_id="client-a",
            client_profile="allowlist",
            linked_task_id=task.task_id,
        )
        self.assertTrue(started["running"])
        self.assertTrue(started["healthy"])
        self.assertEqual(started["status"], "healthy")
        self.assertEqual(started["linked_task"]["task_id"], task.task_id)

        health = self.manager.health_server("api", client_id="client-a", client_profile="allowlist")
        self.assertTrue(health["healthy"])
        self.assertGreaterEqual(len(health["history"]), 1)

        metrics = self.manager.metrics_server("api", client_id="client-a", client_profile="allowlist")
        self.assertTrue(metrics["alive"])
        self.assertGreater(metrics["memory_rss_bytes"], 0)
        self.assertGreaterEqual(metrics["num_threads"], 1)

        # Live logs must stream while process is still running (redacted)
        logs_out: dict = {}
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            logs_out = self.manager.logs_server("api", client_id="client-a", client_profile="allowlist", stream="stdout")
            if "BOOT DB_PASS=" in logs_out.get("text", ""):
                break
            time.sleep(0.05)
        logs_err = self.manager.logs_server("api", client_id="client-a", client_profile="allowlist", stream="stderr")
        self.assertIn("BOOT DB_PASS=", logs_out["text"])
        self.assertNotIn("super-secret-db-pass-987", logs_out["text"])
        self.assertNotIn("super-secret-db-pass-987", logs_err["text"])

        # Cross-client stop must fail closed
        with self.assertRaises(PermissionError):
            self.manager.stop_server("api", client_id="client-b", client_profile="full")

        stopped = self.manager.stop_server("api", client_id="client-a", client_profile="allowlist")
        self.assertFalse(stopped["running"])
        self.assertTrue(stopped["stopped"])

    def test_crash_restart_with_backoff_and_limit(self) -> None:
        port = _free_port()
        profile = ServerProfile(
            name="flaky",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port), "--crash-after", "0.25", "--exit-code", "2"),
            cwd=str(self.root),
            host="127.0.0.1",
            port=port,
            readiness=ReadinessConfig(kind="none"),
            restart=RestartConfig(policy="on-failure", max_attempts=2, base_backoff_seconds=0.15, max_backoff_seconds=0.4),
        )
        self.store.upsert_profile(profile)
        self.manager.start_server("flaky", client_id="owner", wait_readiness=False)

        deadline = time.monotonic() + 8.0
        final_status = {}
        while time.monotonic() < deadline:
            final_status = self.manager.status_server("flaky", client_id="owner")
            if final_status["status"] == "failed" and not final_status["running"]:
                break
            time.sleep(0.1)

        self.assertEqual(final_status["status"], "failed")
        self.assertEqual(final_status["restart_count"], 2)

    def test_controlled_process_tree_cleanup_and_independent_mode(self) -> None:
        platform = get_platform()
        port_tree = _free_port()
        child_pid_file = self.root / "child.pid"
        tree_prof = ServerProfile(
            name="tree_srv",
            argv=(
                sys.executable,
                FIXTURE_SERVER,
                "--port", str(port_tree),
                "--spawn-child",
                "--child-pid-file", str(child_pid_file),
            ),
            cwd=str(self.root),
            lifecycle="controlled",
            host="127.0.0.1",
            port=port_tree,
            readiness=ReadinessConfig(kind="tcp", host="127.0.0.1", port=port_tree, timeout_seconds=8.0),
        )
        self.store.upsert_profile(tree_prof)
        self.manager.start_server("tree_srv", client_id="owner")

        deadline = time.monotonic() + 5.0
        while not child_pid_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
        child_id = platform.capture_process_identity(child_pid)
        self.assertIsNotNone(child_id)

        self.manager.stop_server("tree_srv", client_id="owner")
        self.assertFalse(platform.verify_process_identity(child_id))  # type: ignore[arg-type]

        # Independent mode must remain alive across stop_server and manager.close()
        port_ind = _free_port()
        ind_pid_file = self.root / "ind.pid"
        ind_prof = ServerProfile(
            name="detached_srv",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_ind), "--pid-file", str(ind_pid_file)),
            cwd=str(self.root),
            lifecycle="independent",
            host="127.0.0.1",
            port=port_ind,
            readiness=ReadinessConfig(kind="tcp", host="127.0.0.1", port=port_ind, timeout_seconds=8.0),
        )
        self.store.upsert_profile(ind_prof)
        ind_ident = None
        try:
            self.manager.start_server("detached_srv", client_id="owner")
            ind_pid = int(ind_pid_file.read_text(encoding="utf-8").strip())
            ind_ident = platform.capture_process_identity(ind_pid)
            self.assertIsNotNone(ind_ident)

            stop_res = self.manager.stop_server("detached_srv", client_id="owner")
            self.assertFalse(stop_res["stopped"])
            self.assertTrue(stop_res["running"])
            self.assertTrue(platform.verify_process_identity(ind_ident))  # type: ignore[arg-type]
        finally:
            if ind_ident is not None:
                platform.terminate_process_tree(ind_ident, grace_seconds=0.5, include_parent=True)
            entry = self.manager._entries.get("detached_srv")
            if entry is not None and entry.handle is not None:
                try:
                    entry.handle.process.wait(timeout=2.0)
                except Exception:
                    pass
                for th in entry.handle._reader_threads:
                    th.join(timeout=1.0)

    def test_dependency_ordered_start_and_port_conflict_protection(self) -> None:
        port_db = _free_port()
        port_app = _free_port()
        db_prof = ServerProfile(
            name="db",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_db)),
            cwd=str(self.root),
            host="127.0.0.1",
            port=port_db,
            readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_db, timeout_seconds=8.0),
        )
        app_prof = ServerProfile(
            name="app",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port_app)),
            cwd=str(self.root),
            host="127.0.0.1",
            port=port_app,
            depends_on=("db",),
            readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=port_app, timeout_seconds=8.0),
        )
        self.store.upsert_profile(db_prof)
        self.store.upsert_profile(app_prof)

        app_state = self.manager.start_server("app", client_id="owner")
        self.assertTrue(app_state["healthy"])
        db_state = self.manager.status_server("db", client_id="owner")
        self.assertTrue(db_state["healthy"])
        self.manager.stop_server("app", client_id="owner")
        self.manager.stop_server("db", client_id="owner")

        # Port conflict with foreign listener refuses start without closing listener
        conflict_port = _free_port()
        self.store.upsert_profile(
            ServerProfile(
                name="db",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(conflict_port)),
                cwd=str(self.root),
                host="127.0.0.1",
                port=conflict_port,
                readiness=ReadinessConfig(kind="http", host="127.0.0.1", port=conflict_port, timeout_seconds=8.0),
            )
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", conflict_port))
        sock.listen(1)
        try:
            with self.assertRaises(RuntimeError):
                self.manager.start_server("app", client_id="owner")
            self.assertEqual(sock.getsockname()[1], conflict_port)
            self.assertFalse(self.manager.status_server("app", client_id="owner")["running"])
        finally:
            sock.close()

    def test_oauth_managed_server_wrapper_compatibility(self) -> None:
        port = _free_port()
        self.store.upsert_profile(
            ServerProfile(
                name="compat",
                argv=(sys.executable, FIXTURE_SERVER, "--port", str(port)),
                cwd=str(self.root),
                host="127.0.0.1",
                port=port,
            )
        )
        compat = ManagedServers(self.store.path, runner=self.runner, secret_store=self.store.secret_store)
        try:
            res = compat.start("client-x", "compat")
            self.assertTrue(res["running"])
            with self.assertRaises(ValueError):
                compat.stop("client-y", "compat")
            stopped = compat.stop("client-x", "compat")
            self.assertFalse(stopped["running"])
        finally:
            compat.close()

    def test_headless_gui_create_template_edit_and_live_metrics(self) -> None:
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        page = ServersPage(
            config_path=self.root / "gui_servers.json",
            secrets_dir=self.root / "gui_secrets",
            redactor=self.redactor,
        )
        try:
            self.assertTrue(page.empty_state.isVisibleTo(page) or page.table.rowCount() == 0)

            port = _free_port()
            # Exercise ServerProfileDialog directly without blocking on exec()
            dlg = ServerProfileDialog(page.store, is_new=True, parent=page)
            dlg.name_edit.setText("gui_api")
            dlg.exe_edit.setText(sys.executable)
            dlg.args_edit.setText(f'"{FIXTURE_SERVER}" --port {port} --secret-env GUI_SECRET')
            dlg.cwd_edit.setText(str(self.root))
            dlg.port_spin.setValue(port)
            dlg.readiness_combo.setCurrentIndex(dlg.readiness_combo.findData("http"))
            dlg.secret_env_edit.setPlainText("GUI_SECRET=gui-top-secret-456")
            dlg._on_accept()
            self.assertIsNotNone(dlg.saved_profile)
            page.save_profile(dlg.saved_profile)  # type: ignore[arg-type]

            self.assertEqual(page.table.rowCount(), 1)
            page.table.selectRow(0)
            page.start_selected()
            self.app.processEvents()
            snap = page.server_manager.status_server("gui_api", client_id="owner")
            self.assertTrue(snap["healthy"])
            self.assertNotIn("gui-top-secret-456", page.info_view.toPlainText())
            page.stop_selected()

            # Exercise TemplateWizardDialog validation + generation
            tpl = TemplateWizardDialog(page.store, parent=page)
            tpl.name_edit.setText("gui_static")
            tpl.cwd_edit.setText(str(self.root))
            tpl.template_combo.setCurrentIndex(tpl.template_combo.findData("static_http"))
            tpl.port_spin.setValue(_free_port())
            tpl._on_accept()
            self.assertIsNotNone(tpl.saved_profile)
            page.save_profile(tpl.saved_profile)  # type: ignore[arg-type]
            self.assertEqual(page.table.rowCount(), 2)

            i18n.set_language(LANG_EN)
            page.retranslate()
            self.assertEqual(page.add_btn.text(), "Add")
            i18n.set_language(LANG_RU)
            page.retranslate()
        finally:
            page.shutdown()
            i18n.set_language(LANG_RU)
            theme.apply(self.app, theme.THEME_DARK)

    def test_oauth_revoke_blocks_scheduled_restart_and_registry_enforces_profiles(self) -> None:
        oauth_store = OAuthStore(
            self.root / "oauth.sqlite3",
            "https://srv.example.com",
            "https://srv.example.com/mcp",
        )
        oauth_store.bind_owner("owner-tok")
        exec_approvals = ExecutionApprovals(oauth_store)
        oauth_store.save_client(
            OAuthClientInformationFull(
                client_id="c-alpha",
                client_name="alpha",
                redirect_uris=["http://127.0.0.1:19999/cb"],
                token_endpoint_auth_method="none",
            )
        )
        oauth_store.mark_approved("c-alpha")
        principal = AccessToken(
            token="tok",
            client_id="c-alpha",
            scopes=["mcp:read"],
            resource="https://srv.example.com/mcp",
        )

        # Safe profile denies all server_* tools; allowlist/full expose them at tool-registry level
        exec_approvals.set_profile("safe")
        self.assertEqual(DEFAULT_REGISTRY.allowed_tools(oauth_store, principal, exec_approvals) & SERVER_TOOLS, frozenset())
        exec_approvals.set_profile("allowlist")
        self.assertEqual(DEFAULT_REGISTRY.allowed_tools(oauth_store, principal, exec_approvals) & SERVER_TOOLS, SERVER_TOOLS)

        def rechecker(cid: str, srv: ServerProfile) -> None:
            if not exec_approvals.client_approved(cid) or exec_approvals.emergency_stopped():
                raise PermissionError("revoked")
            self.manager._authorize_profile(
                srv, client_id=cid, client_profile=exec_approvals.profile_for(cid)
            )

        self.manager.auth_rechecker = rechecker
        port = _free_port()
        prof = ServerProfile(
            name="revocable",
            argv=(sys.executable, FIXTURE_SERVER, "--port", str(port), "--crash-after", "0.3", "--exit-code", "1"),
            cwd=str(self.root),
            host="127.0.0.1",
            port=port,
            readiness=ReadinessConfig(kind="none"),
            restart=RestartConfig(policy="on-failure", max_attempts=3, base_backoff_seconds=0.35),
            min_profile="allowlist",
            allowed_clients=("c-alpha",),
        )
        self.store.upsert_profile(prof)
        self.manager.start_server("revocable", client_id="c-alpha", client_profile="allowlist", wait_readiness=False)
        oauth_store.revoke_client("c-alpha")

        deadline = time.monotonic() + 5.0
        state = {}
        while time.monotonic() < deadline:
            state = self.manager.status_server("revocable", client_id="owner")
            if state["status"] == "failed" and not state["running"]:
                break
            time.sleep(0.1)

        self.assertEqual(state["status"], "failed")
        self.assertIn("revoked", state["last_error"])


if __name__ == "__main__":
    unittest.main()
