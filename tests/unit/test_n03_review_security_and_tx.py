"""TDD reproducer & regression tests for Stage N03 independent review (N03-02 .. N03-06)."""
from __future__ import annotations

import asyncio
import errno
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.atomic_io import cross_process_lock
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore, SecretStoreError
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import (
    ReadinessConfig,
    RestartConfig,
    ServerProfile,
)
from backend.servers.store import ServerConfigStore
from backend.tasks.manager import TaskManager
from backend.tasks.models import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    TaskSpec,
)
from backend.tasks.store import TaskStore
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_server(
    name: str,
    cwd: str,
    *,
    argv: tuple[str, ...] | None = None,
    min_profile: str = "allowlist",
    allowed_clients: tuple[str, ...] = (),
    depends_on: tuple[str, ...] = (),
    port: int | None = None,
    readiness: ReadinessConfig | None = None,
    restart: RestartConfig | None = None,
    env: dict[str, str] | None = None,
    env_secret_refs: dict[str, str] | None = None,
    enabled: bool = True,
) -> ServerProfile:
    return ServerProfile(
        name=name,
        display_name=f"Server {name}",
        argv=argv or (sys.executable, "-c", "import time; time.sleep(0.2)"),
        cwd=cwd,
        env=env or {},
        env_secret_refs=env_secret_refs or {},
        lifecycle="controlled",
        host="127.0.0.1",
        port=port,
        readiness=readiness or ReadinessConfig(),
        depends_on=depends_on,
        restart=restart or RestartConfig(),
        enabled=enabled,
        min_profile=min_profile,
        allowed_clients=allowed_clients,
    )


class N03ReviewSecurityAndTxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secret_store = SecretStore(self.root / "secrets")
        self.ws_dir = self.root / "ws_alpha"
        self.ws_dir_b = self.root / "ws_beta"
        self.ws_dir.mkdir(parents=True)
        self.ws_dir_b.mkdir(parents=True)
        self.automation_dir = self.root / "automation"
        self.ws_store = WorkspaceStore(self.root / "workspaces" / "workspaces.json", secret_store=self.secret_store)
        self.srv_store = ServerConfigStore(self.root / "servers" / "managed_servers.json", secret_store=self.secret_store)
        self.coordinator = WorkspaceServerCoordinator(
            self.ws_store,
            self.srv_store,
            automation_dir=self.automation_dir,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ------------------------------------------------------------------ N03-02
    def test_n03_02_unlink_and_delete_do_not_widen_access_until_explicit_owner_action(self) -> None:
        # Client c1 is allowed by ServerProfile, but DENIED by linked ws_a.
        self.srv_store.upsert_profile(
            _make_server("svc", str(self.ws_dir), min_profile="allowlist", allowed_clients=("c1", "c2"))
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_a",
                name="WS A",
                root_path=str(self.ws_dir),
                linked_servers=(),
                permissions=WorkspacePermissions(read=True, execute=False),
                allowed_clients=("c2",),
                min_profile="allowlist",
            )
        )
        self.coordinator.link_server("ws_a", "svc")

        # While linked: c1 is denied even though ServerProfile allows c1.
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation(
                "svc", client_id="c1", client_profile="full", mode="read"
            )
        # c2 allowed for read, denied for control (execute=False).
        self.assertEqual(
            self.coordinator.authorize_server_operation("svc", client_id="c2", client_profile="full", mode="read"),
            ["ws_a"],
        )
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation(
                "svc", client_id="c2", client_profile="full", mode="control"
            )

        # Unlinking the last workspace via unlink_server OR set_workspace_servers MUST NOT implicitly widen c1/c2!
        self.coordinator.unlink_server("ws_a", "svc")
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation("svc", client_id="c1", client_profile="full", mode="read")

        # Re-link then set_workspace_servers([]) -> still must fail-closed for non-owners.
        self.coordinator.link_server("ws_a", "svc")
        self.coordinator.set_workspace_servers("ws_a", [])
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation("svc", client_id="c1", client_profile="full", mode="read")

        # Re-link then delete workspace -> STILL must not implicitly widen c1!
        self.coordinator.link_server("ws_a", "svc")
        self.assertTrue(self.coordinator.delete_workspace_preserving_servers("ws_a"))
        self.assertIsNotNone(self.srv_store.get_profile("svc"))
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation("svc", client_id="c1", client_profile="full", mode="read")

        # Explicit owner policy change enables unscoped standalone access.
        updated = self.coordinator.set_server_workspace_scoped("svc", False)
        self.assertFalse(updated.workspace_scoped)
        self.assertEqual(
            self.coordinator.authorize_server_operation("svc", client_id="c1", client_profile="full", mode="control"),
            [],
        )

    def test_n03_02_multi_workspace_disabled_and_stale_links(self) -> None:
        self.srv_store.upsert_profile(_make_server("shared", str(self.ws_dir), min_profile="allowlist"))
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_disabled",
                name="Disabled",
                root_path=str(self.ws_dir),
                linked_servers=("shared", "stale_ghost"),
                permissions=WorkspacePermissions(read=True, execute=True),
                enabled=False,
            )
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_ro",
                name="ReadOnly",
                root_path=str(self.ws_dir_b),
                linked_servers=("shared",),
                permissions=WorkspacePermissions(read=True, execute=False),
                enabled=True,
            )
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_exec",
                name="Exec",
                root_path=str(self.ws_dir),
                linked_servers=("shared",),
                permissions=WorkspacePermissions(read=True, execute=True),
                enabled=True,
            )
        )

        # Disabled workspace explicitly or standalone must deny
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation(
                "shared", client_id="c1", client_profile="full", mode="read", workspace_id="ws_disabled"
            )
        # Read-only workspace cannot start
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation(
                "shared", client_id="c1", client_profile="full", mode="control", workspace_id="ws_ro"
            )
        # Exec workspace succeeds cleanly
        self.assertEqual(
            self.coordinator.authorize_server_operation(
                "shared", client_id="c1", client_profile="full", mode="control", workspace_id="ws_exec"
            ),
            ["ws_exec"],
        )
        # Stale link reported in missing_by_workspace without crash; client cannot start nonexistent server
        snap = self.coordinator.partition_servers()
        self.assertEqual(snap.missing_by_workspace["ws_disabled"], ("stale_ghost",))
        with self.assertRaises(KeyError):
            self.coordinator.authorize_server_operation(
                "stale_ghost", client_id="c1", client_profile="full", mode="read"
            )

    def test_n03_02_empty_missing_after_init_and_unknown_schema_fail_closed(self) -> None:
        self.srv_store.upsert_profile(_make_server("srv1", str(self.ws_dir), min_profile="allowlist"))
        self.ws_store.upsert_workspace(
            WorkspaceProfile(workspace_id="ws1", name="WS1", root_path=str(self.ws_dir), linked_servers=())
        )
        self.coordinator.link_server("ws1", "srv1")

        # Empty 0-byte workspaces.json must fail closed everywhere (never look like valid empty {})
        saved_ws_bytes = self.ws_store.path.read_text(encoding="utf-8")
        self.ws_store.path.write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.ws_store.load_workspaces()
        with self.assertRaises(ValueError):
            self.coordinator.partition_servers()
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation("srv1", client_id="c1", client_profile="full", mode="read")

        # Unknown schema_version must raise ValueError and deny client authorization
        for bad_ver in (99, 0, -1, "2", True):
            self.ws_store.path.write_text(
                json.dumps({"schema_version": bad_ver, "workspaces": {}}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError, msg=f"schema_version={bad_ver!r} should be rejected"):
                self.ws_store.load_workspaces()
            with self.assertRaises(PermissionError):
                self.coordinator.authorize_server_operation("srv1", client_id="c1", client_profile="full", mode="read")

        # Missing workspaces.json AFTER prior initialization must fail closed
        self.ws_store.path.write_text(saved_ws_bytes, encoding="utf-8")
        self.assertIsNotNone(self.ws_store.get_workspace("ws1"))
        self.ws_store.path.unlink()
        with self.assertRaises(ValueError):
            self.ws_store.load_workspaces()
        with self.assertRaises(ValueError):
            self.coordinator.partition_servers()
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation("srv1", client_id="c1", client_profile="full", mode="read")

        # Empty / unknown schema_version in managed_servers.json also fails closed
        self.ws_store.path.write_text(saved_ws_bytes, encoding="utf-8")
        self.srv_store.path.write_text("   ", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.srv_store.load_profiles(strict=True)
        self.srv_store.path.write_text(json.dumps({"schema_version": 42, "servers": {}}), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.srv_store.load_profiles(strict=True)

    # ------------------------------------------------------------------ N03-03
    def test_n03_03_rename_fault_injection_and_schedule_links(self) -> None:
        ref = self.srv_store.set_env_secret("api_old", "TOKEN", "top-secret-token-xyz")
        self.srv_store.upsert_profile(
            _make_server("api_old", str(self.ws_dir), env_secret_refs={"TOKEN": ref}, allowed_clients=("c1",))
        )
        self.srv_store.upsert_profile(_make_server("worker", str(self.ws_dir), depends_on=("api_old",)))
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws1",
                name="WS1",
                root_path=str(self.ws_dir),
                linked_servers=("api_old",),
                linked_tasks=("task-1", "task-2"),
                permissions=WorkspacePermissions(read=True, execute=True),
            )
        )
        sched = AutomationScheduler(self.automation_dir)
        sched.upsert_schedule(
            ScheduleSpec(
                schedule_id="srv_job",
                name="Restart API",
                trigger_type="interval",
                interval_seconds=60,
                tool_name="server_start",
                arguments={"name": "api_old"},
            )
        )

        # 1) Fault inside SecretStore.set_secret -> nothing changed, old secret still intact
        with patch.object(self.secret_store, "set_secret", side_effect=SecretStoreError("dpapi locked")):
            with self.assertRaises(SecretStoreError):
                self.coordinator.rename_server("api_old", "api_new")
        self.assertEqual(self.secret_store.resolve_ref(ref), "top-secret-token-xyz")
        self.assertIsNotNone(self.srv_store.get_profile("api_old"))
        self.assertEqual(self.ws_store.get_workspace("ws1").linked_servers, ("api_old",))  # type: ignore[union-attr]

        # 2) PermissionError / ENOSPC on saving workspaces.json AFTER managed_servers.json saved
        from app.core.atomic_io import atomic_write_json as real_atomic_json

        for err in (PermissionError("access denied"), OSError(errno.ENOSPC, "No space left on device")):
            real_ws_path = self.ws_store.path

            def fail_ws_save(path, *args, _target=real_ws_path, _err=err, **kwargs):
                if Path(path) == _target:
                    raise _err
                return real_atomic_json(path, *args, **kwargs)

            with patch("backend.workspaces.store.atomic_write_json", side_effect=fail_ws_save), patch(
                "backend.workspaces.server_links.atomic_write_json",
                side_effect=fail_ws_save,
            ):
                with self.assertRaises(type(err)):
                    self.coordinator.rename_server("api_old", "api_new")

            # Critical invariant: old profile, old secret, depends_on, linked_tasks, and schedules MUST be intact!
            self.assertEqual(self.secret_store.resolve_ref(ref), "top-secret-token-xyz")
            old_p = self.srv_store.get_profile("api_old")
            self.assertIsNotNone(old_p)
            self.assertIsNone(self.srv_store.get_profile("api_new"))
            self.assertEqual(self.srv_store.get_profile("worker").depends_on, ("api_old",))  # type: ignore[union-attr]
            ws = self.ws_store.get_workspace("ws1")
            assert ws is not None
            self.assertEqual(ws.linked_servers, ("api_old",))
            self.assertEqual(ws.linked_tasks, ("task-1", "task-2"))
            self.assertEqual(sched.list_schedules()[0]["arguments"]["name"], "api_old")

        # 3) Clean full rename MUST update secret refs, depends_on, linked_servers, linked_tasks preserved, and schedules!
        renamed = self.coordinator.rename_server("api_old", "api_new")
        self.assertEqual(renamed.name, "api_new")
        self.assertIsNone(self.srv_store.get_profile("api_old"))
        self.assertEqual(self.srv_store.get_profile("worker").depends_on, ("api_new",))  # type: ignore[union-attr]
        ws_after = self.ws_store.get_workspace("ws1")
        assert ws_after is not None
        self.assertEqual(ws_after.linked_servers, ("api_new",))
        self.assertEqual(ws_after.linked_tasks, ("task-1", "task-2"))
        self.assertEqual(sched.list_schedules()[0]["arguments"]["name"], "api_new")
        merged_env, _ = self.srv_store.resolve_profile_env(renamed)
        self.assertEqual(merged_env["TOKEN"], "top-secret-token-xyz")

    def test_n03_03_delete_server_and_crash_recovery_rollback(self) -> None:
        ref = self.srv_store.set_env_secret("srv_del", "K", "secret-keep-on-fail")
        self.srv_store.upsert_profile(_make_server("srv_del", str(self.ws_dir), env_secret_refs={"K": ref}))
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws1",
                name="WS1",
                root_path=str(self.ws_dir),
                linked_servers=("srv_del",),
                linked_tasks=("t9",),
            )
        )
        # Fault during workspace save AFTER server profile save in delete_server_and_unlink
        from app.core.atomic_io import atomic_write_json as real_atomic_json

        ws_target = self.ws_store.path
        with patch(
            "backend.workspaces.store.atomic_write_json",
            side_effect=lambda p, *a, **kw: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
            if Path(p) == ws_target
            else real_atomic_json(p, *a, **kw),
        ), patch(
            "backend.workspaces.server_links.atomic_write_json",
            side_effect=lambda p, *a, **kw: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
            if Path(p) == ws_target
            else real_atomic_json(p, *a, **kw),
        ):
            with self.assertRaises(OSError):
                self.coordinator.delete_server_and_unlink("srv_del")

        # Profile, secret, and workspace link MUST all still exist!
        self.assertIsNotNone(self.srv_store.get_profile("srv_del"))
        self.assertEqual(self.secret_store.resolve_ref(ref), "secret-keep-on-fail")
        self.assertEqual(self.ws_store.get_workspace("ws1").linked_servers, ("srv_del",))  # type: ignore[union-attr]

        # Also simulate interrupted tx journal left on disk after partial managed_servers mutation
        tx_path = self.ws_store.path.parent / ".n03_coordinator_tx.json"
        if tx_path.parent.exists():
            orig_srv_raw = self.srv_store.path.read_text(encoding="utf-8")
            orig_ws_raw = self.ws_store.path.read_text(encoding="utf-8")
            self.srv_store.path.write_text(json.dumps({"schema_version": 2, "servers": {}}), encoding="utf-8")
            tx_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "files": {
                            str(self.srv_store.path): orig_srv_raw,
                            str(self.ws_store.path): orig_ws_raw,
                        },
                        "created_secrets": [],
                    }
                ),
                encoding="utf-8",
            )
            fresh_coord = WorkspaceServerCoordinator(
                WorkspaceStore(self.ws_store.path, secret_store=self.secret_store),
                ServerConfigStore(self.srv_store.path, secret_store=self.secret_store),
                automation_dir=self.automation_dir,
            )
            snap = fresh_coord.partition_servers()
            self.assertIn("srv_del", snap.servers)
            self.assertEqual(self.secret_store.resolve_ref(ref), "secret-keep-on-fail")
            self.assertFalse(tx_path.exists())

    # ------------------------------------------------------------------ N03-04
    def test_n03_04_lock_order_and_concurrent_store_operations(self) -> None:
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_conc",
                name="Concurrent",
                root_path=str(self.ws_dir),
                permissions=WorkspacePermissions(read=True, execute=True),
            )
        )
        for i in range(8):
            self.srv_store.upsert_profile(_make_server(f"s_{i}", str(self.ws_dir)))

        runner = ProcessRunner(spool_dir=self.root / "spool")
        srv_mgr = ServerManager(self.srv_store, runner=runner, workspace_authorizer=self.coordinator.authorize_server_operation)
        errors: list[BaseException] = []

        def task_appender() -> None:
            try:
                for idx in range(25):
                    self.ws_store.append_linked_task("ws_conc", f"task-{idx}")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def linker(offset: int) -> None:
            try:
                c = WorkspaceServerCoordinator(
                    WorkspaceStore(self.ws_store.path, secret_store=self.secret_store),
                    ServerConfigStore(self.srv_store.path, secret_store=self.secret_store),
                )
                for idx in range(offset, 8, 2):
                    c.link_server("ws_conc", f"s_{idx}")
                    c.partition_servers()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def status_reader() -> None:
            try:
                for _ in range(25):
                    srv_mgr.list_servers(client_id="owner")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def renamer() -> None:
            try:
                self.coordinator.rename_server("s_0", "s_0_renamed", server_manager=srv_mgr)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        try:
            threads = [
                threading.Thread(target=task_appender, daemon=True, name="task_appender"),
                threading.Thread(target=linker, args=(0,), daemon=True, name="linker_0"),
                threading.Thread(target=linker, args=(1,), daemon=True, name="linker_1"),
                threading.Thread(target=status_reader, daemon=True, name="status_reader"),
            ]
            for t in threads:
                t.start()
            deadline = time.monotonic() + 5.0
            for t in threads:
                t.join(timeout=max(0.05, deadline - time.monotonic()))
                self.assertFalse(t.is_alive(), f"Thread {t.name} deadlocked")

            # Also contend directly on same store instance vs coordinator (AB-BA order test)
            t_read = threading.Thread(target=status_reader, daemon=True, name="status_reader_2")
            t_ren = threading.Thread(target=renamer, daemon=True, name="renamer")
            t_task = threading.Thread(target=task_appender, daemon=True, name="task_appender_2")
            t_read.start()
            t_ren.start()
            t_task.start()
            deadline2 = time.monotonic() + 5.0
            for t in (t_read, t_ren, t_task):
                t.join(timeout=max(0.05, deadline2 - time.monotonic()))
                self.assertFalse(t.is_alive(), f"Thread {t.name} deadlocked")
            self.assertEqual(errors, [])

            ws = self.ws_store.get_workspace("ws_conc")
            assert ws is not None
            self.assertIn("task-24", ws.linked_tasks)
            self.assertIsNotNone(self.srv_store.get_profile("s_0_renamed"))
        finally:
            srv_mgr.close()
            runner.close()

    def test_n03_04_bounded_timeout_cross_thread_and_cross_process(self) -> None:
        lock_file = self.root / "contend.lock"

        # 1) Cross-thread bounded timeout
        entered = threading.Event()
        release = threading.Event()

        def holder() -> None:
            with cross_process_lock(lock_file, timeout=5.0):
                entered.set()
                release.wait(timeout=3.0)

        t = threading.Thread(target=holder, daemon=True)
        t.start()
        self.assertTrue(entered.wait(timeout=2.0))
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            with cross_process_lock(lock_file, timeout=0.15):
                pass
        elapsed = time.monotonic() - t0
        release.set()
        t.join(timeout=2.0)
        self.assertLess(elapsed, 1.2, f"Thread lock ignored bounded timeout (took {elapsed:.2f}s)")

        # 2) Exception releases lock cleanly
        with self.assertRaises(RuntimeError):
            with cross_process_lock(lock_file, timeout=0.5):
                raise RuntimeError("boom")
        with cross_process_lock(lock_file, timeout=0.2):
            pass

        # 3) Cross-process bounded timeout
        repo_root = str(Path(__file__).resolve().parents[2])
        script = (
            "import sys, time\n"
            f"sys.path.insert(0, {repo_root!r})\n"
            "from pathlib import Path\n"
            "from app.core.atomic_io import cross_process_lock\n"
            f"p = Path({str(lock_file)!r})\n"
            "with cross_process_lock(p, timeout=5.0):\n"
            "    print('LOCKED', flush=True)\n"
            "    time.sleep(1.5)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            line = proc.stdout.readline().strip()
            self.assertEqual(line, "LOCKED")
            t1 = time.monotonic()
            with self.assertRaises(TimeoutError):
                with cross_process_lock(lock_file, timeout=0.15):
                    pass
            self.assertLess(time.monotonic() - t1, 1.2)
        finally:
            proc.terminate()
            proc.wait(timeout=3.0)
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()

    # ------------------------------------------------------------------ N03-05
    def test_n03_05_live_auth_during_dependency_wait_and_supervisor_restart(self) -> None:
        dep_port = _free_port()
        # Dep waits ~0.55s before listening on dep_port
        dep_code = (
            f"import socket, time; time.sleep(0.55); "
            f"s = socket.socket(); s.bind(('127.0.0.1', {dep_port})); s.listen(1); time.sleep(3.0)"
        )
        app_marker = self.root / "app_spawned.flag"
        app_code = f"from pathlib import Path; Path({str(app_marker)!r}).write_text('1'); import time; time.sleep(2.0)"

        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_dep",
                name="WS Dep",
                root_path=str(self.ws_dir),
                linked_servers=("dep_srv", "app_srv"),
                permissions=WorkspacePermissions(read=True, execute=True),
                allowed_clients=("c1",),
                min_profile="allowlist",
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "dep_srv",
                str(self.ws_dir),
                argv=(sys.executable, "-c", dep_code),
                port=dep_port,
                readiness=ReadinessConfig(kind="tcp", host="127.0.0.1", port=dep_port, timeout_seconds=5.0, interval_seconds=0.05),
                allowed_clients=("c1",),
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "app_srv",
                str(self.ws_dir),
                argv=(sys.executable, "-c", app_code),
                depends_on=("dep_srv",),
                allowed_clients=("c1",),
            )
        )

        # Scenario A: OAuth revoked while dep_srv is warming up -> app_srv must NOT spawn!
        revoked = {"flag": False}

        def live_auth(cid: str | None, tool: str) -> str:
            if cid == "c1" and revoked["flag"]:
                raise PermissionError("OAuth client revoked mid-startup")
            return "full"

        runner = ProcessRunner(spool_dir=self.root / "spool_n03_05")
        mgr_kwargs: dict = {
            "runner": runner,
            "workspace_authorizer": self.coordinator.authorize_server_operation,
            "live_client_authorizer": live_auth,
        }
        mgr = ServerManager(self.srv_store, **mgr_kwargs)
        try:
            def revoke_soon() -> None:
                time.sleep(0.25)
                revoked["flag"] = True

            threading.Thread(target=revoke_soon, daemon=True).start()
            with self.assertRaises(PermissionError):
                mgr.start_server("app_srv", client_id="c1", client_profile="full", wait_readiness=False)
            self.assertFalse(app_marker.exists(), "Dependent app_srv spawned after live OAuth revocation")
            mgr.stop_server("dep_srv", client_id="owner")
        finally:
            mgr.close()

        # Scenario B: ServerProfile or WorkspaceProfile changed during dependency readiness wait
        revoked["flag"] = False
        mgr2 = ServerManager(self.srv_store, **mgr_kwargs)
        try:
            def disable_ws_soon() -> None:
                time.sleep(0.25)
                ws = self.ws_store.get_workspace("ws_dep")
                assert ws is not None
                from dataclasses import replace

                self.ws_store.upsert_workspace(
                    replace(ws, permissions=WorkspacePermissions(read=True, execute=False))
                )

            threading.Thread(target=disable_ws_soon, daemon=True).start()
            with self.assertRaises(PermissionError):
                mgr2.start_server("app_srv", client_id="c1", client_profile="full", wait_readiness=False)
            self.assertFalse(app_marker.exists(), "Dependent app_srv spawned after Workspace execute=False")
            mgr2.stop_server("dep_srv", client_id="owner")
        finally:
            mgr2.close()

        # Scenario C: _supervisor_tick auto-restart preserves workspace_id & re-reads fresh disk profile
        from dataclasses import replace

        ws = self.ws_store.get_workspace("ws_dep")
        assert ws is not None
        self.ws_store.upsert_workspace(replace(ws, permissions=WorkspacePermissions(read=True, execute=True)))
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_deny",
                name="Deny",
                root_path=str(self.ws_dir_b),
                linked_servers=("flaky_srv",),
                permissions=WorkspacePermissions(read=True, execute=False),
            )
        )
        self.srv_store.upsert_profile(
            _make_server(
                "flaky_srv",
                str(self.ws_dir),
                argv=(sys.executable, "-c", "import sys; sys.exit(1)"),
                restart=RestartConfig(policy="always", max_attempts=3, base_backoff_seconds=0.1, max_backoff_seconds=0.2),
                allowed_clients=("c1",),
            )
        )
        self.coordinator.link_server("ws_dep", "flaky_srv")

        mgr3 = ServerManager(self.srv_store, supervisor_poll_seconds=0.05, **mgr_kwargs)
        try:
            mgr3.start_server("flaky_srv", client_id="c1", client_profile="full", workspace_id="ws_dep", wait_readiness=False)
            time.sleep(0.2)
            # Now revoke ws_dep execute permission on disk; supervisor auto-restart MUST block with STATUS_FAILED
            ws_now = self.ws_store.get_workspace("ws_dep")
            assert ws_now is not None
            self.ws_store.upsert_workspace(replace(ws_now, permissions=WorkspacePermissions(read=True, execute=False)))
            deadline = time.monotonic() + 3.0
            st = {}
            while time.monotonic() < deadline:
                st = mgr3.status_server("flaky_srv", client_id="owner")
                if st.get("status") == STATUS_FAILED:
                    break
                time.sleep(0.05)
            self.assertEqual(st.get("status"), STATUS_FAILED)
        finally:
            mgr3.close()
            runner.close()

    def test_n03_05_workspace_run_task_live_pre_dispatch(self) -> None:
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_t",
                name="WS Task",
                root_path=str(self.ws_dir),
                commands={"hello": f'"{sys.executable}" -c "print(\'OK\')"'},
                permissions=WorkspacePermissions(read=True, execute=True),
                allowed_clients=("c1",),
            )
        )
        runner = ProcessRunner(spool_dir=self.root / "ws_spool")
        task_store = TaskStore(self.root / "tasks.sqlite3")
        history = WorkspaceHistory(self.root / "history")

        def deny_live(cid: str | None, tool: str) -> str:
            raise PermissionError("Global profile downgraded to safe")

        wm = WorkspaceManager(
            self.ws_store,
            history,
            runner=runner,
            task_store=task_store,
            artifacts_dir=self.root / "artifacts",
            live_client_authorizer=deny_live,
        )
        try:
            with self.assertRaises(PermissionError):
                asyncio.run(wm.run_workspace_task("ws_t", "hello", client_id="c1", client_profile="full"))
        finally:
            wm.close()
            runner.close()

    # ------------------------------------------------------------------ N03-06
    def test_n03_06_workspace_task_full_task_manager_parity_cancel_restart_and_redaction(self) -> None:
        secret_tok = "ultra-secret-ws-987654"
        redactor = SecretRedactor([secret_tok])
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_run",
                name="WS Run",
                root_path=str(self.ws_dir),
                commands={
                    "echo_secret": f'"{sys.executable}" -c "import os, sys; print(\'OUT:\' + os.environ.get(\'MY_SEC\', \'\')); sys.stderr.write(\'ERR_TAG\\n\')"',
                    "sleeper": f'"{sys.executable}" -c "import time; print(\'STARTED\', flush=True); time.sleep(5)"',
                },
                env_secret_refs={"MY_SEC": self.ws_store.set_env_secret("ws_run", "MY_SEC", secret_tok)},
                permissions=WorkspacePermissions(read=True, execute=True),
                allowed_clients=("c1",),
            )
        )
        task_store = TaskStore(self.root / "tasks.sqlite3")
        spool_dir = self.root / "shared_spool"
        artifacts_dir = self.root / "shared_artifacts"
        runner = ProcessRunner(spool_dir=spool_dir, redactor=redactor)
        history = WorkspaceHistory(self.root / "ws_history")
        wm = WorkspaceManager(
            self.ws_store,
            history,
            redactor=redactor,
            task_store=task_store,
            spool_dir=spool_dir,
            artifacts_dir=artifacts_dir,
        )
        tm = TaskManager(
            task_store,
            runner,
            artifacts_dir=artifacts_dir,
            redactor=redactor,
            workspace_task_executor=wm.execute_restarted_task,
        )

        try:
            # 1) run_workspace_task integrates with TaskManager status/list/output/result/artifacts
            out = asyncio.run(wm.run_workspace_task("ws_run", "echo_secret", client_id="c1", client_profile="full"))
            tid = out["task_id"]
            st = tm.status_dict(tid, owner_client_id="c1")
            self.assertEqual(st["status"], STATUS_SUCCEEDED)
            self.assertEqual([t["task_id"] for t in tm.list_dicts(owner_client_id="c1")], [tid])
            stdout_page = tm.read_output(tid, owner_client_id="c1", stream="stdout")
            stderr_page = tm.read_output(tid, owner_client_id="c1", stream="stderr")
            self.assertIn("OUT:", stdout_page["text"])
            self.assertIn("ERR_TAG", stderr_page["text"])
            self.assertNotIn(secret_tok, stdout_page["text"])
            res_payload = tm.result_dict(tid, owner_client_id="c1")
            self.assertIn("result", res_payload)
            arts = tm.read_artifacts(tid, owner_client_id="c1", artifact_name="result.json")
            self.assertIn("OUT:", arts["content"])
            self.assertNotIn(secret_tok, arts["content"])

            # Verify TaskSpec on disk contains no raw secrets and preserves workspace linkage
            spec = task_store.get_spec(tid)
            assert spec is not None
            self.assertIsInstance(spec, TaskSpec)
            self.assertEqual(spec.workspace_id, "ws_run")
            self.assertEqual(spec.workspace_command, "echo_secret")
            self.assertNotIn(secret_tok, spec.command)

            # 2) TaskManager.restart runs inside workspace context (has MY_SEC injected in ws env!)
            async def _run_restart() -> dict:
                restarted = await tm.restart(tid, owner_client_id="c1")
                new_tid = restarted["task_id"]
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    cur = tm.status_dict(new_tid, owner_client_id="c1")
                    if cur["status"] in (STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELLED):
                        await tm.close()
                        return cur
                    await asyncio.sleep(0.05)
                await tm.close()
                return tm.status_dict(new_tid, owner_client_id="c1")

            restarted_final = asyncio.run(_run_restart())
            self.assertEqual(restarted_final["status"], STATUS_SUCCEEDED, restarted_final)
            restarted_out = tm.read_output(restarted_final["task_id"], owner_client_id="c1", stream="stdout")
            self.assertIn("OUT:", restarted_out["text"])

            # 3) Cancel via SQLite request_cancel stops long-running workspace task and marks STATUS_CANCELLED
            async def _cancel_via_db() -> str:
                task_coro = asyncio.create_task(
                    wm.run_workspace_task("ws_run", "sleeper", timeout=30, client_id="c1", client_profile="full")
                )
                found_id = ""
                deadline = time.monotonic() + 4.0
                while time.monotonic() < deadline:
                    rows = task_store.list_tasks(owner_client_id="c1", status=STATUS_RUNNING, limit=10)
                    if rows:
                        found_id = rows[0].task_id
                        break
                    await asyncio.sleep(0.03)
                self.assertTrue(found_id)
                task_store.request_cancel(found_id, owner_client_id="c1")
                await asyncio.wait_for(task_coro, timeout=5.0)
                return found_id

            cancelled_tid = asyncio.run(_cancel_via_db())
            c_rec = task_store.get_task(cancelled_tid)
            assert c_rec is not None
            self.assertEqual(c_rec.status, STATUS_CANCELLED)

            # 4) asyncio.CancelledError does not leave task stuck in running
            async def _cancel_coro() -> str:
                task_coro = asyncio.create_task(
                    wm.run_workspace_task("ws_run", "sleeper", timeout=30, client_id="c1", client_profile="full")
                )
                found_id = ""
                deadline = time.monotonic() + 4.0
                while time.monotonic() < deadline:
                    rows = task_store.list_tasks(owner_client_id="c1", status=STATUS_RUNNING, limit=10)
                    if rows:
                        found_id = rows[0].task_id
                        break
                    await asyncio.sleep(0.03)
                self.assertTrue(found_id)
                task_coro.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task_coro
                return found_id

            aborted_tid = asyncio.run(_cancel_coro())
            a_rec = task_store.get_task(aborted_tid)
            assert a_rec is not None
            self.assertEqual(a_rec.status, STATUS_CANCELLED)

            # 5) Timeout marks STATUS_FAILED with timed_out=True, and wm.close() marks orphans STATUS_INTERRUPTED
            timed_out_res = asyncio.run(
                wm.run_workspace_task("ws_run", "sleeper", timeout=1, client_id="c1", client_profile="full")
            )
            self.assertTrue(timed_out_res["timed_out"])
            to_rec = task_store.get_task(timed_out_res["task_id"])
            assert to_rec is not None
            self.assertEqual(to_rec.status, STATUS_FAILED)

            orphan_rec = task_store.create_running_task(
                owner_client_id="c1",
                profile="full",
                title="orphan",
                spec=TaskSpec(kind="windows", command="python -V", workspace_id="ws_run", workspace_command="echo_secret"),
            )
            with wm._active_tasks_lock:
                wm._active_task_ids.add(orphan_rec.task_id)
            wm.close()
            recovered_rec = task_store.get_task(orphan_rec.task_id)
            assert recovered_rec is not None
            self.assertEqual(recovered_rec.status, STATUS_INTERRUPTED)
        finally:
            wm.close()
            runner.close()

    # ------------------------------------------------------------- N03-FINAL-02
    def test_n03_final_02_tx_journal_allowlist_schema_types_symlinks_and_secrets_fail_closed(self) -> None:
        auto_dir = self.root / "automation"
        sched = AutomationScheduler(auto_dir)
        sched.upsert_schedule(
            ScheduleSpec(
                schedule_id="sch_tx",
                name="Start Srv",
                trigger_type="interval",
                interval_seconds=60,
                tool_name="server_start",
                arguments={"name": "srv_tx"},
            )
        )
        coord = WorkspaceServerCoordinator(self.ws_store, self.srv_store, automation_dir=auto_dir)
        self.secret_store.set_secret("owner", "owner_tok", "OWNER-KEEP")
        self.secret_store.set_secret("workspaces", "ws_keep__K", "WS-KEEP")
        s_old_ref = self.srv_store.set_env_secret("srv_tx", "TOKEN", "SRV-KEEP")
        self.srv_store.upsert_profile(
            _make_server("srv_tx", str(self.ws_dir), env_secret_refs={"TOKEN": s_old_ref})
        )
        self.ws_store.upsert_workspace(
            WorkspaceProfile(
                workspace_id="ws_keep",
                name="Keep",
                root_path=str(self.ws_dir),
                linked_servers=("srv_tx",),
            )
        )
        srv_path = self.srv_store.path
        ws_path = self.ws_store.path
        victim = self.root / "outside_victim.txt"
        victim.write_text("DO_NOT_TOUCH", encoding="utf-8")
        srv_before = srv_path.read_text(encoding="utf-8")
        ws_before = ws_path.read_text(encoding="utf-8")
        sched_before = (auto_dir / "schedules.json").read_text(encoding="utf-8")

        tx_path = ws_path.parent / ".n03_coordinator_tx.json"

        bad_journals: list[dict] = [
            # Arbitrary file overwrite & null unlink outside allowlist
            {"schema_version": 1, "files": {str(victim): "PWNED"}, "created_secrets": []},
            {"schema_version": 1, "files": {str(victim): None}, "created_secrets": []},
            # Unsupported schema_version / unexpected top-level key
            {"schema_version": 99, "files": {}, "created_secrets": []},
            {"schema_version": True, "files": {}, "created_secrets": []},
            {"schema_version": 1, "files": {}, "created_secrets": [], "extra": 1},
            # Mixed valid first entry + invalid second entry must be atomic (neither applied)
            {
                "schema_version": 1,
                "files": {str(ws_path): json.dumps({"schema_version": 2, "workspaces": []}), str(victim): "BAD"},
                "created_secrets": [],
            },
            # Non-string / non-JSON preimage content
            {"schema_version": 1, "files": {str(ws_path): 123}, "created_secrets": []},
            {"schema_version": 1, "files": {str(ws_path): "{bad"}, "created_secrets": []},
            # Cross-namespace & pre-existing server secret deletion forbidden
            {
                "schema_version": 1,
                "files": {str(srv_path): srv_before},
                "created_secrets": [["owner", "owner_tok"]],
            },
            {
                "schema_version": 1,
                "files": {str(srv_path): srv_before},
                "created_secrets": [["workspaces", "ws_keep__K"]],
            },
            {
                "schema_version": 1,
                "files": {str(srv_path): srv_before},
                "created_secrets": [["servers", "srv_tx__TOKEN"]],
            },
        ]
        for payload in bad_journals:
            tx_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                coord.partition_servers()
            with self.assertRaises(PermissionError):
                coord.authorize_server_operation("srv_tx", client_id="owner", client_profile="full")
            self.assertTrue(tx_path.exists())
            self.assertEqual(victim.read_text(encoding="utf-8"), "DO_NOT_TOUCH")
            self.assertEqual(srv_path.read_text(encoding="utf-8"), srv_before)
            self.assertEqual(ws_path.read_text(encoding="utf-8"), ws_before)
            self.assertEqual(self.secret_store.get_secret("owner", "owner_tok"), "OWNER-KEEP")
            self.assertEqual(self.secret_store.get_secret("workspaces", "ws_keep__K"), "WS-KEEP")
            self.assertEqual(self.secret_store.get_secret("servers", "srv_tx__TOKEN"), "SRV-KEEP")

        # Symlink / reparse point check (fails closed on target reparse)
        tx_path.write_text(
            json.dumps({"schema_version": 1, "files": {str(srv_path): srv_before}, "created_secrets": []}),
            encoding="utf-8",
        )
        with patch("backend.workspaces.server_links.is_reparse_or_symlink", side_effect=lambda p: Path(p) == srv_path):
            with self.assertRaises(ValueError):
                coord.partition_servers()
        tx_path.unlink(missing_ok=True)

        # Valid recovery touching schedules.json MUST acquire .automation.lock even from partition_servers()
        mutated_sched = json.loads(sched_before)
        mutated_sched["schedules"]["sch_tx"]["arguments"]["name"] = "srv_mutated"
        (auto_dir / "schedules.json").write_text(json.dumps(mutated_sched), encoding="utf-8")
        tx_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "files": {
                        str(ws_path): ws_before,
                        str(srv_path): srv_before,
                        str(auto_dir / "schedules.json"): sched_before,
                    },
                    "created_secrets": [],
                }
            ),
            encoding="utf-8",
        )
        auto_lock = auto_dir / ".automation.lock"
        locked_ev = threading.Event()
        release_ev = threading.Event()

        def _hold_auto_lock() -> None:
            with cross_process_lock(auto_lock, timeout=5.0):
                locked_ev.set()
                release_ev.wait(timeout=5.0)

        t_hold = threading.Thread(target=_hold_auto_lock, daemon=True)
        t_hold.start()
        self.assertTrue(locked_ev.wait(timeout=2.0))
        snap_done = threading.Event()
        snap_err: list[Exception] = []

        def _run_partition() -> None:
            try:
                coord.partition_servers()
            except Exception as exc:  # noqa: BLE001
                snap_err.append(exc)
            finally:
                snap_done.set()

        t_part = threading.Thread(target=_run_partition, daemon=True)
        t_part.start()
        # Must still be waiting for .automation.lock!
        self.assertFalse(snap_done.wait(timeout=0.2))
        release_ev.set()
        t_hold.join(timeout=3.0)
        t_part.join(timeout=3.0)
        self.assertEqual(snap_err, [])
        self.assertFalse(tx_path.exists())
        self.assertEqual(
            json.loads((auto_dir / "schedules.json").read_text(encoding="utf-8"))["schedules"]["sch_tx"]["arguments"]["name"],
            "srv_tx",
        )
        # Idempotent second recovery call
        coord.partition_servers()


if __name__ == "__main__":
    unittest.main()
