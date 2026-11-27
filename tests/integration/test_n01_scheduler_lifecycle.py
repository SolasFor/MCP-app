"""Regression & lifecycle acceptance tests for N01-FINAL-01 (Automation Scheduler)."""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from mcp.types import CallToolResult, TextContent
from PyQt6.QtWidgets import QApplication
from starlette.testclient import TestClient

from app.core.redaction import SecretRedactor
from app.ui.pages.automation_page import AutomationPage
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec
from backend.gateway.models import GatewayServerStatus, UpstreamServerProfile, UpstreamToolEntry


def _isolated_backend_env(tpath: Path, **extra: str) -> dict[str, str]:
    env = {
        "MCP_SECRET_TOKEN": secrets.token_urlsafe(18),
        "MCP_ADMIN_TOKEN": secrets.token_urlsafe(18),
        "MCP_PUBLIC_URL": "https://sched-test.example.com/mcp",
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
        "MCP_EXEC_AUDIT_PATH": str(tpath / "exec_audit.jsonl"),
        "MCP_SCHEDULER_TICK_SECONDS": "0.1",
    }
    env.update(extra)
    return env


def _load_isolated_server(tpath: Path, **extra_env: str):
    env = _isolated_backend_env(tpath, **extra_env)
    with patch.dict(os.environ, env, clear=False):
        import backend.server as srv_mod

        return importlib.reload(srv_mod)


def _cleanup_server_module(srv) -> None:
    import backend as backend_pkg

    for h in list(logging.getLogger().handlers):
        if isinstance(h, logging.FileHandler):
            h.close()
            logging.getLogger().removeHandler(h)
    for h in list(logging.getLogger("MCPApp").handlers):
        logging.getLogger("MCPApp").removeHandler(h)
    if srv is not None:
        try:
            asyncio.run(srv.TASK_MANAGER.close())
        except Exception:
            pass
        try:
            asyncio.run(srv.GATEWAY_ROUTER.close_all())
        except Exception:
            pass
        srv.PROCESS_RUNNER.close()
        srv.EXEC_AUDIT.close()
        srv.REMOTE_MANAGER.close()
        srv.EXTENSION_MANAGER.shutdown_all()
        srv.MANAGED_SERVERS.close()
        try:
            srv._LOGGING_MGR.shutdown(timeout=1.0)
        except Exception:
            pass
    sys.modules.pop("backend.server", None)
    if hasattr(backend_pkg, "server"):
        delattr(backend_pkg, "server")


class AutomationSchedulerLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_no_executor_fails_closed_never_succeeded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sched = AutomationScheduler(Path(tmp))
            sched.upsert_schedule(
                ScheduleSpec(
                    schedule_id="no-exec",
                    name="No Exec",
                    trigger_type="interval",
                    tool_name="server_info",
                    next_run_at=100.0,
                ),
                now=90.0,
            )
            manual = sched.trigger_now("no-exec", trigger="manual", now=101.0)
            self.assertEqual(manual["status"], "failed")
            self.assertIn("executor", manual["error"].lower())

            tick_res = sched.tick(now=101.0)
            self.assertEqual(len(tick_res), 1)
            self.assertEqual(tick_res[0]["status"], "failed")

    def test_gui_backend_unavailable_emits_error_and_records_no_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg"
            cfg.mkdir()
            toasts: list[tuple[str, str]] = []
            page = AutomationPage(
                automation_dir=cfg / "automation",
                config_root=cfg,
                redactor=SecretRedactor(),
                admin_client_provider=lambda: None,
                backend_running_checker=lambda: False,
            )
            page.status_message.connect(lambda msg, lvl: toasts.append((msg, lvl)))
            try:
                page.create_schedule(
                    ScheduleSpec(
                        schedule_id="offline-job",
                        name="Offline Job",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )
                page.schedules_table.selectRow(0)
                page.run_selected_schedule()
                self.app.processEvents()

                self.assertTrue(any(lvl == "error" for _, lvl in toasts), toasts)
                hist_path = cfg / "automation" / "history.json"
                if hist_path.is_file():
                    self.assertNotIn("succeeded", hist_path.read_text(encoding="utf-8"))
            finally:
                page.shutdown()
                page.close()

    def test_gui_manual_run_reaches_backend_executor_and_updates_history(self) -> None:
        import socket
        import uvicorn
        from app.core.admin_client import LocalAdminClient

        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            cfg = tpath / "gui_cfg"
            cfg.mkdir()
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            admin_token = secrets.token_urlsafe(18)
            try:
                srv = _load_isolated_server(tpath, MCP_ADMIN_TOKEN=admin_token)
                calls: list[str] = []

                async def _probe_exec(spec: ScheduleSpec, _idem: str) -> dict:
                    calls.append(spec.schedule_id)
                    return {"ok": True, "via": "backend"}

                srv.AUTOMATION_SCHEDULER._async_executor = _probe_exec
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="gui-to-backend",
                        name="GUI To Backend",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = int(sock.getsockname()[1])

                admin_app = srv.build_local_admin_app()
                server = uvicorn.Server(
                    uvicorn.Config(admin_app, host="127.0.0.1", port=port, access_log=False, log_level="warning")
                )
                th = threading.Thread(target=server.run, daemon=True)
                th.start()
                deadline = time.monotonic() + 8.0
                client = LocalAdminClient(port=port, token=admin_token)
                while time.monotonic() < deadline and not server.started:
                    time.sleep(0.05)

                page = AutomationPage(
                    automation_dir=tpath / "other_ui_dir",
                    config_root=cfg,
                    redactor=SecretRedactor(),
                    admin_client_provider=lambda: client,
                    backend_running_checker=lambda: True,
                )
                try:
                    page.reload()
                    self.assertEqual(page.schedules_table.rowCount(), 1)
                    page.schedules_table.selectRow(0)
                    page.run_selected_schedule()
                    self.assertTrue(page.wait_for_pending_runs(timeout=5.0))
                    self.app.processEvents()
                    self.assertEqual(calls, ["gui-to-backend"])
                    self.assertIn("succeeded", page.history_view.toPlainText())
                finally:
                    page.shutdown()
                    page.close()
                    server.should_exit = True
                    th.join(timeout=5.0)
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_backend_lifespan_runs_startup_interval_cron_event_once_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            try:
                srv = _load_isolated_server(tpath)
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="boot-once",
                        name="Boot Once",
                        trigger_type="startup",
                        tool_name="server_info",
                        idempotency_key="boot",
                    )
                )
                sec_in_min = time.time() % 60.0
                if sec_in_min > 57.5:
                    time.sleep(60.05 - sec_in_min)

                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="iv-due",
                        name="Interval Due",
                        trigger_type="interval",
                        interval_seconds=60,
                        tool_name="server_info",
                        misfire_policy="run_once",
                        next_run_at=time.time() - 1.0,
                    )
                )
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="cron-due",
                        name="Cron Due",
                        trigger_type="cron",
                        cron_expr="* * * * *",
                        tool_name="server_info",
                        misfire_policy="run_once",
                        next_run_at=time.time() - 1.0,
                    )
                )
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="ev-tunnel",
                        name="On Tunnel",
                        trigger_type="event",
                        event_name="tunnel.ready",
                        tool_name="server_info",
                    )
                )

                before_threads = {t.ident for t in threading.enumerate()}
                with TestClient(srv.build_app()):
                    self.assertTrue(srv.AUTOMATION_SCHEDULER.is_running)
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        hist = srv.AUTOMATION_SCHEDULER.list_history(limit=50)
                        ok_ids = [h["schedule_id"] for h in hist if h["status"] == "succeeded"]
                        if {"boot-once", "iv-due", "cron-due"}.issubset(ok_ids):
                            break
                        time.sleep(0.05)

                    # Trigger existing event trigger through Admin API
                    admin_tc = TestClient(
                        srv.build_local_admin_app(),
                        base_url="http://127.0.0.1:8001",
                        client=("127.0.0.1", 52100),
                    )
                    ev_resp = admin_tc.post(
                        "/api/v1/events",
                        headers={"Authorization": f"Bearer {srv.ADMIN_TOKEN}"},
                        json={"event_name": "tunnel.ready", "payload": {"url": "https://x.trycloudflare.com/mcp"}},
                    )
                    self.assertEqual(ev_resp.status_code, 200)

                    # Keep lifespan alive briefly to verify exact-once (no repeated triggers)
                    time.sleep(0.35)
                    hist = srv.AUTOMATION_SCHEDULER.list_history(limit=100)
                    for sid in ("boot-once", "iv-due", "cron-due", "ev-tunnel"):
                        count = sum(1 for h in hist if h["schedule_id"] == sid and h["status"] == "succeeded")
                        self.assertEqual(count, 1, f"{sid} executed {count} times: {hist}")

                self.assertFalse(srv.AUTOMATION_SCHEDULER.is_running)
                after_threads = [t for t in threading.enumerate() if t.ident not in before_threads and t.is_alive()]
                sched_threads = [t for t in after_threads if "sched" in t.name.lower()]
                self.assertEqual(sched_threads, [])
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_oauth_revocation_permission_change_and_retry_block_and_tool_error(self) -> None:
        from mcp.shared.auth import OAuthClientInformationFull
        from pydantic import AnyHttpUrl

        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            try:
                srv = _load_isolated_server(tpath)
                cid = "sched-client-rev"
                srv.oauth_provider.store.save_client(
                    OAuthClientInformationFull(
                        client_id=cid,
                        client_name="Sched Client",
                        redirect_uris=[AnyHttpUrl("http://127.0.0.1/cb")],
                    )
                )
                srv.oauth_provider.store.mark_approved(cid)
                srv.oauth_execution.set_client_profile(cid, "allowlist")

                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="client-job",
                        name="Client Job",
                        trigger_type="interval",
                        tool_name="device_list",
                        client_id=cid,
                        safe_retry=True,
                        max_retries=1,
                    )
                )
                ok_run = srv.AUTOMATION_SCHEDULER.trigger_now("client-job", now=100.0)
                self.assertEqual(ok_run["status"], "succeeded")

                # Downgrade permission to safe (device_list requires allowlist)
                srv.oauth_execution.set_client_profile(cid, "safe")
                downgraded = srv.AUTOMATION_SCHEDULER.trigger_now("client-job", now=110.0)
                self.assertEqual(downgraded["status"], "paused_revoked")

                # Re-enable and revoke OAuth before retry
                srv.oauth_execution.set_client_profile(cid, "allowlist")
                srv.AUTOMATION_SCHEDULER.set_schedule_enabled("client-job", True)
                srv.oauth_provider.store.revoke_client(cid)
                revoked = srv.AUTOMATION_SCHEDULER.trigger_now("client-job", now=120.0)
                self.assertEqual(revoked["status"], "paused_revoked")

                # Tool error must fail, never succeed
                async def _failing_tool(_name, _args):
                    return {"error": "boom", "ok": False}

                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="err-job",
                        name="Err Job",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )
                with patch.object(srv.mcp, "call_tool", side_effect=_failing_tool):
                    err_run = srv.AUTOMATION_SCHEDULER.trigger_now("err-job", now=130.0)
                self.assertEqual(err_run["status"], "failed")
                self.assertIn("boom", err_run["error"])

                # Mid-retry revocation blocks attempt #2 immediately
                calls = 0

                async def _fail_once_then_revoke(_spec, _idem):
                    nonlocal calls
                    calls += 1
                    srv.oauth_execution.set_client_profile("owner-recheck-probe", "safe")
                    raise RuntimeError("transient")

                cid2 = "sched-retry-rev"
                srv.oauth_provider.store.save_client(
                    OAuthClientInformationFull(
                        client_id=cid2,
                        client_name="Retry Client",
                        redirect_uris=[AnyHttpUrl("http://127.0.0.1/cb")],
                    )
                )
                srv.oauth_provider.store.mark_approved(cid2)
                srv.oauth_execution.set_client_profile(cid2, "allowlist")

                async def _flaky_and_revoke(_spec, _idem):
                    nonlocal calls
                    calls += 1
                    srv.oauth_provider.store.revoke_client(cid2)
                    raise RuntimeError("first attempt transient")

                sched_retry = AutomationScheduler(
                    tpath / "retry_auto",
                    async_executor=_flaky_and_revoke,
                    permission_checker=srv._scheduler_permission_check,
                )
                sched_retry.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="retry-block",
                        name="Retry Block",
                        trigger_type="interval",
                        tool_name="device_list",
                        client_id=cid2,
                        safe_retry=True,
                        max_retries=2,
                    )
                )
                retry_res = sched_retry.trigger_now("retry-block", now=140.0)
                self.assertEqual(retry_res["status"], "paused_revoked")
                self.assertEqual(calls, 1)
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_gateway_tool_executes_on_same_active_event_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            try:
                srv = _load_isolated_server(tpath)
                srv.GATEWAY_STORE.upsert(
                    UpstreamServerProfile(
                        server_id="gw1",
                        name="GW1",
                        transport="stdio",
                        command="python",
                        min_profile="safe",
                        enabled=True,
                        approved_by_owner=True,
                    )
                )
                srv.GATEWAY_ROUTER._initialized = True
                srv.GATEWAY_ROUTER._catalog["gw.gw1.ping"] = UpstreamToolEntry(
                    namespaced_name="gw.gw1.ping",
                    server_id="gw1",
                    raw_name="ping",
                    description="Ping",
                    input_schema={"type": "object", "properties": {}},
                )
                srv.GATEWAY_ROUTER._statuses["gw1"] = GatewayServerStatus(
                    server_id="gw1", name="GW1", transport="stdio", health="healthy", tool_count=1
                )

                class _FakeHandle:
                    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
                        self.session = object()
                        self._owner_loop = loop
                        self._loop_lock = asyncio.Lock()

                    async def call_tool(self, name: str, _args: dict):
                        cur_loop = asyncio.get_running_loop()
                        if cur_loop is not self._owner_loop:
                            raise RuntimeError("Cross-event-loop Gateway invocation detected")
                        async with self._loop_lock:
                            return CallToolResult(
                                content=[TextContent(type="text", text=f"pong:{name}")],
                                isError=False,
                            )

                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="gw-sched",
                        name="GW Sched",
                        trigger_type="interval",
                        tool_name="gw.gw1.ping",
                    )
                )

                async def _run_in_server_loop() -> dict:
                    srv_loop = asyncio.get_running_loop()
                    srv.GATEWAY_ROUTER._handles[("gw1", "client:owner")] = _FakeHandle(srv_loop)  # type: ignore[assignment]
                    return await srv.AUTOMATION_SCHEDULER.trigger_now_async("gw-sched")

                res = asyncio.run(_run_in_server_loop())
                self.assertEqual(res["status"], "succeeded", res)
                self.assertIn("pong:ping", res["result_summary"])
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_long_running_schedule_nonblocking_timeout_and_cancel(self) -> None:
        import socket
        import uvicorn
        from app.core.admin_client import LocalAdminClient

        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            cfg = tpath / "gui_cfg"
            cfg.mkdir()
            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            admin_token = secrets.token_urlsafe(18)
            try:
                srv = _load_isolated_server(tpath, MCP_ADMIN_TOKEN=admin_token)

                async def _slow_tool(spec: ScheduleSpec, _idem: str) -> dict:
                    if spec.schedule_id == "timeout-job":
                        await asyncio.sleep(1.5)
                    else:
                        await asyncio.sleep(0.55)
                    return {"ok": True}

                srv.AUTOMATION_SCHEDULER._async_executor = _slow_tool
                srv.AUTOMATION_SCHEDULER._execution_timeout = 0.25
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="timeout-job",
                        name="Timeout Job",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )
                timeout_res = srv.AUTOMATION_SCHEDULER.trigger_now("timeout-job")
                self.assertEqual(timeout_res["status"], "failed")
                self.assertIn("timed out", timeout_res["error"].lower())

                # Now give generous timeout and prove Admin API + GUI stay non-blocking during 0.55s job
                srv.AUTOMATION_SCHEDULER._execution_timeout = 5.0
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="slow-job",
                        name="Slow Job",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = int(sock.getsockname()[1])

                server = uvicorn.Server(
                    uvicorn.Config(
                        srv.build_local_admin_app(),
                        host="127.0.0.1",
                        port=port,
                        access_log=False,
                        log_level="warning",
                    )
                )
                th = threading.Thread(target=server.run, daemon=True)
                th.start()
                while not server.started:
                    time.sleep(0.05)

                client = LocalAdminClient(port=port, token=admin_token)
                page = AutomationPage(
                    automation_dir=cfg / "auto",
                    config_root=cfg,
                    redactor=SecretRedactor(),
                    admin_client_provider=lambda: client,
                    backend_running_checker=lambda: True,
                )
                try:
                    page.reload()
                    slow_row = next(
                        i for i, sp in enumerate(page._schedules) if sp["schedule_id"] == "slow-job"
                    )
                    page.schedules_table.selectRow(slow_row)
                    t0 = time.monotonic()
                    page.run_selected_schedule()
                    gui_elapsed = time.monotonic() - t0
                    self.assertLess(gui_elapsed, 0.2, "GUI froze waiting for slow schedule run")

                    t_api = time.monotonic()
                    mon = client.get_monitoring(timeout=2.0)
                    api_elapsed = time.monotonic() - t_api
                    self.assertIn("mcp_metrics", mon)
                    self.assertLess(api_elapsed, 0.25, "Admin API blocked by slow schedule run")

                    self.assertTrue(page.wait_for_pending_runs(timeout=5.0))
                finally:
                    page.shutdown()
                    page.close()
                    server.should_exit = True
                    th.join(timeout=5.0)

                # Shutdown while slow scheduled task is in flight cancels cleanly with status=cancelled
                async def _very_slow_tool(_spec: ScheduleSpec, _idem: str) -> dict:
                    await asyncio.sleep(5.0)
                    return {"ok": True}

                srv.AUTOMATION_SCHEDULER._async_executor = _very_slow_tool
                srv.AUTOMATION_SCHEDULER.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="cancel-on-stop",
                        name="Cancel On Stop",
                        trigger_type="startup",
                        tool_name="server_info",
                    )
                )
                with TestClient(srv.build_app()):
                    time.sleep(0.15)
                    self.assertGreaterEqual(len(srv.AUTOMATION_SCHEDULER._inflight_tasks), 1)
                self.assertFalse(srv.AUTOMATION_SCHEDULER.is_running)
                self.assertEqual(len(srv.AUTOMATION_SCHEDULER._inflight_tasks), 0)
                hist_statuses = [
                    h["status"]
                    for h in srv.AUTOMATION_SCHEDULER.list_history(limit=20)
                    if h["schedule_id"] == "cancel-on-stop"
                ]
                self.assertIn("cancelled", hist_statuses)
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_concurrent_schedule_and_history_mutations_lose_no_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            s1 = AutomationScheduler(base, executor=lambda _sp, _id: {"ok": True})
            s2 = AutomationScheduler(base, executor=lambda _sp, _id: {"ok": True})

            for i in range(6):
                s1.upsert_schedule(
                    ScheduleSpec(
                        schedule_id=f"c-{i}",
                        name=f"C {i}",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )

            def _worker(idx: int) -> None:
                target = s1 if idx % 2 == 0 else s2
                target.upsert_schedule(
                    ScheduleSpec(
                        schedule_id=f"extra-{idx}",
                        name=f"Extra {idx}",
                        trigger_type="interval",
                        tool_name="server_info",
                    )
                )
                target.trigger_now(f"c-{idx % 6}", idem_suffix=f"run-{idx}")

            with ThreadPoolExecutor(max_workers=6) as pool:
                list(pool.map(_worker, range(12)))

            schedules = {s["schedule_id"] for s in s1.list_schedules()}
            for i in range(6):
                self.assertIn(f"c-{i}", schedules)
            for idx in range(12):
                self.assertIn(f"extra-{idx}", schedules)
            hist = s2.list_history(limit=50)
            self.assertEqual(len(hist), 12)
            self.assertEqual([p.name for p in base.glob("*.tmp")], [])

    def test_historical_v1_schedules_paused_and_ephemeral_owners_cleaned(self) -> None:
        from mcp.shared.auth import OAuthClientInformationFull
        from pydantic import AnyHttpUrl

        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            auto_dir = tpath / "automation"
            auto_dir.mkdir(parents=True)
            # Legacy v1 schedules.json where enabled=True schedules never had live execution
            (auto_dir / "schedules.json").write_text(
                json.dumps({
                    "version": 1,
                    "schedules": {
                        "legacy-boot": {
                            "schedule_id": "legacy-boot",
                            "name": "Legacy Boot",
                            "trigger_type": "startup",
                            "tool_name": "server_info",
                            "enabled": True,
                        },
                        "legacy-iv": {
                            "schedule_id": "legacy-iv",
                            "name": "Legacy Interval",
                            "trigger_type": "interval",
                            "interval_seconds": 10,
                            "tool_name": "server_info",
                            "enabled": True,
                            "next_run_at": 1.0,
                        },
                    },
                }),
                encoding="utf-8",
            )

            old_cwd = os.getcwd()
            os.chdir(tpath)
            srv = None
            try:
                srv = _load_isolated_server(tpath)
                # Simulate leftover crash-orphaned sched-owner client before server lifespan boots
                srv.oauth_provider.store.save_client(
                    OAuthClientInformationFull(
                        client_id="sched-owner-deadbeef",
                        client_name="Orphaned",
                        redirect_uris=[AnyHttpUrl("http://127.0.0.1/cb")],
                    )
                )

                with TestClient(srv.build_app()):
                    time.sleep(0.25)
                    # Historical v1 schedules must NOT auto-execute without owner approval
                    self.assertEqual(srv.AUTOMATION_SCHEDULER.list_history(limit=20), [])
                    for item in srv.AUTOMATION_SCHEDULER.list_schedules():
                        self.assertFalse(item["enabled"])
                        self.assertFalse(item["live_execution_approved"])

                    # Stale crashed ephemeral owner must be purged at startup
                    cids = {c["client_id"] for c in srv.oauth_provider.store.list_clients()}
                    self.assertNotIn("sched-owner-deadbeef", cids)

                    # Exception during set_client_profile still cleans up new sched-owner-*
                    srv.AUTOMATION_SCHEDULER.set_schedule_enabled("legacy-boot", True)
                    srv.AUTOMATION_SCHEDULER.upsert_schedule(
                        ScheduleSpec(
                            schedule_id="ephem-err",
                            name="Ephem Err",
                            trigger_type="interval",
                            tool_name="device_list",
                        )
                    )
                    with patch.object(
                        srv.oauth_execution, "set_client_profile", side_effect=RuntimeError("db fail")
                    ):
                        fail_run = srv.AUTOMATION_SCHEDULER.trigger_now("ephem-err")
                    self.assertEqual(fail_run["status"], "failed")
                    leaked = [
                        c["client_id"]
                        for c in srv.oauth_provider.store.list_clients()
                        if str(c["client_id"]).startswith("sched-owner-")
                    ]
                    self.assertEqual(leaked, [])
            finally:
                _cleanup_server_module(srv)
                os.chdir(old_cwd)

    def test_live_headless_subprocess_runs_startup_and_admin_api_same_loop(self) -> None:
        import socket
        import subprocess
        from app.core.admin_client import LocalAdminClient

        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1,
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2,
        ):
            s1.bind(("127.0.0.1", 0))
            s2.bind(("127.0.0.1", 0))
            mcp_port = int(s1.getsockname()[1])
            admin_port = int(s2.getsockname()[1])

        repo_root = Path(__file__).resolve().parents[2]
        admin_token = secrets.token_urlsafe(18)
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            env = dict(os.environ)
            env.update(
                _isolated_backend_env(
                    tpath,
                    MCP_HOST="127.0.0.1",
                    MCP_PORT=str(mcp_port),
                    MCP_ADMIN_PORT=str(admin_port),
                    MCP_ADMIN_TOKEN=admin_token,
                    MCP_PUBLIC_URL=f"http://127.0.0.1:{mcp_port}/mcp",
                    PYTHONPATH=str(repo_root),
                )
            )
            client = LocalAdminClient(port=admin_port, token=admin_token)
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
                        mon = client.get_monitoring(timeout=1.0)
                        if "mcp_metrics" in mon:
                            ready = True
                            break
                    except Exception:
                        time.sleep(0.2)
                self.assertTrue(ready, "Headless backend Admin API failed to become reachable")

                saved = client.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="subproc-live",
                        name="Subprocess Live",
                        trigger_type="interval",
                        interval_seconds=30,
                        tool_name="server_info",
                    ).to_dict()
                )
                self.assertEqual(saved["schedule_id"], "subproc-live")

                run_res = client.trigger_schedule("subproc-live", timeout=10.0)
                self.assertEqual(run_res["status"], "succeeded")

                scheds, hist = client.list_schedules_and_history()
                self.assertTrue(any(s["schedule_id"] == "subproc-live" for s in scheds))
                self.assertTrue(
                    any(h["schedule_id"] == "subproc-live" and h["status"] == "succeeded" for h in hist)
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5.0)
                if proc.stdout is not None:
                    proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
