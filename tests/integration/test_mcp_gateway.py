"""Integration tests for Stage 4 MCP Gateway across stdio, Streamable HTTP, SSE, OAuth permissions & GUI."""
from __future__ import annotations

import asyncio
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2 as httpx
import uvicorn
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull
from mcp.types import ImageContent, TextContent
from pydantic import AnyUrl
from PyQt6.QtWidgets import QApplication, QMessageBox
from starlette.responses import JSONResponse

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.ui.i18n import LANG_RU, i18n
from app.ui.pages.gateway_page import GatewayPage
from backend.gateway.models import (
    AUTH_BEARER,
    ISOLATION_PER_CLIENT,
    ISOLATION_SHARED,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
)
from backend.gateway.router import GatewayRouter
from backend.gateway.security import GATEWAY_HOP_HEADER, GATEWAY_ID_HEADER, check_loop_headers
from backend.gateway.store import GatewayConfigStore
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.tool_permissions import FORBIDDEN_TOOL, make_tool_middleware

REPO_ROOT = Path(__file__).resolve().parents[2]
STDIO_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "gateway_stdio_server.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(port: int, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"Port {port} did not open within {timeout}s")


class _UvicornThreadServer:
    """Runs an ASGI app cleanly inside a daemon thread on loopback for integration tests."""

    def __init__(self, app, port: int) -> None:  # noqa: ANN001
        self.port = port
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            timeout_graceful_shutdown=0.2,
        )
        self.server = uvicorn.Server(config)
        self.server.force_exit = True
        self._thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> "_UvicornThreadServer":
        self._thread.start()
        _wait_port(self.port)
        return self

    def __exit__(self, *_args) -> None:
        self.server.should_exit = True
        self._thread.join(timeout=5.0)


def _build_http_upstream_app(expected_token: str, forbidden_downstream_token: str, observed: dict):
    srv = MCPServer("upstream-http")

    @srv.tool()
    def collide() -> str:
        return "from_streamable_http"

    @srv.tool()
    def remote_add(a: int, b: int) -> int:
        return a + b

    base_app = srv.streamable_http_app(json_response=True, streamable_http_path="/mcp")

    class _HeaderInspectMiddleware:
        def __init__(self, app):  # noqa: ANN001
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                hdrs = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
                auth = hdrs.get("authorization", "")
                observed["auth_headers"].append(auth)
                if forbidden_downstream_token and forbidden_downstream_token in auth:
                    await JSONResponse({"error": "downstream_token_leaked"}, status_code=500)(scope, receive, send)
                    return
                if auth != f"Bearer {expected_token}":
                    await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
                    return
                sid = hdrs.get("mcp-session-id")
                if sid:
                    observed["session_ids"].add(sid)
            await self.app(scope, receive, send)

    return _HeaderInspectMiddleware(base_app)


def _build_sse_upstream_app():
    srv = MCPServer("upstream-sse")

    @srv.tool()
    def sse_ping(msg: str = "pong") -> str:
        return f"sse:{msg}"

    return srv.sse_app()


class GatewayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_multi_transport_gateway_permissions_isolation_and_redaction(self) -> None:
        upstream_secret = "upstream-bearer-only-777"
        downstream_secret = "downstream-oauth-token-should-never-forward"
        stdio_secret = "super-stdio-secret-42"

        http_port = _free_port()
        sse_port = _free_port()
        dead_port = _free_port()
        observed = {"auth_headers": [], "session_ids": set()}

        http_app = _build_http_upstream_app(upstream_secret, downstream_secret, observed)
        sse_app = _build_sse_upstream_app()

        with _UvicornThreadServer(http_app, http_port), _UvicornThreadServer(sse_app, sse_port):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                secrets = SecretStore(root / "secrets")
                store = GatewayConfigStore(root / "gateway" / "servers.json", secret_store=secrets)

                # 1. Real stdio upstream (per_client isolation, allowlist profile, denied_tools, bounded payload)
                self.assertEqual(
                    store.upsert(
                        UpstreamServerProfile(
                            server_id="stdio_srv",
                            name="Local Stdio",
                            transport=TRANSPORT_STDIO,
                            command=sys.executable,
                            args=(str(STDIO_FIXTURE),),
                            session_isolation=ISOLATION_PER_CLIENT,
                            min_profile="allowlist",
                            denied_tools=("denied_tool",),
                            max_response_bytes=2048,
                            approved_by_owner=True,
                        ),
                        secret_env={"TEST_GATEWAY_SECRET": stdio_secret},
                    ),
                    [],
                )

                # 2. Real Streamable HTTP upstream with bearer isolation + per_client sessions
                self.assertEqual(
                    store.upsert(
                        UpstreamServerProfile(
                            server_id="http_srv",
                            name="Remote HTTP",
                            transport=TRANSPORT_STREAMABLE_HTTP,
                            url=f"http://127.0.0.1:{http_port}/mcp",
                            auth_mode=AUTH_BEARER,
                            allow_local_endpoint=True,
                            session_isolation=ISOLATION_PER_CLIENT,
                            min_profile="allowlist",
                            approved_by_owner=True,
                        ),
                        bearer_token=upstream_secret,
                    ),
                    [],
                )

                # 3. Real legacy SSE upstream (available even to safe clients)
                self.assertEqual(
                    store.upsert(
                        UpstreamServerProfile(
                            server_id="sse_srv",
                            name="Legacy SSE",
                            transport=TRANSPORT_SSE,
                            url=f"http://127.0.0.1:{sse_port}/sse",
                            allow_local_endpoint=True,
                            session_isolation=ISOLATION_SHARED,
                            min_profile="safe",
                            approved_by_owner=True,
                        )
                    ),
                    [],
                )

                # 4. Failing 4th upstream (must isolate fault cleanly)
                self.assertEqual(
                    store.upsert(
                        UpstreamServerProfile(
                            server_id="dead_srv",
                            name="Unreachable Server",
                            transport=TRANSPORT_STREAMABLE_HTTP,
                            url=f"http://127.0.0.1:{dead_port}/mcp",
                            allow_local_endpoint=True,
                            timeout_seconds=1.5,
                            min_profile="safe",
                            approved_by_owner=True,
                        )
                    ),
                    [],
                )

                # Configure OAuthStore + ExecutionApprovals for multiple clients
                oauth_db = OAuthStore(
                    root / "oauth" / "connections.sqlite3",
                    issuer="http://127.0.0.1:8000",
                    resource_url="http://127.0.0.1:8000/mcp",
                )
                for cid, cname in (
                    ("client-safe", "Safe Client"),
                    ("client-allow-a", "Allow A"),
                    ("client-allow-b", "Allow B"),
                    ("client-pending", "Pending"),
                ):
                    oauth_db.save_client(
                        OAuthClientInformationFull(
                            client_id=cid,
                            client_name=cname,
                            redirect_uris=[AnyUrl("http://localhost/cb")],
                            scope="mcp:read",
                        )
                    )
                oauth_db.mark_approved("client-safe")
                oauth_db.mark_approved("client-allow-a")
                oauth_db.mark_approved("client-allow-b")

                execution = ExecutionApprovals(oauth_db)
                execution.set_client_profile("client-safe", "safe")
                execution.set_client_profile("client-allow-a", "allowlist")
                execution.set_client_profile("client-allow-b", "allowlist")

                p_safe = AccessToken(token=downstream_secret, client_id="client-safe", scopes=["mcp:read"])
                p_allow_a = AccessToken(token=downstream_secret, client_id="client-allow-a", scopes=["mcp:read"])
                p_allow_b = AccessToken(token=downstream_secret, client_id="client-allow-b", scopes=["mcp:read"])
                p_pending = AccessToken(token=downstream_secret, client_id="client-pending", scopes=["mcp:read"])

                redactor = SecretRedactor([downstream_secret])
                router = GatewayRouter(store, redactor=redactor)

                async def _scenario() -> None:
                    try:
                        statuses = await router.refresh_all()
                        by_id = {s.server_id: s for s in statuses}
                        self.assertEqual(by_id["stdio_srv"].health, "healthy")
                        self.assertEqual(by_id["http_srv"].health, "healthy")
                        self.assertEqual(by_id["sse_srv"].health, "healthy")
                        self.assertEqual(by_id["dead_srv"].health, "error")

                        # Safe client sees only SSE tool; pending client sees zero; allowlist sees stdio + http + sse minus denied
                        safe_names = {t.name for t in router.list_authorized_tools(p_safe, execution)}
                        self.assertIn("sse_srv__sse_ping", safe_names)
                        self.assertNotIn("stdio_srv__echo_text", safe_names)
                        self.assertNotIn("http_srv__remote_add", safe_names)
                        self.assertEqual(router.list_authorized_tools(p_pending, execution), [])

                        allow_names = {t.name for t in router.list_authorized_tools(p_allow_a, execution)}
                        self.assertIn("stdio_srv__echo_text", allow_names)
                        self.assertIn("stdio_srv__render_preview", allow_names)
                        self.assertIn("stdio_srv__collide", allow_names)
                        self.assertIn("http_srv__collide", allow_names)
                        self.assertIn("http_srv__remote_add", allow_names)
                        self.assertIn("sse_srv__sse_ping", allow_names)
                        self.assertNotIn("stdio_srv__denied_tool", allow_names)

                        # Fail-closed denial on direct call for safe / pending / denied_tool
                        with self.assertRaises(PermissionError):
                            await router.call_authorized_tool("stdio_srv__echo_text", {"text": "hi"}, p_safe, execution)
                        with self.assertRaises(PermissionError):
                            await router.call_authorized_tool("sse_srv__sse_ping", {}, p_pending, execution)
                        with self.assertRaises(PermissionError):
                            await router.call_authorized_tool("stdio_srv__denied_tool", {}, p_allow_a, execution)

                        # Calls across all 3 transports succeed for authorized client
                        r_stdio = await router.call_authorized_tool(
                            "stdio_srv__echo_text", {"text": "hello"}, p_allow_a, execution
                        )
                        self.assertIn("stdio:hello|has_secret=yes", r_stdio.content[0].text)

                        r_http = await router.call_authorized_tool(
                            "http_srv__remote_add", {"a": 19, "b": 23}, p_allow_a, execution
                        )
                        self.assertEqual(r_http.content[0].text, "42")

                        r_sse = await router.call_authorized_tool(
                            "sse_srv__sse_ping", {"msg": "ok"}, p_safe, execution
                        )
                        self.assertEqual(r_sse.content[0].text, "sse:ok")

                        # Collision routing targets distinct backends
                        c1 = await router.call_authorized_tool("stdio_srv__collide", {}, p_allow_a, execution)
                        c2 = await router.call_authorized_tool("http_srv__collide", {}, p_allow_a, execution)
                        self.assertTrue(c1.content[0].text.startswith("from_stdio_pid="))
                        self.assertEqual(c2.content[0].text, "from_streamable_http")

                        # Session isolation: allow_a vs allow_b obtain separate stdio PIDs & HTTP sessions
                        c1_b = await router.call_authorized_tool("stdio_srv__collide", {}, p_allow_b, execution)
                        self.assertNotEqual(c1.content[0].text, c1_b.content[0].text)
                        await router.call_authorized_tool(
                            "http_srv__remote_add", {"a": 1, "b": 2}, p_allow_b, execution
                        )
                        self.assertGreaterEqual(len(observed["session_ids"]), 2)
                        self.assertTrue(
                            all(downstream_secret not in h for h in observed["auth_headers"])
                        )

                        # Multimodal content + structured_content
                        r_mm = await router.call_authorized_tool(
                            "stdio_srv__render_preview", {"label": "bracket"}, p_allow_a, execution
                        )
                        self.assertTrue(any(isinstance(b, TextContent) for b in r_mm.content))
                        self.assertTrue(any(isinstance(b, ImageContent) for b in r_mm.content))
                        self.assertEqual(r_mm.structured_content["label"], "bracket")

                        # Secret redaction in both TextContent and structured_content
                        r_leak = await router.call_authorized_tool(
                            "stdio_srv__leak_secret", {}, p_allow_a, execution
                        )
                        self.assertNotIn(stdio_secret, r_leak.content[0].text)
                        self.assertNotIn(stdio_secret, json.dumps(r_leak.structured_content))

                        # max_response_bytes limit enforced
                        with self.assertRaises(ValueError):
                            await router.call_authorized_tool("stdio_srv__large_payload", {}, p_allow_a, execution)

                        # Dynamic tool + notifications/tools/list_changed updates catalog cleanly
                        await router.call_authorized_tool("stdio_srv__unlock_dynamic_tool", {}, p_allow_a, execution)
                        await asyncio.sleep(0.15)
                        await router.sync_dirty()
                        after_names = {t.name for t in router.list_authorized_tools(p_allow_a, execution)}
                        self.assertIn("stdio_srv__dynamic_ping", after_names)
                        r_dyn = await router.call_authorized_tool("stdio_srv__dynamic_ping", {}, p_allow_a, execution)
                        self.assertEqual(r_dyn.content[0].text, "dynamic_pong")

                        # Downstream MCPServer middleware test (fails closed on safe + routes allowlist)
                        class _Ctx:
                            def __init__(self, method: str, params=None) -> None:
                                self.method = method
                                self.params = params or {}

                        mw = make_tool_middleware(oauth_db, execution, gateway_router=router)
                        with patch("backend.tool_permissions.get_access_token", return_value=p_safe):
                            with self.assertRaises(Exception) as cm_forbid:
                                await mw(_Ctx("tools/call", {"name": "http_srv__remote_add", "arguments": {"a": 1, "b": 2}}), None)
                            self.assertEqual(getattr(cm_forbid.exception, "code", None), FORBIDDEN_TOOL)

                        with patch("backend.tool_permissions.get_access_token", return_value=p_allow_a):
                            res = await mw(
                                _Ctx("tools/call", {"name": "http_srv__remote_add", "arguments": {"a": 5, "b": 7}}),
                                None,
                            )
                            self.assertEqual(res.content[0].text, "12")

                        # Revoke / emergency stop blocks immediately on next call
                        oauth_db.set_emergency_stop(True)
                        with self.assertRaises(PermissionError):
                            await router.call_authorized_tool("sse_srv__sse_ping", {}, p_safe, execution)
                    finally:
                        await router.close_all()

                asyncio.run(_scenario())

                # Verify loop guard catches own instance_id / max hops cleanly (unit + live HTTP ASGI middleware)
                self.assertIsNotNone(check_loop_headers({GATEWAY_ID_HEADER: router.instance_id}, router.instance_id))
                self.assertIsNotNone(check_loop_headers({GATEWAY_HOP_HEADER: "2"}, router.instance_id))

                from backend import server as backend_srv

                loop_app = backend_srv.build_app()

                async def _http_loop_check() -> int:
                    transport = httpx.ASGITransport(app=loop_app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as cli:
                        resp = await cli.post(
                            "/mcp",
                            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                            headers={
                                "Host": "127.0.0.1:8000",
                                GATEWAY_ID_HEADER: backend_srv.GATEWAY_ROUTER.instance_id,
                            },
                        )
                        return resp.status_code

                self.assertEqual(asyncio.run(_http_loop_check()), 400)

    def test_gateway_gui_page_discovery_and_redacted_export(self) -> None:
        i18n.set_language(LANG_RU)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            page = GatewayPage(config_path=root / "gateway" / "servers.json")
            self.assertFalse(page.table_card.isVisibleTo(page))
            self.assertTrue(page.empty_state.isVisibleTo(page))

            # Configure real stdio fixture server via Store (approved)
            page.store.upsert(
                UpstreamServerProfile(
                    server_id="stdio_gui",
                    name="GUI Stdio Test",
                    transport=TRANSPORT_STDIO,
                    command=sys.executable,
                    args=(str(STDIO_FIXTURE),),
                    approved_by_owner=True,
                    enabled=True,
                ),
                secret_env={"TEST_GATEWAY_SECRET": "gui-secret-999"},
            )
            page.reload()
            self.assertEqual(page.server_table.rowCount(), 1)
            self.assertFalse(page.empty_state.isVisibleTo(page))

            # Discover tools synchronously & inspect JSON schema
            statuses = page.refresh_servers_sync()
            self.assertEqual(statuses[0].health, "healthy")
            self.assertGreaterEqual(statuses[0].tool_count, 4)
            self.assertGreaterEqual(page.tools_table.rowCount(), 4)
            self.assertIn('"properties"', page.schema_view.toPlainText())

            # Redacted export contains zero plaintext secret
            exported = page.export_redacted_text()
            self.assertNotIn("gui-secret-999", exported)

            # Toggle & delete with confirmation
            page._toggle_selected()
            self.assertFalse(page.store.get("stdio_gui").enabled)  # type: ignore[union-attr]
            with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                page._delete_selected()
            self.assertIsNone(page.store.get("stdio_gui"))


if __name__ == "__main__":
    unittest.main()
