"""End-to-end acceptance regression tests for OAuth reconnect, live permissions, Computer Use, and server_info (Tasks 6, 8, 9, 10)."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import base64
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from app.config import Settings
from app.core.service_manager import ServiceManager
from app.core.winjob import kill_process_tree
from backend.desktop.manager import DesktopManager
from backend.desktop.models import DesktopPolicy, DesktopPolicyStore
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.tool_permissions import FORBIDDEN_TOOL, make_tool_middleware
from backend.tool_registry import ALL_REGISTERED_OAUTH_TOOLS, DESKTOP_TOOLS, DESKTOP_VIEW_TOOLS
from tests.unit.test_desktop_security import _FakeBackend

ROOT = Path(__file__).resolve().parents[2]
OWNER_A = "owner-token-alpha-secret-123456"
OWNER_B = "owner-token-beta-rotated-987654"
VERIFIER = "acceptance-pkce-code-verifier-entropy-1234567890"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
CALLBACK = "http://127.0.0.1:17945/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _http(
    url: str,
    method: str = "GET",
    data: object = None,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if content_type == "application/json":
            body = json.dumps(data).encode("utf-8")
        else:
            body = urllib.parse.urlencode(data).encode("utf-8")  # type: ignore[arg-type]
            content_type = "application/x-www-form-urlencoded"
        hdrs["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with _OPENER.open(request, timeout=8) as resp:
            return int(resp.status), {k.title(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), {k.title(): v for k, v in exc.headers.items()}, exc.read()


class _Ctx:
    def __init__(self, method: str, params=None) -> None:  # noqa: ANN001
        self.method = method
        self.params = params or {}


class AcceptanceOAuthAndDesktopTests(unittest.TestCase):
    def _free_port(self) -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _start_uvicorn(self, port: int, owner_token: str, oauth_db: Path, desktop_policy: Path, audit: Path) -> subprocess.Popen:
        env = os.environ.copy()
        url = f"http://127.0.0.1:{port}"
        env.update(
            {
                "MCP_PUBLIC_URL": url + "/mcp",
                "MCP_HOST": "127.0.0.1",
                "MCP_PORT": str(port),
                "MCP_SECRET_TOKEN": owner_token,
                "MCP_ENABLE_OAUTH": "1",
                "MCP_ALLOW_QUERY_TOKEN": "0",
                "MCP_JSON_RESPONSE": "1",
                "MCP_DEFAULT_ACCESS_PROFILE": "allowlist",
                "MCP_OAUTH_STORE_PATH": str(oauth_db),
                "MCP_DESKTOP_POLICY_PATH": str(desktop_policy),
                "MCP_EXEC_AUDIT_PATH": str(audit),
            }
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.server:build_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"Uvicorn exited prematurely: {proc.returncode}")
            try:
                status, _, _ = _http(f"{url}/health")
                if status == 200:
                    return proc
            except OSError:
                pass
            time.sleep(0.1)
        kill_process_tree(proc.pid, include_parent=True)
        raise RuntimeError("Uvicorn did not become healthy")

    def _authorize_and_exchange(self, base_url: str, client_id: str, owner_token: str, resource_url: str) -> dict:
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CALLBACK,
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "scope": "mcp:read",
                "state": "reconnect-state-1",
                "resource": resource_url,
            }
        )
        code, hdrs, body = _http(f"{base_url}/authorize?{query}")
        self.assertEqual(code, 302, (code, hdrs, body.decode(errors="replace")))
        ticket = urllib.parse.parse_qs(urllib.parse.urlsplit(hdrs["Location"]).query)["request_id"][0]

        code, chdrs, cbody = _http(
            f"{base_url}/oauth/consent",
            method="POST",
            data={"request_id": ticket, "owner_token": owner_token, "decision": "allow"},
            headers={"Origin": base_url},
        )
        self.assertEqual(code, 303, (code, chdrs, cbody.decode(errors="replace")))
        auth_code = urllib.parse.parse_qs(urllib.parse.urlsplit(chdrs["Location"]).query)["code"][0]

        tcode, _, tbody = _http(
            f"{base_url}/token",
            method="POST",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": CALLBACK,
                "client_id": client_id,
                "code_verifier": VERIFIER,
                "resource": resource_url,
            },
        )
        self.assertEqual(tcode, 200, tbody.decode(errors="replace"))
        return json.loads(tbody)

    def _mcp_call(self, resource_url: str, access_token: str, method: str, params: dict | None = None, session_id: str = "") -> tuple[int, dict[str, str], dict]:
        hdrs = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            hdrs["Mcp-Session-Id"] = session_id
        code, rhdrs, body = _http(
            resource_url,
            method="POST",
            headers=hdrs,
            content_type="application/json",
            data={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        )
        parsed = json.loads(body.decode("utf-8")) if body and body.lstrip().startswith(b"{") else {"raw": body.decode("utf-8", errors="replace")}
        return code, rhdrs, parsed

    def test_task6_owner_token_rotation_reconnect_same_client_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = self._free_port()
            base_url = f"http://127.0.0.1:{port}"
            resource_url = f"{base_url}/mcp"
            oauth_db = root / "oauth" / "connections.sqlite3"
            desktop_policy = root / "desktop" / "policy.json"
            audit = root / "logs" / "audit.jsonl"

            proc = self._start_uvicorn(port, OWNER_A, oauth_db, desktop_policy, audit)
            try:
                # 1. DCR + full auth with OWNER_A
                rcode, _, rbody = _http(
                    f"{base_url}/register",
                    method="POST",
                    content_type="application/json",
                    data={
                        "client_name": "Reconnect Acceptance Client",
                        "redirect_uris": [CALLBACK],
                        "token_endpoint_auth_method": "none",
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "scope": "mcp:read",
                    },
                )
                self.assertEqual(rcode, 201, rbody)
                client_id = json.loads(rbody)["client_id"]
                tok1 = self._authorize_and_exchange(base_url, client_id, OWNER_A, resource_url)

                code, ihdrs, ibody = self._mcp_call(
                    resource_url,
                    tok1["access_token"],
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "acc-test", "version": "1.0"},
                    },
                )
                self.assertEqual(code, 200, ibody)
                caps = ibody["result"]["capabilities"]
                self.assertTrue(caps.get("tools", {}).get("listChanged"), caps)
                sid = ihdrs.get("Mcp-Session-Id", "")
                code, _, info1 = self._mcp_call(
                    resource_url,
                    tok1["access_token"],
                    "tools/call",
                    {"name": "server_info", "arguments": {}},
                    sid,
                )
                self.assertEqual(code, 200)
                self.assertIn("profile=allowlist", info1["result"]["content"][0]["text"])
            finally:
                kill_process_tree(proc.pid, include_parent=True)
                proc.wait(timeout=5)

            # 2. Rotate owner token to OWNER_B and restart server on same issuer/URL
            proc2 = self._start_uvicorn(port, OWNER_B, oauth_db, desktop_policy, audit)
            try:
                # Old OAuth access token & refresh token must be revoked -> 401/400
                code, _, _ = self._mcp_call(
                    resource_url,
                    tok1["access_token"],
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "acc-test", "version": "1.0"},
                    },
                )
                self.assertEqual(code, 401)
                rc, _, _ = _http(
                    f"{base_url}/token",
                    method="POST",
                    data={
                        "grant_type": "refresh_token",
                        "client_id": client_id,
                        "refresh_token": tok1["refresh_token"],
                        "resource": resource_url,
                    },
                )
                self.assertIn(rc, (400, 401))

                # Old owner token must be rejected on /oauth/consent; wrong origin also 403
                auth_q = urllib.parse.urlencode(
                    {
                        "response_type": "code",
                        "client_id": client_id,
                        "redirect_uri": CALLBACK,
                        "code_challenge": CHALLENGE,
                        "code_challenge_method": "S256",
                        "scope": "mcp:read",
                        "state": "reconnect-state-old-owner",
                        "resource": resource_url,
                    }
                )
                acode, ahdrs, abody = _http(f"{base_url}/authorize?{auth_q}")
                self.assertEqual(acode, 302, abody.decode(errors="replace"))
                ticket = urllib.parse.parse_qs(urllib.parse.urlsplit(ahdrs["Location"]).query)["request_id"][0]
                old_consent_code, _, _ = _http(
                    f"{base_url}/oauth/consent",
                    method="POST",
                    data={"request_id": ticket, "owner_token": OWNER_A, "decision": "allow"},
                    headers={"Origin": base_url},
                )
                self.assertEqual(old_consent_code, 403)
                evil_origin_code, _, _ = _http(
                    f"{base_url}/oauth/consent",
                    method="POST",
                    data={"request_id": ticket, "owner_token": OWNER_B, "decision": "allow"},
                    headers={"Origin": "https://evil.example"},
                )
                self.assertEqual(evil_origin_code, 403)

                # Client "Reconnect" reuses SAME client_id cleanly with OWNER_B -> succeeds!
                tok2 = self._authorize_and_exchange(base_url, client_id, OWNER_B, resource_url)
                code, ihdrs2, _ = self._mcp_call(
                    resource_url,
                    tok2["access_token"],
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "acc-test", "version": "1.0"},
                    },
                )
                self.assertEqual(code, 200)
                sid2 = ihdrs2.get("Mcp-Session-Id", "")
                code, _, info2 = self._mcp_call(
                    resource_url,
                    tok2["access_token"],
                    "tools/call",
                    {"name": "server_info", "arguments": {}},
                    sid2,
                )
                self.assertEqual(code, 200)
                self.assertIn("MCP app ready", info2["result"]["content"][0]["text"])
            finally:
                kill_process_tree(proc2.pid, include_parent=True)
                proc2.wait(timeout=5)

    def test_task8_task9_task10_live_permissions_desktop_gating_and_server_info(self) -> None:
        from backend import server as srv

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = self._free_port()
            issuer = f"http://127.0.0.1:{port}"
            resource = f"{issuer}/mcp"
            oauth_db = root / "oauth" / "connections.sqlite3"
            desktop_path = root / "desktop" / "policy.json"

            store = OAuthStore(oauth_db, issuer, resource)
            store.bind_owner(OWNER_A)
            exec_app = ExecutionApprovals(store, default_profile="allowlist")
            policy_store = DesktopPolicyStore(desktop_path)
            fake_desktop = _FakeBackend()
            desk_mgr = DesktopManager(policy_store, fake_desktop, redactor=srv.REDACTOR)
            store.save_client(
                OAuthClientInformationFull(
                    client_id="live-perm-client",
                    client_name="Live Perm Client",
                    redirect_uris=[CALLBACK],
                    token_endpoint_auth_method="none",
                )
            )
            store.mark_approved("live-perm-client")
            tok = AccessToken(token="tok-live", client_id="live-perm-client", scopes=["mcp:read"], resource=resource)

            async def _exercise() -> None:
                from mcp.types import ListToolsResult, Tool

                mw = make_tool_middleware(store, exec_app, desktop_policy_store=policy_store)

                async def _list_all(_req):  # noqa: ANN001
                    return ListToolsResult(tools=[Tool(name=n, inputSchema={"type": "object"}) for n in sorted(ALL_REGISTERED_OAUTH_TOOLS)])

                async def _call_ok(req):  # noqa: ANN001
                    return {"called": req.params["name"]}

                with patch("backend.tool_permissions.get_access_token", return_value=tok), patch(
                    "backend.server.get_access_token", return_value=tok
                ), patch("backend.server.OAUTH_ENABLED", True), patch(
                    "backend.server.oauth_provider", type("_P", (), {"store": store})()
                ), patch("backend.server.oauth_execution", exec_app), patch(
                    "backend.server.DESKTOP_POLICY_STORE", policy_store
                ), patch("backend.server.DESKTOP_MANAGER", desk_mgr):
                    # Task 10: server_info in allowlist + desktop disabled
                    info = srv.server_info()
                    self.assertIn("profile=allowlist", info)
                    self.assertIn("computer_use=disabled", info)
                    self.assertIn("server_mode=standard", info)
                    self.assertNotIn(OWNER_A, info)
                    self.assertNotIn(str(root), info)

                    # Task 9: Desktop disabled -> 0 desktop_* tools
                    listed = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed & DESKTOP_TOOLS, set())
                    self.assertNotIn("oauth_managed_server", listed)

                    # Task 9: Enable view-only -> only 5 view tools + server_info computer_use=view
                    policy_store.save(
                        DesktopPolicy(enabled=True, allow_screen_capture=True, allow_input_control=False)
                    )
                    listed_view = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed_view & DESKTOP_TOOLS, DESKTOP_VIEW_TOOLS)
                    self.assertIn("computer_use=view", srv.server_info())
                    with self.assertRaises(Exception) as cm_click:
                        await mw(_Ctx("tools/call", {"name": "desktop_click", "arguments": {}}), _call_ok)
                    self.assertEqual(getattr(cm_click.exception, "code", None), FORBIDDEN_TOOL)

                    # Task 9: Enable control -> all 13 desktop tools + server_info computer_use=control
                    policy_store.save(
                        DesktopPolicy(enabled=True, allow_screen_capture=True, allow_input_control=True)
                    )
                    listed_ctrl = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed_ctrl & DESKTOP_TOOLS, DESKTOP_TOOLS)
                    self.assertIn("computer_use=control", srv.server_info())

                    # Task 8: Same token, live transitions allowlist -> full -> safe -> allowlist -> safe
                    exec_app.set_client_profile("live-perm-client", "full")
                    listed_full = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertIn("oauth_managed_server", listed_full)
                    self.assertIn("profile=full", srv.server_info())

                    # Add temp grant, then downgrade to safe -> clears grants & hides all elevated + desktop tools
                    exec_app.grant_temporary_access("live-perm-client", profile="full", ttl_seconds=60)
                    exec_app.set_client_profile("live-perm-client", "safe")
                    listed_safe = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed_safe, {"server_info"})
                    self.assertEqual(exec_app.active_temporary_grants("live-perm-client"), [])
                    self.assertIn("profile=safe", srv.server_info())
                    self.assertIn("computer_use=disabled", srv.server_info())
                    with self.assertRaises(Exception) as cm_win:
                        await mw(_Ctx("tools/call", {"name": "oauth_windows_command", "arguments": {"command": "whoami"}}), _call_ok)
                    self.assertEqual(getattr(cm_win.exception, "code", None), FORBIDDEN_TOOL)

                    # Back to allowlist -> works again + emergency stop locks everything fail-closed
                    exec_app.set_client_profile("live-perm-client", "allowlist")
                    listed_back = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed_back & DESKTOP_TOOLS, DESKTOP_TOOLS)
                    policy_store.set_emergency_stop(True, "test")
                    listed_stopped = {t.name for t in (await mw(_Ctx("tools/list"), _list_all)).tools}
                    self.assertEqual(listed_stopped & DESKTOP_TOOLS, set())
                    self.assertIn("computer_use=disabled", srv.server_info())

            asyncio.run(_exercise())

            # Verify ServiceManager._restart_if_running restarts server only & preserves active quick tunnel URL
            settings = Settings()
            with patch("app.core.service_manager.user_data_dir", return_value=root), patch(
                "app.paths.user_data_dir", return_value=root
            ):
                mgr = ServiceManager(settings)
                mgr._quick_url = "https://keep-me.trycloudflare.com/mcp"
                mgr.server.start = lambda *_a, **_kw: None  # type: ignore[method-assign]
                mgr.server.stop = lambda *_a, **_kw: None  # type: ignore[method-assign]
                mgr.server.is_alive = lambda: True  # type: ignore[method-assign]
                mgr.tunnel.is_alive = lambda: True  # type: ignore[method-assign]
                mgr.tunnel.stop = lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("Tunnel must stay up"))  # type: ignore[method-assign]
                err = mgr.set_token(OWNER_B)
                self.assertIsNone(err)
                self.assertEqual(mgr._quick_url, "https://keep-me.trycloudflare.com/mcp")

    @unittest.skipUnless(sys.platform == "win32", "Windows desktop required")
    def test_task9_windows_safe_window_desktop_smoke(self) -> None:
        """Real Windows Win32DesktopBackend view-only & safety guard smoke test against a harmless test window."""
        from backend.desktop.win32_backend import Win32DesktopBackend

        with tempfile.TemporaryDirectory() as td:
            policy_store = DesktopPolicyStore(Path(td) / "desktop" / "policy.json")
            policy_store.save(
                DesktopPolicy(
                    enabled=True,
                    allow_screen_capture=True,
                    allow_input_control=False,
                    allowed_clients=("win-smoke",),
                )
            )
            backend = Win32DesktopBackend()
            mgr = DesktopManager(policy_store, backend)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import tkinter as tk; "
                        "r = tk.Tk(); "
                        "r.title('MCP-App-Safe-Test-Window'); "
                        "r.geometry('240x120+40+40'); "
                        "r.after(8000, r.destroy); "
                        "r.mainloop()"
                    ),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                hwnd = None
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    try:
                        windows = mgr.list_windows(client_id="win-smoke", client_profile="allowlist")
                    except PermissionError as exc:
                        self.skipTest(f"Interactive desktop unavailable in this session: {exc}")
                    matches = [w for w in windows.get("windows", []) if "MCP-App-Safe-Test-Window" in str(w.get("title", ""))]
                    if matches:
                        hwnd = int(matches[0]["hwnd"])
                        break
                    time.sleep(0.15)
                if hwnd is None:
                    self.skipTest("Harmless test window did not appear in active interactive desktop")

                # View-only screenshot of safe test window succeeds in-memory
                shot = mgr.screenshot(client_id="win-smoke", client_profile="allowlist", hwnd=hwnd)
                self.assertGreater(len(shot.png_bytes), 0)
                self.assertGreater(shot.width, 0)

                # Control remains denied in view-only mode
                with self.assertRaises(PermissionError):
                    mgr.click(client_id="win-smoke", client_profile="allowlist", hwnd=hwnd, x=10, y=10)
            finally:
                if proc.poll() is None:
                    kill_process_tree(proc.pid, include_parent=True)
                    proc.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
