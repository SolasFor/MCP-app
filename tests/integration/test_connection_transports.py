"""Integration tests for Stage 3 ConnectionManager, live local_only MCP/OAuth, and GUI."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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

from PyQt6.QtWidgets import QApplication

from app.config import (
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_OPENAI,
    PROVIDER_TAILSCALE,
    Settings,
)
from app.core.secret_store import SecretStore
from app.core.service_manager import ServiceManager
from app.core.tunnels import ALL_PROVIDERS, ConnectionManager
from app.core.winjob import kill_process_tree
from app.ui import theme
from app.ui.i18n import LANG_RU, i18n
from app.ui.main_window import MainWindow
from app.ui.provider_wizards import ProviderConfigDialog

ROOT = Path(__file__).resolve().parents[2]
OWNER = "ci-local-only-owner-token-12345"
VERIFIER = "local-only-code-verifier-entropy-1234567890abcdef"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
CALLBACK = "http://127.0.0.1:17922/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _http(url: str, method: str = "GET", data: object = None, content_type: str | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
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
        with _OPENER.open(request, timeout=5) as resp:
            return int(resp.status), {k.title(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), {k.title(): v for k, v in exc.headers.items()}, exc.read()


class LiveLocalOnlyTransportTests(unittest.TestCase):
    """Real loopback MCP/OAuth end-to-end verification in Local Only mode."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.tmp.name)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()

        secrets = SecretStore(self.root_dir / "secrets")
        self.conn_mgr = ConnectionManager(self.root_dir, secret_store=secrets)
        local = self.conn_mgr.get(PROVIDER_LOCAL)
        ident = local.connection_identity(local_host="127.0.0.1", local_port=self.port, mcp_path="/mcp")
        self.base_url = ident.oauth_issuer
        self.resource_url = ident.oauth_resource_url

        self.env = os.environ.copy()
        self.env.update(
            {
                "MCP_PUBLIC_URL": self.resource_url,
                "MCP_HOST": "127.0.0.1",
                "MCP_PORT": str(self.port),
                "MCP_SECRET_TOKEN": OWNER,
                "MCP_ENABLE_OAUTH": "1",
                "MCP_ALLOW_QUERY_TOKEN": "0",
                "MCP_JSON_RESPONSE": "1",
                "MCP_OAUTH_STORE_PATH": str(self.root_dir / "oauth" / "connections.sqlite3"),
                "MCP_EXEC_AUDIT_PATH": str(self.root_dir / "logs" / "exec.jsonl"),
                "MCP_SPOOL_DIR": str(self.root_dir / "spool"),
            }
        )
        self.proc: subprocess.Popen | None = None
        self._start_server()

    def tearDown(self) -> None:
        self._stop_server()
        self.tmp.cleanup()

    def _start_server(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.server:build_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]
        self.proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                status, _, _ = _http(f"{self.base_url}/health")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.15)
        self.fail("Live local_only MCP server did not respond to /health in time")

    def _stop_server(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            kill_process_tree(self.proc.pid, include_parent=True)
            try:
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def test_live_local_only_oauth_initialize_tools_and_restart_persistence(self) -> None:
        # 1. Negative auth check without Bearer token
        code, _, _ = _http(self.resource_url, method="POST", data={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                           content_type="application/json")
        self.assertEqual(code, 401)

        # 2. DCR + browser consent CSRF/Origin flow + PKCE token exchange on local_only loopback
        code, _, reg_body = _http(
            f"{self.base_url}/register",
            method="POST",
            data={
                "client_name": "Live Local Test Client",
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp:read",
            },
            content_type="application/json",
        )
        self.assertIn(code, (200, 201), reg_body)
        client_id = json.loads(reg_body)["client_id"]

        auth_query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CALLBACK,
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "scope": "mcp:read",
                "state": "local-only-csrf-state",
                "resource": self.resource_url,
            }
        )
        code, hdrs, _ = _http(f"{self.base_url}/authorize?{auth_query}")
        self.assertEqual(code, 302, (code, hdrs))
        consent_url = hdrs["Location"]
        ticket = urllib.parse.parse_qs(urllib.parse.urlsplit(consent_url).query)["request_id"][0]

        code, hdrs, _ = _http(
            f"{self.base_url}/oauth/consent",
            method="POST",
            data={"request_id": ticket, "owner_token": OWNER, "decision": "allow"},
            headers={"Origin": self.base_url},
        )
        self.assertEqual(code, 303, (code, hdrs))
        loc = urllib.parse.urlsplit(hdrs["Location"])
        auth_code = urllib.parse.parse_qs(loc.query)["code"][0]

        code, _, tok_body = _http(
            f"{self.base_url}/token",
            method="POST",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": CALLBACK,
                "client_id": client_id,
                "code_verifier": VERIFIER,
                "resource": self.resource_url,
            },
        )
        self.assertEqual(code, 200, tok_body)
        access_token = json.loads(tok_body)["access_token"]
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json, text/event-stream"}

        # 3. MCP initialize + tools/list + tools/call(server_info)
        code, init_hdrs, init_body = _http(
            self.resource_url,
            method="POST",
            headers=headers,
            content_type="application/json",
            data={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "live-test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(code, 200, init_body)
        session_id = init_hdrs.get("Mcp-Session-Id")
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        code, _, list_body = _http(
            self.resource_url,
            method="POST",
            headers=headers,
            content_type="application/json",
            data={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        self.assertEqual(code, 200, list_body)
        tools = {t["name"] for t in json.loads(list_body)["result"]["tools"]}
        self.assertIn("server_info", tools)

        code, _, call_body = _http(
            self.resource_url,
            method="POST",
            headers=headers,
            content_type="application/json",
            data={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "server_info", "arguments": {}}},
        )
        self.assertEqual(code, 200, call_body)
        self.assertFalse(json.loads(call_body)["result"].get("isError", False))

        # 4. Restart local_only server on same issuer -> same OAuth token still initializes cleanly
        self._stop_server()
        self._start_server()
        re_headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json, text/event-stream"}
        code, re_hdrs, re_init = _http(
            self.resource_url,
            method="POST",
            headers=re_headers,
            content_type="application/json",
            data={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "live-test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(code, 200, re_init)
        if re_hdrs.get("Mcp-Session-Id"):
            re_headers["Mcp-Session-Id"] = re_hdrs["Mcp-Session-Id"]
        code, _, list_after = _http(
            self.resource_url,
            method="POST",
            headers=re_headers,
            content_type="application/json",
            data={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
        )
        self.assertEqual(code, 200, list_after)


class ConnectionManagerGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.tmp.name)
        self.settings_path = self.root_dir / "settings.json"
        self.oauth_path = self.root_dir / "oauth" / "connections.sqlite3"
        self.p1 = patch("app.core.service_manager.user_data_dir", return_value=self.root_dir)
        self.p2 = patch("app.paths.user_data_dir", return_value=self.root_dir)
        self.p3 = patch("app.ui.main_window.default_store_path", return_value=self.oauth_path)
        self.p4 = patch.object(Settings, "path", return_value=self.settings_path)
        for p in (self.p1, self.p2, self.p3, self.p4):
            p.start()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.settings = Settings()
        self.manager = ServiceManager(self.settings)
        self.window = MainWindow(self.manager, self.settings, tray_available=False)

    def tearDown(self) -> None:
        self.window.allow_close()
        self.window.close()
        for p in (self.p1, self.p2, self.p3, self.p4):
            p.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_connections_page_lists_all_six_providers_and_switches_with_issuer_guard(self) -> None:
        self.assertEqual(set(self.window.connections_page.provider_rows.keys()), set(ALL_PROVIDERS))
        self.assertEqual(self.manager.active_provider, PROVIDER_CF_QUICK)

        # Configure OpenAI tunnel via dialog
        dlg = ProviderConfigDialog(self.manager.connections, PROVIDER_OPENAI, parent=self.window)
        dlg.tunnel_id_edit.setText("tunnel_abc123456789")
        dlg.api_key_edit.setText("sk-openai-secret-999")
        dlg.accept() if dlg._apply_current() else self.fail("Expected valid OpenAI config")

        # Switching to Local Only while running prompts/warns on issuer transition
        self.manager._quick_url = "https://old-quick.trycloudflare.com/mcp"
        with patch.object(self.window, "_confirm", return_value=True) as confirm_mock:
            self.window._on_provider_selected(PROVIDER_LOCAL)
            self.assertTrue(confirm_mock.called)
        self.assertEqual(self.manager.active_provider, PROVIDER_LOCAL)
        self.assertEqual(self.manager.public_url, "")
        self.assertIn("127.0.0.1", self.window.home_page.ov_url.text())

        # Local Only preflight succeeds without cloudflared
        self.assertEqual(self.manager.preflight(), [])
        self.assertTrue(len(self.window.connections_page.provider_rows[PROVIDER_NGROK]) > 0)
        self.assertTrue(len(self.window.connections_page.provider_rows[PROVIDER_TAILSCALE]) > 0)


if __name__ == "__main__":
    unittest.main()
