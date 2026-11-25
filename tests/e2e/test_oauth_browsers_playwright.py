"""Real browser OAuth 2.1 + PKCE E2E tests via Playwright (Chromium, Chrome, Edge, Firefox).

Starts an actual local HTTP MCP/OAuth server (uvicorn) and a separate cross-origin
callback HTTP server on a different localhost port, then drives real browser engines
through `/authorize` -> `/oauth/consent` -> POST allow/deny -> 303 cross-origin redirect
-> PKCE `/token` exchange -> MCP `initialize` & `tools/list`.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

OWNER_TOKEN = "pw-owner-secret-token-9876543210"
CODE_VERIFIER = "pw-pkce-code-verifier-0123456789abcdef0123456789abcdef"
CODE_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(CODE_VERIFIER.encode()).digest()).decode().rstrip("=")
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as resp:
            return int(resp.status), {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, exc.read()


class _CallbackServer:
    def __init__(self) -> None:
        self.port = _free_port()
        self.hits: list[dict[str, list[str]]] = []
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path != "/oauth/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                params = urllib.parse.parse_qs(parsed.query)
                parent.hits.append(params)
                body = b"<!doctype html><html><body><h1>OAuth Callback Received</h1></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:  # noqa: A002, ANN001
                return

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self.port}/oauth/callback"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class PlaywrightOAuthBrowserE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root_dir = Path(cls.tmp.name)
        cls.port = _free_port()
        cls.issuer = f"http://127.0.0.1:{cls.port}"
        cls.resource_url = f"{cls.issuer}/mcp"
        cls.logs_dir = cls.root_dir / "logs"

        # Configure isolated environment before importing backend.server in subprocess
        import subprocess

        cls.cb_server = _CallbackServer()
        env = os.environ.copy()
        env.update(
            {
                "MCP_PUBLIC_URL": cls.resource_url,
                "MCP_HOST": "127.0.0.1",
                "MCP_PORT": str(cls.port),
                "MCP_SECRET_TOKEN": OWNER_TOKEN,
                "MCP_ENABLE_OAUTH": "1",
                "MCP_JSON_RESPONSE": "1",
                "MCP_LOGS_DIR": str(cls.logs_dir),
                "MCP_OAUTH_STORE_PATH": str(cls.root_dir / "oauth" / "connections.sqlite3"),
                "MCP_EXEC_AUDIT_PATH": str(cls.logs_dir / "mcp_execution_audit.jsonl"),
                "MCP_GATEWAY_CONFIG_PATH": str(cls.root_dir / "gateway" / "servers.json"),
                "MCP_MANAGED_SERVERS_PATH": str(cls.root_dir / "servers" / "managed_servers.json"),
                "MCP_WORKSPACES_CONFIG_PATH": str(cls.root_dir / "workspaces" / "workspaces.json"),
                "MCP_WORKSPACES_HISTORY_DIR": str(cls.root_dir / "workspaces" / "history"),
                "MCP_DESKTOP_POLICY_PATH": str(cls.root_dir / "desktop" / "policy.json"),
                "MCP_EXTENSIONS_DIR": str(cls.root_dir / "extensions"),
                "MCP_DEVICES_CONFIG_PATH": str(cls.root_dir / "remote" / "devices.json"),
                "MCP_AUTOMATION_DIR": str(cls.root_dir / "automation"),
                "MCP_SECRETS_DIR": str(cls.root_dir / "secrets"),
                "MCP_TASKS_DB_PATH": str(cls.root_dir / "tasks" / "tasks.sqlite3"),
                "MCP_TASKS_ARTIFACTS_DIR": str(cls.root_dir / "tasks" / "artifacts"),
                "MCP_SPOOL_DIR": str(cls.root_dir / "tasks" / "spool"),
            }
        )
        cls.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.server:build_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
                "--log-level",
                "warning",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            try:
                status, _, _ = _http_json(f"{cls.issuer}/health")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.15)
        raise RuntimeError("Uvicorn test backend failed to start within 12s")

    @classmethod
    def tearDownClass(cls) -> None:
        from app.core.winjob import kill_process_tree

        if cls.proc.poll() is None:
            kill_process_tree(cls.proc.pid, include_parent=True)
            cls.proc.wait(timeout=4.0)
        cls.cb_server.close()
        cls.tmp.cleanup()

    def _register_client(self, name: str) -> str:
        code, _, body = _http_json(
            f"{self.issuer}/register",
            method="POST",
            payload={
                "client_name": name,
                "redirect_uris": [self.cb_server.redirect_uri],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp:read",
            },
        )
        self.assertIn(code, (200, 201), body)
        return str(json.loads(body)["client_id"])

    def _authorize_url(self, client_id: str, state: str) -> str:
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self.cb_server.redirect_uri,
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "S256",
                "scope": "mcp:read",
                "state": state,
                "resource": self.resource_url,
            }
        )
        return f"{self.issuer}/authorize?{query}"

    def _run_full_oauth_in_browser(self, browser, label: str) -> None:  # noqa: ANN001
        self.cb_server.hits.clear()
        client_id = self._register_client(f"PW Client {label}")
        state = f"state-{label}"
        auth_url = self._authorize_url(client_id, state)

        context = browser.new_context()
        page = context.new_page()
        console_errors: list[str] = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        try:
            resp = page.goto(auth_url, wait_until="domcontentloaded")
            self.assertIsNotNone(resp)
            assert resp is not None
            self.assertEqual(resp.status, 200)
            csp = resp.headers.get("content-security-policy", "")
            self.assertIn(f"http://localhost:{self.cb_server.port}", csp)

            # 1. Wrong owner token -> clear 403 HTML retry page
            page.fill("input[name='owner_token']", "wrong-owner-token-attempt")
            page.click("button[value='allow']")
            page.wait_for_load_state("domcontentloaded")
            self.assertIn("Incorrect MCP Owner Token", page.content())

            # 2. Valid owner token -> Allow -> 303 redirect to cross-origin callback MUST succeed!
            page.fill("input[name='owner_token']", OWNER_TOKEN)
            page.click("button[value='allow']")
            page.wait_for_url(f"http://localhost:{self.cb_server.port}/oauth/callback**", timeout=8000)
            self.assertIn("OAuth Callback Received", page.content())

            self.assertEqual(len(self.cb_server.hits), 1)
            cb_params = self.cb_server.hits[0]
            self.assertEqual(cb_params.get("state"), [state])
            self.assertIn("code", cb_params)
            auth_code = cb_params["code"][0]

            # 3. Verify CSP errors did NOT occur
            self.assertFalse(
                any("Content Security Policy" in e or "form-action" in e for e in console_errors),
                console_errors,
            )

            # 4. Reuse expired/consumed consent link -> 410 HTML
            reused = page.goto(f"{self.issuer}/oauth/consent?request_id=expired-or-used", wait_until="domcontentloaded")
            assert reused is not None
            self.assertEqual(reused.status, 410)
            self.assertIn("Authorization request expired", page.content())

            # 5. Browser navigating to unknown client_id at /authorize -> HTML error page
            bad_auth = self._authorize_url("nonexistent-client-id-after-restart", "st-bad")
            bad_resp = page.goto(bad_auth, wait_until="domcontentloaded")
            assert bad_resp is not None
            self.assertEqual(bad_resp.status, 400)
            self.assertIn("Reconnect", page.content())

            # 6. Deny flow -> callback receives access_denied
            self.cb_server.hits.clear()
            deny_url = self._authorize_url(client_id, f"deny-{label}")
            page.goto(deny_url, wait_until="domcontentloaded")
            page.click("button[value='deny']")
            page.wait_for_url(f"http://localhost:{self.cb_server.port}/oauth/callback**", timeout=8000)
            self.assertEqual(self.cb_server.hits[0].get("error"), ["access_denied"])
        finally:
            context.close()

        # 7. PKCE /token exchange + MCP tools/list works using real browser-obtained code
        t_code, _, t_body = _http_json(
            f"{self.issuer}/token",
            method="POST",
            form={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "redirect_uri": self.cb_server.redirect_uri,
                "code_verifier": CODE_VERIFIER,
                "resource": self.resource_url,
            },
        )
        self.assertEqual(t_code, 200, t_body)
        tokens = json.loads(t_body)
        access_token = tokens["access_token"]

        mcp_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json, text/event-stream",
        }
        i_code, i_hdrs, i_body = _http_json(
            self.resource_url,
            method="POST",
            headers=mcp_headers,
            payload={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": f"pw-{label}", "version": "1.0"},
                },
            },
        )
        self.assertEqual(i_code, 200, i_body)
        if i_hdrs.get("mcp-session-id"):
            mcp_headers["Mcp-Session-Id"] = i_hdrs["mcp-session-id"]
        l_code, _, l_body = _http_json(
            self.resource_url,
            method="POST",
            headers=mcp_headers,
            payload={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        self.assertEqual(l_code, 200, l_body)
        self.assertNotIn("error", json.loads(l_body))

        # 8. Cross-origin POST rejected with 403 HTML
        evil_code, _, evil_body = _http_json(
            f"{self.issuer}/oauth/consent",
            method="POST",
            form={"request_id": "x", "owner_token": OWNER_TOKEN, "decision": "allow"},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(evil_code, 403)
        self.assertIn(b"Security check failed", evil_body)

        # 9. Verify oauth.log & errors.log never contain secrets
        for log_name in ("oauth.log", "errors.log"):
            p = self.logs_dir / log_name
            if p.is_file():
                txt = p.read_text(encoding="utf-8", errors="replace")
                self.assertNotIn(OWNER_TOKEN, txt)
                self.assertNotIn(access_token, txt)
                self.assertNotIn(auth_code, txt)
                self.assertNotIn(CODE_VERIFIER, txt)

    def test_oauth_flow_in_chromium_and_firefox_and_installed_chrome_edge(self) -> None:
        with sync_playwright() as pw:
            # Always required in test suite: Playwright Chromium + Firefox
            chromium = pw.chromium.launch(headless=True)
            try:
                self._run_full_oauth_in_browser(chromium, "chromium")
            finally:
                chromium.close()

            firefox = pw.firefox.launch(headless=True)
            try:
                self._run_full_oauth_in_browser(firefox, "firefox")
            finally:
                firefox.close()

            # Also verify real installed Google Chrome and Microsoft Edge on Windows
            chrome_path = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
            if chrome_path.is_file():
                chrome = pw.chromium.launch(channel="chrome", headless=True)
                try:
                    self._run_full_oauth_in_browser(chrome, "chrome")
                finally:
                    chrome.close()

            edge_path = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
            if edge_path.is_file():
                edge = pw.chromium.launch(channel="msedge", headless=True)
                try:
                    self._run_full_oauth_in_browser(edge, "msedge")
                finally:
                    edge.close()


if __name__ == "__main__":
    unittest.main()
