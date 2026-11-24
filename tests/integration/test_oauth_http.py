"""Real localhost HTTP OAuth round-trip using the installed MCP SDK.

No external accounts or tunnels required. The tests use a child Uvicorn server
and RFC-standard urllib clients so Windows CI catches ASGI/OAuth integration
errors rather than only exercising provider mocks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
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

ROOT = Path(__file__).resolve().parents[2]
OWNER = "ci-owner-token-not-for-production"
VERIFIER = "code-verifier-with-entropy-aaaaaaaaaaaaaaaaaaaaaaaa"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
CALLBACK = "http://127.0.0.1:17921/callback"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def req(url, method="GET", data=None, content_type=None, headers=None):
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if content_type == "application/json":
            body = json.dumps(data).encode("utf-8")
        else:
            body = urllib.parse.urlencode(data).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        hdrs["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with OPENER.open(request, timeout=5) as r:
            return r.status, {k.title(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.title(): v for k, v in e.headers.items()}, e.read()


class OAuthHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        cls.port = sock.getsockname()[1]
        sock.close()
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls._tempdir = tempfile.TemporaryDirectory()
        env = os.environ.copy()
        env.update({
            "MCP_PUBLIC_URL": cls.url + "/mcp",
            "MCP_PORT": str(cls.port),
            "MCP_SECRET_TOKEN": OWNER,
            "MCP_ENABLE_OAUTH": "1",
            "MCP_ENABLE_ADVANCED": "1",  # must be overridden by read-only OAuth
            "MCP_ENABLE_EXECUTION": "1",
            "MCP_ALLOW_QUERY_TOKEN": "0",
            "MCP_JSON_RESPONSE": "1",
            "MCP_OAUTH_STORE_PATH": str(Path(cls._tempdir.name) / "oauth" / "state.sqlite3"),
            "MCP_EXEC_AUDIT_PATH": str(Path(cls._tempdir.name) / "logs" / "mcp_execution_audit.jsonl"),
            "MCP_SHARED_NOTES_DIR": str(Path(cls._tempdir.name) / "shared_notes"),
        })
        cls._env = env
        cls._command = [
            sys.executable, "-m", "uvicorn", "backend.server:build_app", "--factory",
            "--host", "127.0.0.1", "--port", str(cls.port), "--log-level", "warning",
        ]
        cls._start_child()

    @classmethod
    def _start_child(cls):
        cls.proc = subprocess.Popen(
            cls._command, cwd=ROOT, env=cls._env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            if cls.proc.poll() is not None:
                raise RuntimeError(f"Uvicorn terminated early: {cls.proc.returncode}")
            try:
                status, _, _ = req(cls.url + "/health")
                if status == 200:
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(0.1)
        cls.tearDownClass()
        raise RuntimeError("Uvicorn did not become healthy")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) is not None:
            from app.core.winjob import kill_process_tree

            kill_process_tree(cls.proc.pid, include_parent=True)
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=5)
        if getattr(cls, "_tempdir", None) is not None:
            cls._tempdir.cleanup()

    def test_oauth_endpoints_and_browser_consent(self):
        status, _, body = req(self.url + "/.well-known/oauth-authorization-server")
        self.assertEqual(status, 200, body.decode(errors="replace"))
        metadata = json.loads(body)
        self.assertEqual(metadata["issuer"], self.url)
        endpoint_names = {
            "authorize": "authorization_endpoint",
            "token": "token_endpoint",
            "register": "registration_endpoint",
            "revoke": "revocation_endpoint",
        }
        for path, field in endpoint_names.items():
            self.assertEqual(metadata[field], self.url + f"/{path}")
        status, _, body = req(self.url + "/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertIn(self.url, json.loads(body)["authorization_servers"])

        status, _, body = req(self.url + "/register", method="POST",
            content_type="application/json", data={
                "client_name": "MCP integration test",
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp:read",
            })
        self.assertEqual(status, 201, body.decode(errors="replace"))
        client = json.loads(body)
        client_id = client["client_id"]
        query = urllib.parse.urlencode({
            "client_id": client_id, "redirect_uri": CALLBACK,
            "response_type": "code", "code_challenge": CHALLENGE,
            "code_challenge_method": "S256", "scope": "mcp:read",
            "state": "csrf-client-state", "resource": self.url + "/mcp",
        })
        status, headers, _ = req(self.url + "/authorize?" + query)
        self.assertEqual(status, 302)
        consent_url = headers["Location"]
        self.assertEqual(urllib.parse.urlsplit(consent_url).path, "/oauth/consent")
        status, consent_headers, page = req(consent_url)
        self.assertEqual(status, 200)
        # A normal same-origin HTML form POST must send its real Origin, not
        # Origin: null (which no-referrer could cause in supported browsers).
        self.assertEqual(consent_headers["Referrer-Policy"], "same-origin")
        self.assertIn(b"MCP integration test", page)
        self.assertNotIn(OWNER.encode(), page)
        ticket = urllib.parse.parse_qs(urllib.parse.urlsplit(consent_url).query)["request_id"][0]
        status, _, _ = req(self.url + "/oauth/consent", "POST",
            data={"request_id": ticket, "owner_token": OWNER, "decision": "allow"},
            headers={"Origin": "https://evil.example.com"})
        self.assertEqual(status, 403)
        # Explicit Origin: null or a foreign origin must still be refused.
        status, _, _ = req(self.url + "/oauth/consent", "POST",
            data={"request_id": ticket, "owner_token": OWNER, "decision": "allow"},
            headers={"Origin": "null"})
        self.assertEqual(status, 403)
        status, headers, _ = req(self.url + "/oauth/consent", "POST",
            data={"request_id": ticket, "owner_token": OWNER, "decision": "allow"},
            headers={"Origin": self.url})
        self.assertEqual(status, 303)
        redirect = urllib.parse.urlsplit(headers["Location"])
        self.assertEqual(redirect.path, "/callback")
        redirect_params = urllib.parse.parse_qs(redirect.query)
        self.assertEqual(redirect_params["state"], ["csrf-client-state"])
        code = redirect_params["code"][0]

        # SDK rejects incorrect PKCE without consuming code.
        grant = {
            "grant_type": "authorization_code", "client_id": client_id,
            "code": code, "code_verifier": "wrong-verifier", "redirect_uri": CALLBACK,
            "resource": self.url + "/mcp",
        }
        status, _, _ = req(self.url + "/token", "POST", data=grant)
        self.assertEqual(status, 400)
        grant["code_verifier"] = VERIFIER
        status, _, body = req(self.url + "/token", "POST", data=grant)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        tokens = json.loads(body)
        self.assertTrue(tokens["access_token"])
        self.assertTrue(tokens["refresh_token"])
        self.assertEqual(tokens["scope"], "mcp:read")
        # Real backend restart with the same issuer: registration and access
        # token must remain valid with no new browser consent.
        cls = type(self)
        from app.core.winjob import kill_process_tree
        kill_process_tree(cls.proc.pid, include_parent=True)
        cls.proc.wait(timeout=5)
        cls._start_child()
        status, _, _ = req(self.url + "/token", "POST", data=grant)
        self.assertEqual(status, 400)

        # Authorized MCP initialize actually traverses HTTP auth.
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "mcp-http-test", "version": "0.1"}},
        }
        status, headers, body = req(self.url + "/mcp", "POST", data=init,
            content_type="application/json", headers={
                "Authorization": "Bearer " + tokens["access_token"],
                "Accept": "application/json, text/event-stream",
            })
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertIn("result", json.loads(body))
        session = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
        base_headers = {
            "Authorization": "Bearer " + tokens["access_token"],
            "Accept": "application/json, text/event-stream",
        }
        if session:
            base_headers["Mcp-Session-Id"] = session
        init_notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        req(self.url + "/mcp", "POST", data=init_notification,
            content_type="application/json", headers=base_headers)
        tool_request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        status, _, body = req(self.url + "/mcp", "POST", data=tool_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        # New/updated installations must fail closed: only server_info
        # appears until the owner deliberately selects a stronger profile.
        tools = json.loads(body)["result"]["tools"]
        self.assertEqual({tool["name"] for tool in tools}, {"server_info"})
        call_request = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "server_info", "arguments": {}}}
        status, _, body = req(self.url + "/mcp", "POST", data=call_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertIn("MCP app ready", body.decode())

        from backend.oauth_store import OAuthStore
        from backend.oauth_execution import ExecutionApprovals
        test_root = Path(cls._tempdir.name)
        store = OAuthStore(test_root / "oauth" / "state.sqlite3",
                           self.url, self.url + "/mcp")
        profiles = ExecutionApprovals(store)
        executable = "hostname.exe" if os.name == "nt" else "hostname"
        exec_request = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "oauth_windows_command",
                                   "arguments": {"command": executable}}}

        # Direct calls to a hidden tool must be blocked before dispatch.
        status, _, body = req(self.url + "/mcp", "POST", data=exec_request,
            content_type="application/json", headers=base_headers)
        self.assertIn("not available", body.decode(errors="replace"))

        profiles.set_policy(windows=executable, hosts="test.example.invalid", ssh_commands="uptime")
        profiles.set_profile("allowlist")
        status, _, body = req(self.url + "/mcp", "POST", data=tool_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertEqual(
            {t["name"] for t in json.loads(body)["result"]["tools"]},
            {"server_info", "oauth_windows_command", "oauth_ssh_command"},
        )

        # In allowlist mode the command runs IMMEDIATELY: no approval_id.
        status, _, body = req(self.url + "/mcp", "POST", data=exec_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertIn("Exit code: 0", body.decode(errors="replace"))
        self.assertNotIn("Approval required", body.decode(errors="replace"))

        exec_request["params"]["arguments"]["command"] = "echo not-on-list"
        status, _, body = req(self.url + "/mcp", "POST", data=exec_request,
            content_type="application/json", headers=base_headers)
        self.assertIn("недоступна", body.decode(errors="replace"))

        # Full mode skips command/SSH allowlists but requires the same OAuth
        # client credentials and retains host-key verification for SSH.
        profiles.set_profile("full")
        exec_request["params"]["arguments"]["command"] = "echo full-mode-check"
        status, _, body = req(self.url + "/mcp", "POST", data=exec_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertIn("full-mode-check", body.decode(errors="replace"))
        self.assertIn("Exit code: 0", body.decode(errors="replace"))

        # Live end-to-end audit must correlate with authenticated client, not
        # disclose the command, its output, or OAuth access/refresh tokens.
        audit_path = Path(cls._tempdir.name) / "logs" / "mcp_execution_audit.jsonl"
        raw_audit = audit_path.read_text(encoding="utf-8")
        self.assertNotIn("full-mode-check", raw_audit)
        self.assertNotIn(tokens["access_token"], raw_audit)
        self.assertNotIn(tokens["refresh_token"], raw_audit)
        records = [json.loads(line) for line in raw_audit.splitlines()]
        self.assertTrue(any(
            row["event"] == "completed" and row["profile"] == "full"
            and row["kind"] == "windows" and row["client_id"] == client_id
            and row["exit_code"] == 0
            for row in records
        ))
        self.assertTrue(any(
            row["event"] == "denied" and row["kind"] == "windows"
            and row["client_id"] == client_id
            for row in records
        ))
        self.assertTrue(any(row["event"] == "started" for row in records))

        profiles.set_profile("safe")
        status, _, body = req(self.url + "/mcp", "POST", data=tool_request,
            content_type="application/json", headers=base_headers)
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertEqual(
            [t["name"] for t in json.loads(body)["result"]["tools"]],
            ["server_info"],
        )

        status, _, body = req(self.url + "/token", "POST", data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": tokens["refresh_token"], "scope": "mcp:read",
            "resource": self.url + "/mcp",
        })
        self.assertEqual(status, 200, body.decode(errors="replace"))
        rotated = json.loads(body)
        self.assertNotEqual(rotated["access_token"], tokens["access_token"])
        # SDK 2.3 RevocationRequest includes a required nullable
        # client_secret field even for a registered public client.
        status, _, revoke_body = req(self.url + "/revoke", "POST", data={
            "client_id": client_id, "client_secret": "",
            "token": rotated["access_token"],
            "token_type_hint": "access_token",
        })
        self.assertEqual(status, 200, revoke_body.decode(errors="replace"))
        status, _, _ = req(self.url + "/mcp", "POST", data=init,
            content_type="application/json", headers={
                "Authorization": "Bearer " + rotated["access_token"],
                "Accept": "application/json, text/event-stream",
            })
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
