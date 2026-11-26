"""Unit tests for MCP Gateway onboarding: templates, client configs, HTTP/SSE/OAuth probe."""
from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.gateway.client_configs import (
    detect_ai_client_configs,
    parse_config_file,
    parse_config_text,
)
from backend.gateway.discovery import inspect_stdio_runtime, probe_remote_mcp_url
from backend.gateway.models import TRANSPORT_STDIO, UpstreamServerProfile
from backend.gateway.store import GatewayConfigStore
from backend.gateway.templates import (
    TEMPLATE_CATEGORIES,
    VERIFIED_GATEWAY_TEMPLATES,
    list_templates,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class GatewayOnboardingTests(unittest.TestCase):
    def test_templates_cover_all_7_categories(self) -> None:
        cat_ids = {c[0] for c in TEMPLATE_CATEGORIES}
        self.assertEqual(len(cat_ids), 7)
        tpl_cats = {t.category for t in VERIFIED_GATEWAY_TEMPLATES}
        self.assertEqual(tpl_cats, cat_ids)
        self.assertGreaterEqual(len(list_templates()), 7)

        prof, _sec, _tok = VERIFIED_GATEWAY_TEMPLATES[0].build_profile(values={"allowed_dir": "C:\\Work"})
        self.assertEqual(prof.min_profile, "allowlist")
        self.assertTrue(prof.args)

    def test_parse_json_and_toml_client_configs_with_duplicate_marking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = GatewayConfigStore(root / "gateway.json")
            store.upsert(
                UpstreamServerProfile(
                    server_id="existing_srv",
                    name="Existing",
                    transport=TRANSPORT_STDIO,
                    command="npx",
                    args=("-y", "existing"),
                )
            )
            snippet = json.dumps({
                "mcpServers": {
                    "existing_srv": {"command": "npx", "args": ["-y", "existing"]},
                    "remote_docs": {"url": "https://docs.example.com/mcp", "headers": {"Authorization": "Bearer abc"}},
                }
            })
            parsed = parse_config_text(snippet, store=store)
            self.assertEqual(len(parsed), 2)
            by_id = {x.profile.server_id: x for x in parsed}
            self.assertEqual(by_id["existing_srv"].duplicate_of, "existing_srv")
            self.assertIsNone(by_id["remote_docs"].duplicate_of)
            self.assertIn("http", by_id["remote_docs"].profile.transport)

            codex_toml = root / "config.toml"
            codex_toml.write_text(
                '[mcp_servers.githelper]\ncommand = "uvx"\nargs = ["mcp-server-git"]\n\n'
                '[mcp_servers.hosted]\nurl = "https://hosted.example.com/sse"\n',
                encoding="utf-8",
            )
            entries = parse_config_file(codex_toml, store=store)
            self.assertEqual({e.profile.server_id for e in entries}, {"githelper", "hosted"})

            with patch.dict(os.environ, {"CODEX_HOME": str(root)}, clear=False):
                detected = detect_ai_client_configs(cwd=root)
                codex_src = next(d for d in detected if d.client_key == "codex")
                self.assertEqual(codex_src.config_path, codex_toml)
                self.assertTrue(codex_src.exists)

    def test_stdio_validation_does_not_execute_command(self) -> None:
        res_ok = inspect_stdio_runtime(sys.executable, ["-V"])
        self.assertTrue(res_ok.ok)
        res_bad = inspect_stdio_runtime("definitely-missing-mcp-binary-xyz-1234", [])
        self.assertFalse(res_bad.ok)

    def test_http_probe_detects_401_oauth_challenge_and_live_tools(self) -> None:
        port = _free_port()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_DELETE(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/.well-known/oauth-protected-resource":
                    body = json.dumps({
                        "resource": f"http://127.0.0.1:{port}/oauth-mcp",
                        "authorization_servers": [f"http://127.0.0.1:{port}"],
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/.well-known/oauth-authorization-server":
                    body = json.dumps({
                        "issuer": f"http://127.0.0.1:{port}",
                        "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
                        "token_endpoint": f"http://127.0.0.1:{port}/token",
                        "registration_endpoint": f"http://127.0.0.1:{port}/register",
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(405)
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802
                req_len = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(req_len) if req_len else b"{}"
                if self.path == "/oauth-mcp":
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.send_header(
                        "WWW-Authenticate",
                        f'Bearer resource_metadata="http://127.0.0.1:{port}/.well-known/oauth-protected-resource"',
                    )
                    self.end_headers()
                    return
                if self.path == "/public-mcp":
                    if self.headers.get("Authorization") != "Bearer good-tok":
                        self.send_response(401)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    msg = json.loads(raw.decode("utf-8") or "{}")
                    method = msg.get("method")
                    if method == "initialize":
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "result": {
                                "protocolVersion": "2025-03-26",
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "MockProbeServer", "version": "1.0.0"},
                            },
                        }
                    elif method == "notifications/initialized":
                        self.send_response(202)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    elif method == "tools/list":
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "result": {
                                "tools": [{"name": "ping", "description": "Pong tool", "inputSchema": {"type": "object"}}]
                            },
                        }
                    else:
                        resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}
                    body = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args) -> None:  # noqa: A002, ANN001
                return

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            oauth_res = asyncio.run(
                probe_remote_mcp_url(
                    f"http://127.0.0.1:{port}/oauth-mcp",
                    allow_local_endpoint=True,
                )
            )
            self.assertEqual(oauth_res.status, "auth_required")
            self.assertEqual(oauth_res.auth_kind, "oauth")
            self.assertEqual(oauth_res.oauth_issuer, f"http://127.0.0.1:{port}")

            ok_res = asyncio.run(
                probe_remote_mcp_url(
                    f"http://127.0.0.1:{port}/public-mcp",
                    bearer_token="good-tok",
                    allow_local_endpoint=True,
                )
            )
            self.assertEqual(ok_res.status, "ok")
            self.assertEqual(ok_res.server_name, "MockProbeServer")
            self.assertEqual(ok_res.tools, ("ping",))
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
