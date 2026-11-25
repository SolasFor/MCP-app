"""Unit tests for MCP Gateway security guards, models, config store, and safe import/export."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.core.secret_store import SecretStore
from backend.gateway.models import (
    AUTH_BEARER,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
)
from backend.gateway.security import (
    GATEWAY_HOP_HEADER,
    GATEWAY_ID_HEADER,
    MAX_GATEWAY_HOPS,
    check_loop_headers,
    detect_untrusted_launcher,
    make_namespaced_tool,
    sanitize_tool_description,
    strip_downstream_auth_headers,
    validate_upstream_url,
)
from backend.gateway.store import GatewayConfigStore, solidworks_mcp_template


class GatewaySecurityTests(unittest.TestCase):
    def test_namespace_length_and_collision_disambiguation(self) -> None:
        taken = {"srv__echo", "srv__" + "x" * 58}
        n1 = make_namespaced_tool("srv", "echo", taken)
        self.assertNotIn(n1, taken)
        self.assertLessEqual(len(n1), 64)

        very_long = "tool_" + "a" * 90
        n2 = make_namespaced_tool("very_long_server_id", very_long, set())
        self.assertLessEqual(len(n2), 64)
        n3 = make_namespaced_tool("very_long_server_id", very_long, {n2})
        self.assertNotEqual(n2, n3)
        self.assertLessEqual(len(n3), 64)

    def test_ssrf_and_upstream_url_guards(self) -> None:
        # Cloud metadata and unsafe schemes must always be blocked
        for bad in (
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "ftp://example.com/mcp",
            "https://user:pass@example.com/mcp",
            "http://remote-example.com/mcp",  # plain HTTP non-loopback
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate_upstream_url(bad, allow_local_endpoint=True)

        # Loopback requires explicit allow_local_endpoint=True
        with self.assertRaises(ValueError):
            validate_upstream_url("http://127.0.0.1:9100/mcp", allow_local_endpoint=False)
        self.assertEqual(
            validate_upstream_url("http://127.0.0.1:9100/mcp", allow_local_endpoint=True),
            "http://127.0.0.1:9100/mcp",
        )
        # Self recursion blocked
        with self.assertRaises(ValueError):
            validate_upstream_url(
                "https://mcp.example.com/mcp",
                self_urls=("https://mcp.example.com/mcp/",),
            )

    def test_loop_headers_and_auth_stripping(self) -> None:
        self.assertIsNone(check_loop_headers({GATEWAY_HOP_HEADER: "1"}, "gw-a"))
        self.assertIsNotNone(check_loop_headers({GATEWAY_ID_HEADER: "other,gw-a"}, "gw-a"))
        self.assertIsNotNone(
            check_loop_headers({GATEWAY_HOP_HEADER: str(MAX_GATEWAY_HOPS)}, "gw-b")
        )
        self.assertIsNotNone(check_loop_headers({GATEWAY_HOP_HEADER: "nan"}, "gw-b"))

        stripped = strip_downstream_auth_headers(
            {
                "Authorization": "Bearer secret-client",
                "Cookie": "sid=1",
                "X-Api-Key": "k",
                "Accept": "application/json",
            }
        )
        self.assertEqual(stripped, {"Accept": "application/json"})

    def test_untrusted_launchers_and_description_sanitization(self) -> None:
        self.assertTrue(detect_untrusted_launcher("npx", ["-y", "@evil/pkg"]))
        self.assertTrue(detect_untrusted_launcher("uvx", ["mcp-server-foo"]))
        self.assertTrue(detect_untrusted_launcher("powershell.exe", ["-Command", "iex (irm x)"]))
        self.assertFalse(detect_untrusted_launcher("python", ["-m", "my_local_server"]))

        cleaned = sanitize_tool_description("Line1\n\x00\x07\tLine2  " + "z" * 1200, max_len=64)
        self.assertLessEqual(len(cleaned), 64)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x00", cleaned)

    def test_store_secret_isolation_import_approval_and_redacted_export(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            secrets = SecretStore(root / "secrets")
            store = GatewayConfigStore(root / "gateway" / "servers.json", secret_store=secrets)

            # SolidWorks preset must remain unapproved and disabled until owner enables it
            sw = solidworks_mcp_template()
            self.assertFalse(sw.approved_by_owner)
            self.assertFalse(sw.enabled)
            self.assertEqual(sw.transport, TRANSPORT_STDIO)

            # Standard MCP JSON import requires explicit owner approval
            raw_cfg = json.dumps(
                {
                    "mcpServers": {
                        "remote_api": {
                            "url": "https://api.example.com/mcp",
                            "env": {"API_TOKEN": "plain-inline-secret-999", "MODE": "prod"},
                        },
                        "pkg_runner": {
                            "command": "npx",
                            "args": ["-y", "@example/mcp"],
                        },
                    }
                }
            )
            items = store.preview_standard_mcp_json(raw_cfg)
            self.assertEqual(len(items), 2)
            pkg_item = next(i for i in items if i.profile.server_id == "pkg_runner")
            self.assertTrue(any("Dynamic launcher" in w for w in pkg_item.warnings))

            with self.assertRaises(PermissionError):
                store.commit_import(items, approved_by_owner=False)

            imported = store.commit_import(items, approved_by_owner=True, enable_imported=True)
            self.assertEqual(set(imported), {"remote_api", "pkg_runner"})

            prof = store.get("remote_api")
            assert prof is not None
            self.assertEqual(prof.transport, TRANSPORT_STREAMABLE_HTTP)
            self.assertIn("API_TOKEN", prof.env_secret_refs)
            self.assertNotIn("API_TOKEN", prof.env)

            # Plaintext secret must never appear on disk JSON or in redacted export
            disk_text = (root / "gateway" / "servers.json").read_text(encoding="utf-8")
            exported = store.export_redacted_json()
            for leaked in ("plain-inline-secret-999",):
                self.assertNotIn(leaked, disk_text)
                self.assertNotIn(leaked, exported)

            # Upsert HTTP profile with bearer secret
            errs = store.upsert(
                UpstreamServerProfile(
                    server_id="http_srv",
                    name="Remote Auth",
                    transport=TRANSPORT_STREAMABLE_HTTP,
                    url="https://secure.example.com/mcp",
                    auth_mode=AUTH_BEARER,
                    approved_by_owner=True,
                ),
                bearer_token="bearer-top-secret-123",
            )
            self.assertEqual(errs, [])
            self.assertNotIn("bearer-top-secret-123", store.export_redacted_json())


if __name__ == "__main__":
    unittest.main()
