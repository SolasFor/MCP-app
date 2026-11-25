"""Unit tests for Stage 3 ConnectionManager and all 5 TunnelProvider implementations."""
from __future__ import annotations

import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.secret_store import SecretStore
from app.core.tunnels import (
    ALL_PROVIDERS,
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
    ConnectionManager,
    TailscaleFunnelProvider,
)
from backend.oauth_store import OAuthStore
from mcp.shared.auth import OAuthClientInformationFull


class _MockJsonHandler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict]] = {}

    def do_GET(self) -> None:  # noqa: N802
        status, payload = self.routes.get(self.path, (404, {"error": "not found"}))
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002, ANN001
        return


class ConnectionManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.secrets = SecretStore(self.data_dir / "secrets")
        self.mgr = ConnectionManager(self.data_dir, secret_store=self.secrets)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_five_providers_registered_and_single_active_policy(self) -> None:
        self.assertEqual(len(ALL_PROVIDERS), 5)
        self.assertEqual(set(self.mgr.providers.keys()), set(ALL_PROVIDERS))
        self.assertEqual(self.mgr.active_provider_id, PROVIDER_CF_QUICK)
        self.mgr.set_active_provider(PROVIDER_NGROK)
        self.assertEqual(self.mgr.active_provider_id, PROVIDER_NGROK)
        self.mgr.set_active_provider(PROVIDER_LOCAL)
        self.assertEqual(self.mgr.active_provider_id, PROVIDER_LOCAL)

    def test_local_only_enforces_loopback_and_no_public_url(self) -> None:
        local = self.mgr.get(PROVIDER_LOCAL)
        self.assertTrue(local.detect().installed)
        self.assertEqual(local.validate_config({"bind_host": "127.0.0.1"}), [])
        self.assertTrue(local.validate_config({"bind_host": "0.0.0.0"}))
        ident = local.connection_identity(local_host="127.0.0.1", local_port=8123, mcp_path="/mcp")
        self.assertFalse(ident.is_public_url)
        self.assertEqual(ident.public_url, "")
        self.assertEqual(ident.local_url, "http://127.0.0.1:8123/mcp")
        self.assertEqual(ident.oauth_issuer, "http://127.0.0.1:8123")

    def test_ngrok_stores_secret_only_in_secret_store_and_polls_local_api(self) -> None:
        class NgrokHandler(_MockJsonHandler):
            routes = {
                "/api/endpoints": (200, {"endpoints": [{"public_url": "https://demo-mcp.ngrok-free.app"}]})
            }

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NgrokHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            errors = self.mgr.configure_provider(
                PROVIDER_NGROK,
                {
                    "reserved_domain": "demo-mcp.ngrok-free.app",
                    "local_api_url": f"http://127.0.0.1:{port}",
                },
                secrets={"authtoken": "ng_secret_tok_987654"},
            )
            self.assertEqual(errors, [])
            raw_json = (self.data_dir / "tunnels" / "connections.json").read_text(encoding="utf-8")
            self.assertNotIn("ng_secret_tok_987654", raw_json)

            ngrok = self.mgr.get(PROVIDER_NGROK)
            with patch("pathlib.Path.is_file", return_value=True), patch(
                "app.core.tunnels.ngrok._candidate_ngrok_paths",
                return_value=[Path("C:/mock/ngrok.exe")],
            ), patch("app.core.tunnels.ngrok.run_cli_capture", return_value=(0, "ngrok version 3.18.0", "")):
                spec = ngrok.build_launch_spec(local_host="127.0.0.1", local_port=8000, mcp_path="/mcp")
            assert spec is not None
            self.assertIn("https://demo-mcp.ngrok-free.app", " ".join(spec.args))
            self.assertNotIn("ng_secret_tok_987654", " ".join(spec.args))
            self.assertEqual(spec.env.get("NGROK_AUTHTOKEN"), "ng_secret_tok_987654")

            url, warns = ngrok.poll_active_endpoint()  # type: ignore[attr-defined]
            self.assertEqual(url, "https://demo-mcp.ngrok-free.app")
            self.assertTrue(any("interstitial" in w for w in warns))
        finally:
            server.shutdown()
            server.server_close()

    def test_tailscale_funnel_checks_ports_foreign_routes_and_stops_only_owned_route(self) -> None:
        ts = self.mgr.get(PROVIDER_TAILSCALE)
        assert isinstance(ts, TailscaleFunnelProvider)
        self.assertTrue(ts.validate_config({"https_port": 9443}))
        self.assertEqual(ts.validate_config({"https_port": 8443}), [])
        ts.configure({"https_port": 8443})

        status_json = json.dumps(
            {
                "BackendState": "Running",
                "Self": {
                    "DNSName": "devbox.tailnet.ts.net.",
                    "Capabilities": ["https://tailscale.com/cap/funnel"],
                },
            }
        )
        foreign_funnel_json = json.dumps(
            {
                "Web": {
                    "devbox.tailnet.ts.net:8443": {
                        "Handlers": {"/mcp": {"Proxy": "http://127.0.0.1:9999/other"}}
                    }
                }
            }
        )
        calls: list[list[str]] = []

        def fake_cli(cmd: list[str], **_kwargs) -> tuple[int, str, str]:
            calls.append(cmd)
            if cmd[1:] == ["version"]:
                return 0, "1.104.2", ""
            if cmd[1:] == ["status", "--json"]:
                return 0, status_json, ""
            if cmd[1:] == ["funnel", "status", "--json"]:
                return 0, foreign_funnel_json, ""
            return 0, "", ""

        with patch("app.core.tunnels.tailscale._find_tailscale", return_value="tailscale.exe"), patch(
            "app.core.tunnels.tailscale.run_cli_capture", side_effect=fake_cli
        ):
            ok, msg = ts.start(local_host="127.0.0.1", local_port=8000, mcp_path="/mcp")
            self.assertFalse(ok)
            self.assertIn("Foreign Tailscale Funnel route", msg)

        foreign_funnel_json = json.dumps({"Web": {}})
        with patch("app.core.tunnels.tailscale._find_tailscale", return_value="tailscale.exe"), patch(
            "app.core.tunnels.tailscale.run_cli_capture", side_effect=fake_cli
        ):
            ok, url = ts.start(local_host="127.0.0.1", local_port=8000, mcp_path="/mcp")
            self.assertTrue(ok, url)
            self.assertEqual(url, "https://devbox.tailnet.ts.net:8443/mcp")

            calls.clear()
            stopped, _ = ts.stop()
            self.assertTrue(stopped)
            funnel_calls = [cmd for cmd in calls if "funnel" in cmd]
            self.assertEqual(len(funnel_calls), 1)
            self.assertIn("off", funnel_calls[0])
            self.assertNotIn("reset", funnel_calls[0])

    def test_legacy_openai_tunnel_migrates_safely_and_purges_only_legacy_secret(self) -> None:
        tunnels_dir = self.data_dir / "tunnels"
        tunnels_dir.mkdir(parents=True, exist_ok=True)
        (tunnels_dir / "connections.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "active_provider": "openai_tunnel",
                    "providers": {
                        "openai_tunnel": {"tunnel_id": "tunnel_legacy_123", "profile_name": "workstation"},
                        "ngrok": {"reserved_domain": "demo.ngrok.app"},
                    },
                }
            ),
            encoding="utf-8",
        )
        self.secrets.set_secret("tunnel", "openai_tunnel_api_key", "sk-legacy-secret")
        self.secrets.set_secret("tunnel", "ngrok_authtoken", "ng-keep-secret")

        migrated_mgr = ConnectionManager(self.data_dir, secret_store=self.secrets)
        self.assertEqual(migrated_mgr.migrated_from_provider, "openai_tunnel")
        self.assertEqual(migrated_mgr.active_provider_id, PROVIDER_LOCAL)
        self.assertIsNone(migrated_mgr.providers.get("openai_tunnel"))

        saved_raw = (tunnels_dir / "connections.json").read_text(encoding="utf-8")
        self.assertNotIn("openai_tunnel", saved_raw)
        self.assertTrue(migrated_mgr.has_legacy_openai_secret())
        self.assertTrue(migrated_mgr.purge_legacy_openai_secret())
        self.assertFalse(migrated_mgr.has_legacy_openai_secret())
        self.assertIsNone(self.secrets.get_secret("tunnel", "openai_tunnel_api_key"))
        self.assertEqual(self.secrets.get_secret("tunnel", "ngrok_authtoken"), "ng-keep-secret")

    def test_issuer_transition_warning_and_oauth_store_isolation(self) -> None:
        self.mgr.configure_provider(PROVIDER_NGROK, {"reserved_domain": "alpha.ngrok.app"})
        first_ident = self.mgr.get(PROVIDER_NGROK).connection_identity(
            local_host="127.0.0.1", local_port=8000, mcp_path="/mcp"
        )
        warn = self.mgr.check_issuer_transition(
            previous_identity=first_ident,
            next_provider_id=PROVIDER_LOCAL,
            local_host="127.0.0.1",
            local_port=8000,
            mcp_path="/mcp",
        )
        self.assertTrue(warn.issuer_changed)
        self.assertEqual(warn.previous_issuer, "https://alpha.ngrok.app")
        self.assertEqual(warn.next_issuer, "http://127.0.0.1:8000")

        db_path = self.data_dir / "oauth" / "connections.sqlite3"
        store_a = OAuthStore(db_path, "https://alpha.ngrok.app", "https://alpha.ngrok.app/mcp")
        store_a.bind_owner("owner-secret")
        store_a.save_client(
            OAuthClientInformationFull(
                client_id="client-alpha",
                client_name="Alpha",
                redirect_uris=["http://127.0.0.1:3105/cb"],
                token_endpoint_auth_method="none",
            )
        )
        store_a.mark_approved("client-alpha")
        self.assertIsNotNone(store_a.get_client("client-alpha"))

        store_b = OAuthStore(db_path, "http://127.0.0.1:8000", "http://127.0.0.1:8000/mcp")
        store_b.bind_owner("owner-secret")
        self.assertIsNone(store_b.get_client("client-alpha"))


if __name__ == "__main__":
    unittest.main()
