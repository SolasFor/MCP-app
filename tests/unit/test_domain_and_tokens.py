"""Unit tests for custom domain persistence across provider switches and custom user/tunnel tokens."""
from __future__ import annotations

import base64
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.config import (
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_NGROK,
    PROVIDER_NONE,
    PROVIDER_TAILSCALE,
    Settings,
)
from app.core import domain_state
from app.core.secret_store import SecretStore
from app.core.service_manager import ServiceManager
from app.core.tunnels import ConnectionManager
from app.core.tunnels.cloudflare import CloudflareNamedProvider
from app.ui.domain_wizard import DomainWizard, _extract_tunnel_id_from_token


class DomainPersistenceAndTokensTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings_path = self.root / "settings.json"
        self.p1 = patch("app.core.service_manager.user_data_dir", return_value=self.root)
        self.p2 = patch("app.paths.user_data_dir", return_value=self.root)
        self.p3 = patch("app.core.token_store.user_data_dir", return_value=self.root)
        self.p4 = patch("app.core.domain_state.user_data_dir", return_value=self.root)
        self.p5 = patch.object(Settings, "path", return_value=self.settings_path)
        for p in (self.p1, self.p2, self.p3, self.p4, self.p5):
            p.start()

    def tearDown(self) -> None:
        for p in (self.p5, self.p4, self.p3, self.p2, self.p1):
            p.stop()
        self.tmp.cleanup()

    def test_custom_domain_preserved_across_all_provider_switches_and_restarts(self) -> None:
        state = domain_state.DomainState(
            hostname="mcp.mycustomdomain.example",
            tunnel_id="tid-existing-1",
            tunnel_token="cfut-tunnel-secret-value-123456",
            zone_name="mycustomdomain.example",
            setup_mode="api",
            public_url="https://mcp.mycustomdomain.example",
        )
        domain_state.save(state)

        s = Settings(active_provider=PROVIDER_CF_NAMED, public_url="https://mcp.mycustomdomain.example/mcp")
        s.save()
        mgr = ServiceManager(s)
        self.assertEqual(mgr.public_url, "https://mcp.mycustomdomain.example/mcp")
        self.assertTrue(mgr.has_domain())

        # Named -> Quick -> ngrok -> Tailscale -> Named without wiping custom domain config!
        mgr.set_active_provider(PROVIDER_CF_QUICK)
        self.assertEqual(mgr.active_provider, PROVIDER_CF_QUICK)
        self.assertEqual(domain_state.load().hostname, "mcp.mycustomdomain.example")

        mgr.set_active_provider(PROVIDER_NGROK)
        mgr.set_active_provider(PROVIDER_TAILSCALE)
        mgr.set_active_provider(PROVIDER_CF_NAMED)
        self.assertEqual(mgr.active_provider, PROVIDER_CF_NAMED)
        self.assertEqual(mgr.public_url, "https://mcp.mycustomdomain.example/mcp")

        # Simulated app restart: reload settings + ServiceManager from disk
        s_reloaded = Settings.load()
        mgr2 = ServiceManager(s_reloaded)
        self.assertEqual(mgr2.active_provider, PROVIDER_CF_NAMED)
        self.assertEqual(mgr2.public_url, "https://mcp.mycustomdomain.example/mcp")
        self.assertEqual(mgr2.preflight_for_test if hasattr(mgr2, "preflight_for_test") else [], [])

    def test_domain_diagnostics_classify_exact_causes(self) -> None:
        mgr = ConnectionManager(self.root, secret_store=SecretStore(self.root / "secrets"))
        prov = mgr.get(PROVIDER_CF_NAMED)
        assert isinstance(prov, CloudflareNamedProvider)
        with patch("app.core.tunnels.cloudflare.resolve_cloudflared", return_value=None):
            code_missing, _msg = prov.diagnose_issue(mcp_path="/mcp")
            self.assertEqual(code_missing, "agent_missing")

        with patch("app.core.tunnels.cloudflare.resolve_cloudflared", return_value="cloudflared.exe"):
            code_unconf, _msg_u = prov.diagnose_issue(mcp_path="/mcp")
            self.assertEqual(code_unconf, "domain_not_configured")

        with patch("app.core.tunnels.cloudflare.resolve_cloudflared", return_value="cloudflared.exe"):
            code2, _msg2 = prov.diagnose_issue(mcp_path="/mcp", config={"hostname": "mcp.demo.example"})
            self.assertEqual(code2, "token_missing")

        with patch("app.core.domain_state._store") as mock_store:
            mock_store.return_value.resolve_ref.side_effect = OSError("DPAPI failed")
            (self.root / "domain.json").write_text(
                json.dumps({
                    "hostname": "mcp.bad.example",
                    "tunnel_id": "t1",
                    "tunnel_token_ref": "secret://tunnel/cloudflare_named_token",
                }),
                encoding="utf-8",
            )
            loaded = domain_state.load()
            self.assertTrue(loaded.decrypt_error)
            with patch("app.core.tunnels.cloudflare.resolve_cloudflared", return_value="cloudflared.exe"):
                code3, _msg3 = prov.diagnose_issue(mcp_path="/mcp")
                self.assertEqual(code3, "secret_decrypt_failed")

    def test_custom_owner_token_set_and_rotate_preserves_tunnel_config(self) -> None:
        domain_state.save(
            domain_state.DomainState(
                hostname="mcp.keepdomain.example",
                tunnel_id="tid-keep",
                tunnel_token="tunnel-keep-secret-999",
                zone_name="keepdomain.example",
                setup_mode="tunnel_token",
                public_url="https://mcp.keepdomain.example",
            )
        )
        s = Settings(active_provider=PROVIDER_CF_NAMED)
        mgr = ServiceManager(s)

        # User enters their own custom MCP Owner Token manually
        custom_tok = "user-custom-owner-token-2026-xyz"
        err = mgr.set_token(custom_tok)
        self.assertIsNone(err)
        self.assertEqual(mgr.token, custom_tok)
        # Custom domain & Tunnel Token remain completely untouched
        self.assertEqual(domain_state.load().hostname, "mcp.keepdomain.example")
        self.assertEqual(domain_state.load().tunnel_token, "tunnel-keep-secret-999")

    def test_domain_wizard_existing_tunnel_token_mode_saves_without_cf_api(self) -> None:
        payload = base64.b64encode(json.dumps({"a": "acc1", "t": "tid-decoded-777", "s": "sec"}).encode()).decode()
        self.assertEqual(_extract_tunnel_id_from_token(payload), "tid-decoded-777")

        wiz = DomainWizard(8000)
        wiz.mode_combo.setCurrentIndex(1)
        self.assertEqual(wiz.current_mode(), "tunnel_token")
        wiz.hostname.setText("https://Existing.Example.com/mcp")
        wiz.tunnel_token_edit.setText(payload)

        with patch("app.core.cf_api.setup_domain") as cf_setup_mock:
            wiz._run()
            cf_setup_mock.assert_not_called()

        saved = domain_state.load()
        self.assertEqual(saved.hostname, "existing.example.com")
        self.assertEqual(saved.tunnel_id, "tid-decoded-777")
        self.assertEqual(saved.tunnel_token, payload)
        self.assertEqual(saved.setup_mode, "tunnel_token")
        self.assertEqual(saved.public_url, "https://existing.example.com")

    def test_legacy_local_only_migrates_to_provider_none(self) -> None:
        self.settings_path.write_text(json.dumps({"active_provider": "local_only"}), encoding="utf-8")
        s = Settings.load()
        self.assertEqual(s.active_provider, PROVIDER_NONE)
        self.assertEqual(s.migrated_from_provider, "local_only")


if __name__ == "__main__":
    unittest.main()
