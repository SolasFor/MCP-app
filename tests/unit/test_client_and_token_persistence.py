"""Regression tests for MCP Owner Token persistence and per-client OAuth/tool/desktop permissions."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull
from PyQt6.QtWidgets import QApplication

from app.backend_entry import _hydrate_headless_env
from app.config import (
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
    Settings,
)
from app.core import domain_state
from app.core.secret_store import SecretStore, SecretStoreError
from app.core.service_manager import ServiceManager
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.oauth_execution_dialogs import ClientPermissionsDialog
from app.ui.pages.clients_page import ClientsPage
from backend.desktop.models import DesktopPolicy, DesktopPolicyStore, desktop_tool_permissions
from backend.gateway.models import UpstreamServerProfile, UpstreamToolEntry
from backend.gateway.router import GatewayRouter
from backend.gateway.store import GatewayConfigStore
from backend.oauth_execution import (
    PROFILE_ALLOWLIST,
    PROFILE_FULL,
    PROFILE_SAFE,
    ExecutionApprovals,
)
from backend.oauth_provider import LocalConsentOAuthProvider
from backend.oauth_store import OAuthStore
from backend.tool_registry import DEFAULT_REGISTRY


class OwnerTokenPersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch("app.paths.user_data_dir", return_value=self.root),
            patch("app.core.service_manager.user_data_dir", return_value=self.root),
            patch("app.core.token_store.user_data_dir", return_value=self.root),
            patch("app.core.domain_state.user_data_dir", return_value=self.root),
            patch.object(Settings, "path", return_value=self.root / "settings.json"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_auto_and_custom_owner_tokens_survive_restarts_provider_switches_and_headless(self) -> None:
        s = Settings(active_provider=PROVIDER_CF_QUICK)
        s.save()
        mgr = ServiceManager(s)
        initial_auto = mgr.token
        self.assertTrue(initial_auto)
        self.assertEqual(mgr.token_storage_error, "")

        # Restart 1: auto token stays identical across provider switches
        for prov in (PROVIDER_NGROK, PROVIDER_TAILSCALE, PROVIDER_CF_QUICK):
            mgr.set_active_provider(prov)
        mgr2 = ServiceManager(Settings.load())
        self.assertEqual(mgr2.token, initial_auto)

        # Custom token set by owner survives restarts and headless hydration
        custom_tok = "my-custom-owner-token-2026#alpha"
        self.assertIsNone(mgr2.set_token(custom_tok))
        mgr3 = ServiceManager(Settings.load())
        self.assertEqual(mgr3.token, custom_tok)

        with patch.dict(os.environ, {"MCP_SECRET_TOKEN": "", "MCP_OWNER_SECRET_B64": ""}, clear=False):
            _hydrate_headless_env()
            self.assertEqual(os.environ["MCP_SECRET_TOKEN"], custom_tok)

    def test_vault_read_failure_never_regenerates_owner_token_or_wipes_oauth_clients(self) -> None:
        domain_state.save(
            domain_state.DomainState(
                hostname="mcp.persist.example",
                tunnel_id="tid-1",
                tunnel_token="eyJhIjoiYWNjMSIsInQiOiJ0aWQtMSIsInMiOiJzZWNyZXQifQ==",
                public_url="https://mcp.persist.example",
            )
        )
        s = Settings(active_provider=PROVIDER_CF_NAMED, public_url="https://mcp.persist.example/mcp")
        s.save()
        mgr = ServiceManager(s)
        original_token = mgr.token
        original_marker = (self.root / "token.json").read_text(encoding="utf-8")

        # Register & approve an OAuth client with Full profile bound to original_token
        oauth_path = self.root / "oauth" / "connections.sqlite3"
        issuer = "https://mcp.persist.example"
        res_url = "https://mcp.persist.example/mcp"
        store = OAuthStore(oauth_path, issuer, res_url)
        store.bind_owner(original_token)
        store.save_client(
            OAuthClientInformationFull(
                client_id="claude-desktop",
                client_name="Claude Desktop",
                redirect_uris=["http://127.0.0.1:43123/cb"],
            )
        )
        store.mark_approved("claude-desktop")
        store.save_token(
            AccessToken(
                token="live-oauth-access-token-1",
                client_id="claude-desktop",
                scopes=["mcp:read"],
                expires_at=9999999999,
                resource=res_url,
            ),
            "access",
            "fam-1",
        )
        approvals = ExecutionApprovals(store)
        approvals.set_client_profile("claude-desktop", PROFILE_FULL)

        # Simulate transient DPAPI / ACL failure reading SecretStore on next app launch
        with patch.object(SecretStore, "get_secret", side_effect=SecretStoreError("DPAPI temporarily locked")):
            mgr_locked = ServiceManager(Settings.load())
            self.assertEqual(mgr_locked.token, "")
            self.assertIn("SecretStoreError", mgr_locked.token_storage_error)
            # token.json must NOT be overwritten
            self.assertEqual((self.root / "token.json").read_text(encoding="utf-8"), original_marker)
            # preflight must block cleanly rather than starting server with a random token
            with patch.object(mgr_locked, "cloudflared_path", return_value="cloudflared.exe"):
                problems = mgr_locked.preflight()
            self.assertTrue(any("--repair-acl" in p for p in problems), problems)

        # Once SecretStore is readable again, preflight recovers original_token and OAuth client stays intact!
        with patch.object(mgr_locked, "cloudflared_path", return_value="cloudflared.exe"):
            self.assertEqual(mgr_locked.preflight(), [])
        self.assertEqual(mgr_locked.token, original_token)
        self.assertEqual(approvals.profile_for("claude-desktop"), PROFILE_FULL)
        self.assertIsNotNone(store.get_token("live-oauth-access-token-1", "access"))

    def test_ephemeral_provider_with_bind_owner_false_preserves_saved_clients(self) -> None:
        oauth_path = self.root / "oauth" / "connections.sqlite3"
        issuer = "http://127.0.0.1:8000"
        res_url = "http://127.0.0.1:8000/mcp"
        store = OAuthStore(oauth_path, issuer, res_url)
        store.bind_owner("real-saved-owner-token")
        store.save_client(
            OAuthClientInformationFull(
                client_id="cursor-ide",
                client_name="Cursor",
                redirect_uris=["http://127.0.0.1:50000/callback"],
            )
        )
        store.mark_approved("cursor-ide")
        approvals = ExecutionApprovals(store)
        approvals.set_client_profile("cursor-ide", PROFILE_FULL)

        # Unconfigured manual backend launch (TOKEN_FROM_ENV=False -> bind_owner=False)
        _ephemeral = LocalConsentOAuthProvider(
            issuer,
            res_url,
            "random-ephemeral-token-not-from-env",
            store_path=oauth_path,
            bind_owner=False,
        )
        self.assertTrue(approvals.client_approved("cursor-ide"))
        self.assertEqual(approvals.profile_for("cursor-ide"), PROFILE_FULL)


class ClientGranularPermissionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "oauth" / "connections.sqlite3"
        self.desktop_path = self.root / "desktop" / "policy.json"
        self.gw_path = self.root / "gateway" / "servers.json"
        self.issuer = "https://mcp.team.example"
        self.res_url = "https://mcp.team.example/mcp"
        self.store = OAuthStore(self.db_path, self.issuer, self.res_url)
        self.store.bind_owner("owner-secret-1")
        self.approvals = ExecutionApprovals(self.store, default_profile=PROFILE_ALLOWLIST)
        self.desktop_store = DesktopPolicyStore(self.desktop_path)
        self.desktop_store.save(
            DesktopPolicy(
                enabled=True,
                allow_screen_capture=True,
                allow_input_control=True,
                min_profile="allowlist",
            )
        )

        for cid, name in (
            ("claude-safe", "Claude Safe"),
            ("chatgpt-allow", "ChatGPT Allowlist"),
            ("https://cursor.example/oauth/client", "Cursor CIMD"),
            ("vscode-inherit", "VS Code Inherit"),
        ):
            self.store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=name,
                    redirect_uris=["http://127.0.0.1:3333/cb"],
                )
            )
            self.store.mark_approved(cid)

        self.approvals.set_client_profile("claude-safe", PROFILE_SAFE)
        self.approvals.set_client_profile("chatgpt-allow", PROFILE_ALLOWLIST)
        self.approvals.set_client_profile("https://cursor.example/oauth/client", PROFILE_FULL)
        # vscode-inherit has NO explicit override -> inherits global default

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def _principal(client_id: str) -> Any:
        return SimpleNamespace(client_id=client_id, scopes=["mcp:read"])

    def test_global_default_sync_updates_fallback_without_overwriting_individual_clients(self) -> None:
        self.assertEqual(self.approvals.profile_for("vscode-inherit"), PROFILE_ALLOWLIST)
        ExecutionApprovals.sync_default_profile(self.db_path, profile=PROFILE_SAFE)

        reloaded = ExecutionApprovals(OAuthStore(self.db_path, self.issuer, self.res_url))
        self.assertEqual(reloaded.profile(), PROFILE_SAFE)
        self.assertEqual(reloaded.profile_for("vscode-inherit"), PROFILE_SAFE)
        # Explicit client overrides stay untouched!
        self.assertEqual(reloaded.profile_for("claude-safe"), PROFILE_SAFE)
        self.assertEqual(reloaded.profile_for("chatgpt-allow"), PROFILE_ALLOWLIST)
        self.assertEqual(reloaded.profile_for("https://cursor.example/oauth/client"), PROFILE_FULL)
        # Future new issuer inherits updated __default__ template too
        new_issuer_exec = ExecutionApprovals(
            OAuthStore(self.db_path, "https://new-quick.trycloudflare.com", "https://new-quick.trycloudflare.com/mcp")
        )
        self.assertEqual(new_issuer_exec.profile(), PROFILE_SAFE)

    def test_per_client_denied_tools_and_desktop_overrides_apply_live_across_registry_and_gateway(self) -> None:
        cursor_id = "https://cursor.example/oauth/client"
        # Block destructive tools specifically for Cursor even though Cursor has Full profile
        self.approvals.set_client_tool_policy(
            cursor_id,
            denied_tools=["workspace_delete_file", "git_commit", "demo__drop_db"],
        )
        # Restrict ChatGPT to view-only Computer Use, disable Computer Use for Cursor
        self.desktop_store.set_client_override("chatgpt-allow", "view")
        self.desktop_store.set_client_override(cursor_id, "disabled")

        cursor_tools = DEFAULT_REGISTRY.allowed_tools(
            self.store,
            self._principal(cursor_id),
            self.approvals,
            desktop_policy_store=self.desktop_store,
        )
        self.assertIn("oauth_windows_command", cursor_tools)
        self.assertIn("workspace_read_file", cursor_tools)
        self.assertNotIn("workspace_delete_file", cursor_tools)
        self.assertNotIn("git_commit", cursor_tools)
        self.assertNotIn("desktop_screenshot", cursor_tools)
        with self.assertRaises(PermissionError):
            DEFAULT_REGISTRY.authorize_call(
                "workspace_delete_file",
                self.store,
                self._principal(cursor_id),
                self.approvals,
                desktop_policy_store=self.desktop_store,
            )

        chatgpt_tools = DEFAULT_REGISTRY.allowed_tools(
            self.store,
            self._principal("chatgpt-allow"),
            self.approvals,
            desktop_policy_store=self.desktop_store,
        )
        self.assertIn("desktop_screenshot", chatgpt_tools)
        self.assertNotIn("desktop_click", chatgpt_tools)

        # Safe profile never gets Computer Use even if client_overrides specifies control
        self.desktop_store.set_client_override("claude-safe", "control")
        self.assertEqual(
            desktop_tool_permissions(self.desktop_store.load(), "claude-safe", PROFILE_SAFE),
            (False, False),
        )

        # GatewayRouter honors per-client denied_tools on both raw and namespaced names
        gw_store = GatewayConfigStore(self.gw_path, secret_store=SecretStore(self.root / "secrets"))
        prof = UpstreamServerProfile(
            server_id="demo",
            name="Demo Upstream",
            transport="stdio",
            command="python",
            enabled=True,
            approved_by_owner=True,
            min_profile="allowlist",
        )
        self.assertEqual(gw_store.upsert(prof), [])
        router = GatewayRouter(gw_store)
        router._server_tools["demo"] = [
            UpstreamToolEntry("demo__ping", "demo", "ping", "Ping", {"type": "object", "properties": {}}),
            UpstreamToolEntry("demo__drop_db", "demo", "drop_db", "Drop", {"type": "object", "properties": {}}),
        ]
        router._rebuild_catalog()
        visible_for_cursor = [
            t.name for t in router.list_authorized_tools(self._principal(cursor_id), self.approvals)
        ]
        self.assertEqual(visible_for_cursor, ["demo__ping"])
        with self.assertRaises(PermissionError):
            router.authorize_tool_call("demo__drop_db", self._principal(cursor_id), self.approvals)

    def test_clients_page_and_permissions_dialog_persist_and_reset_overrides(self) -> None:
        self.assertEqual(OAuthStore.latest_persistent_resource_url(self.db_path), self.res_url)

        page = ClientsPage(
            store_path_fn=lambda: self.db_path,
            default_profile_fn=lambda: PROFILE_ALLOWLIST,
            desktop_policy_path=self.desktop_path,
        )
        page.set_public_url(self.res_url)
        self.assertEqual(page.table.rowCount(), 4)

        dlg = ClientPermissionsDialog(
            page._execution,  # type: ignore[arg-type]
            "chatgpt-allow",
            "ChatGPT Allowlist",
            desktop_store=self.desktop_store,
        )
        dlg.use_custom_allowlist.setChecked(True)
        dlg.windows_edit.setPlainText("whoami\nipconfig")
        dlg.denied_tools_edit.setPlainText("workspace_write_file")
        dlg.desktop_combo.setCurrentIndex(dlg.desktop_combo.findData("view"))
        with patch.object(SilentMessageBox, "warning", return_value=SilentMessageBox.StandardButton.Yes):
            dlg.save()

        reloaded = ExecutionApprovals(OAuthStore(self.db_path, self.issuer, self.res_url))
        self.assertEqual(reloaded.client_allowlist("chatgpt-allow")["windows"], ("whoami", "ipconfig"))  # type: ignore[index]
        self.assertEqual(reloaded.client_tool_policy("chatgpt-allow")["denied_tools"], ("workspace_write_file",))
        self.assertEqual(self.desktop_store.load().client_overrides.get("chatgpt-allow"), "view")

        # Reset custom overrides restores clean inheritance
        page._reset_custom_profile("chatgpt-allow")
        reloaded2 = ExecutionApprovals(OAuthStore(self.db_path, self.issuer, self.res_url))
        self.assertFalse(reloaded2.has_client_overrides("chatgpt-allow"))
        self.assertNotIn("chatgpt-allow", self.desktop_store.load().client_overrides)


if __name__ == "__main__":
    unittest.main()
