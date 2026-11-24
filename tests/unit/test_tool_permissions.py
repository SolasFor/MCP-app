"""Fixed OAuth permission tests: no editable grants, notes, or SSH bypass."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull
from mcp.shared.exceptions import MCPError
from mcp.types import ListToolsResult, Tool

from backend.oauth_store import OAuthStore
from backend.oauth_execution import ExecutionApprovals
from backend.tool_permissions import (
    BASIC_TOOLS, OAUTH_TOOLS, FULL_TOOLS, EXEC_MANAGED, EXEC_WINDOWS, EXEC_SSH,
    allowed_tools, make_tool_middleware, require_execution_permission,
)

BASE = "https://fixed.example.com"
RESOURCE = BASE + "/mcp"


def principal(client_id: str, scopes=None) -> AccessToken:
    return AccessToken(
        token="unit-test-token", client_id=client_id,
        scopes=["mcp:read"] if scopes is None else scopes,
        resource=RESOURCE,
    )


class FixedOAuthToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = OAuthStore(Path(self.temp.name) / "oauth.sqlite3", BASE, RESOURCE)
        self.store.bind_owner("owner-token")
        self.exec = ExecutionApprovals(self.store)
        for cid in ("alpha", "beta"):
            self.store.save_client(OAuthClientInformationFull(
                client_id=cid, client_name=cid,
                redirect_uris=["http://127.0.0.1:12345/callback"],
                token_endpoint_auth_method="none",
            ))
        self.store.mark_approved("alpha")

    def tearDown(self):
        self.temp.cleanup()

    def test_three_profiles_change_tool_visibility_without_restart(self):
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), BASIC_TOOLS)
        self.assertFalse(self.exec.can_request("alpha", "windows", command="whoami"))
        self.exec.set_profile("allowlist")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), OAUTH_TOOLS)
        self.exec.set_profile("full")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), FULL_TOOLS)
        self.exec.set_profile("safe")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), BASIC_TOOLS)

    def test_each_client_has_independent_tool_visibility(self):
        self.store.mark_approved("beta")
        self.exec.set_profile("allowlist")
        self.exec.set_client_profile("alpha", "full")
        self.exec.set_client_profile("beta", "safe")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), FULL_TOOLS)
        self.assertEqual(allowed_tools(self.store, principal("beta"), self.exec), BASIC_TOOLS)
        self.exec.set_client_profile("alpha", "safe")
        self.exec.set_client_profile("beta", "allowlist")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), BASIC_TOOLS)
        self.assertEqual(allowed_tools(self.store, principal("beta"), self.exec), OAUTH_TOOLS)
        self.exec.set_profile("full")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), BASIC_TOOLS)
        self.assertEqual(allowed_tools(self.store, principal("beta"), self.exec), OAUTH_TOOLS)

    def test_managed_server_requires_full_access(self):
        self.exec.set_profile("allowlist")
        with patch("backend.tool_permissions.get_access_token", return_value=principal("alpha")):
            with self.assertRaises(PermissionError):
                require_execution_permission(EXEC_MANAGED, self.store, self.exec)
            self.exec.set_client_profile("alpha", "full")
            self.assertEqual(require_execution_permission(EXEC_MANAGED, self.store, self.exec), "alpha")
            self.exec.set_client_profile("alpha", "safe")
            with self.assertRaises(PermissionError):
                require_execution_permission(EXEC_MANAGED, self.store, self.exec)

    def test_unknown_unapproved_owner_and_missing_scope_deny(self):
        for identity in (
            None, principal("beta"), principal("missing"),
            principal("mcp-app-user"), principal("alpha", scopes=[]),
        ):
            with self.subTest(identity=str(identity)):
                self.assertEqual(allowed_tools(self.store, identity, self.exec), BASIC_TOOLS)

    def test_revocation_removes_fixed_tools(self):
        self.exec.set_profile("full")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), FULL_TOOLS)
        self.store.revoke_client("alpha")
        self.assertEqual(allowed_tools(self.store, principal("alpha"), self.exec), BASIC_TOOLS)

    def test_handler_rejects_owner_and_accepts_approved_client(self):
        with patch("backend.tool_permissions.get_access_token", return_value=principal("mcp-app-user")):
            with self.assertRaises(PermissionError):
                require_execution_permission(EXEC_WINDOWS, self.store, self.exec)
        self.exec.set_profile("allowlist")
        with patch("backend.tool_permissions.get_access_token", return_value=principal("alpha")):
            self.assertEqual(
                require_execution_permission(EXEC_WINDOWS, self.store, self.exec), "alpha"
            )
            self.assertEqual(
                require_execution_permission(EXEC_SSH, self.store, self.exec), "alpha"
            )

    def test_middleware_filters_typed_catalog(self):
        middleware = make_tool_middleware(self.store, self.exec)
        all_tools = [
            Tool(name=name, input_schema={"type": "object", "properties": {}})
            for name in ("server_info", EXEC_WINDOWS, EXEC_SSH, "shared_note_read")
        ]
        async def next_list(ctx):
            return ListToolsResult(tools=all_tools)
        ctx = SimpleNamespace(method="tools/list", params={})
        self.exec.set_profile("allowlist")
        with patch("backend.tool_permissions.get_access_token", return_value=principal("alpha")):
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual({x.name for x in result.tools}, OAUTH_TOOLS)
        with patch("backend.tool_permissions.get_access_token", return_value=principal("beta")):
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual([x.name for x in result.tools], ["server_info"])

    def test_middleware_filters_dict_catalog(self):
        middleware = make_tool_middleware(self.store, self.exec)
        async def next_list(ctx):
            return {"tools": [
                {"name": "server_info"}, {"name": EXEC_WINDOWS},
                {"name": EXEC_SSH}, {"name": "shared_notes_list"},
            ]}
        ctx = SimpleNamespace(method="tools/list", params={})
        self.exec.set_profile("allowlist")
        with patch("backend.tool_permissions.get_access_token", return_value=principal("alpha")):
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual(
                {item["name"] for item in result["tools"]}, OAUTH_TOOLS
            )
        with patch("backend.tool_permissions.get_access_token", return_value=principal("beta")):
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual(result["tools"], [{"name": "server_info"}])

    def test_middleware_refuses_unapproved_tools_calls(self):
        middleware = make_tool_middleware(self.store, self.exec)
        calls = []
        async def next_call(ctx):
            calls.append(ctx.params["name"])
            return "executed"
        ctx = SimpleNamespace(method="tools/call", params={
            "name": EXEC_WINDOWS, "arguments": {"command": "hostname.exe"},
        })
        with patch("backend.tool_permissions.get_access_token", return_value=principal("beta")):
            with self.assertRaises(MCPError):
                asyncio.run(middleware(ctx, next_call))
            self.assertEqual(calls, [])
        self.exec.set_profile("allowlist")
        with patch("backend.tool_permissions.get_access_token", return_value=principal("alpha")):
            self.assertEqual(asyncio.run(middleware(ctx, next_call)), "executed")
            self.assertEqual(calls, [EXEC_WINDOWS])


if __name__ == "__main__":
    unittest.main()
