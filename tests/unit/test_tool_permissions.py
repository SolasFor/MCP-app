"""Security tests for OAuth per-client tool visibility and dispatch gates."""
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
from backend.tool_permissions import (
    ALWAYS_VISIBLE, NOTE_LIST, NOTE_READ, NOTE_WRITE,
    allowed_tools, make_tool_middleware, require_note_permission,
)

BASE = "https://notes.example.com"
RESOURCE = BASE + "/mcp"


def principal(client_id: str, scopes=None):
    return AccessToken(
        token="dummy-token", client_id=client_id,
        scopes=["mcp:read"] if scopes is None else scopes,
        resource=RESOURCE,
    )


class ToolPermissionsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = OAuthStore(Path(self.temp.name) / "oauth.sqlite3", BASE, RESOURCE)
        self.store.bind_owner("owner token")
        for cid in ("client-a", "client-b"):
            self.store.save_client(OAuthClientInformationFull(
                client_id=cid, client_name=cid,
                redirect_uris=["http://127.0.0.1:10001/"],
                token_endpoint_auth_method="none",
            ))
            self.store.mark_approved(cid)

    def tearDown(self):
        self.temp.cleanup()

    def test_only_connectivity_by_default(self):
        for p in (None, principal("unknown"), principal("mcp-app-user"), principal("client-a", [])):
            with self.subTest(p=str(p)):
                self.assertEqual(allowed_tools(self.store, p), ALWAYS_VISIBLE)

    def test_grants_do_not_cross_clients(self):
        self.store.set_note_permissions("client-a", read=True, write=False)
        self.assertEqual(
            allowed_tools(self.store, principal("client-a")),
            frozenset({"server_info", NOTE_LIST, NOTE_READ}),
        )
        self.assertEqual(allowed_tools(self.store, principal("client-b")), ALWAYS_VISIBLE)
        self.store.set_note_permissions("client-a", read=False, write=True)
        self.assertEqual(
            allowed_tools(self.store, principal("client-a")),
            frozenset({"server_info", NOTE_WRITE}),
        )

    def test_fresh_revocation_immediately_hides_tools(self):
        self.store.set_note_permissions("client-a", read=True, write=True)
        self.assertIn(NOTE_WRITE, allowed_tools(self.store, principal("client-a")))
        self.store.set_note_permissions("client-a", read=False, write=False)
        self.assertEqual(allowed_tools(self.store, principal("client-a")), ALWAYS_VISIBLE)
        self.store.revoke_client("client-a")
        self.assertEqual(allowed_tools(self.store, principal("client-a")), ALWAYS_VISIBLE)

    def test_handler_rejects_even_without_middleware(self):
        with patch("backend.tool_permissions.get_access_token", return_value=principal("client-a")):
            with self.assertRaises(PermissionError):
                require_note_permission(NOTE_READ, self.store)
            self.store.set_note_permissions("client-a", read=True, write=False)
            require_note_permission(NOTE_READ, self.store)
            with self.assertRaises(PermissionError):
                require_note_permission(NOTE_WRITE, self.store)

    def test_middleware_hides_ungranted_tools(self):
        middleware = make_tool_middleware(self.store)
        tools = [
            Tool(name=name, input_schema={"type": "object", "properties": {}})
            for name in ("server_info", NOTE_LIST, NOTE_READ, NOTE_WRITE)
        ]
        async def next_list(ctx):
            return ListToolsResult(tools=tools)

        with patch("backend.tool_permissions.get_access_token", return_value=principal("client-a")):
            ctx = SimpleNamespace(method="tools/list", params={})
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual([t.name for t in result.tools], ["server_info"])
            self.store.set_note_permissions("client-a", read=True, write=False)
            result = asyncio.run(middleware(ctx, next_list))
            self.assertEqual(
                [t.name for t in result.tools],
                ["server_info", NOTE_LIST, NOTE_READ],
            )

    def test_middleware_refuses_ungranted_call_before_dispatch(self):
        middleware = make_tool_middleware(self.store)
        calls = []
        async def next_call(ctx):
            calls.append(ctx.params["name"])
            return "executed"
        with patch("backend.tool_permissions.get_access_token", return_value=principal("client-a")):
            ctx = SimpleNamespace(method="tools/call", params={"name": NOTE_WRITE, "arguments": {}})
            with self.assertRaises(MCPError):
                asyncio.run(middleware(ctx, next_call))
            self.assertEqual(calls, [])
            self.store.set_note_permissions("client-a", read=False, write=True)
            result = asyncio.run(middleware(ctx, next_call))
            self.assertEqual(result, "executed")
            self.assertEqual(calls, [NOTE_WRITE])


if __name__ == "__main__":
    unittest.main()
