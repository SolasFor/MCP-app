"""Per-client MCP tool visibility and authorization.

The SDK's middleware hides unauthorized tools during tools/list and denies
tools/call before dispatch. Every note tool ALSO calls require_note_permission:
this second check is the security boundary if middleware behavior changes in
an SDK minor version or a tool is called directly in-process.

The owner's shared Bearer token is never a client permission grant.
"""
from __future__ import annotations

from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.shared.exceptions import MCPError
from mcp.types import ListToolsResult

from .oauth_store import OAuthStore

NOTE_LIST = "shared_notes_list"
NOTE_READ = "shared_note_read"
NOTE_WRITE = "shared_note_write"
NOTES = frozenset({NOTE_LIST, NOTE_READ, NOTE_WRITE})
ALWAYS_VISIBLE = frozenset({"server_info"})
FORBIDDEN_TOOL = -32602


def allowed_tools(store: OAuthStore | None, principal: Any) -> frozenset[str]:
    """Re-evaluate live SQLite grants on every request, never cache sessions."""
    basic = ALWAYS_VISIBLE
    if store is None or principal is None:
        return basic
    client_id = getattr(principal, "client_id", "")
    # The owner token is also accepted as a Bearer token for compatibility.
    # It must never get per-client grants or turn into a privileged OAuth client.
    if not isinstance(client_id, str) or client_id == "mcp-app-user" or not client_id:
        return basic
    if "mcp:read" not in (getattr(principal, "scopes", None) or []):
        return basic
    can_read, can_write = store.get_note_permissions(client_id)
    allowed = set(basic)
    if can_read:
        allowed.update({NOTE_LIST, NOTE_READ})
    if can_write:
        allowed.add(NOTE_WRITE)
    return frozenset(allowed)


def require_note_permission(name: str, store: OAuthStore | None) -> None:
    """Fail closed on missing identity, client approval, or stale permissions."""
    if name not in NOTES or name not in allowed_tools(store, get_access_token()):
        raise PermissionError("OAuth client does not have permission for this note tool")


def make_tool_middleware(store: OAuthStore | None):
    async def restrict_tools(ctx, call_next):
        method = ctx.method
        if method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        allowed = allowed_tools(store, get_access_token())
        if method == "tools/call":
            params = ctx.params
            name = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
            if name in NOTES and name not in allowed:
                raise MCPError(code=FORBIDDEN_TOOL, message="This tool is not permitted for this client")
            return await call_next(ctx)
        result = await call_next(ctx)
        if isinstance(result, ListToolsResult):
            # Do not mutate cached SDK response instances in place.
            return result.model_copy(update={"tools": [t for t in result.tools if t.name in allowed]})
        return result

    return restrict_tools
