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

try:
    from .oauth_store import OAuthStore
    from .oauth_execution import ExecutionApprovals
except ImportError:
    from oauth_store import OAuthStore
    from oauth_execution import ExecutionApprovals

NOTE_LIST = "shared_notes_list"
NOTE_READ = "shared_note_read"
NOTE_WRITE = "shared_note_write"
NOTES = frozenset({NOTE_LIST, NOTE_READ, NOTE_WRITE})
EXEC_WINDOWS = "oauth_windows_command"
EXEC_SSH = "oauth_ssh_command"
EXEC_TOOLS = frozenset({EXEC_WINDOWS, EXEC_SSH})
ALWAYS_VISIBLE = frozenset({"server_info"})
FORBIDDEN_TOOL = -32602


def allowed_tools(
    store: OAuthStore | None,
    principal: Any,
    execution: ExecutionApprovals | None = None,
) -> frozenset[str]:
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
    if execution is not None:
        can_windows, can_ssh = execution.grants(client_id)
        policy = execution.policy()
        if can_windows and policy["windows"]:
            allowed.add(EXEC_WINDOWS)
        if can_ssh and policy["hosts"] and policy["ssh_commands"]:
            allowed.add(EXEC_SSH)
    return frozenset(allowed)


def require_note_permission(name: str, store: OAuthStore | None) -> None:
    """Fail closed on missing identity, client approval, or stale permissions."""
    if name not in NOTES or name not in allowed_tools(store, get_access_token()):
        raise PermissionError("OAuth client does not have permission for this note tool")


def require_execution_permission(
    tool: str, store: OAuthStore | None,
    execution: ExecutionApprovals | None,
) -> str:
    principal = get_access_token()
    if tool not in EXEC_TOOLS or tool not in allowed_tools(store, principal, execution):
        raise PermissionError("OAuth client is not permitted to request remote execution")
    return principal.client_id


def make_tool_middleware(
    store: OAuthStore | None, execution: ExecutionApprovals | None = None,
):
    async def restrict_tools(ctx, call_next):
        method = ctx.method
        if method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        allowed = allowed_tools(store, get_access_token(), execution)
        if method == "tools/call":
            params = ctx.params
            name = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
            if name in NOTES | EXEC_TOOLS and name not in allowed:
                raise MCPError(code=FORBIDDEN_TOOL, message="This tool is not permitted for this client")
            return await call_next(ctx)
        result = await call_next(ctx)
        if isinstance(result, ListToolsResult):
            # Do not mutate cached SDK response instances in place.
            return result.model_copy(update={"tools": [t for t in result.tools if t.name in allowed]})
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            # SDK 2.x may return a raw mapping from a handler.
            return {**result, "tools": [
                tool for tool in result["tools"]
                if (tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)) in allowed
            ]}
        # Refuse to send an unfiltered catalog when the SDK changes its result
        # shape. Handler-level permission checks remain the independent gate.
        raise MCPError(code=-32603, message="Unrecognized tools/list response type")

    return restrict_tools
