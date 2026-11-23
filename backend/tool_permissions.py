"""Fixed OAuth tool capability: Windows commands and SSH only.

Each OAuth client can have an owner-selected profile overriding the global
default. Safe hides command/SSH tools; whitelist/full expose both.
There are no note/file tools and no network-accessible permission controls.
The exact command/host allowlists and one-use local action approval are
separate mandatory execution safety checks, never permissions to bypass.
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

EXEC_WINDOWS = "oauth_windows_command"
EXEC_SSH = "oauth_ssh_command"
EXEC_TOOLS = frozenset({EXEC_WINDOWS, EXEC_SSH})
BASIC_TOOLS = frozenset({"server_info"})
OAUTH_TOOLS = BASIC_TOOLS | EXEC_TOOLS
FORBIDDEN_TOOL = -32602


def allowed_tools(
    store: OAuthStore | None,
    principal: Any,
    execution: ExecutionApprovals | None = None,
) -> frozenset[str]:
    """An approved OAuth principal gets both capabilities; never cache approval."""
    if store is None or execution is None or principal is None:
        return BASIC_TOOLS
    client_id = getattr(principal, "client_id", None)
    scopes = getattr(principal, "scopes", None) or []
    if not isinstance(client_id, str) or "mcp:read" not in scopes:
        return BASIC_TOOLS
    if not execution.client_approved(client_id):
        return BASIC_TOOLS
    # Live read from SQLite on every tools/list and tools/call. Upgrading to
    # full mode never makes stale, unapproved bearer tokens privileged.
    return OAUTH_TOOLS if execution.profile_for(client_id) != "safe" else BASIC_TOOLS


def require_execution_permission(
    tool: str, store: OAuthStore | None,
    execution: ExecutionApprovals | None,
) -> str:
    principal = get_access_token()
    if tool not in EXEC_TOOLS or tool not in allowed_tools(store, principal, execution):
        raise PermissionError("OAuth client is not authorized to request execution")
    return principal.client_id


def make_tool_middleware(
    store: OAuthStore | None, execution: ExecutionApprovals | None = None,
):
    async def restrict_tools(ctx, call_next):
        if ctx.method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        allowed = allowed_tools(store, get_access_token(), execution)
        if ctx.method == "tools/call":
            params = ctx.params
            name = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
            if name in EXEC_TOOLS and name not in allowed:
                raise MCPError(code=FORBIDDEN_TOOL, message="Execution is not available to this OAuth client")
            return await call_next(ctx)
        result = await call_next(ctx)
        if isinstance(result, ListToolsResult):
            return result.model_copy(update={
                "tools": [tool for tool in result.tools if tool.name in allowed],
            })
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return {**result, "tools": [
                tool for tool in result["tools"]
                if (tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)) in allowed
            ]}
        # Avoid leaking unexpected SDK registry types.
        raise MCPError(code=-32603, message="Unrecognized tools/list response type")

    return restrict_tools
