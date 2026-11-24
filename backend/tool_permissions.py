"""OAuth tool capability: Windows, SSH and Full-only managed servers.

Delegates discovery and per-call authorization to `backend.tool_registry.ToolRegistry`.
Each OAuth client can have an owner-selected profile overriding the global default.
"""
from __future__ import annotations

from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.shared.exceptions import MCPError
from mcp.types import ListToolsResult

if __package__:
    from .oauth_execution import ExecutionApprovals
    from .oauth_store import OAuthStore
    from .tool_registry import (
        BASIC_TOOLS,
        DEFAULT_REGISTRY,
        EXEC_MANAGED,
        EXEC_SSH,
        EXEC_TOOLS,
        EXEC_WINDOWS,
        FULL_TOOLS,
        OAUTH_TOOLS,
        ToolRegistry,
    )
else:
    from oauth_execution import ExecutionApprovals
    from oauth_store import OAuthStore
    from tool_registry import (
        BASIC_TOOLS,
        DEFAULT_REGISTRY,
        EXEC_MANAGED,
        EXEC_SSH,
        EXEC_TOOLS,
        EXEC_WINDOWS,
        FULL_TOOLS,
        OAUTH_TOOLS,
        ToolRegistry,
    )

__all__ = [
    "BASIC_TOOLS",
    "DEFAULT_REGISTRY",
    "EXEC_MANAGED",
    "EXEC_SSH",
    "EXEC_TOOLS",
    "EXEC_WINDOWS",
    "FORBIDDEN_TOOL",
    "FULL_TOOLS",
    "OAUTH_TOOLS",
    "ToolRegistry",
    "allowed_tools",
    "make_tool_middleware",
    "require_execution_permission",
]

FORBIDDEN_TOOL = -32602


def allowed_tools(
    store: OAuthStore | None,
    principal: Any,
    execution: ExecutionApprovals | None = None,
    registry: ToolRegistry = DEFAULT_REGISTRY,
) -> frozenset[str]:
    """Return tools permitted for this OAuth principal; never caches approval."""
    return registry.allowed_tools(store, principal, execution)


def require_execution_permission(
    tool: str,
    store: OAuthStore | None,
    execution: ExecutionApprovals | None,
    registry: ToolRegistry = DEFAULT_REGISTRY,
) -> str:
    principal = get_access_token()
    if tool not in EXEC_TOOLS:
        raise PermissionError("OAuth client is not authorized to request execution")
    return registry.authorize_call(tool, store, principal, execution)


def make_tool_middleware(
    store: OAuthStore | None,
    execution: ExecutionApprovals | None = None,
    registry: ToolRegistry = DEFAULT_REGISTRY,
):
    async def restrict_tools(ctx, call_next):
        if ctx.method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        allowed = allowed_tools(store, get_access_token(), execution, registry)
        if ctx.method == "tools/call":
            params = ctx.params
            name = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
            if name in EXEC_TOOLS and name not in allowed:
                raise MCPError(
                    code=FORBIDDEN_TOOL, message="Execution is not available to this OAuth client"
                )
            return await call_next(ctx)
        result = await call_next(ctx)
        if isinstance(result, ListToolsResult):
            return result.model_copy(
                update={
                    "tools": [tool for tool in result.tools if tool.name in allowed],
                }
            )
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return {
                **result,
                "tools": [
                    tool
                    for tool in result["tools"]
                    if (tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None))
                    in allowed
                ],
            }
        raise MCPError(code=-32603, message="Unrecognized tools/list response type")

    return restrict_tools
