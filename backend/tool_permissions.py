"""OAuth tool capability: Windows, SSH and Full-only managed servers.

Delegates discovery and per-call authorization to `backend.tool_registry.ToolRegistry`.
Each OAuth client can have an owner-selected profile overriding the global default.
"""
from __future__ import annotations

import time
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.shared.exceptions import MCPError
from mcp.types import ListToolsResult

if __package__:
    from .oauth_execution import ExecutionApprovals
    from .oauth_store import OAuthStore
    from .tool_registry import (
        ALL_REGISTERED_OAUTH_TOOLS,
        BASIC_TOOLS,
        DEFAULT_REGISTRY,
        DESKTOP_CONTROL_TOOLS,
        DESKTOP_TOOLS,
        DESKTOP_VIEW_TOOLS,
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
        ALL_REGISTERED_OAUTH_TOOLS,
        BASIC_TOOLS,
        DEFAULT_REGISTRY,
        DESKTOP_CONTROL_TOOLS,
        DESKTOP_TOOLS,
        DESKTOP_VIEW_TOOLS,
        EXEC_MANAGED,
        EXEC_SSH,
        EXEC_TOOLS,
        EXEC_WINDOWS,
        FULL_TOOLS,
        OAUTH_TOOLS,
        ToolRegistry,
    )

__all__ = [
    "ALL_REGISTERED_OAUTH_TOOLS",
    "BASIC_TOOLS",
    "DEFAULT_REGISTRY",
    "DESKTOP_CONTROL_TOOLS",
    "DESKTOP_TOOLS",
    "DESKTOP_VIEW_TOOLS",
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
    *,
    desktop_policy_store: Any = None,
) -> frozenset[str]:
    """Return tools permitted for this OAuth principal; never caches approval."""
    return registry.allowed_tools(
        store, principal, execution, desktop_policy_store=desktop_policy_store
    )


def require_execution_permission(
    tool: str,
    store: OAuthStore | None,
    execution: ExecutionApprovals | None,
    registry: ToolRegistry = DEFAULT_REGISTRY,
    *,
    desktop_policy_store: Any = None,
) -> str:
    principal = get_access_token()
    if tool not in EXEC_TOOLS:
        raise PermissionError("OAuth client is not authorized to request execution")
    return registry.authorize_call(
        tool, store, principal, execution, desktop_policy_store=desktop_policy_store
    )


def make_tool_middleware(
    store: OAuthStore | None,
    execution: ExecutionApprovals | None = None,
    registry: ToolRegistry = DEFAULT_REGISTRY,
    gateway_router: Any = None,
    metrics_registry: Any = None,
    desktop_policy_store: Any = None,
    session_tracker: Any = None,
):
    async def restrict_tools(ctx, call_next):
        if ctx.method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        principal = get_access_token()
        allowed = allowed_tools(
            store, principal, execution, registry, desktop_policy_store=desktop_policy_store
        )
        if session_tracker is not None and getattr(ctx, "session", None) is not None:
            gw_names: frozenset[str] = frozenset()
            if gateway_router is not None:
                try:
                    gw_names = frozenset(
                        t.name for t in gateway_router.list_authorized_tools(principal, execution)
                    )
                except Exception:  # noqa: BLE001
                    gw_names = frozenset()
            session_tracker.observe(ctx.session, principal, allowed | gw_names)
        if ctx.method == "tools/call":
            params = ctx.params
            name = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
            t0 = time.monotonic()
            try:
                if isinstance(name, str) and name in registry.registered_names() and name not in allowed:
                    raise MCPError(
                        code=FORBIDDEN_TOOL,
                        message=(
                            f"Execution of '{name}' is not available to this OAuth client "
                            "(check client access scenario, Computer Use opt-in, or tool restrictions)."
                        ),
                    )
                if gateway_router is not None and isinstance(name, str):
                    await gateway_router.ensure_initialized()
                    await gateway_router.sync_dirty()
                    if gateway_router.is_gateway_tool(name):
                        arguments = (
                            params.get("arguments")
                            if isinstance(params, dict)
                            else getattr(params, "arguments", None)
                        )
                        try:
                            res = await gateway_router.call_authorized_tool(
                                name, arguments, principal, execution
                            )
                        except PermissionError as exc:
                            raise MCPError(code=FORBIDDEN_TOOL, message=str(exc)) from exc
                        except Exception as exc:
                            raise MCPError(code=-32603, message=f"Gateway tool call failed: {exc}") from exc
                        if metrics_registry is not None:
                            is_err = (
                                bool(getattr(res, "isError", False))
                                or bool(getattr(res, "is_error", False))
                                or (isinstance(res, dict) and bool(res.get("isError")))
                            )
                            metrics_registry.record_call(name, (time.monotonic() - t0) * 1000.0, error=is_err)
                        return res
                res = await call_next(ctx)
            except Exception:
                if metrics_registry is not None:
                    metrics_registry.record_call(
                        str(name or "unknown"), (time.monotonic() - t0) * 1000.0, error=True
                    )
                raise
            if metrics_registry is not None:
                is_err = (
                    bool(getattr(res, "isError", False))
                    or bool(getattr(res, "is_error", False))
                    or (isinstance(res, dict) and bool(res.get("isError")))
                )
                metrics_registry.record_call(
                    str(name or "unknown"), (time.monotonic() - t0) * 1000.0, error=is_err
                )
            return res
        result = await call_next(ctx)
        extra_tools = []
        if gateway_router is not None:
            await gateway_router.ensure_initialized()
            await gateway_router.sync_dirty()
            extra_tools = gateway_router.list_authorized_tools(principal, execution)
        if isinstance(result, ListToolsResult):
            filtered = [tool for tool in result.tools if tool.name in allowed]
            return result.model_copy(
                update={
                    "tools": [*filtered, *extra_tools],
                }
            )
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            filtered = [
                tool
                for tool in result["tools"]
                if (tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None))
                in allowed
            ]
            return {
                **result,
                "tools": [*filtered, *extra_tools],
            }
        raise MCPError(code=-32603, message="Unrecognized tools/list response type")

    return restrict_tools
