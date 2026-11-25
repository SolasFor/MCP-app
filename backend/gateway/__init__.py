"""Universal MCP Gateway supporting stdio, Streamable HTTP, and optional legacy SSE."""
from __future__ import annotations

__all__ = [
    "AUTH_BEARER",
    "AUTH_HEADERS",
    "AUTH_NONE",
    "GatewayConfigStore",
    "GatewayRouter",
    "GatewayServerStatus",
    "ISOLATION_PER_CLIENT",
    "ISOLATION_SHARED",
    "ImportPreviewItem",
    "TRANSPORT_SSE",
    "TRANSPORT_STDIO",
    "TRANSPORT_STREAMABLE_HTTP",
    "UpstreamServerProfile",
    "UpstreamSessionHandle",
    "UpstreamToolEntry",
    "solidworks_mcp_template",
]

from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_HEADERS,
    AUTH_NONE,
    ISOLATION_PER_CLIENT,
    ISOLATION_SHARED,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    GatewayServerStatus,
    ImportPreviewItem,
    UpstreamServerProfile,
    UpstreamToolEntry,
)
from backend.gateway.router import GatewayRouter
from backend.gateway.store import GatewayConfigStore, solidworks_mcp_template
from backend.gateway.upstream_client import UpstreamSessionHandle
