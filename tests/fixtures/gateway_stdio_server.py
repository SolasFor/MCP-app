"""Minimal real stdio MCP server fixture for Stage 4 MCP Gateway integration tests."""
from __future__ import annotations

import os

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import CallToolResult, ImageContent, TextContent

PNG_1PX_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)

mcp = MCPServer("gateway-stdio-fixture")


@mcp.tool()
def echo_text(text: str) -> str:
    """Echo input text safely without leaking environment secrets."""
    has_secret = "yes" if os.environ.get("TEST_GATEWAY_SECRET") else "no"
    return f"stdio:{text}|has_secret={has_secret}"


@mcp.tool()
def leak_secret() -> CallToolResult:
    """Deliberately echo TEST_GATEWAY_SECRET to verify Gateway redaction across text and structured outputs."""
    sec = os.environ.get("TEST_GATEWAY_SECRET", "")
    return CallToolResult(
        content=[TextContent(type="text", text=f"raw-text:{sec}")],
        structured_content={"secret_copy": sec, "nested": [sec]},
        is_error=False,
    )


@mcp.tool()
def render_preview(label: str) -> CallToolResult:
    """Return multimodal TextContent + ImageContent + structured_content."""
    return CallToolResult(
        content=[
            TextContent(type="text", text=f"Preview ready: {label}"),
            ImageContent(type="image", data=PNG_1PX_B64, mime_type="image/png"),
        ],
        structured_content={"label": label, "format": "png", "width": 1, "height": 1},
        is_error=False,
    )


@mcp.tool()
def collide() -> str:
    """Intentional tool name collision across upstream servers."""
    return f"from_stdio_pid={os.getpid()}"


@mcp.tool()
def denied_tool() -> str:
    """Tool that gateway per-server denied_tools must block."""
    return "should_never_execute"


@mcp.tool()
def large_payload() -> str:
    """Returns > 2048 bytes to test max_response_bytes caps."""
    return "A" * 4096


@mcp.tool()
async def unlock_dynamic_tool(ctx: Context) -> str:
    """Dynamically registers `dynamic_ping` and emits notifications/tools/list_changed."""

    @mcp.tool()
    def dynamic_ping() -> str:
        return "dynamic_pong"

    await ctx.session.send_tool_list_changed()
    return "unlocked"


if __name__ == "__main__":
    mcp.run(transport="stdio")
