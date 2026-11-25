"""Real upstream MCP client sessions supporting stdio, Streamable HTTP, and legacy SSE."""
from __future__ import annotations

import asyncio
from collections import deque
from contextlib import AsyncExitStack
from typing import Any, Callable

import httpx2 as httpx
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import (
    CallToolResult,
    PaginatedRequestParams,
    ServerCapabilities,
    Tool,
    ToolListChangedNotification,
)

from app.core.redaction import SecretRedactor, sanitize_child_env
from backend.gateway.models import (
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
)
from backend.gateway.security import (
    GATEWAY_HOP_HEADER,
    GATEWAY_ID_HEADER,
    strip_downstream_auth_headers,
)


class UpstreamSessionHandle:
    """Maintains an isolated live MCP ClientSession for one upstream server (+ client context)."""

    def __init__(
        self,
        profile: UpstreamServerProfile,
        *,
        env: dict[str, str],
        headers: dict[str, str],
        gateway_instance_id: str,
        redactor: SecretRedactor | None = None,
        client_id: str | None = None,
        on_tools_changed: Callable[[str, str | None], None] | None = None,
    ) -> None:
        self.profile = profile
        self._env = dict(env)
        self._headers = dict(headers)
        self._instance_id = gateway_instance_id
        self._redactor = redactor or SecretRedactor()
        self._client_id = client_id
        self._on_tools_changed = on_tools_changed
        self._lifecycle_task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self.session: ClientSession | None = None
        self.capabilities: ServerCapabilities | None = None
        self.health = "stopped"
        self.last_error = ""
        self._logs: deque[str] = deque(maxlen=150)

    def _log(self, text: str) -> None:
        self._logs.append(self._redactor.redact_text(text))

    def logs(self) -> tuple[str, ...]:
        return tuple(self._logs)

    async def connect(self) -> ServerCapabilities | None:
        if self.session is not None:
            return self.capabilities
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[ServerCapabilities | None] = loop.create_future()
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._lifecycle_task = asyncio.create_task(
            self._run_lifecycle(ready, stop_event),
            name=f"gateway-{self.profile.server_id}",
        )
        try:
            return await asyncio.wait_for(
                ready,
                timeout=min(float(self.profile.timeout_seconds) + 2.0, 35.0),
            )
        except BaseException as exc:
            await self.close()
            if isinstance(exc, asyncio.CancelledError):
                raise ConnectionError(f"Upstream {self.profile.server_id} connection aborted") from exc
            raise

    async def _run_lifecycle(
        self,
        ready: asyncio.Future[ServerCapabilities | None],
        stop_event: asyncio.Event,
    ) -> None:
        """Own AsyncExitStack enter+exit inside a single asyncio Task for clean anyio cancel scopes."""
        stack = AsyncExitStack()
        try:
            if self.profile.transport == TRANSPORT_STDIO:
                child_env = sanitize_child_env(extra_env=self._env)
                params = StdioServerParameters(
                    command=self.profile.command,
                    args=list(self.profile.args),
                    env=child_env,
                    cwd=self.profile.cwd or None,
                )
                read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
            else:
                safe_headers = strip_downstream_auth_headers({})
                safe_headers.update(self._headers)
                safe_headers[GATEWAY_HOP_HEADER] = "1"
                existing_ids = safe_headers.get(GATEWAY_ID_HEADER, "")
                safe_headers[GATEWAY_ID_HEADER] = (
                    f"{existing_ids},{self._instance_id}" if existing_ids else self._instance_id
                )
                if self.profile.transport == TRANSPORT_STREAMABLE_HTTP:
                    http_client = await stack.enter_async_context(
                        httpx.AsyncClient(
                            headers=safe_headers,
                            follow_redirects=self.profile.allow_redirects,
                            timeout=httpx.Timeout(self.profile.timeout_seconds),
                        )
                    )
                    read_stream, write_stream = await stack.enter_async_context(
                        streamable_http_client(self.profile.url, http_client=http_client)
                    )
                elif self.profile.transport == TRANSPORT_SSE:
                    def _sse_http_factory(
                        headers: dict[str, str] | None = None,
                        timeout: httpx.Timeout | None = None,
                        auth: httpx.Auth | None = None,
                    ) -> httpx.AsyncClient:
                        kwargs: dict[str, Any] = {
                            "follow_redirects": self.profile.allow_redirects,
                            "timeout": timeout or httpx.Timeout(self.profile.timeout_seconds),
                        }
                        if headers is not None:
                            kwargs["headers"] = headers
                        if auth is not None:
                            kwargs["auth"] = auth
                        return httpx.AsyncClient(**kwargs)

                    read_stream, write_stream = await stack.enter_async_context(
                        sse_client(
                            self.profile.url,
                            headers=safe_headers,
                            timeout=min(self.profile.timeout_seconds, 15.0),
                            sse_read_timeout=max(self.profile.timeout_seconds, 60.0),
                            httpx_client_factory=_sse_http_factory,
                        )
                    )
                else:
                    raise ValueError(f"Unsupported transport: {self.profile.transport}")

            async def _on_message(message: Any) -> None:
                root = getattr(message, "root", message)
                if isinstance(root, ToolListChangedNotification) or (
                    getattr(root, "method", None) == "notifications/tools/list_changed"
                ):
                    self._log(f"Upstream {self.profile.server_id} emitted notifications/tools/list_changed")
                    if self._on_tools_changed is not None:
                        self._on_tools_changed(self.profile.server_id, self._client_id)

            session = await stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=float(self.profile.timeout_seconds),
                    message_handler=_on_message,
                )
            )
            init_result = await asyncio.wait_for(
                session.initialize(),
                timeout=min(self.profile.timeout_seconds, 30.0),
            )
            self.session = session
            self.capabilities = init_result.capabilities
            self.health = "healthy"
            self.last_error = ""
            self._log(f"Initialized upstream {self.profile.server_id} ({self.profile.transport})")
            if not ready.done():
                ready.set_result(self.capabilities)
            await stop_event.wait()
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError) and stop_event.is_set():
                raise
            err: Exception = (
                ConnectionError(f"Upstream {self.profile.server_id} transport aborted")
                if not isinstance(exc, Exception)
                else exc
            )
            self.health = "error"
            self.last_error = self._redactor.redact_text(f"{type(err).__name__}: {err}")
            self._log(f"Connect failed: {self.last_error}")
            if not ready.done():
                ready.set_exception(err)
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            self.session = None
            self.capabilities = None
            try:
                await stack.aclose()
            except BaseException:
                pass
            if not ready.done():
                ready.set_exception(
                    ConnectionError(f"Upstream {self.profile.server_id} exited before initialization")
                )

    async def list_tools(self) -> list[Tool]:
        if self.session is None:
            await self.connect()
        assert self.session is not None
        tools: list[Tool] = []
        cursor: str | None = None
        for _ in range(25):  # bounded pagination guard
            page_params = PaginatedRequestParams(cursor=cursor) if cursor else None
            res = await asyncio.wait_for(
                self.session.list_tools(params=page_params),
                timeout=self.profile.timeout_seconds,
            )
            tools.extend(res.tools)
            cursor = getattr(res, "next_cursor", None)
            if not cursor:
                break
        return tools

    async def call_tool(self, raw_name: str, arguments: dict[str, Any] | None) -> CallToolResult:
        """Execute a tool call with strict deadline and NO automatic retry on non-idempotent failures."""
        if self.session is None:
            await self.connect()
        assert self.session is not None
        try:
            result = await asyncio.wait_for(
                self.session.call_tool(raw_name, arguments or {}),
                timeout=self.profile.timeout_seconds,
            )
            self.health = "healthy"
            return result
        except Exception as exc:
            self.health = "degraded"
            self.last_error = self._redactor.redact_text(f"{type(exc).__name__}: {exc}")
            self._log(f"Tool call `{raw_name}` failed: {self.last_error}")
            await self.close()
            raise

    async def list_resources(self) -> list[Any]:
        if self.session is None:
            await self.connect()
        if self.capabilities is None or self.capabilities.resources is None:
            return []
        assert self.session is not None
        res = await asyncio.wait_for(self.session.list_resources(), timeout=self.profile.timeout_seconds)
        return list(res.resources)

    async def list_prompts(self) -> list[Any]:
        if self.session is None:
            await self.connect()
        if self.capabilities is None or self.capabilities.prompts is None:
            return []
        assert self.session is not None
        res = await asyncio.wait_for(self.session.list_prompts(), timeout=self.profile.timeout_seconds)
        return list(res.prompts)

    async def close(self) -> None:
        stop_event = self._stop_event
        task = self._lifecycle_task
        self._stop_event = None
        self._lifecycle_task = None
        self.session = None
        self.capabilities = None
        self.health = "stopped"
        if stop_event is not None:
            stop_event.set()
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except BaseException:
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=1.5)
                except BaseException:
                    pass


def capability_names(caps: ServerCapabilities | None) -> tuple[str, ...]:
    if caps is None:
        return ()
    out: list[str] = []
    if caps.tools is not None:
        out.append("tools")
    if caps.resources is not None:
        out.append("resources")
    if caps.prompts is not None:
        out.append("prompts")
    return tuple(out)
