"""MCP Gateway Router: namespace catalog, per-client permissions, session isolation, fault isolation."""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from mcp.types import CallToolResult, ImageContent, TextContent
from mcp.types import Tool as MCPTool

from app.core.redaction import SecretRedactor
from backend.gateway.models import (
    ISOLATION_PER_CLIENT,
    GatewayServerStatus,
    UpstreamServerProfile,
    UpstreamToolEntry,
)
from backend.gateway.security import make_namespaced_tool, sanitize_tool_description, validate_upstream_url
from backend.gateway.store import GatewayConfigStore
from backend.gateway.upstream_client import UpstreamSessionHandle, capability_names
from backend.oauth_execution import ExecutionApprovals

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}


class GatewayRouter:
    """Aggregates approved upstream MCP servers with fail-closed client isolation."""

    def __init__(
        self,
        store: GatewayConfigStore,
        *,
        instance_id: str | None = None,
        self_urls: tuple[str, ...] = (),
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.store = store
        self.instance_id = instance_id or f"mcp-gw-{uuid.uuid4().hex[:12]}"
        self._self_urls = self_urls
        self._redactor = redactor or SecretRedactor()
        for sec in self.store.collect_secret_values():
            self._redactor.register(sec)

        # (server_id, session_key) -> UpstreamSessionHandle
        self._handles: dict[tuple[str, str], UpstreamSessionHandle] = {}
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._catalog: dict[str, UpstreamToolEntry] = {}
        self._server_tools: dict[str, list[UpstreamToolEntry]] = {}
        self._statuses: dict[str, GatewayServerStatus] = {}
        self._dirty_servers: dict[str, str | None] = {}
        self._initialized = False
        self._init_lock = asyncio.Lock()

    def _mark_dirty(self, server_id: str, client_id: str | None = None) -> None:
        self._dirty_servers[server_id] = client_id

    async def sync_dirty(self) -> None:
        """Refresh catalogs for servers that emitted notifications/tools/list_changed."""
        if not self._dirty_servers:
            return
        dirty = sorted(self._dirty_servers.items())
        self._dirty_servers.clear()
        for sid, cid in dirty:
            if self.store.get(sid) is not None:
                await self.refresh_server(sid, client_id=cid or "__discovery__")

    async def ensure_initialized(self) -> None:
        """Lazily load and discover enabled approved upstream servers once."""
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            await self.refresh_all()

    def _session_key(self, profile: UpstreamServerProfile, client_id: str | None) -> str:
        if profile.session_isolation == ISOLATION_PER_CLIENT:
            return f"client:{client_id or 'anonymous'}"
        return "__shared__"

    def _get_lock(self, key: tuple[str, str]) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def _new_handle(self, profile: UpstreamServerProfile, client_id: str | None = None) -> UpstreamSessionHandle:
        env, headers = self.store.resolve_runtime_secrets(profile)
        for v in (*env.values(), *headers.values()):
            self._redactor.register(v)
        return UpstreamSessionHandle(
            profile,
            env=env,
            headers=headers,
            gateway_instance_id=self.instance_id,
            self_urls=self._self_urls,
            redactor=self._redactor,
            client_id=client_id,
            on_tools_changed=self._mark_dirty,
        )

    async def _get_or_connect(
        self,
        profile: UpstreamServerProfile,
        client_id: str | None,
    ) -> UpstreamSessionHandle:
        if not profile.approved_by_owner:
            raise PermissionError(f"Upstream server {profile.server_id!r} is not approved by owner.")
        if not profile.enabled:
            raise PermissionError(f"Upstream server {profile.server_id!r} is disabled.")
        if profile.transport != "stdio":
            validate_upstream_url(
                profile.url,
                allow_local_endpoint=profile.allow_local_endpoint,
                self_urls=self._self_urls,
            )

        skey = self._session_key(profile, client_id)
        hkey = (profile.server_id, skey)
        async with self._get_lock(hkey):
            handle = self._handles.get(hkey)
            if handle is not None and handle.session is not None:
                return handle
            handle = self._new_handle(profile, client_id)
            await handle.connect()
            self._handles[hkey] = handle
            return handle

    async def refresh_server(self, server_id: str, client_id: str | None = "__discovery__") -> GatewayServerStatus:
        """Connect/query one server with full fault isolation so one outage never affects others."""
        profile = self.store.get(server_id)
        if profile is None:
            raise KeyError(f"Unknown gateway server: {server_id!r}")
        if not profile.enabled or not profile.approved_by_owner:
            self._server_tools.pop(server_id, None)
            self._rebuild_catalog()
            status = GatewayServerStatus(
                server_id=profile.server_id,
                name=profile.name,
                transport=profile.transport,
                health="stopped",
                tool_count=0,
                last_error="" if profile.approved_by_owner else "Pending owner approval",
            )
            self._statuses[server_id] = status
            return status

        try:
            handle = await self._get_or_connect(profile, client_id)
            raw_tools = await handle.list_tools()
            taken = {
                name
                for name, entry in self._catalog.items()
                if entry.server_id != server_id
            }
            entries: list[UpstreamToolEntry] = []
            for tool in raw_tools:
                ns_name = make_namespaced_tool(server_id, tool.name, taken)
                taken.add(ns_name)
                entries.append(
                    UpstreamToolEntry(
                        namespaced_name=ns_name,
                        server_id=server_id,
                        raw_name=tool.name,
                        description=sanitize_tool_description(tool.description),
                        input_schema=dict(tool.input_schema or {"type": "object", "properties": {}}),
                    )
                )
            self._server_tools[server_id] = entries
            self._rebuild_catalog()
            status = GatewayServerStatus(
                server_id=profile.server_id,
                name=profile.name,
                transport=profile.transport,
                health="healthy",
                tool_count=len(entries),
                capabilities=capability_names(handle.capabilities),
                logs=handle.logs(),
            )
            self._statuses[server_id] = status
            return status
        except Exception as exc:
            msg = self._redactor.redact_text(f"{type(exc).__name__}: {exc}")
            status = GatewayServerStatus(
                server_id=profile.server_id,
                name=profile.name,
                transport=profile.transport,
                health="error",
                tool_count=len(self._server_tools.get(server_id, ())),
                last_error=msg,
            )
            self._statuses[server_id] = status
            return status

    async def refresh_all(self) -> list[GatewayServerStatus]:
        self._initialized = True
        self.store.load()
        profiles = self.store.list_profiles()
        active_ids = {p.server_id for p in profiles}
        for stale in list(self._server_tools):
            if stale not in active_ids:
                del self._server_tools[stale]
                self._statuses.pop(stale, None)
        statuses: list[GatewayServerStatus] = []
        for prof in profiles:
            statuses.append(await self.refresh_server(prof.server_id))
        return statuses

    def catalog_entries(self, server_id: str | None = None) -> list[UpstreamToolEntry]:
        """Return currently discovered upstream tool entries, optionally filtered by server."""
        entries = list(self._catalog.values())
        if server_id is not None:
            return [entry for entry in entries if entry.server_id == server_id]
        return entries

    async def disconnect_server(self, server_id: str) -> None:
        """Close all cached upstream sessions for a single server and drop its tools."""
        keys = [key for key in self._handles if key[0] == server_id]
        for key in keys:
            handle = self._handles.pop(key)
            await handle.close()
        self._server_tools.pop(server_id, None)
        self._rebuild_catalog()
        prof = self.store.get(server_id)
        if prof is not None:
            self._statuses[server_id] = GatewayServerStatus(
                server_id=prof.server_id,
                name=prof.name,
                transport=prof.transport,
                health="stopped",
                tool_count=0,
            )

    def _rebuild_catalog(self) -> None:
        merged: dict[str, UpstreamToolEntry] = {}
        for sid in sorted(self._server_tools):
            for entry in self._server_tools[sid]:
                merged[entry.namespaced_name] = entry
        self._catalog = merged

    def is_gateway_tool(self, namespaced_name: str) -> bool:
        return namespaced_name in self._catalog

    def _is_authorized(
        self,
        profile: UpstreamServerProfile,
        raw_tool_name: str,
        principal: Any,
        execution: ExecutionApprovals | None,
        *,
        namespaced_name: str = "",
    ) -> bool:
        if not profile.enabled or not profile.approved_by_owner:
            return False
        if execution is None or principal is None:
            return False
        if execution.emergency_stopped():
            return False
        client_id = getattr(principal, "client_id", None)
        scopes = getattr(principal, "scopes", None) or []
        if not isinstance(client_id, str) or "mcp:read" not in scopes:
            return False
        if not execution.client_approved(client_id):
            return False
        client_mode = execution.profile_for(client_id)
        if _PROFILE_RANK.get(client_mode, 0) < _PROFILE_RANK.get(profile.min_profile, 99):
            return False
        if profile.allowed_clients and client_id not in profile.allowed_clients:
            return False
        if raw_tool_name in profile.denied_tools:
            return False
        if profile.allowed_tools and raw_tool_name not in profile.allowed_tools:
            return False
        tool_pol = execution.client_tool_policy(client_id)
        denied = set(tool_pol.get("denied_tools", ()))
        only = set(tool_pol.get("allowed_tools_only", ()))
        if "*" in denied or raw_tool_name in denied or (namespaced_name and namespaced_name in denied):
            return False
        if only and raw_tool_name not in only and (not namespaced_name or namespaced_name not in only):
            return False
        return True

    def list_authorized_tools(
        self,
        principal: Any,
        execution: ExecutionApprovals | None,
    ) -> list[MCPTool]:
        visible: list[MCPTool] = []
        for entry in self._catalog.values():
            prof = self.store.get(entry.server_id)
            if prof is None:
                continue
            if self._is_authorized(
                prof, entry.raw_name, principal, execution, namespaced_name=entry.namespaced_name
            ):
                visible.append(
                    MCPTool(
                        name=entry.namespaced_name,
                        description=entry.description,
                        input_schema=entry.input_schema,
                    )
                )
        return visible

    def authorize_tool_call(
        self,
        namespaced_name: str,
        principal: Any,
        execution: ExecutionApprovals | None,
    ) -> UpstreamToolEntry:
        entry = self._catalog.get(namespaced_name)
        if entry is None:
            raise PermissionError(f"Unknown gateway tool: {namespaced_name!r}")
        prof = self.store.get(entry.server_id)
        if prof is None or not self._is_authorized(
            prof, entry.raw_name, principal, execution, namespaced_name=entry.namespaced_name
        ):
            raise PermissionError("OAuth client is not authorized for this upstream gateway tool.")
        return entry

    async def call_authorized_tool(
        self,
        namespaced_name: str,
        arguments: dict[str, Any] | None,
        principal: Any,
        execution: ExecutionApprovals | None,
    ) -> CallToolResult:
        entry = self.authorize_tool_call(namespaced_name, principal, execution)
        prof = self.store.get(entry.server_id)
        assert prof is not None
        client_id = str(getattr(principal, "client_id", ""))
        handle = await self._get_or_connect(prof, client_id)
        raw_res = await handle.call_tool(entry.raw_name, arguments)
        return self._sanitize_result(raw_res, prof.max_response_bytes)

    def _sanitize_result(self, result: CallToolResult, max_bytes: int) -> CallToolResult:
        total = 0
        blocks: list[Any] = []
        for block in result.content:
            if isinstance(block, TextContent):
                cleaned = self._redactor.redact_text(block.text)
                b_len = len(cleaned.encode("utf-8"))
                if total + b_len > max_bytes:
                    raise ValueError(f"Upstream response exceeded max_response_bytes ({max_bytes}).")
                total += b_len
                blocks.append(TextContent(type="text", text=cleaned))
            elif isinstance(block, ImageContent):
                b_len = len(block.data.encode("utf-8"))
                if total + b_len > max_bytes:
                    raise ValueError(f"Upstream image content exceeded max_response_bytes ({max_bytes}).")
                total += b_len
                blocks.append(block)
            else:
                b_len = len(str(block).encode("utf-8"))
                if total + b_len > max_bytes:
                    raise ValueError(f"Upstream content block exceeded max_response_bytes ({max_bytes}).")
                total += b_len
                blocks.append(block)
        structured = self._redact_value(result.structured_content) if result.structured_content is not None else None
        if structured is not None:
            s_len = len(json.dumps(structured, ensure_ascii=False).encode("utf-8"))
            if total + s_len > max_bytes:
                raise ValueError(f"Upstream structured content exceeded max_response_bytes ({max_bytes}).")
        return CallToolResult(
            content=blocks,
            structured_content=structured,
            is_error=result.is_error,
        )

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redactor.redact_text(value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._redact_value(item) for item in value]
        if isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        return value

    def status_snapshot(self) -> list[GatewayServerStatus]:
        return [
            self._statuses.get(
                p.server_id,
                GatewayServerStatus(
                    server_id=p.server_id,
                    name=p.name,
                    transport=p.transport,
                    health="stopped",
                    tool_count=len(self._server_tools.get(p.server_id, ())),
                ),
            )
            for p in self.store.list_profiles()
        ]

    async def close_all(self) -> None:
        handles = list(self._handles.values())
        self._handles.clear()
        for handle in handles:
            await handle.close()
