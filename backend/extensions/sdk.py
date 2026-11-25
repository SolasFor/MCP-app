"""Lightweight out-of-process Python SDK (JSON-RPC 2.0 over stdio) for MCP-app Extensions.

Extensions run in a separate OS process spawned by MCP-app Core. Note: a separate
OS process isolates crashes and memory, NOT a security sandbox against malicious code
running as the same OS user.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from backend.extensions.models import SDK_API_VERSION


class ExtensionApp:
    """Minimal standalone SDK app serving JSON-RPC 2.0 requests over newline-delimited stdio."""

    def __init__(self, extension_id: str, version: str, *, api_version: str = SDK_API_VERSION) -> None:
        self.extension_id = extension_id
        self.version = version
        self.api_version = api_version
        self._tools: dict[str, tuple[Callable[..., Any], str, dict[str, Any]]] = {}
        self._ui_handler: Callable[[], dict[str, Any]] | None = None
        self._secrets: dict[str, str] = {}
        self.data_dir = Path(os.environ.get("MCP_EXTENSION_DATA_DIR") or ".").resolve()

    def tool(
        self,
        name: str | None = None,
        *,
        description: str = "",
        schema: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register an extension tool handler."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = (name or func.__name__).strip()
            self._tools[tool_name] = (func, description or (func.__doc__ or "").strip(), dict(schema or {}))
            return func

        return decorator

    def ui_provider(self) -> Callable[[Callable[[], dict[str, Any]]], Callable[[], dict[str, Any]]]:
        """Register a provider returning dynamic declarative UI state."""

        def decorator(func: Callable[[], dict[str, Any]]) -> Callable[[], dict[str, Any]]:
            self._ui_handler = func
            return func

        return decorator

    def secret(self, key: str, default: str = "") -> str:
        """Read a declared secret supplied via `initialize` IPC (never read core secrets)."""
        return self._secrets.get(key, default)

    def _handle_request(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            data_dir = params.get("data_dir")
            if isinstance(data_dir, str) and data_dir:
                self.data_dir = Path(data_dir)
                self.data_dir.mkdir(parents=True, exist_ok=True)
            raw_secrets = params.get("secrets")
            if isinstance(raw_secrets, dict):
                self._secrets = {str(k): str(v) for k, v in raw_secrets.items()}
            return {
                "extension_id": self.extension_id,
                "version": self.version,
                "api_version": self.api_version,
                "tools": sorted(self._tools),
            }
        if method == "health":
            return {"status": "ok", "extension_id": self.extension_id, "version": self.version}
        if method == "list_tools":
            return {
                "tools": [
                    {"name": k, "description": desc, "input_schema": schema}
                    for k, (_, desc, schema) in sorted(self._tools.items())
                ]
            }
        if method == "call_tool":
            tool_name = str(params.get("name") or "").strip()
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise ValueError("Tool arguments must be a JSON object")
            entry = self._tools.get(tool_name)
            if entry is None:
                raise KeyError(f"Unknown extension tool: {tool_name}")
            func = entry[0]
            return func(**arguments)
        if method == "ui.describe":
            if self._ui_handler is not None:
                return self._ui_handler()
            return {"status": "ok", "metrics": []}
        if method == "shutdown":
            return {"stopping": True}
        raise ValueError(f"Unsupported RPC method: {method!r}")

    def run_stdio(self) -> int:
        """Run blocking JSON-RPC 2.0 request/response loop over stdin/stdout."""
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            reconf = getattr(stream, "reconfigure", None)
            if callable(reconf):
                try:
                    reconf(encoding="utf-8")
                except Exception:  # noqa: BLE001
                    pass

        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            req_id: Any = None
            try:
                msg = json.loads(line)
                req_id = msg.get("id")
                method = str(msg.get("method") or "")
                params = msg.get("params") or {}
                if not isinstance(params, dict):
                    raise ValueError("RPC params must be an object")
                result = self._handle_request(method, params)
                reply = {"jsonrpc": "2.0", "id": req_id, "result": result}
                sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
                sys.stdout.flush()
                if method == "shutdown":
                    break
            except Exception as exc:  # noqa: BLE001
                err_reply = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": str(exc) or type(exc).__name__,
                        "type": type(exc).__name__,
                        "detail": traceback.format_exc(limit=3),
                    },
                }
                sys.stdout.write(json.dumps(err_reply, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        return 0
