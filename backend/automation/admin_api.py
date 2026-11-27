"""Localhost-only authenticated admin REST API (monitoring, schedules, redacted diagnostics)."""
from __future__ import annotations

import asyncio
import hmac
import inspect
import json
from typing import Any, Callable
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_ALLOWED_CLIENT_IPS = frozenset({"127.0.0.1", "::1", "localhost"})
_TUNNEL_HEADERS = (
    "cf-ray",
    "cf-connecting-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "ngrok-trace-id",
    "tailscale-user-login",
)


def _extract_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("x-mcp-admin-token") or "").strip()


def _authorize_request(
    request: Request,
    admin_tokens: dict[str, frozenset[str]],
    required_scope: str,
) -> Response | None:
    host_hdr = (request.headers.get("host") or "").strip().lower()
    try:
        hostname = urlsplit(f"http://{host_hdr}").hostname or ""
    except ValueError:
        return JSONResponse({"error": "Invalid Host header"}, status_code=403)
    if hostname not in _ALLOWED_HOSTS:
        return JSONResponse({"error": "Admin API is strictly loopback-only"}, status_code=403)
    if any(hdr in request.headers for hdr in _TUNNEL_HEADERS):
        return JSONResponse({"error": "Forwarded/tunnel headers rejected on Admin API"}, status_code=403)
    if request.client and request.client.host not in _ALLOWED_CLIENT_IPS:
        return JSONResponse({"error": "Non-loopback client address rejected"}, status_code=403)

    presented = _extract_token(request)
    if not presented:
        return JSONResponse({"error": "Missing admin credentials"}, status_code=401)

    matched_scopes: frozenset[str] | None = None
    presented_b = presented.encode("utf-8")
    for expected_tok, scopes in admin_tokens.items():
        if expected_tok and hmac.compare_digest(presented_b, expected_tok.encode("utf-8")):
            matched_scopes = scopes
            break
    if matched_scopes is None:
        return JSONResponse({"error": "Invalid admin credentials"}, status_code=401)
    if required_scope not in matched_scopes:
        return JSONResponse({"error": f"Insufficient admin scope (requires {required_scope})"}, status_code=403)
    return None


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _read_json_object(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw.strip():
        return {}
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Request JSON body must be an object")
    return parsed


class _AdminEndpoints:
    """Endpoint methods extracted from factory closure to keep handler complexity low."""

    def __init__(
        self,
        *,
        admin_tokens: dict[str, frozenset[str]],
        snapshot_provider: Callable[[], dict[str, Any]],
        scheduler_list_provider: Callable[[], list[dict[str, Any]]],
        scheduler_trigger_fn: Callable[[str], Any],
        diagnostics_export_fn: Callable[[], str],
        scheduler_history_provider: Callable[[], list[dict[str, Any]]] | None,
        scheduler_upsert_fn: Callable[[dict[str, Any]], dict[str, Any]] | None,
        scheduler_delete_fn: Callable[[str], bool] | None,
        scheduler_enable_fn: Callable[[str, bool], dict[str, Any]] | None,
        scheduler_event_fn: Callable[[str, dict[str, Any]], Any] | None,
        server_list_provider: Callable[[], list[dict[str, Any]]] | None = None,
        server_status_fn: Callable[[str], dict[str, Any]] | None = None,
        server_start_fn: Callable[[str, str, bool], dict[str, Any]] | None = None,
        server_stop_fn: Callable[[str], dict[str, Any]] | None = None,
        server_restart_fn: Callable[[str, str, bool], dict[str, Any]] | None = None,
        server_health_fn: Callable[[str], dict[str, Any]] | None = None,
        server_logs_fn: Callable[[str, str, int, int], dict[str, Any]] | None = None,
        server_metrics_fn: Callable[[str], dict[str, Any]] | None = None,
        server_autostart_fn: Callable[[], list[dict[str, Any]]] | None = None,
        workspace_run_task_fn: Callable[[str, str], Any] | None = None,
    ) -> None:
        self._tokens = admin_tokens
        self._snapshot = snapshot_provider
        self._list = scheduler_list_provider
        self._trigger = scheduler_trigger_fn
        self._diag = diagnostics_export_fn
        self._history = scheduler_history_provider
        self._upsert = scheduler_upsert_fn
        self._delete = scheduler_delete_fn
        self._enable = scheduler_enable_fn
        self._event = scheduler_event_fn
        self._srv_list = server_list_provider
        self._srv_status = server_status_fn
        self._srv_start = server_start_fn
        self._srv_stop = server_stop_fn
        self._srv_restart = server_restart_fn
        self._srv_health = server_health_fn
        self._srv_logs = server_logs_fn
        self._srv_metrics = server_metrics_fn
        self._srv_autostart = server_autostart_fn
        self._ws_run_task = workspace_run_task_fn

    def _deny(self, request: Request, scope: str) -> Response | None:
        return _authorize_request(request, self._tokens, scope)

    async def get_monitoring(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        return denied if denied is not None else JSONResponse(self._snapshot())

    async def get_schedules(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        payload: dict[str, Any] = {"schedules": self._list()}
        if self._history is not None:
            payload["history"] = self._history()
        return JSONResponse(payload)

    async def get_schedule_history(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        runs = self._history() if self._history is not None else []
        return JSONResponse({"runs": runs})

    async def upsert_schedule(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._upsert is None:
            return JSONResponse({"error": "Schedule mutation not configured"}, status_code=501)
        try:
            body = await _read_json_object(request)
            saved = await _maybe_await(self._upsert(body))
            return JSONResponse({"schedule": saved})
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except (ValueError, json.JSONDecodeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def delete_schedule(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._delete is None:
            return JSONResponse({"error": "Schedule deletion not configured"}, status_code=501)
        sid = request.path_params["schedule_id"]
        try:
            removed = await _maybe_await(self._delete(sid))
            return JSONResponse({"removed": bool(removed)})
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)

    async def set_schedule_enabled(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._enable is None:
            return JSONResponse({"error": "Schedule enable toggle not configured"}, status_code=501)
        sid = request.path_params["schedule_id"]
        try:
            body = await _read_json_object(request)
            updated = await _maybe_await(self._enable(sid, bool(body.get("enabled", True))))
            return JSONResponse({"schedule": updated})
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except (ValueError, json.JSONDecodeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def trigger_schedule(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        sid = request.path_params["schedule_id"]
        try:
            res = await _maybe_await(self._trigger(sid))
            return JSONResponse(res)
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)

    async def dispatch_event(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._event is None:
            return JSONResponse({"error": "Event dispatch not configured"}, status_code=501)
        try:
            body = await _read_json_object(request)
            event_name = str(body.get("event_name") or "").strip()
            if not event_name:
                return JSONResponse({"error": "event_name is required"}, status_code=400)
            payload = body.get("payload")
            if payload is not None and not isinstance(payload, dict):
                return JSONResponse({"error": "payload must be a JSON object"}, status_code=400)
            runs = await _maybe_await(self._event(event_name, payload or {}))
            return JSONResponse({"runs": list(runs or ())})
        except (ValueError, json.JSONDecodeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def export_diagnostics(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        return Response(content=self._diag(), media_type="application/json")

    @staticmethod
    def _error_response(exc: BaseException) -> Response:
        if isinstance(exc, PermissionError):
            return JSONResponse({"error": str(exc)}, status_code=403)
        if isinstance(exc, KeyError):
            return JSONResponse({"error": str(exc)}, status_code=404)
        if isinstance(exc, ValueError):
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse({"error": str(exc)}, status_code=500)

    async def list_servers(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        if self._srv_list is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            items = await asyncio.to_thread(self._srv_list)
            return JSONResponse({"servers": list(items)})
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def autostart_servers(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._srv_autostart is None:
            return JSONResponse({"error": "Server autostart not configured"}, status_code=501)
        try:
            items = await asyncio.to_thread(self._srv_autostart)
            return JSONResponse({"servers": list(items)})
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_status(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        if self._srv_status is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            res = await asyncio.to_thread(self._srv_status, request.path_params["server_name"])
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_start(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._srv_start is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            body = await _read_json_object(request)
            res = await asyncio.to_thread(
                self._srv_start,
                request.path_params["server_name"],
                str(body.get("workspace_id") or ""),
                bool(body.get("wait_readiness", True)),
            )
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_stop(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._srv_stop is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            res = await asyncio.to_thread(self._srv_stop, request.path_params["server_name"])
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_restart(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._srv_restart is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            body = await _read_json_object(request)
            res = await asyncio.to_thread(
                self._srv_restart,
                request.path_params["server_name"],
                str(body.get("workspace_id") or ""),
                bool(body.get("wait_readiness", True)),
            )
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_health(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._srv_health is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            res = await asyncio.to_thread(self._srv_health, request.path_params["server_name"])
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_logs(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        if self._srv_logs is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            stream = "stderr" if request.query_params.get("stream") == "stderr" else "stdout"
            offset = int(request.query_params.get("offset", "0") or "0")
            limit = int(request.query_params.get("limit", "16000") or "16000")
            res = await asyncio.to_thread(
                self._srv_logs,
                request.path_params["server_name"],
                stream,
                offset,
                limit,
            )
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def server_metrics(self, request: Request) -> Response:
        denied = self._deny(request, "admin:read")
        if denied is not None:
            return denied
        if self._srv_metrics is None:
            return JSONResponse({"error": "Server runtime not configured"}, status_code=501)
        try:
            res = await asyncio.to_thread(self._srv_metrics, request.path_params["server_name"])
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)

    async def run_workspace_task(self, request: Request) -> Response:
        denied = self._deny(request, "admin:write")
        if denied is not None:
            return denied
        if self._ws_run_task is None:
            return JSONResponse({"error": "Workspace task runner not configured"}, status_code=501)
        try:
            wid = request.path_params["workspace_id"]
            cname = request.path_params["command_name"]
            res = await _maybe_await(self._ws_run_task(wid, cname))
            return JSONResponse(res)
        except Exception as exc:  # noqa: BLE001
            return self._error_response(exc)


def build_admin_app(
    *,
    admin_tokens: dict[str, frozenset[str]],
    snapshot_provider: Callable[[], dict[str, Any]],
    scheduler_list_provider: Callable[[], list[dict[str, Any]]],
    scheduler_trigger_fn: Callable[[str], Any],
    diagnostics_export_fn: Callable[[], str],
    scheduler_history_provider: Callable[[], list[dict[str, Any]]] | None = None,
    scheduler_upsert_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    scheduler_delete_fn: Callable[[str], bool] | None = None,
    scheduler_enable_fn: Callable[[str, bool], dict[str, Any]] | None = None,
    scheduler_event_fn: Callable[[str, dict[str, Any]], Any] | None = None,
    server_list_provider: Callable[[], list[dict[str, Any]]] | None = None,
    server_status_fn: Callable[[str], dict[str, Any]] | None = None,
    server_start_fn: Callable[[str, str, bool], dict[str, Any]] | None = None,
    server_stop_fn: Callable[[str], dict[str, Any]] | None = None,
    server_restart_fn: Callable[[str, str, bool], dict[str, Any]] | None = None,
    server_health_fn: Callable[[str], dict[str, Any]] | None = None,
    server_logs_fn: Callable[[str, str, int, int], dict[str, Any]] | None = None,
    server_metrics_fn: Callable[[str], dict[str, Any]] | None = None,
    server_autostart_fn: Callable[[], list[dict[str, Any]]] | None = None,
    workspace_run_task_fn: Callable[[str, str], Any] | None = None,
) -> Starlette:
    """Create Starlette app enforcing loopback Host, no tunnel headers, and scoped bearer auth."""
    ep = _AdminEndpoints(
        admin_tokens=admin_tokens,
        snapshot_provider=snapshot_provider,
        scheduler_list_provider=scheduler_list_provider,
        scheduler_trigger_fn=scheduler_trigger_fn,
        diagnostics_export_fn=diagnostics_export_fn,
        scheduler_history_provider=scheduler_history_provider,
        scheduler_upsert_fn=scheduler_upsert_fn,
        scheduler_delete_fn=scheduler_delete_fn,
        scheduler_enable_fn=scheduler_enable_fn,
        scheduler_event_fn=scheduler_event_fn,
        server_list_provider=server_list_provider,
        server_status_fn=server_status_fn,
        server_start_fn=server_start_fn,
        server_stop_fn=server_stop_fn,
        server_restart_fn=server_restart_fn,
        server_health_fn=server_health_fn,
        server_logs_fn=server_logs_fn,
        server_metrics_fn=server_metrics_fn,
        server_autostart_fn=server_autostart_fn,
        workspace_run_task_fn=workspace_run_task_fn,
    )
    routes = [
        Route("/api/v1/monitoring", ep.get_monitoring, methods=["GET"]),
        Route("/api/v1/schedules", ep.get_schedules, methods=["GET"]),
        Route("/api/v1/schedules", ep.upsert_schedule, methods=["POST"]),
        Route("/api/v1/schedules/history", ep.get_schedule_history, methods=["GET"]),
        Route("/api/v1/schedules/{schedule_id}", ep.delete_schedule, methods=["DELETE"]),
        Route("/api/v1/schedules/{schedule_id}/enabled", ep.set_schedule_enabled, methods=["POST"]),
        Route("/api/v1/schedules/{schedule_id}/run", ep.trigger_schedule, methods=["POST"]),
        Route("/api/v1/events", ep.dispatch_event, methods=["POST"]),
        Route("/api/v1/diagnostics/export", ep.export_diagnostics, methods=["GET"]),
        Route("/api/v1/servers", ep.list_servers, methods=["GET"]),
        Route("/api/v1/servers/autostart", ep.autostart_servers, methods=["POST"]),
        Route("/api/v1/servers/{server_name}/status", ep.server_status, methods=["GET"]),
        Route("/api/v1/servers/{server_name}/start", ep.server_start, methods=["POST"]),
        Route("/api/v1/servers/{server_name}/stop", ep.server_stop, methods=["POST"]),
        Route("/api/v1/servers/{server_name}/restart", ep.server_restart, methods=["POST"]),
        Route("/api/v1/servers/{server_name}/health", ep.server_health, methods=["POST"]),
        Route("/api/v1/servers/{server_name}/logs", ep.server_logs, methods=["GET"]),
        Route("/api/v1/servers/{server_name}/metrics", ep.server_metrics, methods=["GET"]),
        Route("/api/v1/workspaces/{workspace_id}/tasks/{command_name}/run", ep.run_workspace_task, methods=["POST"]),
    ]
    return Starlette(routes=routes)
