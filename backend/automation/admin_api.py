"""Localhost-only authenticated admin REST API (monitoring, schedules, redacted diagnostics)."""
from __future__ import annotations

import hmac
from typing import Any, Callable
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
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


def build_admin_app(
    *,
    admin_tokens: dict[str, frozenset[str]],
    snapshot_provider: Callable[[], dict[str, Any]],
    scheduler_list_provider: Callable[[], list[dict[str, Any]]],
    scheduler_trigger_fn: Callable[[str], dict[str, Any]],
    diagnostics_export_fn: Callable[[], str],
) -> Starlette:
    """Create Starlette app enforcing loopback Host, no tunnel headers, and scoped bearer auth."""

    def _authorize(request: Request, required_scope: str) -> Response | None:
        host_hdr = (request.headers.get("host") or "").strip().lower()
        try:
            hostname = urlsplit(f"http://{host_hdr}").hostname or ""
        except ValueError:
            return JSONResponse({"error": "Invalid Host header"}, status_code=403)
        if hostname not in _ALLOWED_HOSTS:
            return JSONResponse({"error": "Admin API is strictly loopback-only"}, status_code=403)
        for hdr in _TUNNEL_HEADERS:
            if hdr in request.headers:
                return JSONResponse({"error": "Forwarded/tunnel headers rejected on Admin API"}, status_code=403)
        if request.client and request.client.host not in ("127.0.0.1", "::1", "localhost"):
            return JSONResponse({"error": "Non-loopback client address rejected"}, status_code=403)

        presented = _extract_token(request)
        if not presented:
            return JSONResponse({"error": "Missing admin credentials"}, status_code=401)

        matched_scopes: frozenset[str] | None = None
        for expected_tok, scopes in admin_tokens.items():
            if expected_tok and hmac.compare_digest(presented.encode("utf-8"), expected_tok.encode("utf-8")):
                matched_scopes = scopes
                break
        if matched_scopes is None:
            return JSONResponse({"error": "Invalid admin credentials"}, status_code=401)
        if required_scope not in matched_scopes:
            return JSONResponse({"error": f"Insufficient admin scope (requires {required_scope})"}, status_code=403)
        return None

    async def get_monitoring(request: Request) -> Response:
        denied = _authorize(request, "admin:read")
        if denied is not None:
            return denied
        return JSONResponse(snapshot_provider())

    async def get_schedules(request: Request) -> Response:
        denied = _authorize(request, "admin:read")
        if denied is not None:
            return denied
        return JSONResponse({"schedules": scheduler_list_provider()})

    async def trigger_schedule(request: Request) -> Response:
        denied = _authorize(request, "admin:write")
        if denied is not None:
            return denied
        sid = request.path_params["schedule_id"]
        try:
            return JSONResponse(scheduler_trigger_fn(sid))
        except KeyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)

    async def export_diagnostics(request: Request) -> Response:
        denied = _authorize(request, "admin:read")
        if denied is not None:
            return denied
        return Response(content=diagnostics_export_fn(), media_type="application/json")

    routes = [
        Route("/api/v1/monitoring", get_monitoring, methods=["GET"]),
        Route("/api/v1/schedules", get_schedules, methods=["GET"]),
        Route("/api/v1/schedules/{schedule_id}/run", trigger_schedule, methods=["POST"]),
        Route("/api/v1/diagnostics/export", export_diagnostics, methods=["GET"]),
    ]
    return Starlette(routes=routes)
