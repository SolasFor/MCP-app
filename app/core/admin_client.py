"""Loopback-only authenticated HTTP client for communicating with the local Admin REST API."""
from __future__ import annotations

import http.client
import json
import urllib.parse
from typing import Any

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class AdminBackendUnavailableError(RuntimeError):
    """Raised when the local MCP backend Admin API is stopped or unreachable."""


class AdminApiError(RuntimeError):
    """Raised when the local Admin API returns a non-connection HTTP error response."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class LocalAdminClient:
    """Strictly loopback-only REST client for GUI <-> backend Admin API control calls."""

    def __init__(self, *, port: int, token: str, host: str = "127.0.0.1") -> None:
        clean_host = (host or "127.0.0.1").strip().lower()
        if clean_host not in _LOOPBACK_HOSTS:
            raise ValueError(f"Admin API host must be loopback, got {host!r}")
        if int(port) <= 0 or int(port) > 65535:
            raise ValueError(f"Invalid Admin API port: {port!r}")
        if not (token or "").strip():
            raise ValueError("Admin API token must not be empty")
        self._host = clean_host
        self._port = int(port)
        self._token = token
        self._host_header = f"[{clean_host}]:{self._port}" if ":" in clean_host else f"{clean_host}:{self._port}"

    def _request_raw(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        timeout: float = 15.0,
    ) -> tuple[int, str]:
        headers: dict[str, str] = {
            "Host": self._host_header,
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Connection": "close",
        }
        payload: bytes | None = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        conn: http.client.HTTPConnection | None = None
        try:
            conn = http.client.HTTPConnection(
                self._host,
                self._port,
                timeout=max(0.5, float(timeout)),
            )
            conn.request(method.upper(), path, body=payload, headers=headers)
            resp = conn.getresponse()
            status = int(resp.status)
            text = resp.read().decode("utf-8", errors="replace")
        except (http.client.HTTPException, ConnectionError, TimeoutError, OSError) as exc:
            raise AdminBackendUnavailableError(f"Backend Admin API unreachable: {exc}") from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

        if status >= 400:
            msg = text
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and parsed.get("error"):
                    msg = str(parsed["error"])
            except json.JSONDecodeError:
                pass
            raise AdminApiError(status, msg or f"Admin API HTTP {status}")
        return status, text

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        _status, text = self._request_raw(method, path, body=body, timeout=timeout)
        parsed = json.loads(text) if text.strip() else {}
        if not isinstance(parsed, dict):
            raise AdminApiError(502, "Unexpected non-object response from Admin API")
        return parsed

    def get_monitoring(self, *, timeout: float = 5.0) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/monitoring", timeout=timeout)

    def list_schedules_and_history(self, *, timeout: float = 5.0) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        data = self._request_json("GET", "/api/v1/schedules", timeout=timeout)
        schedules = data.get("schedules")
        history = data.get("history")
        if not isinstance(schedules, list):
            schedules = []
        if not isinstance(history, list):
            hist_data = self._request_json("GET", "/api/v1/schedules/history", timeout=timeout)
            raw_runs = hist_data.get("runs")
            history = raw_runs if isinstance(raw_runs, list) else []
        return list(schedules), list(history)

    def upsert_schedule(self, spec_dict: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
        res = self._request_json("POST", "/api/v1/schedules", body=spec_dict, timeout=timeout)
        saved = res.get("schedule")
        return dict(saved) if isinstance(saved, dict) else res

    def delete_schedule(self, schedule_id: str, *, timeout: float = 5.0) -> bool:
        quoted = urllib.parse.quote(schedule_id, safe="")
        res = self._request_json("DELETE", f"/api/v1/schedules/{quoted}", timeout=timeout)
        return bool(res.get("removed", False))

    def set_schedule_enabled(self, schedule_id: str, enabled: bool, *, timeout: float = 5.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(schedule_id, safe="")
        res = self._request_json(
            "POST", f"/api/v1/schedules/{quoted}/enabled", body={"enabled": bool(enabled)}, timeout=timeout
        )
        updated = res.get("schedule")
        return dict(updated) if isinstance(updated, dict) else res

    def trigger_schedule(self, schedule_id: str, *, timeout: float = 130.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(schedule_id, safe="")
        return self._request_json("POST", f"/api/v1/schedules/{quoted}/run", body={}, timeout=timeout)

    def emit_event(
        self, event_name: str, payload: dict[str, Any] | None = None, *, timeout: float = 5.0
    ) -> list[dict[str, Any]]:
        res = self._request_json(
            "POST",
            "/api/v1/events",
            body={"event_name": event_name, "payload": payload or {}},
            timeout=timeout,
        )
        runs = res.get("runs")
        return list(runs) if isinstance(runs, list) else []

    def export_diagnostics(self, *, timeout: float = 5.0) -> str:
        _status, text = self._request_raw("GET", "/api/v1/diagnostics/export", timeout=timeout)
        return text

    def list_servers(self, *, timeout: float = 5.0) -> list[dict[str, Any]]:
        res = self._request_json("GET", "/api/v1/servers", timeout=timeout)
        items = res.get("servers")
        return list(items) if isinstance(items, list) else []

    def autostart_servers(self, *, timeout: float = 120.0) -> list[dict[str, Any]]:
        res = self._request_json("POST", "/api/v1/servers/autostart", body={}, timeout=timeout)
        items = res.get("servers")
        return list(items) if isinstance(items, list) else []

    def server_status(self, name: str, *, timeout: float = 5.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json("GET", f"/api/v1/servers/{quoted}/status", timeout=timeout)

    def start_server(
        self, name: str, *, workspace_id: str = "", wait_readiness: bool = True, timeout: float = 130.0
    ) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json(
            "POST",
            f"/api/v1/servers/{quoted}/start",
            body={"workspace_id": workspace_id, "wait_readiness": bool(wait_readiness)},
            timeout=timeout,
        )

    def stop_server(self, name: str, *, timeout: float = 30.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json("POST", f"/api/v1/servers/{quoted}/stop", body={}, timeout=timeout)

    def restart_server(
        self, name: str, *, workspace_id: str = "", wait_readiness: bool = True, timeout: float = 130.0
    ) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json(
            "POST",
            f"/api/v1/servers/{quoted}/restart",
            body={"workspace_id": workspace_id, "wait_readiness": bool(wait_readiness)},
            timeout=timeout,
        )

    def health_server(self, name: str, *, timeout: float = 30.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json("POST", f"/api/v1/servers/{quoted}/health", body={}, timeout=timeout)

    def server_logs(
        self, name: str, *, stream: str = "stdout", offset: int = 0, limit: int = 16000, timeout: float = 5.0
    ) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        q = urllib.parse.urlencode({"stream": stream, "offset": int(offset), "limit": int(limit)})
        return self._request_json("GET", f"/api/v1/servers/{quoted}/logs?{q}", timeout=timeout)

    def server_metrics(self, name: str, *, timeout: float = 5.0) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self._request_json("GET", f"/api/v1/servers/{quoted}/metrics", timeout=timeout)

    def run_workspace_task(self, workspace_id: str, command_name: str, *, timeout: float = 610.0) -> dict[str, Any]:
        q_wid = urllib.parse.quote(workspace_id, safe="")
        q_cmd = urllib.parse.quote(command_name, safe="")
        return self._request_json(
            "POST", f"/api/v1/workspaces/{q_wid}/tasks/{q_cmd}/run", body={}, timeout=timeout
        )
