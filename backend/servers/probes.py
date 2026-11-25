"""Port conflict checks, TCP/HTTP readiness probes, and identity-verified process metrics."""
from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

import psutil

from app.platform import ProcessIdentity, get_platform
from backend.servers.models import ReadinessConfig


def _probe_host(host: str) -> str:
    clean = (host or "127.0.0.1").strip()
    if clean in ("0.0.0.0", ""):
        return "127.0.0.1"
    if clean == "::":
        return "::1"
    return clean


def _hosts_conflict(requested: str, listening_ip: str) -> bool:
    req = requested.strip().lower()
    lst = (listening_ip or "").strip().lower()
    if req in ("0.0.0.0", "::", "*") or lst in ("0.0.0.0", "::", "*"):
        return True
    if req in ("127.0.0.1", "localhost") and lst in ("127.0.0.1", "::1"):
        return True
    return req == lst


def check_port_conflict(
    host: str,
    port: int | None,
    *,
    owned_pids: Iterable[int] = (),
) -> dict[str, Any] | None:
    """Detect whether another process is already listening on `(host, port)`.

    Read-only: NEVER kills or modifies foreign processes.
    """
    if port is None:
        return None
    target_port = int(port)
    owned = {int(p) for p in owned_pids if isinstance(p, int) and p > 0}
    target_host = _probe_host(host)

    try:
        for conn in psutil.net_connections(kind="inet"):
            if (
                conn.status == psutil.CONN_LISTEN
                and conn.laddr
                and getattr(conn.laddr, "port", None) == target_port
            ):
                if conn.pid in owned:
                    return None
                listen_ip = str(getattr(conn.laddr, "ip", "") or "")
                if _hosts_conflict(target_host, listen_ip):
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except psutil.Error:
                            proc_name = ""
                    label = f"{proc_name} (PID {conn.pid})" if proc_name and conn.pid else (
                        f"PID {conn.pid}" if conn.pid else "foreign listener"
                    )
                    return {
                        "host": target_host,
                        "port": target_port,
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "detail": f"Port {target_host}:{target_port} is already in use by {label}",
                    }
    except psutil.Error:
        pass

    # Fallback active connect probe for platforms/containers restricting net_connections
    try:
        with socket.create_connection((target_host, target_port), timeout=0.2):
            return {
                "host": target_host,
                "port": target_port,
                "pid": None,
                "process_name": "",
                "detail": f"Port {target_host}:{target_port} is already accepting connections",
            }
    except OSError:
        return None


def probe_readiness(
    config: ReadinessConfig,
    *,
    default_host: str = "127.0.0.1",
    default_port: int | None = None,
) -> tuple[bool, str]:
    """Run one synchronous TCP or HTTP readiness probe without using system proxies."""
    kind = config.kind
    if kind == "none":
        return True, "No readiness probe configured"

    host = _probe_host(config.host or default_host)
    port = config.port if config.port is not None else default_port
    if port is None:
        return False, "Readiness probe port is missing"

    timeout = float(config.request_timeout_seconds)
    if kind == "tcp":
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True, f"TCP {host}:{port} reachable"
        except OSError as exc:
            return False, f"TCP {host}:{port} failed: {type(exc).__name__}"

    if kind == "http":
        url = f"http://{host}:{int(port)}{config.http_path}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(url, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = int(resp.status)
                if status in config.expected_status:
                    return True, f"HTTP {status} from {config.http_path}"
                return False, f"HTTP {status} from {config.http_path} (expected {list(config.expected_status)})"
        except urllib.error.HTTPError as exc:
            if int(exc.code) in config.expected_status:
                return True, f"HTTP {exc.code} from {config.http_path}"
            return False, f"HTTP {exc.code} from {config.http_path}"
        except (OSError, ValueError) as exc:
            return False, f"HTTP probe failed: {type(exc).__name__}"

    return False, f"Unsupported readiness kind: {kind}"


def collect_process_metrics(
    identity: ProcessIdentity | None,
    *,
    include_children: bool = True,
) -> dict[str, Any]:
    """Collect CPU/RAM metrics only after verifying process identity (never foreign PIDs)."""
    empty: dict[str, Any] = {
        "alive": False,
        "pid": identity.pid if identity else None,
        "cpu_percent": 0.0,
        "memory_rss_bytes": 0,
        "memory_mb": 0.0,
        "num_threads": 0,
        "child_pids": [],
        "uptime_seconds": 0.0,
        "collected_at": time.time(),
    }
    if identity is None:
        return empty

    platform = get_platform()
    if not platform.verify_process_identity(identity):
        return empty

    try:
        proc = psutil.Process(identity.pid)
        cpu = float(proc.cpu_percent(interval=None))
        rss = int(proc.memory_info().rss)
        threads = int(proc.num_threads())
        uptime = max(0.0, time.time() - float(proc.create_time()))
        child_pids: list[int] = []
        if include_children:
            for child in proc.children(recursive=True):
                try:
                    child_pids.append(child.pid)
                    cpu += float(child.cpu_percent(interval=None))
                    rss += int(child.memory_info().rss)
                    threads += int(child.num_threads())
                except psutil.Error:
                    continue
        return {
            "alive": True,
            "pid": identity.pid,
            "cpu_percent": round(cpu, 2),
            "memory_rss_bytes": rss,
            "memory_mb": round(rss / (1024.0 * 1024.0), 2),
            "num_threads": threads,
            "child_pids": sorted(child_pids),
            "uptime_seconds": round(uptime, 2),
            "collected_at": time.time(),
        }
    except psutil.Error:
        return empty
