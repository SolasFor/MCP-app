"""Runtime metrics registry, system telemetry snapshot, and redacted diagnostics export."""
from __future__ import annotations

import json
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from app.core.redaction import SecretRedactor


@dataclass
class _ToolStat:
    calls: int = 0
    errors: int = 0
    latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=200))

    def to_dict(self) -> dict[str, Any]:
        vals = sorted(self.latencies_ms)
        avg = round(sum(vals) / len(vals), 2) if vals else 0.0
        p95_idx = min(len(vals) - 1, int(0.95 * len(vals))) if vals else 0
        p95 = round(vals[p95_idx], 2) if vals else 0.0
        return {
            "calls": self.calls,
            "errors": self.errors,
            "avg_ms": avg,
            "p95_ms": p95,
        }


class MetricsRegistry:
    """Thread-safe MCP call counts, latency percentiles, and error counters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.time()
        self._total = 0
        self._errors = 0
        self._by_tool: dict[str, _ToolStat] = {}

    def record_call(self, tool_name: str, duration_ms: float, *, error: bool = False) -> None:
        clean = (tool_name or "unknown").strip()
        with self._lock:
            self._total += 1
            if error:
                self._errors += 1
            st = self._by_tool.setdefault(clean, _ToolStat())
            st.calls += 1
            if error:
                st.errors += 1
            st.latencies_ms.append(max(0.0, float(duration_ms)))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": max(0, int(time.time() - self._started_at)),
                "total_requests": self._total,
                "error_requests": self._errors,
                "tools": {k: v.to_dict() for k, v in sorted(self._by_tool.items())},
            }


def collect_system_snapshot(
    metrics: MetricsRegistry,
    *,
    clients: list[dict[str, Any]] | None = None,
    tunnel_status: dict[str, Any] | None = None,
    gateway_status: dict[str, Any] | None = None,
    scheduler_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble live host CPU/RAM/disk, MCP request telemetry, clients, tunnel & gateway health."""
    vm = psutil.virtual_memory()
    root_path = "C:\\" if sys.platform == "win32" else "/"
    disk = psutil.disk_usage(root_path)
    return {
        "timestamp": time.time(),
        "system": {
            "cpu_percent": float(psutil.cpu_percent(interval=None)),
            "ram_total_mb": round(vm.total / (1024 * 1024), 1),
            "ram_used_mb": round(vm.used / (1024 * 1024), 1),
            "ram_percent": float(vm.percent),
            "disk_free_gb": round(disk.free / (1024 ** 3), 2),
            "disk_percent": float(disk.percent),
        },
        "mcp_metrics": metrics.snapshot(),
        "clients": list(clients or []),
        "tunnel": dict(tunnel_status or {}),
        "gateway": dict(gateway_status or {}),
        "scheduler": dict(scheduler_stats or {}),
    }


def export_redacted_diagnostics(
    snapshot: dict[str, Any],
    *,
    audit_lines: list[str] | None = None,
    redactor: SecretRedactor | None = None,
) -> str:
    """Serialize monitoring + audit diagnostic bundle with all registered secrets redacted."""
    red = redactor or SecretRedactor()
    payload = {
        "schema_version": 1,
        "exported_at": time.time(),
        "snapshot": snapshot,
        "recent_audit": [red.redact_text(line) for line in (audit_lines or [])[-200:]],
    }
    return red.redact_text(json.dumps(payload, indent=2, ensure_ascii=False))


def filter_audit_entries(
    entries: list[str],
    *,
    query: str = "",
    level: str = "",
    limit: int = 200,
) -> list[str]:
    """Filter audit log lines case-insensitively by query and level, returning the newest tail."""
    q = (query or "").strip().lower()
    lvl = (level or "").strip().lower()
    cap = max(1, int(limit))
    matched: list[str] = []
    for line in entries:
        low = line.lower()
        if lvl and f"[{lvl}]" not in low and lvl not in low:
            continue
        if q and q not in low:
            continue
        matched.append(line)
    return matched[-cap:]


def prune_audit_file(path: Path, *, max_lines: int = 5000) -> int:
    """Atomically trim an audit file to at most `max_lines` newest lines; returns removed count."""
    from app.core.atomic_io import atomic_write_text

    target = Path(path)
    if not target.is_file():
        return 0
    keep = max(1, int(max_lines))
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) <= keep:
        return 0
    removed = len(lines) - keep
    trimmed = "\n".join(lines[-keep:]) + "\n"
    atomic_write_text(target, trimmed, restrict_acl=True)
    return removed
