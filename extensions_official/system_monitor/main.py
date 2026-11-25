"""Official System Monitor extension (separate-process SDK worker)."""
from __future__ import annotations

import sys
import time
from typing import Any

import psutil

from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("system_monitor", "1.0.0")


@app.tool("system_metrics", description="Read CPU, memory, root disk, and uptime metrics.")
def system_metrics() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    root_path = "C:\\" if sys.platform == "win32" else "/"
    disk = psutil.disk_usage(root_path)
    return {
        "cpu_percent": float(psutil.cpu_percent(interval=0.05)),
        "cpu_count": int(psutil.cpu_count(logical=True) or 1),
        "ram_total_mb": round(vm.total / (1024 * 1024), 1),
        "ram_used_mb": round(vm.used / (1024 * 1024), 1),
        "ram_percent": float(vm.percent),
        "disk_path": root_path,
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "disk_percent": float(disk.percent),
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
    }


@app.tool("top_processes", description="List top processes sorted by RSS memory.")
def top_processes(limit: int = 10) -> dict[str, Any]:
    cap = max(1, min(int(limit), 25))
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            info = proc.info
            mem = info.get("memory_info")
            rss_mb = round((mem.rss if mem else 0) / (1024 * 1024), 1)
            rows.append({"pid": info["pid"], "name": info.get("name") or "", "rss_mb": rss_mb})
        except psutil.Error:
            continue
    rows.sort(key=lambda r: float(r["rss_mb"]), reverse=True)
    return {"processes": rows[:cap]}


@app.ui_provider()
def describe_ui() -> dict[str, Any]:
    m = system_metrics()
    return {
        "status": f"CPU {m['cpu_percent']}% | RAM {m['ram_percent']}%",
        "metrics": m,
    }


if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
