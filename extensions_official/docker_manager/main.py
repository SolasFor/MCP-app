"""Official Docker Manager extension (fails honestly when Docker CLI/daemon is absent)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any

from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("docker_manager", "1.0.0")


def _docker_run(args: list[str]) -> tuple[bool, str]:
    docker_exe = shutil.which("docker")
    if not docker_exe:
        return False, "docker CLI not found in PATH"
    kw: dict[str, Any] = {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace", "timeout": 10}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        res = subprocess.run([docker_exe, *args], **kw)
    except OSError as exc:
        return False, str(exc)
    if res.returncode != 0:
        return False, res.stderr.strip() or f"docker exited with {res.returncode}"
    return True, res.stdout


@app.tool("docker_status", description="Check whether local Docker CLI and daemon are available.")
def docker_status() -> dict[str, Any]:
    ok, out = _docker_run(["version", "--format", "{{json .Client}}"])
    if not ok:
        return {"available": False, "detail": out}
    return {"available": True, "client": json.loads(out) if out.strip().startswith("{") else out.strip()}


@app.tool("docker_containers", description="List local Docker containers.")
def docker_containers(all_containers: bool = True) -> dict[str, Any]:
    args = ["ps", "--format", "{{json .}}"]
    if all_containers:
        args.insert(1, "-a")
    ok, out = _docker_run(args)
    if not ok:
        return {"available": False, "detail": out, "containers": []}
    rows = [json.loads(line) for line in out.splitlines() if line.strip().startswith("{")]
    return {"available": True, "containers": rows[:100]}


if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
