"""Official Git Manager extension (safe read-only git inspection without hooks)."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("git_manager", "1.0.0")


def _run_git(repo_path: str, args: list[str]) -> str:
    git_exe = shutil.which("git")
    if not git_exe:
        raise RuntimeError("git executable not installed")
    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {root}")
    cmd = [git_exe, "-c", "core.hooksPath=", "-c", "core.fsmonitor=false", *args]
    kw: dict[str, Any] = {"cwd": str(root), "capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace", "timeout": 10}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    res = subprocess.run(cmd, **kw)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"git exited with code {res.returncode}")
    return res.stdout


@app.tool("git_repo_status", description="Read short porcelain git status for a directory.")
def git_repo_status(repo_path: str) -> dict[str, Any]:
    out = _run_git(repo_path, ["status", "--porcelain=v1", "-b"])
    lines = out.splitlines()
    return {"branch_line": lines[0] if lines else "", "changed_count": max(0, len(lines) - 1), "lines": lines[:100]}


@app.tool("git_repo_log", description="Read recent commits from a local repository.")
def git_repo_log(repo_path: str, limit: int = 10) -> dict[str, Any]:
    cap = max(1, min(int(limit), 50))
    out = _run_git(repo_path, ["log", f"-n{cap}", "--oneline"])
    return {"commits": out.splitlines()}


if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
