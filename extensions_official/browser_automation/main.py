"""Official Browser Automation extension with isolated profile directories and URL validation."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("browser_automation", "1.0.0")
_PROFILE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def _find_browser() -> str | None:
    candidates = [
        "msedge",
        "chrome",
        "chromium",
        "firefox",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for item in candidates:
        found = shutil.which(item) or (item if os.path.isabs(item) and Path(item).is_file() else None)
        if found:
            return found
    return None


def _validate_http_url(url: str) -> str:
    parsed = urlsplit((url or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError("Only http:// and https:// URLs with a valid host are allowed")
    return parsed.geturl()


@app.tool("browser_profiles", description="Detect browser binary and list isolated profiles.")
def browser_profiles() -> dict[str, Any]:
    prof_root = app.data_dir / "profiles"
    prof_root.mkdir(parents=True, exist_ok=True)
    profiles = sorted(p.name for p in prof_root.iterdir() if p.is_dir())
    binary = _find_browser()
    return {"browser_found": bool(binary), "browser_path": binary or "", "profiles": profiles}


@app.tool("browser_open_url", description="Open an http(s) URL inside an isolated profile directory.")
def browser_open_url(url: str, profile: str = "default") -> dict[str, Any]:
    clean_url = _validate_http_url(url)
    clean_prof = (profile or "default").strip()
    if not _PROFILE_RE.match(clean_prof):
        raise ValueError("Invalid browser profile name")
    binary = _find_browser()
    if not binary:
        return {"opened": False, "reason": "No supported browser executable detected"}
    prof_dir = (app.data_dir / "profiles" / clean_prof).resolve()
    prof_dir.mkdir(parents=True, exist_ok=True)
    args = [binary]
    if "firefox" in Path(binary).name.lower():
        args += ["-profile", str(prof_dir), clean_url]
    else:
        args += [f"--user-data-dir={prof_dir}", "--no-first-run", clean_url]
    kw: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    proc = subprocess.Popen(args, **kw)
    return {"opened": True, "pid": proc.pid, "url": clean_url, "profile_dir": str(prof_dir)}


if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
