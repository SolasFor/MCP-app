"""Пути приложения: одинаково работают из исходников и из собранного .exe."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from app import APP_ID, LEGACY_APP_ID


def is_frozen() -> bool:
    """True, если мы внутри .exe, собранного PyInstaller."""
    return bool(getattr(sys, "frozen", False))


def project_root() -> Path:
    """Корень репозитория (только dev-режим)."""
    return Path(__file__).resolve().parent.parent


def resource_dir() -> Path:
    """Папка с read-only ресурсами (assets/, bin/).

    В сборке PyInstaller 6 (onedir) это <папка установки>\\_internal.
    """
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return project_root()


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA") or Path.home())


def legacy_user_data_dir() -> Path:
    """%APPDATA%\\SouronMCP — папка прежней версии (только для переноса данных)."""
    return _appdata() / LEGACY_APP_ID


def user_data_dir() -> Path:
    """%APPDATA%\\MCPApp — настройки, токен, логи (всегда доступна на запись)."""
    path = _appdata() / APP_ID
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_backend_workdir() -> Path:
    """Рабочая папка бэкенда (туда пишется mcp_audit.log).

    В .exe это %APPDATA%\\MCPApp: папка установки может быть только для чтения.
    """
    if is_frozen():
        return user_data_dir()
    return project_root() / "backend"


def backend_command() -> tuple[str, list[str]]:
    """Команда запуска MCP-бэкенда как дочернего процесса.

    .exe запускает сам себя с --backend; в dev — python main.py --backend.
    """
    if is_frozen():
        return sys.executable, ["--backend"]

    exe = Path(sys.executable)
    # Если GUI запущен через pythonw.exe (автозапуск), бэкенду нужен консольный
    # python.exe — иначе могут пропасть stdout/stderr. Окно консоли не появится:
    # QProcess ставит CREATE_NO_WINDOW, когда у родителя нет консоли.
    if exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")
        if console.exists():
            exe = console
    return str(exe), ["-u", str(project_root() / "main.py"), "--backend"]


def bundled_cloudflared() -> Path:
    """cloudflared.exe, который кладёт в сборку packaging/build.ps1."""
    return resource_dir() / "bin" / "cloudflared.exe"


_CLOUDFLARED_DEFAULTS = (
    Path(r"C:\Program Files (x86)\cloudflared\cloudflared.exe"),
    Path(r"C:\Program Files\cloudflared\cloudflared.exe"),
)


def resolve_cloudflared(configured: str = "") -> str | None:
    """Найти cloudflared.exe: путь из настроек -> встроенный в сборку -> Program Files -> PATH."""
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate)
        found = shutil.which(configured)
        if found:
            return found

    for candidate in (bundled_cloudflared(), *_CLOUDFLARED_DEFAULTS):
        if candidate.is_file():
            return str(candidate)

    return shutil.which("cloudflared")
