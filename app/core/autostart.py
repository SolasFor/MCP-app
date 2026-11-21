"""Автозапуск с Windows: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.

Не требует прав администратора и виден в Диспетчере задач -> Автозагрузка.
Приложение стартует с --minimized (сразу в трей).
"""
from __future__ import annotations

import sys
from pathlib import Path

from app import APP_NAME
from app.paths import is_frozen, project_root

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def launch_command() -> str:
    if is_frozen():
        return f'"{sys.executable}" --minimized'
    # dev-режим: pythonw.exe, чтобы при входе в систему не появлялось окно консоли
    pyw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pyw if pyw.exists() else Path(sys.executable)
    return f'"{interpreter}" "{project_root() / "main.py"}" --minimized'


def is_supported() -> bool:
    return sys.platform == "win32"


def _read() -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return str(value)
    except FileNotFoundError:
        return None


def is_enabled() -> bool:
    return is_supported() and _read() is not None


def set_enabled(enabled: bool) -> None:
    if not is_supported():
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, launch_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


def refresh_if_moved() -> None:
    """Если автозапуск включён, но .exe перенесли — обновить путь в реестре."""
    current = _read() if is_supported() else None
    if current is not None and current != launch_command():
        set_enabled(True)
