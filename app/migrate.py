"""Перенос данных прежней версии (SouronMCP) в MCP app — один раз, при первом старте.

* %APPDATA%\\SouronMCP\\*  ->  %APPDATA%\\MCPApp\\  (settings.json, token.json, логи)
  Файлы КОПИРУЮТСЯ, старая папка остаётся нетронутой: если что-то пойдёт не так,
  данные не потеряются. Токен сохраняется — подключённые клиенты не отвалятся.
* Автозапуск HKCU\\...\\Run\\SouronMCP  ->  HKCU\\...\\Run\\MCPApp (с новым путём).

Вызывается из gui.py до Settings.load(). Возвращает строки для журнала.
"""
from __future__ import annotations

import shutil
import sys

from app import APP_ID, LEGACY_APP_ID
from app.paths import legacy_user_data_dir, user_data_dir

MARKER = ".migrated-from-souronmcp"


def run() -> list[str]:
    notes: list[str] = []
    notes += _migrate_data_dir()
    notes += _migrate_autostart()
    return notes


def _migrate_data_dir() -> list[str]:
    old = legacy_user_data_dir()
    new = user_data_dir()
    if not old.is_dir() or (new / MARKER).exists():
        return []
    if (new / "settings.json").exists() or (new / "token.json").exists():
        # Новая версия уже настроена — ничего не перезаписываем.
        (new / MARKER).write_text("skipped: new data already present\n", encoding="utf-8")
        return []

    copied = []
    for item in old.iterdir():
        target = new / item.name
        if target.exists():
            continue
        try:
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
            copied.append(item.name)
        except OSError:
            continue

    if "token.json" in copied:
        # Скопированный файл наследует ACL папки — снова ограничиваем доступ.
        from app.core import token_store

        token_store.restrict(new / "token.json")

    (new / MARKER).write_text(f"copied: {', '.join(copied)}\n", encoding="utf-8")
    if not copied:
        return []
    return [f"✔ Перенесены данные прежней версии ({LEGACY_APP_ID}): {', '.join(copied)}"]


def _migrate_autostart() -> list[str]:
    if sys.platform != "win32":
        return []
    import winreg

    from app.core import autostart

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, autostart.RUN_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                winreg.QueryValueEx(key, LEGACY_APP_ID)
            except FileNotFoundError:
                return []
            winreg.DeleteValue(key, LEGACY_APP_ID)
        autostart.set_enabled(True)
    except OSError:
        return []
    return [f"✔ Автозапуск перенесён: {LEGACY_APP_ID} → {APP_ID}"]
