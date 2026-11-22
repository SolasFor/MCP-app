# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller: MCP app -> dist/MCPApp/MCPApp.exe (onedir, без консоли).

Запускать через packaging/build.ps1: он заранее кладёт bin/cloudflared.exe
и генерирует build/MCPApp.ico и build/version_info.txt.

Почему onedir, а не onefile:
* onefile распаковывается во %TEMP% при КАЖДОМ запуске — а MCPApp.exe запускает
  сам себя ещё раз как MCP-сервер (--backend), это двойная распаковка и медленный старт;
* антивирусы заметно чаще ругаются на самораспаковывающиеся onefile-сборки;
* установщик (installer.iss) всё равно упаковывает папку в один Setup.exe.
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 — SPECPATH задаёт PyInstaller
BUILD = ROOT / "build"
APP_ID = "MCPApp"

cloudflared = ROOT / "bin" / "cloudflared.exe"
if not cloudflared.is_file():
    raise SystemExit("bin/cloudflared.exe не найден — запустите packaging/build.ps1, он скачает его сам.")

datas = [(str(cloudflared), "bin")]
if (ROOT / "assets").is_dir():
    datas.append((str(ROOT / "assets"), "assets"))

# Сервер импортируется лениво (только в режиме --backend), а uvicorn и mcp подгружают
# часть модулей через importlib — PyInstaller их не видит без подсказки.
hiddenimports = [
    "backend.server",
    "app.backend_entry",
    "app.selftest",
    *collect_submodules("uvicorn"),
    *collect_submodules("mcp", filter=lambda name: not name.startswith("mcp.cli")),
]

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc_data", "PyQt6.QtWebEngineCore", "PyQt6.QtQuick", "PyQt6.QtQml"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_ID,
    icon=str(BUILD / f"{APP_ID}.ico"),
    version=str(BUILD / "version_info.txt"),
    console=False,          # окно и трей; сервер (--backend) пишет в pipe, который читает GUI
    disable_windowed_traceback=False,
    upx=False,              # UPX — частая причина ложных срабатываний антивирусов
    uac_admin=False,        # права администратора не нужны
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name=APP_ID,
)
