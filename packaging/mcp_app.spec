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

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 — SPECPATH задаёт PyInstaller
BUILD = ROOT / "build"
APP_ID = "MCPApp"

cloudflared = ROOT / "bin" / "cloudflared.exe"
if not cloudflared.is_file():
    raise SystemExit("bin/cloudflared.exe не найден — запустите packaging/build.ps1, он скачает его сам.")

datas = [(str(cloudflared), "bin")]
if (ROOT / "assets").is_dir():
    datas.append((str(ROOT / "assets"), "assets"))
if (ROOT / "extensions_official").is_dir():
    datas.append((str(ROOT / "extensions_official"), "extensions_official"))
for _meta_pkg in ("mcp", "pydantic", "paramiko", "cryptography"):
    datas.extend(copy_metadata(_meta_pkg))

# Сервер импортируется лениво (только в режиме --backend), а uvicorn и mcp подгружают
# часть модулей через importlib — PyInstaller их не видит без подсказки.
hiddenimports = [
    "backend.server",
    "backend.managed_servers",
    "backend.process_runner",
    "backend.output_stream",
    "backend.tool_registry",
    "app.backend_entry",
    "app.selftest",
    "app.platform",
    "app.platform.base",
    "app.platform.windows",
    "app.platform.posix",
    "app.core.atomic_io",
    "app.core.acl_recovery",
    "app.core.admin_client",
    "app.core.secret_store",
    "app.core.redaction",
    "app.core.logging_manager",
    "app.core.diagnostics_bundle",
    "app.core.reconnect",
    "app.core.network_watch",
    "ntsecuritycon",
    "pywintypes",
    "win32api",
    "win32con",
    "win32security",
    *collect_submodules("app.core.tunnels"),
    *collect_submodules("app.updater"),
    *collect_submodules("backend.gateway"),
    *collect_submodules("backend.tasks"),
    *collect_submodules("backend.servers"),
    *collect_submodules("backend.workspaces"),
    *collect_submodules("backend.desktop"),
    *collect_submodules("backend.extensions"),
    *collect_submodules("backend.remote"),
    *collect_submodules("backend.automation"),
    *collect_submodules("app.ui"),
    *collect_submodules("uvicorn", filter=lambda name: "tests" not in name),
    *collect_submodules("mcp", filter=lambda name: not name.startswith("mcp.cli") and "tests" not in name),
]

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "unittest",
        "pydoc_data",
        "doctest",
        "pdb",
        "idlelib",
        "ensurepip",
        "lib2to3",
        "setuptools",
        "pkg_resources",
        "pip",
        "wheel",
        "pytest",
        "playwright",
        "PyQt6.QtWebEngineCore",
        "PyQt6.QtQuick",
        "PyQt6.QtQml",
        "PyQt6.QtOpenGL",
        "PyQt6.QtOpenGLWidgets",
        "PyQt6.QtSql",
        "PyQt6.QtMultimedia",
        "PyQt6.QtBluetooth",
        "PyQt6.QtDBus",
        "PyQt6.QtNfc",
        "PyQt6.QtPositioning",
        "PyQt6.QtRemoteObjects",
        "PyQt6.QtSensors",
        "PyQt6.QtSerialPort",
        "PyQt6.QtSpatialAudio",
        "PyQt6.QtTest",
        "PyQt6.QtTextToSpeech",
        "PyQt6.QtWebChannel",
        "PyQt6.QtWebSockets",
        "PyQt6.QtXml",
    ],
    noarchive=False,
)

# ----------------------------------------------------------------------
# Safe _internal optimization (keep onedir, metadata, licenses, RU/EN Qt)
# ----------------------------------------------------------------------
_DROP_BINARY_NAMES = {
    "opengl32sw.dll",  # 20+ MB software OpenGL renderer unused by pure QtWidgets UI
    "qtuiotouchplugin.dll",
    "qnetworklistmanager.dll",
    "qminimal.dll",
    "qopensslbackend.dll",
    "qcertonlybackend.dll",
    "qgif.dll",
    "qicns.dll",
    "qjpeg.dll",
    "qtga.dll",
    "qtiff.dll",
    "qwbmp.dll",
    "qwebp.dll",
}
_ROOT_CRT_NAMES = {"msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll", "vcruntime140.dll", "vcruntime140_1.dll"}
_existing_root_bins = {
    dest.replace("\\", "/").lower()
    for dest, _src, _kind in a.binaries
    if "/" not in dest.replace("\\", "/")
}


def _keep_binary(dest: str) -> bool:
    norm = dest.replace("\\", "/").lower()
    fname = norm.rsplit("/", 1)[-1]
    if fname in _DROP_BINARY_NAMES:
        return False
    # Deduplicate CRT DLLs inside PyQt6/Qt6/bin if identical filename is already at _internal root.
    if norm.startswith("pyqt6/qt6/bin/") and fname in _ROOT_CRT_NAMES and fname in _existing_root_bins:
        return False
    return True


_KEEP_QM = {"qtbase_ru.qm", "qtbase_en.qm"}
_DROP_DIST_FILES = {"installer", "record", "requested", "wheel"}


def _keep_data(dest: str) -> bool:
    norm = dest.replace("\\", "/").lower()
    fname = norm.rsplit("/", 1)[-1]
    if norm.startswith("pyqt6/qt6/translations/") and norm.endswith(".qm"):
        return fname in _KEEP_QM
    if ".dist-info/" in norm:
        if "/sboms/" in norm:
            return False
        if fname in _DROP_DIST_FILES:
            return False
    if "/__pycache__/" in norm or "/tests/" in norm or "/test/" in norm:
        return False
    return True


a.binaries = [item for item in a.binaries if _keep_binary(item[0])]
a.datas = [item for item in a.datas if _keep_data(item[0])]

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
