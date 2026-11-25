"""Самопроверка собранного .exe: MCPApp.exe --selftest <файл-отчёта>.

Запускается из packaging/build.ps1 сразу после сборки. Ловит то, что PyInstaller
молча пропускает: забытые скрытые импорты (uvicorn, mcp, anyio…), отсутствующий
cloudflared.exe, сломанный Qt. Окна не открывает, порт не занимает.

Отчёт пишется в файл: у оконного .exe нет консоли. Код выхода 0 = всё в порядке.
"""
from __future__ import annotations

import os
import tempfile
import traceback
from pathlib import Path


def run(argv: list[str]) -> int:
    report_path = _report_path(argv)
    lines: list[str] = []
    ok = True

    def check(title: str, func) -> None:
        nonlocal ok
        try:
            detail = func()
            lines.append(f"OK    {title}" + (f": {detail}" if detail else ""))
        except Exception:  # noqa: BLE001 — нужен полный отчёт, а не первое падение
            ok = False
            lines.append(f"FAIL  {title}\n{traceback.format_exc()}")

    check("Qt (QtWidgets, QtNetwork)", _check_qt)
    check("cloudflared", _check_cloudflared)
    check("MCP-сервер (импорт и сборка приложения)", _check_backend)

    lines.append("RESULT " + ("OK" if ok else "FAIL"))
    text = "\n".join(lines) + "\n"
    if report_path:
        Path(report_path).write_text(text, encoding="utf-8")
    else:
        try:
            print(text)
        except (OSError, AttributeError):
            pass
    return 0 if ok else 1


def _report_path(argv: list[str]) -> str:
    args = argv[1:]
    if "--selftest" in args:
        index = args.index("--selftest")
        if index + 1 < len(args):
            return args[index + 1]
    return ""


def _check_qt() -> str:
    from PyQt6 import QtCore, QtNetwork, QtWidgets  # noqa: F401
    # Ensure that the newly added OAuth and connection diagnostic dialogs
    # were actually included by PyInstaller, without opening any window.
    from app.ui.oauth_clients_dialog import OAuthClientsDialog  # noqa: F401
    from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog  # noqa: F401
    from app.ui.connection_diagnostics_dialog import ConnectionDiagnosticsDialog  # noqa: F401

    return QtCore.PYQT_VERSION_STR


def _check_cloudflared() -> str:
    import subprocess

    from app.paths import is_frozen, resolve_cloudflared

    exe = resolve_cloudflared("")
    if exe is None:
        raise RuntimeError("cloudflared.exe не найден (в сборке должен лежать _internal/bin/cloudflared.exe)")
    if is_frozen() and "_internal" not in exe:
        raise RuntimeError(f"используется не встроенный cloudflared: {exe}")
    result = subprocess.run(
        [exe, "--version"], capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    version = (result.stdout or result.stderr).strip().splitlines()
    return f"{exe} ({version[0] if version else 'версия не определена'})"


def _check_backend() -> str:
    # Сервер читает настройки из env при импорте — подставляем безопасные значения,
    # а лог аудита пишем во временную папку, чтобы не мусорить.
    os.environ["MCP_SECRET_TOKEN"] = "selftest-token-0123456789abcdef"
    os.environ["MCP_PUBLIC_URL"] = "https://selftest.example.com/mcp"
    os.environ["MCP_JSON_RESPONSE"] = "1"
    os.environ["MCP_ENABLE_OAUTH"] = "1"
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        # Never touch a real user's encrypted OAuth/Gateway/Tasks state during selftest.
        os.environ["MCP_OAUTH_STORE_PATH"] = str(Path(tmp) / "oauth" / "selftest.sqlite3")
        os.environ["MCP_GATEWAY_CONFIG_PATH"] = str(Path(tmp) / "gateway" / "servers.json")
        os.environ["MCP_TASKS_DB_PATH"] = str(Path(tmp) / "tasks" / "selftest_tasks.sqlite3")
        os.environ["MCP_TASKS_ARTIFACTS_DIR"] = str(Path(tmp) / "tasks" / "artifacts")
        os.environ["MCP_SPOOL_DIR"] = str(Path(tmp) / "tasks" / "spool")
        os.chdir(tmp)
        try:
            import uvicorn  # noqa: F401
            from app import platform as _platform  # noqa: F401
            from app.core import redaction as _redaction, secret_store as _secret_store  # noqa: F401
            from backend import output_stream as _out, process_runner as _pr, server, tool_registry as _tr  # noqa: F401

            app = server.build_app()
            if server.oauth_execution is None:
                raise RuntimeError("OAuth execution approvals are missing")
            import asyncio
            registered = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
            expected = set(_tr.FULL_TOOLS)
            if registered != expected:
                raise RuntimeError(f"OAuth tool registry mismatch: {registered}")
            return type(app).__name__
        finally:
            # Close root FileHandlers + audit handler before TemporaryDirectory cleanup on Windows.
            import logging

            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)
            if "server" in locals():
                server.PROCESS_RUNNER.close()
                server.EXEC_AUDIT.close()
            os.chdir(previous)
