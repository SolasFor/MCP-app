"""Запуск MCP-бэкенда в дочернем процессе (main.py --backend / MCPApp.exe --backend)."""
from __future__ import annotations

import os
import sys


def _open_std_handle(fd: int):
    """Открыть унаследованный от QProcess pipe как текстовый поток.

    В оконном .exe (PyInstaller console=False) sys.stdout/sys.stderr = None.
    Сначала пробуем CRT-дескриптор 1/2; если CRT его не инициализировал (GUI-подсистема),
    берём Win32-хэндл через GetStdHandle и превращаем его в дескриптор.
    """
    try:
        os.fstat(fd)
        return open(fd, "w", encoding="utf-8", errors="replace", buffering=1, closefd=False)
    except OSError:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            import msvcrt

            std_id = -11 if fd == 1 else -12  # STD_OUTPUT_HANDLE / STD_ERROR_HANDLE
            handle = ctypes.windll.kernel32.GetStdHandle(std_id)
            if handle and handle != -1:
                new_fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
                return open(new_fd, "w", encoding="utf-8", errors="replace", buffering=1, closefd=False)
        except (OSError, AttributeError, ValueError):
            pass
    return open(os.devnull, "w", encoding="utf-8")


def _ensure_std_streams() -> None:
    """Гарантируем построчный UTF-8 вывод в pipe, который читает GUI."""
    for name, fd in (("stdout", 1), ("stderr", 2)):
        stream = getattr(sys, name)
        if stream is None:
            setattr(sys, name, _open_std_handle(fd))
        else:
            try:
                stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            except (AttributeError, ValueError):
                pass


def run_backend() -> None:
    _ensure_std_streams()
    from app.core.logging_manager import LogConfig, configure_logging
    import os

    level = os.environ.get("MCP_LOG_LEVEL", "INFO")
    lm = configure_logging(config=LogConfig(level=level))
    lm.install_exception_hooks()
    lm.info("backend", "MCP backend child process starting", event_code="backend_boot")
    try:
        from backend.server import main as server_main

        server_main()
    except Exception as exc:  # noqa: BLE001
        lm.log_crash(type(exc), exc, exc.__traceback__, context="backend_entry")
        raise
    finally:
        lm.shutdown(timeout=1.5)
