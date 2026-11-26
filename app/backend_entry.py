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


def _hydrate_headless_env() -> None:
    """Load persisted MCP Owner Token and default settings when launched via ``--headless``."""
    import base64

    from app.config import Settings
    from app.core import token_store

    if not os.environ.get("MCP_SECRET_TOKEN", "").strip():
        status = token_store.load_status()
        if status.error:
            raise RuntimeError(status.error)
        owner_tok = status.token
        if not owner_tok and not status.exists_on_disk:
            owner_tok = token_store.generate()
            token_store.save(owner_tok)
        if owner_tok:
            os.environ["MCP_SECRET_TOKEN"] = token_store.transport_bearer_token(owner_tok)
            os.environ["MCP_OWNER_SECRET_B64"] = base64.b64encode(owner_tok.encode("utf-8")).decode("ascii")

    if not os.environ.get("MCP_DEFAULT_ACCESS_PROFILE", "").strip() or not os.environ.get("MCP_PUBLIC_URL", "").strip():
        try:
            s = Settings.load()
            if not os.environ.get("MCP_DEFAULT_ACCESS_PROFILE", "").strip():
                os.environ["MCP_DEFAULT_ACCESS_PROFILE"] = s.default_access_profile
            if not os.environ.get("MCP_PUBLIC_URL", "").strip() and s.public_url:
                os.environ["MCP_PUBLIC_URL"] = s.public_url
        except Exception:  # noqa: BLE001
            pass


def run_backend() -> None:
    _ensure_std_streams()
    from app.core.logging_manager import LogConfig, configure_logging

    level = os.environ.get("MCP_LOG_LEVEL", "INFO")
    lm = configure_logging(config=LogConfig(level=level))
    lm.install_exception_hooks()
    lm.info("backend", "MCP backend child process starting", event_code="backend_boot")
    try:
        _hydrate_headless_env()
        from backend.server import main as server_main

        server_main()
    except Exception as exc:  # noqa: BLE001
        lm.log_crash(type(exc), exc, exc.__traceback__, context="backend_entry")
        raise
    finally:
        lm.shutdown(timeout=1.5)
