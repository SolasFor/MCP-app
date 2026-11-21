"""Запуск MCP-бэкенда в дочернем процессе (main.py --backend)."""
from __future__ import annotations

import os
import sys


def _ensure_std_streams() -> None:
    """Гарантируем построчный UTF-8 вывод в pipe, который читает GUI.

    В оконном .exe (PyInstaller --windowed) sys.stdout/sys.stderr могут быть None —
    тогда заново открываем дескрипторы 1/2, унаследованные от QProcess.
    """
    for name, fd in (("stdout", 1), ("stderr", 2)):
        stream = getattr(sys, name)
        if stream is None:
            try:
                stream = open(fd, "w", encoding="utf-8", errors="replace", buffering=1, closefd=False)
            except OSError:
                stream = open(os.devnull, "w", encoding="utf-8")
            setattr(sys, name, stream)
        else:
            try:
                stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            except (AttributeError, ValueError):
                pass


def run_backend() -> None:
    _ensure_std_streams()
    # backend/server.py должен экспортировать main(), которая делает то же,
    # что сейчас стоит под `if __name__ == "__main__":` (запуск streamable-http на :8000).
    from backend.server import main as server_main

    server_main()
