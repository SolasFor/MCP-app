"""Единая точка входа SouronMCP.

    python main.py              -> GUI (окно + трей)
    python main.py --minimized  -> GUI сразу в трее (так стартует автозапуск)
    python main.py --backend    -> MCP-сервер (backend/server.py)

В собранном .exe то же самое: GUI запускает сам себя с флагом --backend
как дочерний процесс, поэтому отдельный server.exe не нужен.
"""
from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    multiprocessing.freeze_support()

    if "--backend" in sys.argv[1:]:
        from app.backend_entry import run_backend

        run_backend()
        return 0

    # GUI добавляется на шаге 3 (app/ui).
    from app.gui import run_gui

    return run_gui(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
