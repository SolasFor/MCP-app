"""Единая точка входа MCP app.

    python main.py                    -> GUI (окно + трей)
    python main.py --minimized        -> GUI сразу в трее (так стартует автозапуск)
    python main.py --backend          -> MCP-сервер (backend/server.py)
    python main.py --headless         -> MCP-сервер без GUI (для службы/контейнера)
    python main.py --selftest <файл>  -> самопроверка сборки (пишет отчёт в файл)
    python main.py --run-extension <путь> -> изолированный процесс расширения

В собранном MCPApp.exe то же самое: GUI запускает сам себя с флагом --backend
как дочерний процесс, поэтому отдельный server.exe не нужен.
"""
from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    multiprocessing.freeze_support()
    args = sys.argv[1:]

    if "--version" in args:
        from app import APP_NAME, __version__
        from app.backend_entry import _ensure_std_streams

        _ensure_std_streams()
        print(f"{APP_NAME} {__version__}")
        return 0

    if "--apply-update" in args:
        from app.updater.helper import run_apply_update_cli

        return run_apply_update_cli(args)

    if "--run-extension" in args:
        idx = args.index("--run-extension")
        if idx + 1 >= len(args):
            raise SystemExit("Missing extension entrypoint path")
        from backend.extensions.runtime import run_extension_entrypoint

        return run_extension_entrypoint(args[idx + 1])

    if "--backend" in args or "--headless" in args:
        from app.backend_entry import run_backend

        run_backend()
        return 0

    if "--selftest" in args:
        from app.selftest import run

        return run(sys.argv)

    if "--repair-acl" in args:
        from app.core.acl_recovery import run_repair_acl_cli

        return run_repair_acl_cli(sys.argv)

    from app.gui import run_gui

    return run_gui(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
