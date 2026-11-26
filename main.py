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
        import json
        from pathlib import Path

        from app.core.acl_recovery import diagnose_data_acls, repair_data_acls
        from app.paths import user_data_dir

        idx = args.index("--repair-acl")
        out_path = args[idx + 1] if idx + 1 < len(args) and not args[idx + 1].startswith("--") else ""
        data_root = user_data_dir()
        diag = diagnose_data_acls(data_root)
        report = repair_data_acls(data_root, isolate_unreadable=True) if diag.has_issues else None
        payload = {
            "data_dir": str(data_root),
            "detected_issues": len(diag.issues),
            "repaired_paths": list(report.repaired_paths) if report else [],
            "unrecoverable_paths": [
                {"path": p, "reason": r} for p, r in (report.unrecoverable_paths if report else ())
            ],
            "backup_paths": list(report.backup_paths) if report else [],
            "ok": True if report is None else report.ok,
        }
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if out_path:
            Path(out_path).write_text(text, encoding="utf-8")
        else:
            try:
                print(text, end="")
            except (OSError, AttributeError):
                pass
        return 0 if payload["ok"] else 1

    from app.gui import run_gui

    return run_gui(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
