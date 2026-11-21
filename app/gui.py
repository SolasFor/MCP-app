"""ВРЕМЕННО: консольный прогон ядра без окна (шаг 2).

    python main.py   -> старт server + tunnel, логи в консоль, Ctrl+C = остановка.

На шаге 3 этот файл заменит настоящий GUI (app/ui/main_window.py + трей),
а ServiceManager останется ровно таким же.
"""
from __future__ import annotations

import signal
from datetime import datetime

from PyQt6.QtCore import QCoreApplication, QTimer

from app.config import Settings
from app.core.service_manager import ServiceManager


def run_gui(argv: list[str]) -> int:
    app = QCoreApplication(argv)
    settings = Settings.load()
    manager = ServiceManager(settings)

    def on_log(source: str, line: str) -> None:
        print(f"{datetime.now():%H:%M:%S} [{source:<6}] {line}", flush=True)

    manager.log_line.connect(on_log)
    manager.overall_state_changed.connect(lambda s: print(f"==== СТАТУС: {s.value.upper()} ====", flush=True))
    manager.service_state_changed.connect(lambda n, s: print(f"     {n}: {s.value}", flush=True))

    def on_sigint(*_: object) -> None:
        print("\nCtrl+C — останавливаю…", flush=True)
        manager.shutdown()
        app.quit()

    signal.signal(signal.SIGINT, on_sigint)
    # Цикл Qt не отдаёт управление Python — без этого «пульса» Ctrl+C не сработает.
    pulse = QTimer()
    pulse.timeout.connect(lambda: None)
    pulse.start(200)

    QTimer.singleShot(0, manager.start_all)
    return app.exec()
