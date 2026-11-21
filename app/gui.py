"""Запуск GUI: QApplication + главное окно + трей поверх ServiceManager.

    python main.py              -> окно (+ иконка в трее)
    python main.py --minimized  -> сразу в трей (так стартует автозапуск)

Один экземпляр на пользователя: повторный запуск не поднимает вторую копию
(она бы упёрлась в занятый порт 8000), а показывает окно уже работающей.

Выход (меню трея, Ctrl+C в консоли, выход из системы) всегда проходит через
aboutToQuit -> ServiceManager.shutdown(): туннель и сервер останавливаются до выхода.
Если GUI убить жёстко, дочерние процессы завершит Job Object (app/core/winjob.py).
"""
from __future__ import annotations

import ctypes
import os
import re
import signal
import sys
from typing import Callable

from PyQt6.QtCore import QTimer
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon

from app import APP_NAME, __version__
from app.config import Settings
from app.core import autostart
from app.core.service_manager import ServiceManager
from app.ui import icons, theme
from app.ui.main_window import MainWindow
from app.ui.tray import TrayIcon

APP_USER_MODEL_ID = "Souron.SouronMCP"  # своя иконка в панели задач вместо иконки python.exe


# ====================================================================== один экземпляр
def _instance_key() -> str:
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return f"{APP_NAME}-{re.sub(r'[^A-Za-z0-9_.-]', '_', user)}"


def _notify_running_instance(key: str, show: bool) -> bool:
    """True, если приложение уже запущено (ему отправлена команда «показать окно»)."""
    socket = QLocalSocket()
    socket.connectToServer(key)
    if not socket.waitForConnected(300):
        return False
    socket.write(b"show" if show else b"ping")
    socket.flush()
    socket.waitForBytesWritten(500)
    socket.disconnectFromServer()
    return True


def _listen_for_instances(key: str, on_show: Callable[[], None]) -> QLocalServer:
    server = QLocalServer()
    server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    if not server.listen(key):
        QLocalServer.removeServer(key)  # хвост от аварийно завершённого экземпляра
        server.listen(key)

    def on_new_connection() -> None:
        while server.hasPendingConnections():
            conn = server.nextPendingConnection()
            if conn is None:
                break

            def on_ready(c=conn) -> None:
                if bytes(c.readAll()).strip() == b"show":
                    on_show()

            conn.readyRead.connect(on_ready)
            conn.disconnected.connect(conn.deleteLater)
            if conn.bytesAvailable():
                on_ready()

    server.newConnection.connect(on_new_connection)
    return server


def _set_app_user_model_id() -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        except (AttributeError, OSError):
            pass


# ====================================================================== точка входа
def run_gui(argv: list[str]) -> int:
    minimized = "--minimized" in argv[1:]
    _set_app_user_model_id()

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(False)  # закрытое окно ≠ выход: живём в трее

    key = _instance_key()
    if _notify_running_instance(key, show=not minimized):
        return 0

    theme.apply(app)
    app.setWindowIcon(icons.app_icon())

    settings = Settings.load()
    try:
        autostart.refresh_if_moved()  # .exe перенесли — поправить путь в реестре
    except OSError:
        pass

    manager = ServiceManager(settings)
    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    window = MainWindow(manager, settings, tray_available=tray_available)
    window.quit_requested.connect(app.quit)

    tray: TrayIcon | None = None
    if tray_available:
        tray = TrayIcon(manager, settings, should_notify=lambda: not window.isVisible())
        tray.show_requested.connect(window.show_and_raise)
        tray.quit_requested.connect(app.quit)
        window.hidden_to_tray.connect(lambda: tray.showMessage(
            APP_NAME,
            "Приложение продолжает работать в трее. Выход — правой кнопкой по значку.",
            QSystemTrayIcon.MessageIcon.Information,
            4000,
        ))
        tray.show()

    instance_server = _listen_for_instances(key, window.show_and_raise)

    def on_about_to_quit() -> None:
        window.allow_close()
        if tray is not None:
            tray.hide()  # иначе в трее остаётся «призрак» до наведения мыши
        manager.shutdown()  # блокирующая остановка туннеля и сервера (до ~6 с)
        instance_server.close()

    app.aboutToQuit.connect(on_about_to_quit)

    # Ctrl+C в консоли (dev-режим). Цикл Qt не отдаёт управление Python —
    # без этого «пульса» обработчик сигнала никогда не вызовется.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    pulse = QTimer()
    pulse.timeout.connect(lambda: None)
    pulse.start(250)

    if not (minimized and tray_available):
        window.show_and_raise()
    if settings.start_services_on_launch:
        QTimer.singleShot(0, manager.start_all)

    return app.exec()
