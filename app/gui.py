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
import traceback
from datetime import datetime
from typing import Callable

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon

from app import APP_ID, APP_NAME, __version__, migrate
from app.config import Settings
from app.core import autostart
from app.core.service_manager import APP, ServiceManager
from app.paths import user_data_dir
from app.ui import icons, theme
from app.ui.i18n import i18n
from app.ui.main_window import MainWindow
from app.ui.tray import TrayIcon

APP_USER_MODEL_ID = "MCPApp.Desktop"  # своя иконка в панели задач вместо иконки python.exe
# Именованный мьютекс: по нему установщик (AppMutex в installer.iss) видит, что
# приложение запущено, и просит закрыть его перед обновлением или удалением.
INSTALLER_MUTEX = "MCPApp-Running"
CRASH_LOG = "crash.log"

_mutex_handle = None


# ====================================================================== один экземпляр
def _instance_key() -> str:
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return f"{APP_ID}-{re.sub(r'[^A-Za-z0-9_.-]', '_', user)}"


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


# ====================================================================== Windows
def _set_app_user_model_id() -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        except (AttributeError, OSError):
            pass


def _create_installer_mutex() -> None:
    global _mutex_handle
    if sys.platform == "win32":
        try:
            _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, INSTALLER_MUTEX)
        except (AttributeError, OSError):
            pass


def _install_crash_handler() -> None:
    """В оконном .exe нет консоли: необработанное исключение пишем в crash.log и показываем."""

    def hook(exc_type, exc, tb) -> None:  # noqa: ANN001
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            with open(user_data_dir() / CRASH_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} · {APP_NAME} {__version__} ===\n{text}")
        except OSError:
            pass
        if QApplication.instance() is not None:
            box = QMessageBox(QMessageBox.Icon.Critical, APP_NAME,
                              "Внутренняя ошибка. Приложение продолжит работу.")
            box.setInformativeText(f"Подробности записаны в {user_data_dir() / CRASH_LOG}")
            box.setDetailedText(text)
            box.exec()

    sys.excepthook = hook


# ====================================================================== точка входа
def run_gui(argv: list[str]) -> int:
    minimized = "--minimized" in argv[1:]
    _set_app_user_model_id()
    _install_crash_handler()
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(False)  # закрытое окно ≠ выход: живём в трее

    key = _instance_key()
    if _notify_running_instance(key, show=not minimized):
        return 0
    _create_installer_mutex()

    migration_notes = migrate.run()  # данные SouronMCP -> MCP app, до чтения настроек

    settings = Settings.load()
    i18n.set_language(settings.language)
    theme.apply(app, settings.theme_mode)
    app.setWindowIcon(icons.app_icon())
    try:
        autostart.refresh_if_moved()  # .exe перенесли — поправить путь в реестре
    except OSError:
        pass

    manager = ServiceManager(settings)
    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    window = MainWindow(manager, settings, tray_available=tray_available)
    window.quit_requested.connect(app.quit)
    for note in migration_notes:
        manager.log_line.emit(APP, note)

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
