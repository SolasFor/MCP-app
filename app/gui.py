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

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon

from app.ui.components.silent_dialog import SilentMessageBox

from app import APP_ID, APP_NAME, __version__, migrate
from app.config import PROVIDER_NONE, Settings
from app.core import autostart
from app.core.logging_manager import LogConfig, configure_logging, default_logs_dir, get_logging_manager
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


def _close_installer_mutex() -> None:
    global _mutex_handle
    if sys.platform == "win32" and _mutex_handle:
        try:
            ctypes.windll.kernel32.CloseHandle(_mutex_handle)
        except (AttributeError, OSError):
            pass
        _mutex_handle = None


def _run_startup_acl_recovery(data_root, lm) -> None:  # noqa: ANN001
    from app.core.acl_recovery import diagnose_data_acls, repair_data_acls

    acl_diag = diagnose_data_acls(data_root)
    if not acl_diag.has_issues:
        return
    lm.warning(
        "app",
        f"Detected {len(acl_diag.issues)} damaged Windows ACL item(s) in {data_root}",
        event_code="acl_damaged_detected",
    )
    details_text = "\n".join(
        f"{item.path} [{item.reason}]" + ("" if item.owned_by_current_user else " (not owned by current user)")
        for item in acl_diag.issues
    )
    confirmed = SilentMessageBox.question(
        None,
        i18n.t("acl.recovery.title"),
        i18n.t("acl.recovery.body", data_dir=str(data_root)),
        detailed_text=details_text,
    )
    if confirmed != SilentMessageBox.StandardButton.Yes:
        return
    rep = repair_data_acls(data_root, isolate_unreadable=True)
    lm.set_base_dir(default_logs_dir())
    lm.info(
        "app",
        f"ACL recovery finished: repaired={len(rep.repaired_paths)} unrecoverable={len(rep.unrecoverable_paths)}",
        event_code="acl_recovery_completed",
    )
    if not rep.unrecoverable_paths:
        return
    unrec_details = "\n".join(f"{p} [{reason}]" for p, reason in rep.unrecoverable_paths)
    if rep.backup_paths:
        unrec_details += "\n\nBackups:\n" + "\n".join(rep.backup_paths)
    SilentMessageBox.warning(
        None,
        i18n.t("acl.recovery.unrecoverable_title"),
        i18n.t("acl.recovery.unrecoverable_body", repaired=len(rep.repaired_paths), failed=len(rep.unrecoverable_paths)),
        detailed_text=unrec_details,
    )


def _run_boot_update_recovery(data_root, lm) -> bool:  # noqa: ANN001
    from app.updater.helper import recover_interrupted_update_on_boot

    try:
        recovered_tx = recover_interrupted_update_on_boot(
            data_root / "updates" / "state.json",
            data_root / "updates",
        )
        if recovered_tx is not None and recovered_tx.state == "ACTIVE_EXTERNAL":
            lm.warning("app", "Active updater transaction in progress; deferring GUI startup", event_code="updater_active_defer")
            return False
        if recovered_tx is not None:
            lm.warning(
                "app",
                f"Recovered interrupted update tx={recovered_tx.tx_id} state={recovered_tx.state}",
                event_code="updater_boot_recovery",
            )
    except Exception as exc:  # noqa: BLE001
        lm.warning("app", f"Boot update recovery check skipped: {exc}", event_code="updater_boot_recovery_err")
    return True


def _launch_pending_update_handoff(window: MainWindow, lm) -> None:  # noqa: ANN001
    if not window.consume_pending_update_handoff():
        return
    try:
        launched = window.automation_page.update_manager.launch_staged_install_handoff(restart_gui=True)
        lm.info("app", f"Launched out-of-tree updater helper: {launched}", event_code="updater_handoff")
    except Exception as exc:  # noqa: BLE001
        lm.warning("app", f"Updater handoff failed: {exc}", event_code="updater_handoff_err")


def _install_crash_handler() -> None:
    """В оконном .exe нет консоли: необработанное исключение пишем в logs/crash.log и показываем."""

    def hook(exc_type, exc, tb) -> None:  # noqa: ANN001
        lm = get_logging_manager()
        text = lm.log_crash(exc_type, exc, tb, context="gui_excepthook")
        crash_path = lm.component_path("crash")
        if QApplication.instance() is not None:
            SilentMessageBox.critical(
                None,
                APP_NAME,
                "Внутренняя ошибка. Приложение продолжит работу.",
                informative_text=f"Подробности записаны в {crash_path}",
                detailed_text=text,
            )

    sys.excepthook = hook
    import threading

    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        tname = getattr(args.thread, "name", "thread")
        get_logging_manager().log_crash(
            args.exc_type, args.exc_value, args.exc_traceback, context=f"gui_thread:{tname}"
        )

    threading.excepthook = _thread_hook


# ====================================================================== точка входа
def run_gui(argv: list[str]) -> int:
    minimized = "--minimized" in argv[1:]
    _set_app_user_model_id()
    lm = configure_logging(base_dir=default_logs_dir(), data_root=user_data_dir())
    lm.info("app", f"Starting {APP_NAME} {__version__} (GUI)", event_code="gui_boot")
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
        lm.info("app", "Activated already-running instance", event_code="single_instance")
        lm.shutdown(timeout=1.0)
        return 0
    _create_installer_mutex()

    data_root = user_data_dir()
    theme.apply(app, "dark")
    _run_startup_acl_recovery(data_root, lm)
    if not _run_boot_update_recovery(data_root, lm):
        _close_installer_mutex()
        lm.shutdown(timeout=1.0)
        return 0

    migration_notes = migrate.run()  # данные SouronMCP -> MCP app, до чтения настроек

    settings = Settings.load()
    lm.update_config(
        LogConfig(
            enabled=settings.logging_enabled,
            level=settings.logging_level,
            max_file_mb=settings.logging_max_file_mb,
            retention_days=settings.logging_retention_days,
            max_total_mb=settings.logging_max_total_mb,
            auto_rotate=settings.logging_auto_rotate,
            archive_enabled=settings.logging_archive_enabled,
        )
    )
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
        window.task_notification.connect(tray.notify_task_event)
        tray.show()

    instance_server = _listen_for_instances(key, window.show_and_raise)

    def on_about_to_quit() -> None:
        window.allow_close()
        if tray is not None:
            tray.hide()  # иначе в трее остаётся «призрак» до наведения мыши
        manager.shutdown()  # блокирующая остановка туннеля и сервера (до ~6 с)
        instance_server.close()
        _close_installer_mutex()
        _launch_pending_update_handoff(window, lm)
        lm.info("app", "Application shutdown completed cleanly", event_code="gui_shutdown")
        lm.shutdown(timeout=2.0)

    app.aboutToQuit.connect(on_about_to_quit)

    # Ctrl+C в консоли (dev-режим). Цикл Qt не отдаёт управление Python —
    # без этого «пульса» обработчик сигнала никогда не вызовется.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    pulse = QTimer()
    pulse.timeout.connect(lambda: None)
    pulse.start(250)

    if not (minimized and tray_available):
        window.show_and_raise()
    QTimer.singleShot(0, window.servers_page.start_autostart_servers)
    if settings.start_services_on_launch and settings.active_provider != PROVIDER_NONE:
        QTimer.singleShot(0, manager.start_all)
    QTimer.singleShot(4000, window.automation_page.maybe_run_startup_auto_check)

    return app.exec()
