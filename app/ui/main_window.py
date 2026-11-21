"""Главное окно SouronMCP: статусы, Старт/Стоп, публичный URL, параметры, логи.

Окно только показывает состояние и передаёт команды: вся работа с процессами —
в ServiceManager. Статусы и строки лога приходят Qt-сигналами в GUI-поток, поэтому
окно никогда не ждёт процессы и не зависает.
"""
from __future__ import annotations

import ctypes
import sys
from urllib.parse import urlparse

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QGuiApplication
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app import APP_NAME, __version__
from app.config import Settings
from app.core import autostart
from app.core.process import ProcState
from app.core.service_manager import APP, Overall, ServiceManager
from app.ui import icons, theme
from app.ui.widgets import LogView, StatusRow, card, divider, section_label

_PENDING = (ProcState.STARTING, ProcState.STOPPING)
_COPY_TEXT = "Копировать"
_COPIED_TEXT = "✓ Скопировано"


class MainWindow(QMainWindow):
    quit_requested = pyqtSignal()   # окно закрыли, а сворачивание в трей выключено
    hidden_to_tray = pyqtSignal()   # окно впервые ушло в трей — показать подсказку

    def __init__(self, manager: ServiceManager, settings: Settings, tray_available: bool,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.settings = settings
        self._tray_available = tray_available
        self._allow_close = False
        self._tray_hint_shown = False
        self._unseen_errors = 0

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(540)

        self._copy_reset = QTimer(self)
        self._copy_reset.setSingleShot(True)
        self._copy_reset.timeout.connect(lambda: self.copy_btn.setText(_COPY_TEXT))

        self._build_ui()
        self._wire()
        self._set_logs_expanded(settings.logs_expanded, resize=False)
        self._refresh()
        height = 780 if settings.logs_expanded else self.minimumSizeHint().height()
        self.resize(600, height)
        _dark_title_bar(self)

    # ================================================================== публичное API
    def show_and_raise(self) -> None:
        """Показать окно из трея / второго запуска и вывести на передний план."""
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def allow_close(self) -> None:
        """Выход из приложения: следующее закрытие окна больше не уводит его в трей."""
        self._allow_close = True

    # ================================================================== построение UI
    def _build_ui(self) -> None:
        s = self.settings
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)
        self._root_layout = layout

        # --- шапка: логотип, название, общий статус
        header = QHBoxLayout()
        header.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(40, 40))
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel(APP_NAME)
        title.setObjectName("Title")
        subtitle = QLabel(f"MCP-сервер + Cloudflare Tunnel · v{__version__}")
        subtitle.setObjectName("Dim")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        self.badge = QLabel()
        header.addWidget(logo)
        header.addLayout(titles, 1)
        header.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(header)

        # --- карточка статусов
        status_card, status_layout = card()
        self.server_row = StatusRow("MCP-сервер", f"{s.server_host}:{s.server_port}")
        host = urlparse(s.public_url).hostname or s.public_url
        protocol = s.tunnel_protocol.strip().lower() or "auto"
        self.tunnel_row = StatusRow("Cloudflare Tunnel", f"{host} · {protocol}")
        status_layout.addWidget(self.server_row)
        status_layout.addWidget(divider())
        status_layout.addWidget(self.tunnel_row)
        layout.addWidget(status_card)

        # --- главная кнопка
        self.toggle_btn = QPushButton()
        self.toggle_btn.setObjectName("Primary")
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setMinimumHeight(46)
        layout.addWidget(self.toggle_btn)

        # --- публичный адрес
        url_card, url_layout = card()
        url_layout.addWidget(section_label("ПУБЛИЧНЫЙ АДРЕС"))
        url_row = QHBoxLayout()
        url_row.setSpacing(8)
        self.url_edit = QLineEdit(s.public_url)
        self.url_edit.setReadOnly(True)
        self.url_edit.setCursorPosition(0)
        self.url_edit.setToolTip("Адрес для Notion AI / ChatGPT / Claude")
        self.copy_btn = QPushButton(_COPY_TEXT)
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_btn.setMinimumWidth(self.copy_btn.fontMetrics().horizontalAdvance(_COPIED_TEXT) + 40)
        url_row.addWidget(self.url_edit, 1)
        url_row.addWidget(self.copy_btn)
        url_layout.addLayout(url_row)
        layout.addWidget(url_card)

        # --- параметры
        options_card, options_layout = card()
        options_layout.addWidget(section_label("ПАРАМЕТРЫ"))
        self.cb_autostart = QCheckBox("Запускать вместе с Windows (сразу в трей)")
        self.cb_autostart.setEnabled(autostart.is_supported())
        self.cb_autostart.setChecked(autostart.is_enabled())
        self.cb_start_services = QCheckBox("Запускать сервер и туннель при старте приложения")
        self.cb_start_services.setChecked(s.start_services_on_launch)
        self.cb_tray = QCheckBox("Сворачивать в трей при закрытии окна")
        self.cb_tray.setChecked(s.minimize_to_tray_on_close and self._tray_available)
        self.cb_tray.setEnabled(self._tray_available)
        for checkbox in (self.cb_autostart, self.cb_start_services, self.cb_tray):
            options_layout.addWidget(checkbox)
        layout.addWidget(options_card)

        # --- логи (сворачиваются)
        log_header = QHBoxLayout()
        self.logs_btn = QToolButton()
        self.logs_btn.setObjectName("Disclosure")
        self.logs_btn.setCheckable(True)
        self.logs_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.logs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_log_btn = QPushButton("Копировать лог")
        self.copy_log_btn.setObjectName("Small")
        self.clear_log_btn = QPushButton("Очистить")
        self.clear_log_btn.setObjectName("Small")
        log_header.addWidget(self.logs_btn)
        log_header.addStretch(1)
        log_header.addWidget(self.copy_log_btn)
        log_header.addWidget(self.clear_log_btn)
        layout.addLayout(log_header)

        self.log_view = LogView()
        self.log_view.setMinimumHeight(200)
        layout.addWidget(self.log_view, 1)

        # Распорка: когда логи свёрнуты, свободное место уходит сюда, а не между карточками.
        layout.addStretch(0)
        self._spacer_index = layout.count() - 1

    def _wire(self) -> None:
        m = self.manager
        m.log_line.connect(self._on_log)
        m.service_state_changed.connect(lambda *_: self._refresh())
        m.overall_state_changed.connect(lambda *_: self._refresh())

        self.toggle_btn.clicked.connect(self._on_toggle)
        self.copy_btn.clicked.connect(self._copy_url)
        self.cb_autostart.toggled.connect(self._on_autostart_toggled)
        self.cb_start_services.toggled.connect(self._on_start_services_toggled)
        self.cb_tray.toggled.connect(self._on_tray_toggled)
        self.logs_btn.toggled.connect(self._set_logs_expanded)
        self.copy_log_btn.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(self.log_view.plain_text()))
        self.clear_log_btn.clicked.connect(self.log_view.clear_log)

    # ================================================================== состояние -> экран
    def _refresh(self) -> None:
        m = self.manager
        overall = m.overall
        text, color = theme.OVERALL[overall.value]
        self.setWindowTitle(f"{APP_NAME} — {text}")
        self.badge.setText(f"●  {text}")
        self.badge.setStyleSheet(
            f"color: {color}; background: {theme.rgba(color, 0.12)};"
            f"border: 1px solid {theme.rgba(color, 0.35)}; border-radius: 11px;"
            "padding: 3px 10px; font-weight: 600;"
        )

        server_state = m.server.state
        text, color = theme.SERVER_STATES[server_state.value]
        self.server_row.set_state(text, color, pulse=server_state in _PENDING)

        tunnel_state = m.tunnel.state
        if tunnel_state == ProcState.STOPPED and m.is_active:
            # Туннель стартует только после того, как сервер ответил.
            self.tunnel_row.set_state("Ждёт сервер…", theme.AMBER, pulse=True)
        else:
            text, color = theme.TUNNEL_STATES[tunnel_state.value]
            self.tunnel_row.set_state(text, color, pulse=tunnel_state in _PENDING)

        btn = self.toggle_btn
        if m.is_active:
            btn.setText("■   Остановить")
            btn.setEnabled(True)
            running = True
        elif overall == Overall.STOPPING:
            btn.setText("Остановка…")
            btn.setEnabled(False)
            running = False
        else:
            btn.setText("▶   Запустить")
            btn.setEnabled(True)
            running = False
        if btn.property("running") != running:
            btn.setProperty("running", running)
            # Динамическое свойство в QSS применяется только после re-polish.
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _update_logs_title(self) -> None:
        title = "Логи"
        if not self.logs_btn.isChecked() and self._unseen_errors:
            title += f"   ·   новых ошибок: {self._unseen_errors}"
        self.logs_btn.setText(title)

    # ================================================================== слоты
    def _on_log(self, source: str, line: str) -> None:
        self.log_view.append_line(source, line)
        if not self.logs_btn.isChecked() and LogView.level(line) == "error":
            self._unseen_errors += 1
            self._update_logs_title()

    def _on_toggle(self) -> None:
        self.manager.toggle()
        self._refresh()

    def _copy_url(self) -> None:
        QGuiApplication.clipboard().setText(self.url_edit.text())
        self.copy_btn.setText(_COPIED_TEXT)
        self._copy_reset.start(1500)

    def _set_logs_expanded(self, expanded: bool, resize: bool = True) -> None:
        self.logs_btn.blockSignals(True)
        self.logs_btn.setChecked(expanded)
        self.logs_btn.blockSignals(False)
        self.logs_btn.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        self.log_view.setVisible(expanded)
        self.copy_log_btn.setVisible(expanded)
        self.clear_log_btn.setVisible(expanded)
        self._root_layout.setStretch(self._spacer_index, 0 if expanded else 1)
        if expanded:
            self._unseen_errors = 0
        self._update_logs_title()

        if self.settings.logs_expanded != expanded:
            self.settings.logs_expanded = expanded
            self._save_settings()

        if resize and not self.isMaximized():
            if expanded:
                self.resize(self.width(), max(self.height(), 780))
            else:
                # После скрытия логов layout пересчитается в следующем цикле событий.
                QTimer.singleShot(0, lambda: self.resize(self.width(), self.minimumSizeHint().height()))

    def _on_autostart_toggled(self, enabled: bool) -> None:
        try:
            autostart.set_enabled(enabled)
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Не удалось изменить автозапуск:\n{exc}")
            self.cb_autostart.blockSignals(True)
            self.cb_autostart.setChecked(autostart.is_enabled())
            self.cb_autostart.blockSignals(False)
            return
        self._note("Автозапуск с Windows " + ("включён" if enabled else "выключен"))
        if enabled and not self.cb_start_services.isChecked():
            # Автозапуск без старта сервисов бесполезен; галочку можно снять вручную.
            self.cb_start_services.setChecked(True)

    def _on_start_services_toggled(self, enabled: bool) -> None:
        self.settings.start_services_on_launch = enabled
        self._save_settings()

    def _on_tray_toggled(self, enabled: bool) -> None:
        self.settings.minimize_to_tray_on_close = enabled
        self._save_settings()

    # ================================================================== закрытие
    def closeEvent(self, event: QCloseEvent) -> None:
        if self._allow_close:
            event.accept()
            return
        if self._tray_available and self.settings.minimize_to_tray_on_close:
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.hidden_to_tray.emit()
            return
        # Трей выключен: закрытие окна = выход. Процессы остановит aboutToQuit -> shutdown().
        event.ignore()
        self.quit_requested.emit()

    # ================================================================== helpers
    def _save_settings(self) -> None:
        try:
            self.settings.save()
        except OSError as exc:
            self._note(f"✖ Не удалось сохранить настройки: {exc}")

    def _note(self, text: str) -> None:
        self._on_log(APP, text)


def _dark_title_bar(window: QWidget) -> None:
    """Тёмный системный заголовок окна (Windows 10 20H1+ и Windows 11)."""
    if sys.platform != "win32":
        return
    try:
        hwnd = ctypes.c_void_p(int(window.winId()))
        value = ctypes.c_int(1)
        dwmapi = ctypes.windll.dwmapi
        # DWMWA_USE_IMMERSIVE_DARK_MODE: 20 — текущий номер, 19 — старые сборки Windows 10.
        for attribute in (20, 19):
            if dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError):
        pass
