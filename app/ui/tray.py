"""Иконка в системном трее: цвет = общий статус, меню, уведомления.

    ЛКМ / двойной щелчок  -> открыть окно
    ПКМ                    -> Открыть / статус / Запустить–Остановить / Копировать URL / Выход

Адрес берётся из ServiceManager.public_url: в режиме «Временный адрес» он появляется
только после старта туннеля и может меняться при перезапуске.
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from app import APP_NAME
from app.config import Settings
from app.core.service_manager import Overall, ServiceManager
from app.ui import icons, theme

_Info = QSystemTrayIcon.MessageIcon.Information
_Warn = QSystemTrayIcon.MessageIcon.Warning


class TrayIcon(QSystemTrayIcon):
    show_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(self, manager: ServiceManager, settings: Settings,
                 should_notify: Callable[[], bool], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.settings = settings
        self._should_notify = should_notify  # уведомляем, только когда окно скрыто
        self._prev = manager.overall
        self._announced_url = ""

        menu = QMenu()
        self._menu = menu  # держим ссылку: у QMenu нет родителя-виджета

        self._act_open = menu.addAction("Открыть окно")
        bold = self._act_open.font()
        bold.setBold(True)
        self._act_open.setFont(bold)
        self._act_open.triggered.connect(lambda: self.show_requested.emit())
        menu.addSeparator()

        self._act_status = menu.addAction("")
        self._act_status.setEnabled(False)
        self._act_toggle = menu.addAction("")
        self._act_toggle.triggered.connect(self._on_toggle)
        self._act_copy = menu.addAction("Копировать адрес")
        self._act_copy.triggered.connect(self._copy_url)
        menu.addSeparator()

        self._act_quit = menu.addAction("Выход")
        self._act_quit.triggered.connect(lambda: self.quit_requested.emit())

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)
        self.messageClicked.connect(lambda: self.show_requested.emit())
        manager.overall_state_changed.connect(self._on_overall)
        manager.public_url_changed.connect(self._on_public_url)
        self._update(manager.overall)

    # ------------------------------------------------------------------ slots
    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_requested.emit()

    def _on_toggle(self) -> None:
        self.manager.toggle()
        self._update(self.manager.overall)

    def _copy_url(self) -> None:
        url = self.manager.public_url
        if not url:
            return
        QGuiApplication.clipboard().setText(url)
        self.showMessage(APP_NAME, f"Скопировано: {url}", _Info, 2000)

    def _on_public_url(self, url: str) -> None:
        self._update(self.manager.overall)
        # Временный адрес сменился на ходу (cloudflared перезапустился) — клиентам нужен новый.
        if (url and self.manager.is_quick and self._announced_url and url != self._announced_url
                and self._should_notify()):
            self.showMessage(APP_NAME, f"Новый временный адрес: {url}\nОбновите его в клиентах.",
                             _Warn, 6000)
        if url:
            self._announced_url = url

    def _on_overall(self, state: Overall) -> None:
        prev, self._prev = self._prev, state
        self._update(state)
        if not self._should_notify():
            return
        if state == Overall.ERROR:
            self.showMessage(APP_NAME, "Сервисы остановлены из-за ошибки. "
                             "Нажмите, чтобы открыть окно с журналом.", _Warn, 6000)
        elif state == Overall.DEGRADED and prev == Overall.RUNNING:
            self.showMessage(APP_NAME, "Соединение потеряно — перезапускаю…", _Warn, 4000)
        elif state == Overall.RUNNING and prev in (Overall.STARTING, Overall.DEGRADED):
            url = self.manager.public_url
            self.showMessage(APP_NAME, f"В сети: {url}" if url else "В сети", _Info, 3000)

    # ------------------------------------------------------------------ helpers
    def _update(self, state: Overall) -> None:
        text, color = theme.OVERALL[state.value]
        self.setIcon(icons.status_icon(color))
        url = self.manager.public_url
        self.setToolTip(f"{APP_NAME} — {text}" + (f"\n{url}" if url and state == Overall.RUNNING else ""))
        self._act_status.setText(f"●  {text}")
        active = self.manager.is_active
        self._act_toggle.setText("Остановить" if active else "Запустить")
        self._act_toggle.setEnabled(active or state != Overall.STOPPING)
        self._act_copy.setEnabled(bool(url))
