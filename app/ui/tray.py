"""System tray icon: live status dot color, localized menu, and theme-aware ring."""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from app import APP_NAME
from app.config import Settings
from app.core.service_manager import Overall, ServiceManager
from app.ui import icons, theme
from app.ui.components.toast import SilentNotificationPopup, silent_popup_available
from app.ui.i18n import i18n, tr


class TrayIcon(QSystemTrayIcon):
    show_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(
        self,
        manager: ServiceManager,
        settings: Settings,
        should_notify: Callable[[], bool],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.settings = settings
        self._should_notify = should_notify
        self._prev = manager.overall
        self._announced_url = ""
        self._active_popup: SilentNotificationPopup | None = None
        self.last_notification: tuple[str, str, str] | None = None

        menu = QMenu()
        self._menu = menu

        self._act_open = menu.addAction(tr("tray.open"))
        bold = self._act_open.font()
        bold.setBold(True)
        self._act_open.setFont(bold)
        self._act_open.triggered.connect(lambda: self.show_requested.emit())
        menu.addSeparator()

        self._act_status = menu.addAction("")
        self._act_status.setEnabled(False)
        self._act_toggle = menu.addAction("")
        self._act_toggle.triggered.connect(self._on_toggle)
        self._act_copy = menu.addAction(tr("tray.copy"))
        self._act_copy.triggered.connect(self._copy_url)
        menu.addSeparator()

        self._act_quit = menu.addAction(tr("tray.quit"))
        self._act_quit.triggered.connect(lambda: self.quit_requested.emit())

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)
        manager.overall_state_changed.connect(self._on_overall)
        manager.public_url_changed.connect(self._on_public_url)
        theme.manager().theme_changed.connect(self._on_theme_changed)
        i18n.language_changed.connect(self._on_language_changed)
        self._update(manager.overall)

    def show_silent_notification(
        self,
        title: str,
        message: str,
        *,
        variant: str = "info",
        timeout_ms: int = 4000,
    ) -> None:
        """Display a silent custom popup without invoking Win32 tray sounds."""
        self.last_notification = (title, message, variant)
        if not silent_popup_available():
            return
        if self._active_popup is not None:
            try:
                self._active_popup.dismiss()
            except RuntimeError:
                pass
            self._active_popup = None
        popup = SilentNotificationPopup(
            title,
            message,
            variant=variant,
            timeout_ms=timeout_ms,
            on_activate=self.show_requested.emit,
        )
        self._active_popup = popup
        popup.show()

    def _on_theme_changed(self, *_args: object) -> None:
        theme.apply_to_widget(self._menu)
        self._update(self.manager.overall)

    def _on_language_changed(self, *_args: object) -> None:
        self.retranslate()

    def retranslate(self) -> None:
        self._act_open.setText(tr("tray.open"))
        self._act_copy.setText(tr("tray.copy"))
        self._act_quit.setText(tr("tray.quit"))
        self._update(self.manager.overall)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_requested.emit()

    def _on_toggle(self) -> None:
        self.manager.toggle()
        self._update(self.manager.overall)

    def _copy_url(self) -> None:
        url = self.manager.public_url
        if not url:
            return
        QGuiApplication.clipboard().setText(url)
        self.show_silent_notification(APP_NAME, f"{url}", variant="info", timeout_ms=2000)

    def _on_public_url(self, url: str) -> None:
        self._update(self.manager.overall)
        if (
            url
            and self.manager.is_quick
            and self._announced_url
            and url != self._announced_url
            and self._should_notify()
        ):
            self.show_silent_notification(APP_NAME, f"{url}", variant="warn", timeout_ms=6000)
        if url:
            self._announced_url = url

    def _on_overall(self, state: Overall) -> None:
        prev, self._prev = self._prev, state
        self._update(state)
        if not self._should_notify():
            return
        if state == Overall.ERROR:
            self.show_silent_notification(APP_NAME, tr("home.err.banner"), variant="warn", timeout_ms=6000)
        elif state == Overall.DEGRADED and prev == Overall.RUNNING:
            self.show_silent_notification(APP_NAME, tr("overview.degraded.lead"), variant="warn", timeout_ms=4000)
        elif state == Overall.RUNNING and prev in (Overall.STARTING, Overall.DEGRADED):
            url = self.manager.public_url
            self.show_silent_notification(APP_NAME, url or tr("status.overall.running"), variant="info", timeout_ms=3000)

    def notify_task_event(self, task_id: str, title: str, status: str) -> None:
        if not self._should_notify():
            return
        variant = "info" if status == "succeeded" else "warn"
        label = tr(f"tasks.status.{status}")
        self.show_silent_notification(APP_NAME, f"{title or task_id}: {label}", variant=variant, timeout_ms=4000)

    def _update(self, state: Overall) -> None:
        text, color = theme.overall_label_color(state.value)
        self.setIcon(icons.status_icon(color, theme.BG))
        url = self.manager.public_url
        self.setToolTip(f"{APP_NAME} — {text}" + (f"\n{url}" if url and state == Overall.RUNNING else ""))
        self._act_status.setText(f"●  {text}")
        active = self.manager.is_active
        self._act_toggle.setText(tr("tray.stop" if active else "tray.start"))
        self._act_toggle.setEnabled(active or state != Overall.STOPPING)
        self._act_copy.setEnabled(bool(url))
