"""Non-blocking bottom-right toast notifications."""
from __future__ import annotations

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from app.ui import icons, theme
from app.ui.widgets import repolish


class _ToastItem(QFrame):
    def __init__(self, message: str, variant: str, on_close, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setProperty("variant", variant)
        self.setMinimumWidth(240)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        repolish(self)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 9, 10, 9)
        row.setSpacing(8)

        icon_name, color = {
            "ok": ("check", theme.OK),
            "warn": ("warning", theme.WARN),
            "err": ("warning", theme.ERR),
        }.get(variant, ("info", theme.ACCENT))
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.vector_icon(icon_name, color, 15).pixmap(15, 15))
        row.addWidget(icon_lbl)

        text = QLabel(message)
        text.setWordWrap(True)
        text.setMaximumWidth(280)
        text.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        row.addWidget(text, 1)

        close_btn = QPushButton("")
        close_btn.setObjectName("Ghost")
        close_btn.setIcon(icons.vector_icon("close", theme.TEXT_MUTED, 12))
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(lambda: on_close(self))
        row.addWidget(close_btn)


class ToastManager:
    """Positions up to 3 transient toast banners inside a host parent widget."""

    def __init__(self, host: QWidget, timeout_ms: int = 3200) -> None:
        self._host = host
        self._timeout_ms = timeout_ms
        self._container = QWidget(host)
        self._container.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        self._items: list[_ToastItem] = []
        self._container.hide()

    def show_toast(self, message: str, variant: str = "info") -> None:
        if not message:
            return
        while len(self._items) >= 3:
            self._dismiss(self._items[0])
        item = _ToastItem(message, variant, self._dismiss, self._container)
        self._items.append(item)
        self._layout.addWidget(item)
        self._container.show()
        self.reposition()
        QTimer.singleShot(self._timeout_ms, lambda i=item: self._dismiss(i))

    def clear_all(self) -> None:
        for item in list(self._items):
            self._dismiss(item)

    def _dismiss(self, item: _ToastItem) -> None:
        if item not in self._items:
            return
        self._items.remove(item)
        self._layout.removeWidget(item)
        item.deleteLater()
        if not self._items:
            self._container.hide()
        else:
            self.reposition()

    def reposition(self) -> None:
        if not self._items:
            return
        self._layout.activate()
        size = self._container.sizeHint()
        self._container.resize(size)
        x = max(12, self._host.width() - size.width() - 18)
        y = max(12, self._host.height() - size.height() - 18)
        self._container.move(x, y)
        self._container.raise_()
