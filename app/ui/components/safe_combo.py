"""Wheel-safe QComboBox component that prevents accidental scroll-wheel value changes."""
from __future__ import annotations

from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QComboBox, QWidget


class SafeComboBox(QComboBox):
    """QComboBox ignoring wheel events while closed so page scrolling never alters selections."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._popup_open = False

    def is_popup_open(self) -> bool:
        view = self.view()
        return self._popup_open or (view is not None and view.isVisible())

    def showPopup(self) -> None:  # noqa: N802
        self._popup_open = True
        super().showPopup()

    def hidePopup(self) -> None:  # noqa: N802
        self._popup_open = False
        super().hidePopup()

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802
        if not self.is_popup_open():
            # Let parent scroll areas / tables handle wheel scrolling without altering selection.
            event.ignore()
            return
        super().wheelEvent(event)
