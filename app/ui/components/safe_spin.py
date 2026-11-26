"""Wheel-safe numeric spinboxes that ignore QWheelEvent even when focused."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QDoubleSpinBox, QSpinBox, QWidget


class SafeSpinBox(QSpinBox):
    """QSpinBox ignoring mouse wheel events so parent scroll areas scroll uninterrupted."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def wheelEvent(self, event: QWheelEvent | None) -> None:  # noqa: N802
        if event is not None:
            event.ignore()


class SafeDoubleSpinBox(QDoubleSpinBox):
    """QDoubleSpinBox ignoring mouse wheel events so parent scroll areas scroll uninterrupted."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def wheelEvent(self, event: QWheelEvent | None) -> None:  # noqa: N802
        if event is not None:
            event.ignore()
