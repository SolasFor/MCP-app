"""Zero-decoration compatibility shims (decorative animations removed per remove-animations)."""
from __future__ import annotations

from PyQt6.QtWidgets import QFrame, QLabel, QPushButton, QWidget

QWIDGETSIZE_MAX = 16_777_215


class SpotlightFrame(QFrame):
    """Static frame shim without cursor-tracking glow."""

    def __init__(
        self,
        object_name: str = "Elevated",
        corner_radius: int = 8,  # noqa: ARG002
        light_radius: int = 260,  # noqa: ARG002
        strength: float = 0.0,  # noqa: ARG002
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName(object_name)


class ShinyLabel(QLabel):
    """Static label shim without infinite shimmer animation."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)

    def set_base_color(self, color: str) -> None:  # noqa: ARG002
        pass

    def set_shine(self, active: bool) -> None:  # noqa: ARG002
        pass


class SparkButton(QPushButton):
    """Standard button shim without decorative click sparks."""


def reveal(widget: QWidget, show: bool, height: int = 0, duration: int = 0) -> None:  # noqa: ARG001
    """Show or hide a widget immediately without layout-height animation."""
    widget.setMaximumHeight(QWIDGETSIZE_MAX)
    widget.setVisible(show)
