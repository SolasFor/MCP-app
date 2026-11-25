"""Reusable cards, badges, section headers, empty states, and error banners."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from app.ui import icons, theme
from app.ui.widgets import repolish


class Divider(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Divider")


class Badge(QLabel):
    """Status pill with semantic variants (`neutral`, `accent`, `ok`, `warn`, `err`)."""

    def __init__(self, text: str = "", variant: str = "neutral", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Pill")
        self.set_variant(variant)

    def set_variant(self, variant: str) -> None:
        self.setProperty("variant", variant)
        repolish(self)


class SectionHeader(QWidget):
    """Card section title row with optional right-side accessory widget."""

    def __init__(self, title: str = "", subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("SectionTitle")
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("Hint")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        texts.addWidget(self.title_label)
        texts.addWidget(self.subtitle_label)
        outer.addLayout(texts, 1)

        self.right_box = QHBoxLayout()
        self.right_box.setSpacing(8)
        outer.addLayout(self.right_box)

    def set_texts(self, title: str, subtitle: str = "") -> None:
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)
        self.subtitle_label.setVisible(bool(subtitle))


class Card(QFrame):
    """Rounded container card (`Card` or `Elevated`) with consistent padding."""

    def __init__(
        self,
        *,
        elevated: bool = False,
        margins: tuple[int, int, int, int] = (18, 16, 18, 16),
        spacing: int = 10,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Elevated" if elevated else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(spacing)


class EmptyState(QFrame):
    """Honest empty or upcoming state with vector icon, heading, description, and optional CTA."""

    def __init__(
        self,
        icon_name: str = "info",
        title: str = "",
        description: str = "",
        cta_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("EmptyState")
        self._icon_name = icon_name

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._icon_label)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("SectionTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setWordWrap(True)
        layout.addWidget(self.title_label)

        self.desc_label = QLabel(description)
        self.desc_label.setObjectName("Hint")
        self.desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.desc_label.setWordWrap(True)
        layout.addWidget(self.desc_label)

        self.cta_button = QPushButton(cta_text)
        self.cta_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cta_button.setVisible(bool(cta_text))
        layout.addWidget(self.cta_button, 0, Qt.AlignmentFlag.AlignCenter)
        self.apply_theme()

    def set_content(self, title: str, description: str, cta_text: str = "") -> None:
        self.title_label.setText(title)
        self.desc_label.setText(description)
        self.cta_button.setText(cta_text)
        self.cta_button.setVisible(bool(cta_text))

    def apply_theme(self) -> None:
        self._icon_label.setPixmap(icons.vector_icon(self._icon_name, theme.TEXT_MUTED, 28).pixmap(28, 28))


class ErrorBanner(QFrame):
    """Inline actionable alert banner for service or validation errors."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ErrorBanner")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(10)

        self._icon = QLabel()
        row.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignVCenter)

        self.message_label = QLabel(text)
        self.message_label.setObjectName("Error")
        self.message_label.setWordWrap(True)
        row.addWidget(self.message_label, 1)

        self.actions_layout = QHBoxLayout()
        self.actions_layout.setSpacing(10)
        row.addLayout(self.actions_layout)
        self.apply_theme()

    def apply_theme(self) -> None:
        self._icon.setPixmap(icons.vector_icon("warning", theme.ERR, 16).pixmap(16, 16))
