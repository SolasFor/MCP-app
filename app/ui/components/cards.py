"""Reusable minimalist UI primitives: cards, sections, setting rows, copy fields, flow toolbars."""
from __future__ import annotations

from PyQt6.QtCore import QPoint, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLayoutItem,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui import icons, theme
from app.ui.widgets import repolish


class FlowLayout(QLayout):
    """Wrapping horizontal layout preventing multi-button toolbars from clipping at narrow widths."""

    def __init__(self, parent: QWidget | None = None, margin: int = 0, spacing: int = 6) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._h_space = spacing
        self._v_space = spacing
        self.setContentsMargins(margin, margin, margin, margin)

    def __del__(self) -> None:
        item = self.takeAt(0)
        while item is not None:
            item = self.takeAt(0)

    def addItem(self, item: QLayoutItem) -> None:  # noqa: N802
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> QLayoutItem | None:  # noqa: N802
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index: int) -> QLayoutItem | None:  # noqa: N802
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self) -> Qt.Orientation:  # noqa: N802
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        left, top, right, bottom = self.getContentsMargins()
        return size + QSize(left + right, top + bottom)

    def _do_layout(self, rect: QRect, *, test_only: bool) -> int:
        left, top, right, bottom = self.getContentsMargins()
        effective = rect.adjusted(left, top, -right, -bottom)
        x = effective.x()
        y = effective.y()
        line_height = 0

        for item in self._items:
            widget = item.widget()
            if widget is not None and not widget.isVisibleTo(widget.parentWidget() or widget):
                continue
            hint = item.sizeHint()
            next_x = x + hint.width() + self._h_space
            if next_x - self._h_space > effective.right() and line_height > 0:
                x = effective.x()
                y = y + line_height + self._v_space
                next_x = x + hint.width() + self._h_space
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + bottom


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
    """Section title row with optional subtitle and right-side accessory layout."""

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


class Section(QWidget):
    """Cardless flat section with crisp heading and optional hairline-divided body."""

    def __init__(
        self,
        title: str = "",
        subtitle: str = "",
        *,
        spacing: int = 8,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(spacing)
        self.header = SectionHeader(title, subtitle)
        root.addWidget(self.header)
        self.body = root

    def set_texts(self, title: str, subtitle: str = "") -> None:
        self.header.set_texts(title, subtitle)


class SettingRow(QWidget):
    """Compact 36-40px settings row: title (+ optional subtitle) left, control right."""

    def __init__(
        self,
        title: str = "",
        control: QWidget | None = None,
        subtitle: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setMinimumHeight(36)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(12)

        texts = QVBoxLayout()
        texts.setContentsMargins(0, 0, 0, 0)
        texts.setSpacing(1)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("SettingTitle")
        self.title_label.setWordWrap(True)
        texts.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("Hint")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        texts.addWidget(self.subtitle_label)
        row.addLayout(texts, 1)

        self._control_holder = QHBoxLayout()
        self._control_holder.setContentsMargins(0, 0, 0, 0)
        self._control_holder.setSpacing(6)
        if control is not None:
            self._control_holder.addWidget(control)
        row.addLayout(self._control_holder, 0)

    def set_texts(self, title: str, subtitle: str = "") -> None:
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)
        self.subtitle_label.setVisible(bool(subtitle))


class CopyField(QFrame):
    """Single-bar monospace URL/address field with inline copy button preserving full text."""

    copy_clicked = pyqtSignal(str, object)

    def __init__(
        self,
        placeholder: str = "",
        button_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("CopyField")
        self.setMinimumHeight(40)
        self._full_value = ""
        self._is_secret = False

        row = QHBoxLayout(self)
        row.setContentsMargins(10, 4, 6, 4)
        row.setSpacing(8)

        self.input = QLineEdit()
        self.input.setObjectName("CopyFieldInput")
        self.input.setReadOnly(True)
        self.input.setPlaceholderText(placeholder)
        self.input.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.input.setMinimumWidth(80)
        row.addWidget(self.input, 1)

        self.copy_button = QPushButton(button_text)
        self.copy_button.setObjectName("CopyFieldBtn")
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_button.clicked.connect(lambda: self.copy_clicked.emit(self._full_value, self.copy_button))
        row.addWidget(self.copy_button, 0)

    def set_value(
        self,
        value: str,
        *,
        display_text: str | None = None,
        secret: bool = False,
        muted: bool = False,
    ) -> None:
        self._full_value = value
        self._is_secret = secret
        shown = value if display_text is None else display_text
        self.input.setText(shown)
        self.input.setCursorPosition(0)
        self.input.setToolTip("" if secret else value)
        self.copy_button.setEnabled(bool(value))
        if muted:
            self.input.setStyleSheet(f"color: {theme.TEXT_FAINT};")
        else:
            self.input.setStyleSheet("")

    def full_text(self) -> str:
        return self._full_value

    def set_button_text(self, text: str) -> None:
        self.copy_button.setText(text)

    def set_placeholder(self, text: str) -> None:
        self.input.setPlaceholderText(text)


class Card(QFrame):
    """Minimalist rounded container card with hairline border and compact padding."""

    def __init__(
        self,
        *,
        elevated: bool = False,
        margins: tuple[int, int, int, int] = (16, 14, 16, 14),
        spacing: int = 10,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Elevated" if elevated else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(spacing)


class EmptyState(QFrame):
    """Compact honest empty state with vector icon, heading, description, and optional CTA."""

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
        self.setMinimumHeight(110)
        self._icon_name = icon_name

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 18, 16, 18)
        layout.setSpacing(6)
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
        self._icon_label.setPixmap(icons.vector_icon(self._icon_name, theme.TEXT_MUTED, 24).pixmap(24, 24))


class ErrorBanner(QFrame):
    """Compact inline actionable alert banner for service or validation errors."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ErrorBanner")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 8, 12, 8)
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


InlineError = ErrorBanner
