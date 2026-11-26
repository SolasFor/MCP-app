"""Shared compact management-page layouts using the application's theme primitives."""
from __future__ import annotations

from collections.abc import Sequence
from html import escape

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import FlowLayout, SectionHeader
from app.ui.components.silent_dialog import SilentDialog
from app.ui.i18n import tr


class ManagementPanel(QFrame):
    """A theme-aware surface with a consistent inset and vertical rhythm."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(10, 10, 10, 10)
        self.body.setSpacing(8)


def management_toolbar(
    search: QLineEdit,
    actions: Sequence[QWidget],
    *,
    filters: Sequence[QWidget] = (),
    compact: bool = False,
) -> ManagementPanel:
    """Separate searching/filtering from actions; wrap actions on narrow windows."""
    panel = ManagementPanel()
    fields = QHBoxLayout()
    fields.setSpacing(8)
    search.setClearButtonEnabled(True)
    search.setMinimumWidth(80)
    if compact:
        search.setFixedHeight(36)
        search.setObjectName("LogFilterInput")
    fields.addWidget(search, 1)
    for control in filters:
        fields.addWidget(control)
    panel.body.addLayout(fields)

    action_row = FlowLayout(spacing=6)
    for action in actions:
        if compact and isinstance(action, QPushButton):
            compact_management_button(action, primary=action.objectName() == "Accent")
        action_row.addWidget(action)
    panel.body.addLayout(action_row)
    return panel


def compact_management_button(button: QPushButton, *, primary: bool = False) -> None:
    button.setObjectName("ManagementPrimary" if primary else "ManagementAction")
    button.setFixedHeight(28)
    button.setCursor(Qt.CursorShape.ArrowCursor)


class ManagementGuideDialog(SilentDialog):
    """Readable localized instructions, including the original security notice."""

    def __init__(self, topic: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr(f"{topic}.title"))
        self.resize(640, 520)
        self.setMinimumSize(440, 320)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        title = QLabel(tr(f"{topic}.title"))
        title.setObjectName("PageTitle")
        title.setWordWrap(True)
        layout.addWidget(title)

        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        notice_key = "extensions.isolation_notice" if topic == "extensions" else "devices.security_notice"
        sections = [
            ("management.guide.purpose", f"{topic}.guide.purpose"),
            ("management.guide.setup", f"{topic}.guide.setup"),
            ("management.guide.usage", f"{topic}.guide.usage"),
            ("management.guide.security", notice_key),
        ]
        body = "".join(
            f"<h3>{escape(tr(heading))}</h3><p>{escape(tr(text)).replace(chr(10), '<br>')}</p>"
            for heading, text in sections
        )
        self.browser.setHtml(body)
        layout.addWidget(self.browser, 1)
        close = QPushButton(tr("management.guide.close"))
        compact_management_button(close)
        close.clicked.connect(self.accept)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)


def management_guide_button(topic: str, parent: QWidget) -> QPushButton:
    button = QPushButton(tr("management.guide.open"), parent)
    compact_management_button(button)
    button.clicked.connect(lambda: ManagementGuideDialog(topic, parent).exec())
    return button


def management_list(table: QWidget, empty: QWidget) -> ManagementPanel:
    """Keep the table and its existing empty state in one resizable surface."""
    panel = ManagementPanel()
    panel.body.addWidget(table, 1)
    panel.body.addWidget(empty, 1)
    return panel


class ManagementTabs(QTabWidget):
    """Full-width inspectors; translated tabs avoid cramped side-by-side panes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._translation_keys: list[str] = []
        self._section_headers: list[tuple[SectionHeader | None, bool]] = []
        self.setUsesScrollButtons(True)

    def add_section(
        self,
        pane: QWidget,
        title_key: str,
        header: SectionHeader | None = None,
        *,
        controls: bool = False,
    ) -> None:
        self._section_headers.append((header, controls))
        self._hide_duplicate_header(header, controls)
        self._translation_keys.append(title_key)
        self.addTab(pane, tr(title_key))

    @staticmethod
    def _hide_duplicate_header(header: SectionHeader | None, controls: bool) -> None:
        if header is not None:
            if controls:
                header.title_label.hide()
                header.subtitle_label.hide()
            else:
                header.hide()

    def retranslate(self) -> None:
        for index, key in enumerate(self._translation_keys):
            self.setTabText(index, tr(key))
            self._hide_duplicate_header(*self._section_headers[index])


def management_split(primary: QWidget, inspector: QWidget) -> QSplitter:
    """Let the owner resize the collection and inspector independently."""
    splitter = QSplitter(Qt.Orientation.Vertical)
    splitter.setChildrenCollapsible(False)
    splitter.setHandleWidth(8)
    splitter.addWidget(primary)
    splitter.addWidget(inspector)
    splitter.setStretchFactor(0, 3)
    splitter.setStretchFactor(1, 2)
    splitter.setSizes([300, 220])
    return splitter
