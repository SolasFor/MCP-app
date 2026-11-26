"""Shared compact management-page layouts using the application's theme primitives."""
from __future__ import annotations

from collections.abc import Sequence

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import FlowLayout, SectionHeader
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
) -> ManagementPanel:
    """Separate searching/filtering from actions; wrap actions on narrow windows."""
    panel = ManagementPanel()
    fields = QHBoxLayout()
    fields.setSpacing(8)
    search.setClearButtonEnabled(True)
    search.setMinimumWidth(80)
    fields.addWidget(search, 1)
    for control in filters:
        fields.addWidget(control)
    panel.body.addLayout(fields)

    action_row = FlowLayout(spacing=6)
    for action in actions:
        action_row.addWidget(action)
    panel.body.addLayout(action_row)
    return panel


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
        self.setUsesScrollButtons(True)

    def add_section(
        self,
        pane: QWidget,
        title_key: str,
        header: SectionHeader | None = None,
        *,
        controls: bool = False,
    ) -> None:
        if header is not None:
            if controls:
                header.title_label.hide()
                header.subtitle_label.hide()
            else:
                header.hide()
        self._translation_keys.append(title_key)
        self.addTab(pane, tr(title_key))

    def retranslate(self) -> None:
        for index, key in enumerate(self._translation_keys):
            self.setTabText(index, tr(key))


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
