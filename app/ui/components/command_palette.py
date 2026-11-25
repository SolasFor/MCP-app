"""Ctrl+K Command Palette dialog for fast navigation and quick actions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui import icons, theme
from app.ui.i18n import tr


@dataclass(frozen=True)
class PaletteAction:
    action_id: str
    title: str
    category: str
    callback: Callable[[], None]
    shortcut: str = ""
    keywords: str = ""


class CommandPaletteDialog(QDialog):
    """Modal quick-search command palette triggered by Ctrl+K."""

    def __init__(self, actions: list[PaletteAction], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setMinimumWidth(520)
        self.setMaximumHeight(420)
        self._actions = actions
        self._filtered: list[PaletteAction] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        frame = QFrame()
        frame.setObjectName("PaletteCard")
        box = QVBoxLayout(frame)
        box.setContentsMargins(12, 12, 12, 12)
        box.setSpacing(8)

        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.vector_icon("search", theme.TEXT_MUTED, 16).pixmap(16, 16))
        search_row.addWidget(icon_lbl)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("UiInput")
        self.search_input.setPlaceholderText(tr("palette.placeholder"))
        self.search_input.textChanged.connect(self._populate)
        self.search_input.installEventFilter(self)
        search_row.addWidget(self.search_input, 1)
        box.addLayout(search_row)

        self.results_list = QListWidget()
        self.results_list.setMinimumHeight(240)
        self.results_list.itemActivated.connect(self._run_selected)
        self.results_list.itemClicked.connect(self._run_selected)
        box.addWidget(self.results_list, 1)

        self.empty_label = QLabel(tr("palette.empty"))
        self.empty_label.setObjectName("Hint")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.hide()
        box.addWidget(self.empty_label)

        root.addWidget(frame)
        self._populate("")
        self.search_input.setFocus()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802
        if obj is self.search_input and event.type() == QEvent.Type.KeyPress:
            key = event.key()  # type: ignore[attr-defined]
            if key == Qt.Key.Key_Down and self.results_list.count() > 0:
                row = (self.results_list.currentRow() + 1) % self.results_list.count()
                self.results_list.setCurrentRow(row)
                return True
            if key == Qt.Key.Key_Up and self.results_list.count() > 0:
                row = (self.results_list.currentRow() - 1) % self.results_list.count()
                self.results_list.setCurrentRow(row)
                return True
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self._run_selected()
                return True
            if key == Qt.Key.Key_Escape:
                self.reject()
                return True
        return super().eventFilter(obj, event)

    def _populate(self, query: str) -> None:
        needle = query.strip().lower()
        self.results_list.clear()
        self._filtered = []
        for action in self._actions:
            hay = f"{action.title} {action.category} {action.keywords}".lower()
            if needle and needle not in hay:
                continue
            self._filtered.append(action)
            label = f"[{action.category}]  {action.title}"
            if action.shortcut:
                label += f"    ({action.shortcut})"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, len(self._filtered) - 1)
            self.results_list.addItem(item)

        has_items = bool(self._filtered)
        self.results_list.setVisible(has_items)
        self.empty_label.setVisible(not has_items)
        if has_items:
            self.results_list.setCurrentRow(0)

    def _run_selected(self, _item: QListWidgetItem | None = None) -> None:
        row = self.results_list.currentRow()
        if row < 0 or row >= len(self._filtered):
            return
        action = self._filtered[row]
        self.accept()
        action.callback()
