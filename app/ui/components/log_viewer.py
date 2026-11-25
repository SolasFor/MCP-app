"""Filterable, exportable log viewer panel."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.paths import user_data_dir
from app.ui.components.cards import Badge
from app.ui.i18n import tr
from app.ui.widgets import LogView


class LogViewerWidget(QWidget):
    """Structured log viewer with source/severity filter pills, search, auto-scroll, and export."""

    copy_requested = pyqtSignal(str, object)
    exported = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        # Toolbar row 1: search + action buttons
        top = QHBoxLayout()
        top.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda txt: self.log_view.set_filters(query=txt))
        top.addWidget(self.search_edit, 1)

        self.auto_scroll_check = QCheckBox()
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.setCursor(Qt.CursorShape.PointingHandCursor)
        self.auto_scroll_check.toggled.connect(self.log_view_auto_scroll)
        top.addWidget(self.auto_scroll_check)

        self.copy_btn = QPushButton()
        self.copy_btn.setObjectName("Ghost")
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_btn.clicked.connect(
            lambda: self.copy_requested.emit(self.log_view.plain_text(), self.copy_btn)
        )
        self.export_btn = QPushButton()
        self.export_btn.setObjectName("Ghost")
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_log)
        self.clear_btn = QPushButton()
        self.clear_btn.setObjectName("Ghost")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        top.addWidget(self.copy_btn)
        top.addWidget(self.export_btn)
        top.addWidget(self.clear_btn)
        root.addLayout(top)

        # Toolbar row 2: source filter pills + severity pills + count badge
        filters = QHBoxLayout()
        filters.setSpacing(6)
        self._source_group = QButtonGroup(self)
        self._source_group.setExclusive(True)
        self._source_buttons: dict[str, QPushButton] = {}
        for key in ("all", "server", "tunnel", "app"):
            btn = QPushButton()
            btn.setObjectName("FilterPill")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setChecked(key == "all")
            btn.clicked.connect(lambda _c=False, k=key: self.log_view.set_filters(source=k))
            self._source_group.addButton(btn)
            self._source_buttons[key] = btn
            filters.addWidget(btn)

        filters.addSpacing(10)
        self._level_group = QButtonGroup(self)
        self._level_group.setExclusive(True)
        self._level_buttons: dict[str, QPushButton] = {}
        for key in ("all", "warn", "err"):
            btn = QPushButton()
            btn.setObjectName("FilterPill")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setChecked(key == "all")
            btn.clicked.connect(lambda _c=False, k=key: self.log_view.set_filters(level=k))
            self._level_group.addButton(btn)
            self._level_buttons[key] = btn
            filters.addWidget(btn)

        filters.addStretch(1)
        self.count_badge = Badge("", variant="neutral")
        filters.addWidget(self.count_badge)
        root.addLayout(filters)

        self.log_view = LogView()
        self.log_view.counts_changed.connect(self._update_count)
        self.clear_btn.clicked.connect(self.log_view.clear_log)
        root.addWidget(self.log_view, 1)

        self.retranslate()
        self._update_count(0, 0)

    def log_view_auto_scroll(self, enabled: bool) -> None:
        self.log_view.set_auto_scroll(enabled)

    def _update_count(self, shown: int, total: int) -> None:
        self.count_badge.setText(tr("logs.count", shown=shown, total=total))

    def export_log(self) -> None:
        default_path = str(user_data_dir() / "mcp-app.log")
        dest, _ = QFileDialog.getSaveFileName(self, tr("logs.export"), default_path, "Log (*.log *.txt)")
        if not dest:
            return
        Path(dest).write_text(self.log_view.plain_text(), encoding="utf-8")
        self.exported.emit(tr("toast.exported"))

    def retranslate(self) -> None:
        self.search_edit.setPlaceholderText(tr("logs.search"))
        self.auto_scroll_check.setText(tr("logs.autoscroll"))
        self.copy_btn.setText(tr("logs.copy"))
        self.export_btn.setText(tr("logs.export"))
        self.clear_btn.setText(tr("logs.clear"))
        for key, btn in self._source_buttons.items():
            btn.setText(tr(f"logs.source.{key}"))
        for key, btn in self._level_buttons.items():
            btn.setText(tr(f"logs.level.{key}"))
        shown, total = self.log_view.records_count()
        self._update_count(shown, total)
        self.log_view.re_render()

    def apply_theme(self) -> None:
        self.log_view.re_render()
