"""Minimalist data table with DPI-aware row heights, aligned cell combos, and row context menus."""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QEvent, QPoint, Qt
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from app.ui.components.context_menu import AppContextMenu, MenuActionSpec, make_row_menu_button
from app.ui.components.safe_combo import SafeComboBox


class TableCellCombo(QWidget):
    """Vertically and horizontally centered SafeComboBox inside a table cell."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 3, 6, 3)
        layout.setSpacing(0)
        self.combo = SafeComboBox(self)
        self.combo.setObjectName("TableCombo")
        self.combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        layout.addWidget(self.combo, 1, Qt.AlignmentFlag.AlignVCenter)

    @property
    def currentIndexChanged(self):  # noqa: N802, ANN201
        return self.combo.currentIndexChanged

    def addItem(self, text: str, userData: object = None) -> None:  # noqa: N802, N803
        self.combo.addItem(text, userData)
        self._sync_min_width()

    def _sync_min_width(self) -> None:
        hint_w = self.combo.sizeHint().width()
        fm_pad = max(130, self.fontMetrics().horizontalAdvance("Полный доступ") + 44)
        self.combo.setMinimumWidth(max(hint_w, fm_pad))
        self.setMinimumWidth(self.combo.minimumWidth() + 12)

    def count(self) -> int:
        return self.combo.count()

    def currentData(self) -> object:  # noqa: N802
        return self.combo.currentData()

    def currentText(self) -> str:  # noqa: N802
        return self.combo.currentText()

    def currentIndex(self) -> int:  # noqa: N802
        return self.combo.currentIndex()

    def setCurrentIndex(self, index: int) -> None:  # noqa: N802
        self.combo.setCurrentIndex(index)

    def findData(self, data: object) -> int:  # noqa: N802
        return self.combo.findData(data)

    def itemData(self, index: int) -> object:  # noqa: N802
        return self.combo.itemData(index)

    def itemText(self, index: int) -> str:  # noqa: N802
        return self.combo.itemText(index)

    def setToolTip(self, tip: str) -> None:  # noqa: N802
        super().setToolTip(tip)
        self.combo.setToolTip(tip)

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802
        super().setEnabled(enabled)
        self.combo.setEnabled(enabled)

    def blockSignals(self, block: bool) -> bool:  # noqa: N802
        return self.combo.blockSignals(block)

    def wheelEvent(self, event: QWheelEvent | None) -> None:  # noqa: N802
        if event is not None:
            event.ignore()


class DataTable(QTableWidget):
    """Read-only row-selectable table with clean headers, filtering, and row context menus."""

    def __init__(self, headers: list[str], parent: QWidget | None = None) -> None:
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self._row_menu_provider: Callable[[int], list[MenuActionSpec] | tuple[MenuActionSpec, ...]] | None = None
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        header = self.horizontalHeader()
        header.setHighlightSections(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        if headers:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            for col in range(1, len(headers)):
                header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._sync_metrics()

    def _sync_metrics(self) -> None:
        fm_h = self.fontMetrics().height()
        self.verticalHeader().setMinimumSectionSize(max(32, fm_h + 16))
        self.verticalHeader().setDefaultSectionSize(max(38, fm_h + 22))
        self.horizontalHeader().setFixedHeight(max(30, fm_h + 14))

    def changeEvent(self, event: QEvent | None) -> None:  # noqa: N802
        super().changeEvent(event)
        if event is not None and event.type() in (QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._sync_metrics()

    def set_row_menu_provider(
        self,
        provider: Callable[[int], list[MenuActionSpec] | tuple[MenuActionSpec, ...]] | None,
    ) -> None:
        """Bind a per-row context menu callback used on right-click and Menu/Shift+F10."""
        self._row_menu_provider = provider
        if provider is None:
            self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
            return
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        try:
            self.customContextMenuRequested.disconnect(self._on_context_menu_requested)
        except (TypeError, RuntimeError):
            pass
        self.customContextMenuRequested.connect(self._on_context_menu_requested)

    def _on_context_menu_requested(self, pos: QPoint) -> None:
        if self._row_menu_provider is None:
            return
        idx = self.indexAt(pos)
        row = idx.row()
        if row < 0:
            return
        self.selectRow(row)
        self._open_row_menu(row, self.viewport().mapToGlobal(pos))

    def keyPressEvent(self, event) -> None:  # noqa: N802, ANN001
        if (
            self._row_menu_provider is not None
            and event is not None
            and (
                event.key() == Qt.Key.Key_Menu
                or (event.key() == Qt.Key.Key_F10 and bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier))
            )
        ):
            row = self.currentRow()
            if row >= 0:
                rect = self.visualRect(self.model().index(row, max(0, self.columnCount() - 1)))
                self._open_row_menu(row, self.viewport().mapToGlobal(rect.center()))
                return
        super().keyPressEvent(event)

    def _open_row_menu(self, row: int, global_pos: QPoint) -> None:
        if self._row_menu_provider is None:
            return
        specs = list(self._row_menu_provider(row))
        if not specs:
            return
        menu = AppContextMenu.from_specs(specs, self)
        menu.exec_clamped(global_pos)

    def clear_cell_widgets(self) -> None:
        """Immediately detach and delete existing cell widgets so reloads never leave ghost controls."""
        for r in range(self.rowCount()):
            for c in range(self.columnCount()):
                w = self.cellWidget(r, c)
                if w is not None:
                    self.removeCellWidget(r, c)
                    w.hide()
                    w.setParent(None)
                    w.deleteLater()

    def set_row_actions_cell(
        self,
        row: int,
        col: int,
        *,
        tooltip: str = "",
    ) -> QPushButton:
        """Install a centered compact '⋯' button bound strictly to ``row``."""
        old = self.cellWidget(row, col)
        if old is not None:
            self.removeCellWidget(row, col)
            old.hide()
            old.setParent(None)
            old.deleteLater()
        if self.item(row, col) is None:
            self.setItem(row, col, QTableWidgetItem(""))
        host = QWidget()
        lay = QHBoxLayout(host)
        lay.setContentsMargins(4, 0, 4, 0)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn = make_row_menu_button(tooltip=tooltip, parent=host)

        def _show() -> None:
            self.selectRow(row)
            pos = btn.mapToGlobal(QPoint(btn.width(), btn.height()))
            self._open_row_menu(row, pos)

        btn.clicked.connect(_show)
        lay.addWidget(btn)
        self.setCellWidget(row, col, host)
        return btn

    def filter_rows(self, query: str) -> int:
        needle = query.strip().lower()
        visible = 0
        for row in range(self.rowCount()):
            if not needle:
                self.setRowHidden(row, False)
                visible += 1
                continue
            row_text = " ".join(
                (self.item(row, col).text() if self.item(row, col) is not None else "")
                for col in range(self.columnCount())
            ).lower()
            match = needle in row_text
            self.setRowHidden(row, not match)
            if match:
                visible += 1
        return visible
