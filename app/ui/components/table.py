"""Styled Docker Desktop-like data table helper."""
from __future__ import annotations

from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QWidget


class DataTable(QTableWidget):
    """Read-only row-selectable table with clean headers and row filtering."""

    def __init__(self, headers: list[str], parent: QWidget | None = None) -> None:
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(38)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.setFocusPolicy(self.focusPolicy())
        header = self.horizontalHeader()
        header.setHighlightSections(False)
        header.setDefaultAlignment(header.defaultAlignment())
        if headers:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            for col in range(1, len(headers)):
                header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

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
