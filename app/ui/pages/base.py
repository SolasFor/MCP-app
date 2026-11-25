"""Shared responsive page scaffold (20px content padding, 16px section rhythm)."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget


class PageScaffold(QWidget):
    MAX_WIDTH = 960

    def __init__(self, *, scroll: bool = True, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Canvas")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        column = QWidget()
        column.setMaximumWidth(self.MAX_WIDTH)
        self.content = QVBoxLayout(column)
        self.content.setContentsMargins(0, 8, 0, 20)
        self.content.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(12)
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        self.title_label = QLabel("")
        self.title_label.setObjectName("PageTitle")
        self.title_label.setWordWrap(True)
        self.lead_label = QLabel("")
        self.lead_label.setObjectName("PageLead")
        self.lead_label.setWordWrap(True)
        title_box.addWidget(self.title_label)
        title_box.addWidget(self.lead_label)
        header.addLayout(title_box, 1)

        self.header_actions = QHBoxLayout()
        self.header_actions.setSpacing(8)
        header.addLayout(self.header_actions)
        self.content.addLayout(header)

        canvas = QWidget()
        canvas.setObjectName("Canvas")
        row = QHBoxLayout(canvas)
        row.setContentsMargins(20, 0, 20, 0)
        row.addStretch(1)
        row.addWidget(column, 100)
        row.addStretch(1)

        if scroll:
            area = QScrollArea()
            area.setObjectName("Page")
            area.setWidgetResizable(True)
            area.setFrameShape(QFrame.Shape.NoFrame)
            area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            area.setWidget(canvas)
            outer.addWidget(area)
        else:
            outer.addWidget(canvas, 1)

    def set_header(self, title: str, lead: str) -> None:
        self.title_label.setText(title)
        self.lead_label.setText(lead)
        self.title_label.setVisible(bool(title))
        self.lead_label.setVisible(bool(lead))

    def retranslate(self) -> None:
        pass

    def apply_theme(self) -> None:
        pass
