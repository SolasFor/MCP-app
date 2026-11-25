"""Logs page hosting the filterable, exportable LogViewerWidget."""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget

from app.ui.components.log_viewer import LogViewerWidget
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold


class LogsPage(PageScaffold):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=False, parent=parent)
        self.viewer = LogViewerWidget()
        self.content.addWidget(self.viewer, 1)
        self.retranslate()

    def retranslate(self) -> None:
        self.set_header(tr("logs.title"), "")
        self.viewer.retranslate()

    def apply_theme(self) -> None:
        self.viewer.apply_theme()
