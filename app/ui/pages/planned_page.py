"""Honest placeholder page for upcoming roadmap modules (v0.9.2–v0.9.9)."""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QWidget

from app.ui.components.cards import Badge, EmptyState
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold


class PlannedPage(PageScaffold):
    """Explicitly communicates scheduled version without pretending future features work now."""

    back_home_requested = pyqtSignal()

    def __init__(self, module_key: str, target_version: str, icon_name: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self.module_key = module_key
        self.target_version = target_version

        self.badge = Badge("", variant="warn")
        self.header_actions.addWidget(self.badge)

        self.empty = EmptyState(icon_name=icon_name)
        self.empty.cta_button.clicked.connect(self.back_home_requested.emit)
        self.content.addWidget(self.empty)
        self.content.addStretch(1)
        self.retranslate()

    def retranslate(self) -> None:
        title = tr(f"planned.{self.module_key}.title")
        lead = tr(f"planned.{self.module_key}.lead")
        self.set_header(title, lead)
        self.badge.setText(tr("planned.badge", version=self.target_version))
        self.empty.set_content(
            title,
            tr("planned.notice", version=self.target_version),
            tr("planned.back_home"),
        )

    def apply_theme(self) -> None:
        self.badge.set_variant("warn")
        self.empty.apply_theme()
