"""Security & Boundaries page: access policy summary, SecretStore status, emergency stop."""
from __future__ import annotations

import sys

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from app.ui.components.cards import Badge, Card, SectionHeader
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class SecurityPage(PageScaffold):
    """Central view of access profiles, DPAPI secret storage, and emergency controls."""

    allowlist_requested = pyqtSignal()
    clients_requested = pyqtSignal()
    diagnostics_requested = pyqtSignal()
    emergency_stop_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self._backend_name = "Windows DPAPI + Credential Manager" if sys.platform == "win32" else "POSIX 0600 Fernet"
        self._active_mode = "safe"

        # --- Policy Card
        policy_card = Card()
        self.policy_header = SectionHeader()
        self.mode_badge = Badge("safe", variant="ok")
        self.policy_header.right_box.addWidget(self.mode_badge)
        policy_card.body.addWidget(self.policy_header)

        p_row = QHBoxLayout()
        p_row.setSpacing(8)
        self.allowlist_btn = _button("")
        self.allowlist_btn.clicked.connect(self.allowlist_requested.emit)
        self.clients_btn = _button("", "Accent")
        self.clients_btn.clicked.connect(self.clients_requested.emit)
        p_row.addWidget(self.allowlist_btn)
        p_row.addWidget(self.clients_btn)
        p_row.addStretch(1)
        policy_card.body.addLayout(p_row)
        self.content.addWidget(policy_card)

        # --- Secret Storage & Honest Sandbox Notice Card
        secret_card = Card()
        self.secret_header = SectionHeader()
        secret_card.body.addWidget(self.secret_header)
        self.secret_desc = QLabel()
        self.secret_desc.setObjectName("Hint")
        self.secret_desc.setWordWrap(True)
        secret_card.body.addWidget(self.secret_desc)
        self.content.addWidget(secret_card)

        # --- Emergency Stop & Diagnostics Card
        action_card = Card()
        self.action_title = QLabel()
        self.action_title.setObjectName("SectionTitle")
        action_card.body.addWidget(self.action_title)

        a_row = QHBoxLayout()
        a_row.setSpacing(8)
        self.emergency_btn = _button("", "Danger")
        self.emergency_btn.clicked.connect(self.emergency_stop_requested.emit)
        self.diag_btn = _button("")
        self.diag_btn.clicked.connect(self.diagnostics_requested.emit)
        a_row.addWidget(self.emergency_btn)
        a_row.addWidget(self.diag_btn)
        a_row.addStretch(1)
        action_card.body.addLayout(a_row)
        self.content.addWidget(action_card)

        self.content.addStretch(1)
        self.retranslate()

    def set_access_mode(self, mode: str) -> None:
        self._active_mode = mode if mode in ("safe", "allowlist", "full") else "safe"
        variant = {"safe": "ok", "allowlist": "warn", "full": "err"}[self._active_mode]
        self.mode_badge.setText(tr(f"clients.role.{self._active_mode}"))
        self.mode_badge.set_variant(variant)

    def retranslate(self) -> None:
        self.set_header(tr("security.title"), tr("security.lead"))
        self.policy_header.set_texts(tr("security.policy.title"), tr("home.access.desc"))
        self.set_access_mode(self._active_mode)
        self.allowlist_btn.setText(tr("home.access.allowlist_btn"))
        self.clients_btn.setText(tr("home.access.clients_btn"))
        self.secret_header.set_texts(tr("security.secrets.title"))
        self.secret_desc.setText(tr("security.secrets.desc", backend=self._backend_name))
        self.action_title.setText(tr("security.actions.title"))
        self.emergency_btn.setText(tr("home.btn.emergency"))
        self.diag_btn.setText(tr("home.access.diag_btn"))

    def apply_theme(self) -> None:
        self.mode_badge.set_variant(str(self.mode_badge.property("variant") or "ok"))
