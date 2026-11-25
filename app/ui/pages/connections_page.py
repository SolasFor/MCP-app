"""Connections & Transports page: Cloudflare active mode, roadmap transports, owner token, proxy."""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from app.ui.components.cards import Badge, Card, Divider, SectionHeader
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.proxy_page import ProxyPage


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class ConnectionsPage(PageScaffold):
    """Advanced transport settings, owner Bearer token editor, and Cloudflare proxy routing."""

    domain_wizard_requested = pyqtSignal()
    domain_guide_requested = pyqtSignal()
    token_edited = pyqtSignal(str)
    token_save_requested = pyqtSignal()
    token_generate_requested = pyqtSignal()
    copy_requested = pyqtSignal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)

        # --- Transport Providers Registry (honest active vs v0.9.1 planned)
        self.providers_card = Card()
        self.providers_header = SectionHeader()
        self.providers_card.body.addWidget(self.providers_header)
        self._provider_rows: list[tuple[str, QLabel, Badge]] = []
        providers = (
            ("cf_quick", "ok"),
            ("cf_named", "accent"),
            ("ngrok", "neutral"),
            ("tailscale", "neutral"),
            ("openai", "neutral"),
            ("local", "neutral"),
        )
        for key, variant in providers:
            row = QHBoxLayout()
            row.setSpacing(10)
            name = QLabel()
            badge = Badge("", variant=variant)
            row.addWidget(name, 1)
            row.addWidget(badge)
            self.providers_card.body.addLayout(row)
            self._provider_rows.append((key, name, badge))

        self.providers_card.body.addWidget(Divider())
        transport_actions = QHBoxLayout()
        transport_actions.setSpacing(12)
        self.wizard_btn = _button("", "Accent")
        self.wizard_btn.clicked.connect(self.domain_wizard_requested.emit)
        self.guide_btn = _button("", "Link")
        self.guide_btn.clicked.connect(self.domain_guide_requested.emit)
        transport_actions.addWidget(self.wizard_btn)
        transport_actions.addWidget(self.guide_btn)
        transport_actions.addStretch(1)
        self.providers_card.body.addLayout(transport_actions)
        self.content.addWidget(self.providers_card)

        # --- Owner Access Token Card
        token_card = Card()
        self.token_header = SectionHeader()
        token_card.body.addWidget(self.token_header)

        t_row = QHBoxLayout()
        t_row.setSpacing(8)
        self.token_edit = QLineEdit()
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_edit.textEdited.connect(self.token_edited.emit)
        self.token_edit.returnPressed.connect(self.token_save_requested.emit)
        self.token_eye = _button("", "Ghost")
        self.token_eye.clicked.connect(self.toggle_token_visibility)
        self.token_save = _button("", "Accent")
        self.token_save.clicked.connect(self.token_save_requested.emit)
        self.token_save.hide()
        self.token_copy = _button("")
        self.token_copy.clicked.connect(lambda: self.copy_requested.emit("token", self.token_copy))
        self.token_gen = _button("")
        self.token_gen.clicked.connect(self.token_generate_requested.emit)
        for w in (self.token_edit, self.token_eye, self.token_save, self.token_copy, self.token_gen):
            t_row.addWidget(w, 1 if w is self.token_edit else 0)
        token_card.body.addLayout(t_row)

        self.token_error = QLabel("")
        self.token_error.setObjectName("Error")
        self.token_error.setWordWrap(True)
        self.token_error.hide()
        token_card.body.addWidget(self.token_error)
        self.content.addWidget(token_card)

        # --- Cloudflare Proxy Card
        proxy_card = Card()
        self.proxy_title = QLabel()
        self.proxy_title.setObjectName("SectionTitle")
        proxy_card.body.addWidget(self.proxy_title)
        self.proxy_page = ProxyPage()
        proxy_card.body.addWidget(self.proxy_page)
        self.content.addWidget(proxy_card)

        self.content.addStretch(1)
        self.retranslate()

    def set_token_visible(self, visible: bool) -> None:
        self.token_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )
        self.token_eye.setText(tr("conn.token.hide" if visible else "conn.token.show"))

    def toggle_token_visibility(self) -> None:
        self.set_token_visible(self.token_edit.echoMode() == QLineEdit.EchoMode.Password)

    def refresh_transport_status(self, *, is_quick: bool, has_domain: bool) -> None:
        for key, _name, badge in self._provider_rows:
            if key == "cf_quick":
                badge.setText(tr("conn.badge.active" if is_quick else "conn.badge.available"))
                badge.set_variant("ok" if is_quick else "accent")
            elif key == "cf_named":
                active_named = (not is_quick) and has_domain
                badge.setText(tr("conn.badge.active" if active_named else "conn.badge.available"))
                badge.set_variant("ok" if active_named else "accent")
            else:
                badge.setText(tr("conn.badge.planned"))
                badge.set_variant("neutral")
        self.wizard_btn.setText(tr("home.wizard.edit" if has_domain else "home.wizard.setup"))

    def retranslate(self) -> None:
        self.set_header(tr("conn.title"), tr("conn.lead"))
        self.providers_header.set_texts(tr("conn.providers.title"), tr("conn.providers.note"))
        for key, name, badge in self._provider_rows:
            name.setText(tr(f"conn.provider.{key}"))
            if key not in ("cf_quick", "cf_named"):
                badge.setText(tr("conn.badge.planned"))
        self.guide_btn.setText(tr("home.guide.open"))
        self.token_header.set_texts(tr("conn.token.title"), tr("conn.token.hint"))
        visible = self.token_edit.echoMode() == QLineEdit.EchoMode.Normal
        self.token_eye.setText(tr("conn.token.hide" if visible else "conn.token.show"))
        self.token_save.setText(tr("conn.token.save"))
        self.token_copy.setText(tr("conn.token.copy"))
        self.token_gen.setText(tr("conn.token.gen"))
        self.proxy_title.setText(tr("conn.proxy.title"))
        self.proxy_page.retranslate()

    def apply_theme(self) -> None:
        for _k, _n, badge in self._provider_rows:
            badge.set_variant(str(badge.property("variant") or "neutral"))
