"""Connections & Transports page: 4 UI transport providers, owner token editor, and proxy."""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from app.config import (
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
)
from app.ui.components.cards import Badge, Card, Divider, ErrorBanner, SectionHeader
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.proxy_page import ProxyPage


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


_PROVIDER_SPEC = (
    (PROVIDER_CF_QUICK, "cf_quick"),
    (PROVIDER_CF_NAMED, "cf_named"),
    (PROVIDER_NGROK, "ngrok"),
    (PROVIDER_TAILSCALE, "tailscale"),
)


class ConnectionsPage(PageScaffold):
    """Transport provider selector/diagnostics, owner Bearer token editor, and proxy settings."""

    domain_wizard_requested = pyqtSignal()
    domain_guide_requested = pyqtSignal()
    provider_selected = pyqtSignal(str)
    provider_configure_requested = pyqtSignal(str)
    provider_diagnose_requested = pyqtSignal(str)
    purge_openai_secret_requested = pyqtSignal()
    token_edited = pyqtSignal(str)
    token_save_requested = pyqtSignal()
    token_generate_requested = pyqtSignal()
    copy_requested = pyqtSignal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self._migration_source = ""

        self.migration_banner = ErrorBanner()
        self.purge_openai_secret_btn = _button("", "Danger")
        self.purge_openai_secret_btn.clicked.connect(self.purge_openai_secret_requested.emit)
        self.migration_banner.actions_layout.addWidget(self.purge_openai_secret_btn)
        self.migration_banner.hide()
        self.content.addWidget(self.migration_banner)

        self.providers_card = Card()
        self.providers_header = SectionHeader()
        self.providers_card.body.addWidget(self.providers_header)

        # provider_id -> (key, name_label, active_badge, select_btn, config_btn, diag_btn)
        self.provider_rows: dict[
            str,
            tuple[str, QLabel, Badge, QPushButton, QPushButton, QPushButton],
        ] = {}
        for pid, key in _PROVIDER_SPEC:
            row = QHBoxLayout()
            row.setSpacing(8)
            name = QLabel()
            active_badge = Badge("", variant="ok")
            active_badge.hide()

            select_btn = _button("")
            select_btn.clicked.connect(lambda _c=False, p=pid: self.provider_selected.emit(p))
            config_btn = _button("", "Ghost")
            config_btn.clicked.connect(lambda _c=False, p=pid: self.provider_configure_requested.emit(p))
            diag_btn = _button("", "Ghost")
            diag_btn.clicked.connect(lambda _c=False, p=pid: self.provider_diagnose_requested.emit(p))

            row.addWidget(name, 1)
            row.addWidget(active_badge)
            row.addWidget(select_btn)
            row.addWidget(config_btn)
            row.addWidget(diag_btn)
            self.providers_card.body.addLayout(row)
            self.provider_rows[pid] = (key, name, active_badge, select_btn, config_btn, diag_btn)

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

        # --- Owner Access Token Card (MCP Server Owner Token)
        token_card = Card()
        self.token_header = SectionHeader()
        token_card.body.addWidget(self.token_header)

        t_row = QHBoxLayout()
        t_row.setSpacing(8)
        self.token_edit = QLineEdit()
        self.token_edit.setObjectName("UiInput")
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_edit.textEdited.connect(self.token_edited.emit)
        self.token_edit.returnPressed.connect(self.token_save_requested.emit)
        self.token_eye = _button("", "Ghost")
        self.token_eye.clicked.connect(self.toggle_token_visibility)
        self.token_paste = _button("", "Ghost")
        self.token_paste.clicked.connect(self._paste_token)
        self.token_save = _button("", "Accent")
        self.token_save.clicked.connect(self.token_save_requested.emit)
        self.token_save.hide()
        self.token_copy = _button("")
        self.token_copy.clicked.connect(lambda: self.copy_requested.emit("token", self.token_copy))
        self.token_gen = _button("")
        self.token_gen.clicked.connect(self.token_generate_requested.emit)
        for w in (
            self.token_edit,
            self.token_eye,
            self.token_paste,
            self.token_save,
            self.token_copy,
            self.token_gen,
        ):
            t_row.addWidget(w, 1 if w is self.token_edit else 0)
        token_card.body.addLayout(t_row)

        self.token_error = QLabel("")
        self.token_error.setObjectName("Error")
        self.token_error.setWordWrap(True)
        self.token_error.hide()
        token_card.body.addWidget(self.token_error)
        self.content.addWidget(token_card)

        # --- Proxy Card
        proxy_card = Card()
        self.proxy_title = QLabel()
        self.proxy_title.setObjectName("SectionTitle")
        proxy_card.body.addWidget(self.proxy_title)
        self.proxy_page = ProxyPage()
        proxy_card.body.addWidget(self.proxy_page)
        self.content.addWidget(proxy_card)

        self.content.addStretch(1)
        self.retranslate()

    def _paste_token(self) -> None:
        clip = QGuiApplication.clipboard()
        raw = clip.text().strip() if clip is not None else ""
        if not raw:
            return
        self.token_edit.setText(raw)
        self.token_edited.emit(raw)

    def set_token_visible(self, visible: bool) -> None:
        self.token_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )
        self.token_eye.setText(tr("conn.token.hide" if visible else "conn.token.show"))

    def toggle_token_visibility(self) -> None:
        self.set_token_visible(self.token_edit.echoMode() == QLineEdit.EchoMode.Password)

    def refresh_providers(
        self,
        *,
        active_provider: str,
        statuses: dict[str, dict] | None = None,  # noqa: ARG002
        has_domain: bool = False,
    ) -> None:
        for pid, (_key, _name, active_badge, select_btn, _cfg, _diag) in self.provider_rows.items():
            is_active = pid == active_provider
            active_badge.setVisible(is_active)
            if is_active:
                active_badge.setText(tr("conn.badge.active"))
                active_badge.set_variant("ok")
            select_btn.setEnabled(not is_active)

        self.wizard_btn.setText(tr("home.wizard.edit" if has_domain else "home.wizard.setup"))

    def refresh_transport_status(self, *, is_quick: bool, has_domain: bool) -> None:
        self.refresh_providers(
            active_provider=PROVIDER_CF_QUICK if is_quick else PROVIDER_CF_NAMED,
            has_domain=has_domain,
        )

    def set_legacy_openai_migration(
        self,
        *,
        migrated: bool,
        has_secret: bool,
        migrated_from: str = "",
    ) -> None:
        self._migration_source = migrated_from or ("openai_tunnel" if (migrated or has_secret) else "")
        self.migration_banner.setVisible(bool(migrated or has_secret or self._migration_source == "local_only"))
        self.purge_openai_secret_btn.setVisible(has_secret)
        banner_key = (
            "conn.local_removed.banner"
            if self._migration_source == "local_only" and not has_secret
            else "conn.openai_removed.banner"
        )
        self.migration_banner.message_label.setText(tr(banner_key))

    def retranslate(self) -> None:
        self.set_header(tr("conn.title"), tr("conn.lead"))
        banner_key = (
            "conn.local_removed.banner"
            if self._migration_source == "local_only"
            else "conn.openai_removed.banner"
        )
        self.migration_banner.message_label.setText(tr(banner_key))
        self.purge_openai_secret_btn.setText(tr("conn.openai_removed.purge_btn"))
        self.providers_header.set_texts(tr("conn.providers.title"), tr("conn.providers.note"))
        for _pid, (key, name, active_badge, select_btn, config_btn, diag_btn) in self.provider_rows.items():
            name.setText(tr(f"conn.provider.{key}"))
            active_badge.setText(tr("conn.badge.active"))
            select_btn.setText(tr("conn.btn.select"))
            config_btn.setText(tr("conn.btn.configure"))
            diag_btn.setText(tr("conn.btn.diagnose"))
        self.guide_btn.setText(tr("home.guide.open"))
        self.token_header.set_texts(tr("conn.token.title"), tr("conn.token.hint"))
        self.token_edit.setPlaceholderText(tr("conn.token.placeholder"))
        visible = self.token_edit.echoMode() == QLineEdit.EchoMode.Normal
        self.token_eye.setText(tr("conn.token.hide" if visible else "conn.token.show"))
        self.token_paste.setText(tr("conn.token.paste"))
        self.token_save.setText(tr("conn.token.save"))
        self.token_copy.setText(tr("conn.token.copy"))
        self.token_gen.setText(tr("conn.token.gen"))
        self.proxy_title.setText(tr("conn.proxy.title"))
        self.proxy_page.retranslate()

    def apply_theme(self) -> None:
        self.migration_banner.apply_theme()
        for _pid, (_k, _n, active_badge, _s, _c, _d) in self.provider_rows.items():
            active_badge.set_variant("ok")
