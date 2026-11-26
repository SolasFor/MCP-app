"""Connections & Transports page: flat hairline sections for providers, owner token, and proxy."""
from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.config import (
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_NGROK,
    PROVIDER_TAILSCALE,
)
from app.ui import icons, theme
from app.ui.components.cards import Badge, Divider, ErrorBanner, FlowLayout, Section
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.proxy_page import ProxyPage


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    if obj_name in ("Link", "SubtleLink"):
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

    provider_selected = pyqtSignal(str)
    provider_configure_requested = pyqtSignal(str)
    provider_diagnose_requested = pyqtSignal(str)
    provider_guide_requested = pyqtSignal(str, arguments=["provider_id"])
    purge_openai_secret_requested = pyqtSignal()
    token_edited = pyqtSignal(str)
    token_save_requested = pyqtSignal()
    token_generate_requested = pyqtSignal()
    copy_requested = pyqtSignal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self._migration_source = ""
        # The complete connection form lives in a single, softly outlined surface.
        outer_content = self.content
        header_item = outer_content.takeAt(0)
        self.connection_panel = QFrame()
        self.connection_panel.setObjectName("ConnectionPanel")
        self.content = QVBoxLayout(self.connection_panel)
        self.content.setContentsMargins(14, 14, 14, 14)
        self.content.setSpacing(14)
        if header_item is not None:
            self.content.addItem(header_item)
        outer_content.addWidget(self.connection_panel)
        outer_content.addStretch(1)

        self.migration_banner = ErrorBanner()
        self.purge_openai_secret_btn = _button("", "Danger")
        self.purge_openai_secret_btn.clicked.connect(self.purge_openai_secret_requested.emit)
        self.migration_banner.actions_layout.addWidget(self.purge_openai_secret_btn)
        self.migration_banner.hide()
        self.content.addWidget(self.migration_banner)

        # --- Section 1: Compact, aligned transport rows
        self.providers_section = Section(spacing=6)
        self.providers_header = self.providers_section.header

        # provider_id -> (key, name_label, active_badge, select_btn, menu_btn, menu)
        self.provider_rows: dict[
            str,
            tuple[str, QLabel, Badge, QPushButton, QPushButton, QMenu],
        ] = {}
        list_col = QVBoxLayout()
        list_col.setContentsMargins(0, 2, 0, 0)
        list_col.setSpacing(8)
        for pid, key in _PROVIDER_SPEC:
            row_w = QFrame()
            row_w.setObjectName("ProviderRow")
            row_w.setMinimumHeight(38)
            row = QHBoxLayout(row_w)
            row.setContentsMargins(7, 4, 5, 4)
            row.setSpacing(8)

            name = QLabel()
            name.setObjectName("ProviderName")
            name.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            active_badge = Badge("", variant="ok")
            active_badge.setObjectName("ProviderStatus")
            active_badge.hide()
            badge_slot = QWidget()
            badge_slot.setFixedWidth(76)
            badge_layout = QHBoxLayout(badge_slot)
            badge_layout.setContentsMargins(0, 0, 0, 0)
            badge_layout.addStretch(1)
            badge_layout.addWidget(active_badge)

            select_btn = _button("", "ProviderSelect")
            select_btn.setMinimumWidth(58)
            select_btn.setFixedHeight(25)
            select_btn.clicked.connect(lambda _c=False, p=pid: self.provider_selected.emit(p))
            menu_btn = _button("", "ProviderMenu")
            menu_btn.setFixedSize(24, 25)
            menu_btn.setIconSize(QSize(15, 15))
            menu_btn.setIcon(icons.vector_icon("more", theme.TEXT_MUTED, 15))
            menu_btn.setCursor(Qt.CursorShape.ArrowCursor)
            menu = QMenu(menu_btn)
            configure = QAction(menu)
            menu.addAction(configure)
            configure.triggered.connect(lambda _c=False, p=pid: self.provider_configure_requested.emit(p))
            diagnose = QAction(menu)
            menu.addAction(diagnose)
            diagnose.triggered.connect(lambda _c=False, p=pid: self.provider_diagnose_requested.emit(p))
            menu.addSeparator()
            guide = QAction(menu)
            menu.addAction(guide)
            guide.triggered.connect(lambda _c=False, p=pid: self.provider_guide_requested.emit(p))
            menu_btn.setMenu(menu)
            row_w.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            row_w.customContextMenuRequested.connect(
                lambda pos, w=row_w, m=menu: m.popup(w.mapToGlobal(pos))
            )

            row.addWidget(name, 1)
            row.addWidget(badge_slot, 0)
            row.addWidget(select_btn, 0)
            row.addWidget(menu_btn, 0)
            list_col.addWidget(row_w)
            self.provider_rows[pid] = (key, name, active_badge, select_btn, menu_btn, menu)
        self.providers_section.body.addLayout(list_col)

        self.content.addWidget(self.providers_section)

        self.content.addWidget(Divider())

        # --- Section 2: MCP Owner Token
        self.token_section = Section(spacing=8)
        self.token_header = self.token_section.header

        t_input_row = QHBoxLayout()
        t_input_row.setSpacing(6)
        self.token_edit = QLineEdit()
        self.token_edit.setObjectName("OwnerTokenInput")
        self.token_edit.setFixedHeight(36)
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_edit.setMinimumWidth(140)
        self.token_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.token_edit.textEdited.connect(self.token_edited.emit)
        self.token_edit.returnPressed.connect(self.token_save_requested.emit)
        self.token_eye = _button("", "OwnerTokenIcon")
        self.token_eye.setFixedSize(29, 29)
        self.token_eye.setIconSize(QSize(15, 15))
        self.token_eye.clicked.connect(self.toggle_token_visibility)
        self.token_copy = _button("", "OwnerTokenIcon")
        self.token_copy.setFixedSize(29, 29)
        self.token_copy.setIconSize(QSize(15, 15))
        self.token_copy.setProperty("iconOnly", True)
        self.token_copy.clicked.connect(lambda: self.copy_requested.emit("token", self.token_copy))
        t_input_row.addWidget(self.token_edit, 1)
        t_input_row.addWidget(self.token_eye, 0)
        t_input_row.addWidget(self.token_copy, 0)
        self.token_section.body.addLayout(t_input_row)

        t_actions = FlowLayout(spacing=6)
        self.token_paste = _button("", "Ghost")
        self.token_paste.clicked.connect(self._paste_token)
        self.token_gen = _button("")
        self.token_gen.clicked.connect(self.token_generate_requested.emit)
        self.token_save = _button("", "Accent")
        self.token_save.clicked.connect(self.token_save_requested.emit)
        self.token_save.hide()
        # Keep paste/generate available in the token field's context menu.
        # The explicit Save action appears only for unsaved edits.
        self.token_paste.setParent(self)
        self.token_gen.setParent(self)
        self.token_paste.hide()
        self.token_gen.hide()
        t_actions.addWidget(self.token_save)
        self.token_section.body.addLayout(t_actions)
        self.token_edit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.token_edit.customContextMenuRequested.connect(self._open_token_menu)

        self.token_error = QLabel("")
        self.token_error.setObjectName("Error")
        self.token_error.setWordWrap(True)
        self.token_error.hide()
        self.token_section.body.addWidget(self.token_error)

        self.token_warning = QLabel("")
        self.token_warning.setObjectName("Hint")
        self.token_warning.setWordWrap(True)
        self.token_warning.hide()
        self.token_section.body.addWidget(self.token_warning)
        self.content.addWidget(self.token_section)

        self.content.addWidget(Divider())

        # --- Section 3: Proxy
        self.proxy_section = Section(spacing=8)
        self.proxy_title = self.proxy_section.header.title_label
        self.proxy_page = ProxyPage()
        self.proxy_section.body.addWidget(self.proxy_page)
        self.content.addWidget(self.proxy_section)

        self.retranslate()
        self.apply_theme()

    def _open_token_menu(self, pos) -> None:  # noqa: ANN001
        menu = self.token_edit.createStandardContextMenu()
        menu.addSeparator()
        paste = menu.addAction(tr("conn.token.paste"))
        paste.triggered.connect(self.token_paste.click)
        generate = menu.addAction(tr("conn.token.gen"))
        generate.triggered.connect(self.token_gen.click)
        menu.exec(self.token_edit.mapToGlobal(pos))
        menu.deleteLater()

    def _paste_token(self) -> None:
        clip = QGuiApplication.clipboard()
        raw = clip.text().rstrip("\r\n") if clip is not None else ""
        if raw == "":
            return
        self.token_edit.setText(raw)
        self.token_edited.emit(raw)

    def set_token_visible(self, visible: bool) -> None:
        self.token_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )
        label = tr("conn.token.hide" if visible else "conn.token.show")
        self.token_eye.setToolTip(label)
        self.token_eye.setAccessibleName(label)
        self.token_eye.setIcon(icons.vector_icon("eye", theme.ACCENT if visible else theme.TEXT_MUTED, 15))

    def toggle_token_visibility(self) -> None:
        self.set_token_visible(self.token_edit.echoMode() == QLineEdit.EchoMode.Password)

    def refresh_providers(
        self,
        *,
        active_provider: str,
        statuses: dict[str, dict] | None = None,  # noqa: ARG002
        has_domain: bool = False,  # noqa: ARG002
    ) -> None:
        for pid, (_key, _name, active_badge, select_btn, _cfg, _diag) in self.provider_rows.items():
            is_active = pid == active_provider
            active_badge.setVisible(is_active)
            if is_active:
                active_badge.setText(tr("conn.badge.active"))
                active_badge.set_variant("ok")
            select_btn.setEnabled(not is_active)

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
        self.set_header(tr("conn.title"), "")
        banner_key = (
            "conn.local_removed.banner"
            if self._migration_source == "local_only"
            else "conn.openai_removed.banner"
        )
        self.migration_banner.message_label.setText(tr(banner_key))
        self.purge_openai_secret_btn.setText(tr("conn.openai_removed.purge_btn"))
        self.providers_header.set_texts(tr("conn.providers.title"))
        for _pid, (key, name, active_badge, select_btn, menu_btn, menu) in self.provider_rows.items():
            text = tr(f"conn.provider.{key}")
            name.setText(text)
            name.setToolTip(text)
            active_badge.setText(tr("conn.badge.active"))
            select_btn.setText(tr("conn.btn.select"))
            menu_btn.setToolTip(tr("conn.btn.more"))
            menu_btn.setAccessibleName(f"{text}: {tr('conn.btn.more')}")
            configure, diagnose, _, guide = menu.actions()
            configure.setText(tr("conn.btn.configure"))
            diagnose.setText(tr("conn.btn.diagnose"))
            guide.setText(tr("conn.btn.guide"))
        self.token_header.set_texts(tr("conn.token.title"))
        self.token_edit.setToolTip(tr("conn.token.hint"))
        self.token_edit.setPlaceholderText(tr("conn.token.placeholder"))
        visible = self.token_edit.echoMode() == QLineEdit.EchoMode.Normal
        label = tr("conn.token.hide" if visible else "conn.token.show")
        self.token_eye.setToolTip(label)
        self.token_eye.setAccessibleName(label)
        self.token_eye.setIcon(icons.vector_icon("eye", theme.ACCENT if visible else theme.TEXT_MUTED, 15))
        self.token_paste.setText(tr("conn.token.paste"))
        self.token_save.setText(tr("conn.token.save"))
        self.token_copy.setToolTip(tr("conn.token.copy"))
        self.token_copy.setAccessibleName(tr("conn.token.copy"))
        self.token_gen.setText(tr("conn.token.gen"))
        self.proxy_title.setText(tr("conn.proxy.title"))
        self.proxy_page.retranslate()

    def apply_theme(self) -> None:
        self.migration_banner.apply_theme()
        for _pid, (_k, _n, active_badge, _s, menu_btn, _d) in self.provider_rows.items():
            active_badge.set_variant("ok")
            menu_btn.setIcon(icons.vector_icon("more", theme.TEXT_MUTED, 15))
        self.token_copy.setIcon(icons.vector_icon("copy", theme.TEXT_MUTED, 15))
        self.set_token_visible(self.token_edit.echoMode() == QLineEdit.EchoMode.Normal)
