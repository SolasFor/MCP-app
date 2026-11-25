"""Minimalist Home page matching the approved visual reference."""
from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from app.ui import icons, theme
from app.ui.components.cards import Card, CopyField, Divider, ErrorBanner
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.widgets import StatusDot, StatusRow


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class HomePage(PageScaffold):
    """Primary operational view: server hero card, connection URL bar, and real component statuses."""

    toggle_requested = pyqtSignal()
    emergency_stop_requested = pyqtSignal()
    open_page_requested = pyqtSignal(str)
    domain_wizard_requested = pyqtSignal()
    connection_diagnostics_requested = pyqtSignal()
    copy_requested = pyqtSignal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self._is_running = False

        # --- Hero Server Status Card (single card on Home)
        self.hero_card = Card(margins=(16, 14, 16, 14), spacing=0)
        hero_row = QHBoxLayout()
        hero_row.setContentsMargins(0, 0, 0, 0)
        hero_row.setSpacing(16)

        left_col = QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(3)

        status_line = QHBoxLayout()
        status_line.setContentsMargins(0, 0, 0, 0)
        status_line.setSpacing(8)
        self.hero_dot = StatusDot(diameter=9)
        self.status_title_lbl = QLabel()
        self.status_title_lbl.setObjectName("HeroStatusTitle")
        status_line.addWidget(self.hero_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        status_line.addWidget(self.status_title_lbl, 1)
        left_col.addLayout(status_line)

        self.local_addr_lbl = QLabel()
        self.local_addr_lbl.setObjectName("ServiceDetail")
        self.local_addr_lbl.setContentsMargins(17, 1, 0, 0)
        left_col.addWidget(self.local_addr_lbl)

        self.tunnel_status_lbl = QLabel()
        self.tunnel_status_lbl.setObjectName("Hint")
        self.tunnel_status_lbl.setContentsMargins(17, 0, 0, 0)
        left_col.addWidget(self.tunnel_status_lbl)

        hero_row.addLayout(left_col, 1)

        self.toggle_btn = _button("", "Primary")
        self.toggle_btn.setMinimumWidth(124)
        self.toggle_btn.setMinimumHeight(34)
        self.toggle_btn.setIconSize(QSize(13, 13))
        self.toggle_btn.clicked.connect(self.toggle_requested.emit)
        hero_row.addWidget(self.toggle_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        self.hero_card.body.addLayout(hero_row)
        self.content.addWidget(self.hero_card)

        # --- Conditional Actionable Error Banner
        self.error_banner = ErrorBanner()
        self.err_logs_btn = _button("", "Link")
        self.err_logs_btn.clicked.connect(lambda: self.open_page_requested.emit("logs"))
        self.err_proxy_btn = _button("", "Link")
        self.err_proxy_btn.clicked.connect(lambda: self.open_page_requested.emit("connections"))
        self.err_domain_btn = _button("", "Link")
        self.err_domain_btn.clicked.connect(self.domain_wizard_requested.emit)
        for btn in (self.err_logs_btn, self.err_proxy_btn, self.err_domain_btn):
            self.error_banner.actions_layout.addWidget(btn)
        self.error_banner.hide()
        self.content.addWidget(self.error_banner)

        # --- Connection URL section (flat, cardless)
        url_block = QVBoxLayout()
        url_block.setContentsMargins(0, 4, 0, 0)
        url_block.setSpacing(8)
        self.url_section_lbl = QLabel()
        self.url_section_lbl.setObjectName("SectionTitle")
        url_block.addWidget(self.url_section_lbl)

        self.copy_field = CopyField()
        self.copy_field.copy_clicked.connect(lambda _val, btn: self.copy_requested.emit("url", btn))
        url_block.addWidget(self.copy_field)

        # Backwards-compatible button aliases used by MainWindow / tests
        self.ov_copy = self.copy_field.copy_button
        self.url_copy = self.copy_field.copy_button
        self.content.addLayout(url_block)

        # --- Component Status flat list (hairline rows, no outer card)
        comp_block = QVBoxLayout()
        comp_block.setContentsMargins(0, 6, 0, 0)
        comp_block.setSpacing(2)
        self.components_section_lbl = QLabel()
        self.components_section_lbl.setObjectName("SectionTitle")
        comp_block.addWidget(self.components_section_lbl)
        comp_block.addSpacing(6)

        self.server_row = StatusRow("")
        self.tunnel_row = StatusRow("")
        self.oauth_row = StatusRow("")
        comp_block.addWidget(self.server_row)
        comp_block.addWidget(Divider())
        comp_block.addWidget(self.tunnel_row)
        comp_block.addWidget(Divider())
        comp_block.addWidget(self.oauth_row)
        self.content.addLayout(comp_block)

        # --- Footer actions: secondary diagnostics link + conditional emergency stop
        footer_row = QHBoxLayout()
        footer_row.setContentsMargins(0, 2, 0, 0)
        footer_row.setSpacing(12)
        self.connection_diagnostics_btn = _button("", "SubtleLink")
        self.connection_diagnostics_btn.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.connection_diagnostics_btn.setIconSize(QSize(13, 13))
        self.connection_diagnostics_btn.clicked.connect(self.connection_diagnostics_requested.emit)
        footer_row.addWidget(self.connection_diagnostics_btn, 0, Qt.AlignmentFlag.AlignLeft)
        footer_row.addStretch(1)

        self.emergency_btn = _button("", "Danger")
        self.emergency_btn.clicked.connect(self.emergency_stop_requested.emit)
        self.emergency_btn.hide()
        footer_row.addWidget(self.emergency_btn, 0, Qt.AlignmentFlag.AlignRight)
        self.content.addLayout(footer_row)

        self.content.addStretch(1)
        self.retranslate()
        self.apply_theme()

    def set_hero_status(
        self,
        *,
        title: str,
        dot_color: str,
        pending: bool,
        local_addr: str,
        tunnel_line: str,
        running: bool,
    ) -> None:
        self._is_running = running
        self.hero_dot.set_state(dot_color, pending)
        self.status_title_lbl.setText(title)
        self.local_addr_lbl.setText(local_addr)
        self.tunnel_status_lbl.setText(tunnel_line)
        self._refresh_toggle_icon()

    def set_endpoint(self, full_url: str, *, display_text: str | None = None, muted: bool = False) -> None:
        self.copy_field.set_value(full_url, display_text=display_text, muted=muted)

    def _refresh_toggle_icon(self) -> None:
        icon_name = "stop" if self._is_running else "play"
        self.toggle_btn.setIcon(icons.vector_icon(icon_name, theme.ACCENT_TEXT, 12))

    def retranslate(self) -> None:
        self.set_header(tr("home.title"), tr("home.lead"))
        self.url_section_lbl.setText(tr("home.url.section"))
        self.copy_field.set_button_text(tr("common.copy"))
        self.copy_field.set_placeholder(tr("home.url.placeholder_quick"))
        self.components_section_lbl.setText(tr("home.components.section"))
        self.server_row.set_title(tr("home.srv.mcp"))
        self.tunnel_row.set_title(tr("home.srv.tunnel"))
        self.oauth_row.set_title(tr("home.srv.oauth"))
        self.connection_diagnostics_btn.setText(tr("home.diag_link"))
        self.emergency_btn.setText(tr("home.btn.emergency"))
        self.emergency_btn.setToolTip(tr("home.btn.emergency_tip"))

        self.error_banner.message_label.setText(tr("home.err.banner"))
        self.err_logs_btn.setText(tr("home.err.logs"))
        self.err_proxy_btn.setText(tr("home.err.proxy"))
        self.err_domain_btn.setText(tr("home.err.domain"))
        self.apply_theme()

    def apply_theme(self) -> None:
        self.error_banner.apply_theme()
        self._refresh_toggle_icon()
        self.connection_diagnostics_btn.setIcon(icons.vector_icon("chevron-right", theme.TEXT_MUTED, 13))
