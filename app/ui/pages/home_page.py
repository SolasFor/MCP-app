"""Unified Overview / Home page: Engine state, endpoint, quick/named mode, OAuth profile, client summary."""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from app.config import TUNNEL_NAMED, TUNNEL_QUICK
from app.ui import theme
from app.ui.components.cards import Card, Divider, ErrorBanner, SectionHeader
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.widgets import StatusRow


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class HomePage(PageScaffold):
    """Unified operational dashboard keeping quick control over Engine, URL, and OAuth profiles."""

    toggle_requested = pyqtSignal()
    emergency_stop_requested = pyqtSignal()
    open_page_requested = pyqtSignal(str)
    domain_wizard_requested = pyqtSignal()
    domain_guide_requested = pyqtSignal()
    mode_selected = pyqtSignal(str)
    url_edited = pyqtSignal(str)
    url_save_requested = pyqtSignal()
    copy_requested = pyqtSignal(str, object)
    access_profile_changed = pyqtSignal(int)
    allowlist_requested = pyqtSignal()
    diagnostics_requested = pyqtSignal()

    def __init__(self, parent=None) -> None:  # noqa: ANN001
        super().__init__(scroll=True, parent=parent)

        # --- Hero Engine Card
        self.hero_card = Card(elevated=True, margins=(20, 18, 20, 18), spacing=12)
        top = QHBoxLayout()
        top.setSpacing(14)
        left = QVBoxLayout()
        left.setSpacing(3)
        self.services_title = QLabel()
        self.services_title.setObjectName("SectionTitle")
        self.mode_caption = QLabel()
        self.mode_caption.setObjectName("Hint")
        self.mode_caption.setWordWrap(True)
        left.addWidget(self.services_title)
        left.addWidget(self.mode_caption)
        top.addLayout(left, 1)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.emergency_btn = _button("", "Danger")
        self.emergency_btn.clicked.connect(self.emergency_stop_requested.emit)
        self.toggle_btn = _button("", "Primary")
        self.toggle_btn.setMinimumWidth(148)
        self.toggle_btn.clicked.connect(self.toggle_requested.emit)
        controls.addWidget(self.emergency_btn)
        controls.addWidget(self.toggle_btn)
        top.addLayout(controls, 0)
        self.hero_card.body.addLayout(top)
        self.hero_card.body.addWidget(Divider())

        self.server_row = StatusRow("")
        self.tunnel_row = StatusRow("")
        self.hero_card.body.addWidget(self.server_row)
        self.hero_card.body.addWidget(self.tunnel_row)
        self.content.addWidget(self.hero_card)

        # --- Actionable Error Banner
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

        # --- Client Endpoint & Mode Card
        endpoint_card = Card()
        head = QHBoxLayout()
        self.url_card_title = QLabel()
        self.url_card_title.setObjectName("SectionTitle")
        head.addWidget(self.url_card_title)
        head.addStretch(1)

        seg = QFrame()
        seg.setObjectName("SegmentGroup")
        seg_row = QHBoxLayout(seg)
        seg_row.setContentsMargins(3, 3, 3, 3)
        seg_row.setSpacing(2)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.mode_buttons: dict[str, QPushButton] = {}
        for mode in (TUNNEL_QUICK, TUNNEL_NAMED):
            btn = _button("", "Segment")
            btn.setCheckable(True)
            btn.setMinimumWidth(140)
            btn.clicked.connect(lambda _c=False, m=mode: self.mode_selected.emit(m))
            self.mode_group.addButton(btn)
            self.mode_buttons[mode] = btn
            seg_row.addWidget(btn)
        head.addWidget(seg)
        endpoint_card.body.addLayout(head)

        self.ov_url = QLabel("")
        self.ov_url.setObjectName("Mono")
        self.ov_url.setWordWrap(True)
        self.ov_url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        endpoint_card.body.addWidget(self.ov_url)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.ov_copy = _button("")
        self.ov_copy.clicked.connect(lambda: self.copy_requested.emit("url", self.ov_copy))
        self.ov_copy_token = _button("")
        self.ov_copy_token.clicked.connect(lambda: self.copy_requested.emit("token", self.ov_copy_token))
        self.open_connections_btn = _button("", "Link")
        self.open_connections_btn.clicked.connect(lambda: self.open_page_requested.emit("connections"))
        actions.addWidget(self.ov_copy)
        actions.addWidget(self.ov_copy_token)
        actions.addStretch(1)
        actions.addWidget(self.open_connections_btn)
        endpoint_card.body.addLayout(actions)

        self.mode_hint = QLabel("")
        self.mode_hint.setObjectName("Hint")
        self.mode_hint.setWordWrap(True)
        endpoint_card.body.addWidget(self.mode_hint)

        links_row = QHBoxLayout()
        links_row.setSpacing(16)
        self.wizard_link = _button("", "Link")
        self.wizard_link.clicked.connect(self.domain_wizard_requested.emit)
        self.guide_link = _button("", "Link")
        self.guide_link.clicked.connect(self.domain_guide_requested.emit)
        links_row.addWidget(self.wizard_link)
        links_row.addWidget(self.guide_link)
        links_row.addStretch(1)
        endpoint_card.body.addLayout(links_row)

        url_edit_row = QHBoxLayout()
        url_edit_row.setSpacing(8)
        self.url_edit = QLineEdit()
        self.url_edit.textEdited.connect(self.url_edited.emit)
        self.url_edit.returnPressed.connect(self.url_save_requested.emit)
        self.url_save = _button("", "Accent")
        self.url_save.clicked.connect(self.url_save_requested.emit)
        self.url_save.hide()
        self.url_copy = _button("")
        self.url_copy.clicked.connect(lambda: self.copy_requested.emit("url", self.url_copy))
        url_edit_row.addWidget(self.url_edit, 1)
        url_edit_row.addWidget(self.url_save)
        url_edit_row.addWidget(self.url_copy)
        endpoint_card.body.addLayout(url_edit_row)

        self.url_error = QLabel("")
        self.url_error.setObjectName("Error")
        self.url_error.setWordWrap(True)
        self.url_error.hide()
        endpoint_card.body.addWidget(self.url_error)

        self.client_hint = QLabel("")
        self.client_hint.setObjectName("Hint")
        self.client_hint.setWordWrap(True)
        endpoint_card.body.addWidget(self.client_hint)
        self.content.addWidget(endpoint_card)

        # --- Access Profile & Clients Card
        access_card = Card()
        self.access_header = SectionHeader()
        access_card.body.addWidget(self.access_header)

        self.access_label = QLabel()
        self.access_label.setObjectName("FieldLabel")
        access_card.body.addWidget(self.access_label)

        self.access_profile = QComboBox()
        self.access_profile.addItem("", "safe")
        self.access_profile.addItem("", "allowlist")
        self.access_profile.addItem("", "full")
        self.access_profile.setEnabled(False)
        self.access_profile.currentIndexChanged.connect(self.access_profile_changed.emit)
        access_card.body.addWidget(self.access_profile)

        self.access_profile_hint = QLabel()
        self.access_profile_hint.setObjectName("Hint")
        self.access_profile_hint.setWordWrap(True)
        access_card.body.addWidget(self.access_profile_hint)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.allowlist_btn = _button("")
        self.allowlist_btn.clicked.connect(self.allowlist_requested.emit)
        self.clients_btn = _button("", "Accent")
        self.clients_btn.clicked.connect(lambda: self.open_page_requested.emit("clients"))
        self.diag_btn = _button("")
        self.diag_btn.clicked.connect(self.diagnostics_requested.emit)
        btn_row.addWidget(self.allowlist_btn)
        btn_row.addWidget(self.clients_btn)
        btn_row.addWidget(self.diag_btn)
        btn_row.addStretch(1)
        access_card.body.addLayout(btn_row)

        access_card.body.addWidget(Divider())
        self.clients_summary_lbl = QLabel()
        self.clients_summary_lbl.setObjectName("FieldLabel")
        access_card.body.addWidget(self.clients_summary_lbl)

        self.clients_table = DataTable(["", "", ""])
        self.clients_table.setMaximumHeight(175)
        self.clients_table.hide()
        access_card.body.addWidget(self.clients_table)

        self.clients_empty_lbl = QLabel()
        self.clients_empty_lbl.setObjectName("Hint")
        self.clients_empty_lbl.setWordWrap(True)
        access_card.body.addWidget(self.clients_empty_lbl)
        self.content.addWidget(access_card)

        self.content.addStretch(1)
        self.retranslate()

    def set_clients_summary(self, rows: list[tuple[str, str, str]]) -> None:
        from PyQt6.QtWidgets import QTableWidgetItem

        if not rows:
            self.clients_table.setRowCount(0)
            self.clients_table.hide()
            self.clients_empty_lbl.show()
            return
        self.clients_empty_lbl.hide()
        self.clients_table.show()
        self.clients_table.setRowCount(len(rows[:5]))
        for idx, (name, status, mode) in enumerate(rows[:5]):
            self.clients_table.setItem(idx, 0, QTableWidgetItem(name))
            self.clients_table.setItem(idx, 1, QTableWidgetItem(status))
            self.clients_table.setItem(idx, 2, QTableWidgetItem(mode))

    def retranslate(self) -> None:
        self.services_title.setText(tr("home.services"))
        self.emergency_btn.setText(tr("home.btn.emergency"))
        self.emergency_btn.setToolTip(tr("home.btn.emergency_tip"))
        self.server_row.set_title(tr("home.srv.mcp"))
        self.tunnel_row.set_title(tr("home.srv.tunnel"))

        self.error_banner.message_label.setText(tr("home.err.banner"))
        self.err_logs_btn.setText(tr("home.err.logs"))
        self.err_proxy_btn.setText(tr("home.err.proxy"))
        self.err_domain_btn.setText(tr("home.err.domain"))

        self.url_card_title.setText(tr("home.url.title"))
        self.mode_buttons[TUNNEL_QUICK].setText(tr("home.mode.quick"))
        self.mode_buttons[TUNNEL_QUICK].setToolTip(tr("home.mode.quick_tip"))
        self.mode_buttons[TUNNEL_NAMED].setText(tr("home.mode.named"))
        self.mode_buttons[TUNNEL_NAMED].setToolTip(tr("home.mode.named_tip"))
        self.ov_copy.setText(tr("home.url.copy"))
        self.ov_copy_token.setText(tr("home.url.copy_token"))
        self.open_connections_btn.setText(tr("home.connections.open"))
        self.guide_link.setText(tr("home.guide.open"))
        self.url_save.setText(tr("common.save"))
        self.url_copy.setText(tr("conn.token.copy"))
        self.client_hint.setText(tr("home.url.client_hint"))

        self.access_header.set_texts(tr("home.access.title"), tr("home.access.desc"))
        self.access_label.setText(tr("home.access.label"))
        self.access_profile.blockSignals(True)
        for idx, key in enumerate(("safe", "allowlist", "full")):
            self.access_profile.setItemText(idx, tr(f"home.access.{key}"))
        self.access_profile.blockSignals(False)
        self.allowlist_btn.setText(tr("home.access.allowlist_btn"))
        self.clients_btn.setText(tr("home.access.clients_btn"))
        self.diag_btn.setText(tr("home.access.diag_btn"))
        self.clients_summary_lbl.setText(tr("home.clients.summary_title"))
        self.clients_empty_lbl.setText(tr("home.clients.empty"))
        self.clients_table.setHorizontalHeaderLabels(
            [tr("clients.col.name"), tr("clients.col.status"), tr("clients.col.rights")]
        )

    def apply_theme(self) -> None:
        self.error_banner.apply_theme()
        if not self.ov_url.text().startswith("http"):
            self.ov_url.setStyleSheet(f"color: {theme.TEXT_FAINT};")
        else:
            self.ov_url.setStyleSheet("")
