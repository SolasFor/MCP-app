"""Compact minimalist navigation sidebar matching approved visual reference."""
from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app import APP_NAME
from app.ui import icons, theme, tokens
from app.ui.components.cards import Divider
from app.ui.i18n import tr
from app.ui.widgets import NavButton, StatusDot


@dataclass(frozen=True)
class NavItemSpec:
    page_id: str
    i18n_key: str
    icon: str
    section: str  # "primary" | "upcoming"
    tag: str = ""
    shortcut: str = ""


class Sidebar(QFrame):
    """Compact navigation rail with 16px vector icons and clean bottom server status."""

    page_selected = pyqtSignal(str)
    palette_requested = pyqtSignal()
    collapse_toggled = pyqtSignal(bool)

    EXPANDED_WIDTH = tokens.SIDEBAR_WIDTH
    COLLAPSED_WIDTH = tokens.SIDEBAR_COLLAPSED_WIDTH

    def __init__(self, specs: tuple[NavItemSpec, ...], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self._specs = specs
        self._collapsed = False
        self._buttons: dict[str, NavButton] = {}
        self._order: list[str] = [s.page_id for s in specs]
        self._current_id = specs[0].page_id if specs else "home"

        self.setFixedWidth(self.EXPANDED_WIDTH)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 12, 10, 12)
        root.setSpacing(8)

        # Brand + collapse toggle
        brand = QHBoxLayout()
        brand.setContentsMargins(6, 0, 2, 4)
        brand.setSpacing(8)
        self._logo = QLabel()
        self._logo.setPixmap(icons.app_icon().pixmap(20, 20))
        brand.addWidget(self._logo)
        self._wordmark = QLabel(APP_NAME)
        self._wordmark.setObjectName("Wordmark")
        brand.addWidget(self._wordmark)
        brand.addStretch(1)

        self._collapse_btn = QPushButton("")
        self._collapse_btn.setObjectName("IconBtn")
        self._collapse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._collapse_btn.setFixedSize(24, 24)
        self._collapse_btn.setIconSize(QSize(14, 14))
        self._collapse_btn.clicked.connect(lambda: self.set_collapsed(not self._collapsed, emit=True))
        brand.addWidget(self._collapse_btn)
        root.addLayout(brand)

        # Scrollable nav items
        scroll = QScrollArea()
        scroll.setObjectName("NavScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_host = QWidget()
        nav_col = QVBoxLayout(nav_host)
        nav_col.setContentsMargins(0, 2, 0, 2)
        nav_col.setSpacing(2)

        for spec in specs:
            btn = self._create_nav_btn(spec)
            nav_col.addWidget(btn)

        nav_col.addStretch(1)
        scroll.setWidget(nav_host)
        root.addWidget(scroll, 1)

        # Clean hairline + bottom server status row
        root.addWidget(Divider())
        self._chip = QFrame()
        self._chip.setObjectName("SidebarFooter")
        chip_row = QHBoxLayout(self._chip)
        chip_row.setContentsMargins(6, 6, 4, 2)
        chip_row.setSpacing(8)
        self._chip_dot = StatusDot(diameter=8)
        chip_row.addWidget(self._chip_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self._chip_text = QLabel("")
        self._chip_text.setObjectName("SidebarStatus")
        chip_row.addWidget(self._chip_text, 1)
        root.addWidget(self._chip)

        self.retranslate()
        self.apply_theme()

    def _create_nav_btn(self, spec: NavItemSpec) -> NavButton:
        btn = NavButton(tr(spec.i18n_key), icon_name=spec.icon, tag_text=spec.tag)
        if spec.shortcut:
            btn.setToolTip(f"{tr(spec.i18n_key)} ({spec.shortcut})")
        else:
            btn.setToolTip(tr(spec.i18n_key))
        btn.clicked.connect(lambda _c=False, pid=spec.page_id: self.page_selected.emit(pid))
        self._buttons[spec.page_id] = btn
        return btn

    def button(self, page_id: str) -> NavButton:
        return self._buttons[page_id]

    @property
    def is_collapsed(self) -> bool:
        return self._collapsed

    def set_current(self, page_id: str) -> None:
        if page_id in self._buttons:
            self._current_id = page_id
            self._buttons[page_id].setChecked(True)

    def set_collapsed(self, collapsed: bool, *, emit: bool = False) -> None:
        self._collapsed = collapsed
        self.setFixedWidth(self.COLLAPSED_WIDTH if collapsed else self.EXPANDED_WIDTH)
        self._wordmark.setVisible(not collapsed)
        self._chip_text.setVisible(not collapsed)
        tip = tr("sidebar.expand" if collapsed else "sidebar.collapse")
        self._collapse_btn.setToolTip(tip)
        self._collapse_btn.setAccessibleName(tip)
        for btn in self._buttons.values():
            btn.set_collapsed(collapsed)
        if emit:
            self.collapse_toggled.emit(collapsed)

    def set_engine_status(self, label: str, detail: str, color: str, pending: bool) -> None:
        self._chip_dot.set_state(color, pending)
        self._chip_text.setText(label)
        if color in (theme.WARN, theme.ERR):
            self._chip_text.setStyleSheet(f"color: {color};")
        elif color == theme.OK:
            self._chip_text.setStyleSheet(f"color: {theme.TEXT};")
        else:
            self._chip_text.setStyleSheet("")
        self._chip.setToolTip(f"{label} — {detail}" if detail else label)

    def set_badge(self, page_id: str, count: int) -> None:
        if page_id in self._buttons:
            self._buttons[page_id].set_badge(count)

    def retranslate(self) -> None:
        tip = tr("sidebar.expand" if self._collapsed else "sidebar.collapse")
        self._collapse_btn.setToolTip(tip)
        self._collapse_btn.setAccessibleName(tip)
        for spec in self._specs:
            btn = self._buttons[spec.page_id]
            title = tr(spec.i18n_key)
            btn.set_label(title)
            btn.setToolTip(f"{title} ({spec.shortcut})" if spec.shortcut else title)

    def apply_theme(self) -> None:
        self._collapse_btn.setIcon(icons.vector_icon("sidebar", theme.TEXT_MUTED, 14))
        for btn in self._buttons.values():
            btn.refresh_theme()
