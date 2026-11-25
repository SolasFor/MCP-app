"""Collapsible Linear-style navigation sidebar."""
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

from app import APP_NAME, __version__
from app.ui import effects, icons, theme
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
    """Collapsible navigation rail with Primary + Roadmap sections and Engine chip."""

    page_selected = pyqtSignal(str)
    palette_requested = pyqtSignal()
    collapse_toggled = pyqtSignal(bool)

    EXPANDED_WIDTH = 232
    COLLAPSED_WIDTH = 62

    def __init__(self, specs: tuple[NavItemSpec, ...], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self._specs = specs
        self._has_upcoming = any(s.section == "upcoming" for s in specs)
        self._collapsed = False
        self._buttons: dict[str, NavButton] = {}
        self._order: list[str] = [s.page_id for s in specs]
        self._current_id = specs[0].page_id if specs else "home"

        self.setFixedWidth(self.EXPANDED_WIDTH)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 14, 10, 12)
        root.setSpacing(6)

        # Brand + collapse button
        brand = QHBoxLayout()
        brand.setContentsMargins(4, 0, 2, 0)
        brand.setSpacing(8)
        self._logo = QLabel()
        self._logo.setPixmap(icons.app_icon().pixmap(22, 22))
        brand.addWidget(self._logo)
        self._wordmark = QLabel(APP_NAME)
        self._wordmark.setObjectName("Wordmark")
        brand.addWidget(self._wordmark)
        brand.addStretch(1)

        self._collapse_btn = QPushButton("")
        self._collapse_btn.setObjectName("Ghost")
        self._collapse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._collapse_btn.setFixedSize(26, 26)
        self._collapse_btn.clicked.connect(lambda: self.set_collapsed(not self._collapsed, emit=True))
        brand.addWidget(self._collapse_btn)
        root.addLayout(brand)

        # Quick command palette trigger
        self._palette_btn = QPushButton()
        self._palette_btn.setObjectName("PaletteTrigger")
        self._palette_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._palette_btn.setIconSize(QSize(14, 14))
        self._palette_btn.clicked.connect(self.palette_requested.emit)
        root.addWidget(self._palette_btn)

        # Scrollable nav list
        scroll = QScrollArea()
        scroll.setObjectName("NavScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_host = QWidget()
        nav_col = QVBoxLayout(nav_host)
        nav_col.setContentsMargins(0, 4, 0, 4)
        nav_col.setSpacing(2)

        self._primary_lbl = QLabel()
        self._primary_lbl.setObjectName("SidebarSection")
        nav_col.addWidget(self._primary_lbl)

        for spec in specs:
            if spec.section == "primary":
                btn = self._create_nav_btn(spec)
                nav_col.addWidget(btn)

        nav_col.addSpacing(8)
        self._upcoming_lbl = QLabel()
        self._upcoming_lbl.setObjectName("SidebarSection")
        self._upcoming_lbl.setVisible(self._has_upcoming)
        nav_col.addWidget(self._upcoming_lbl)

        for spec in specs:
            if spec.section == "upcoming":
                btn = self._create_nav_btn(spec)
                nav_col.addWidget(btn)

        nav_col.addStretch(1)
        scroll.setWidget(nav_host)
        root.addWidget(scroll, 1)

        # Engine status footer chip
        self._chip = QFrame()
        self._chip.setObjectName("StatusChip")
        chip_row = QHBoxLayout(self._chip)
        chip_row.setContentsMargins(8, 7, 10, 7)
        chip_row.setSpacing(6)
        self._chip_dot = StatusDot(diameter=8)
        chip_row.addWidget(self._chip_dot, 0, Qt.AlignmentFlag.AlignTop)
        chip_texts = QVBoxLayout()
        chip_texts.setSpacing(1)
        self._chip_text = effects.ShinyLabel("")
        self._chip_text.setObjectName("ChipText")
        self._chip_detail = QLabel("")
        self._chip_detail.setObjectName("ChipDetail")
        chip_texts.addWidget(self._chip_text)
        chip_texts.addWidget(self._chip_detail)
        self._chip_texts_holder = chip_texts
        chip_row.addLayout(chip_texts, 1)
        root.addWidget(self._chip)

        self._version_lbl = QLabel()
        self._version_lbl.setObjectName("Version")
        root.addWidget(self._version_lbl)

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
        self._primary_lbl.setVisible(not collapsed)
        self._upcoming_lbl.setVisible((not collapsed) and self._has_upcoming)
        self._chip_text.setVisible(not collapsed)
        self._chip_detail.setVisible(not collapsed)
        self._version_lbl.setVisible(not collapsed)
        self._palette_btn.setText("" if collapsed else tr("sidebar.search_btn"))
        self._collapse_btn.setToolTip(tr("sidebar.expand" if collapsed else "sidebar.collapse"))
        for btn in self._buttons.values():
            btn.set_collapsed(collapsed)
        if emit:
            self.collapse_toggled.emit(collapsed)

    def set_engine_status(self, label: str, detail: str, color: str, pending: bool) -> None:
        self._chip_dot.set_state(color, pending)
        self._chip_text.setText(label)
        self._chip_text.setStyleSheet(f"color: {color};")
        self._chip_text.set_base_color(color)
        self._chip_text.set_shine(pending)
        self._chip_detail.setText(detail)
        self._chip.setToolTip(f"{label} — {detail}" if detail else label)

    def set_badge(self, page_id: str, count: int) -> None:
        if page_id in self._buttons:
            self._buttons[page_id].set_badge(count)

    def retranslate(self) -> None:
        self._primary_lbl.setText(tr("nav.section.primary"))
        self._upcoming_lbl.setText(tr("nav.section.upcoming"))
        self._palette_btn.setText("" if self._collapsed else tr("sidebar.search_btn"))
        self._palette_btn.setToolTip(tr("topbar.palette"))
        self._collapse_btn.setToolTip(tr("sidebar.expand" if self._collapsed else "sidebar.collapse"))
        self._version_lbl.setText(tr("sidebar.version", version=__version__))
        for spec in self._specs:
            btn = self._buttons[spec.page_id]
            title = tr(spec.i18n_key)
            btn.set_label(title)
            btn.setToolTip(f"{title} ({spec.shortcut})" if spec.shortcut else title)

    def apply_theme(self) -> None:
        self._collapse_btn.setIcon(icons.vector_icon("sidebar", theme.TEXT_MUTED, 14))
        self._palette_btn.setIcon(icons.vector_icon("search", theme.TEXT_MUTED, 14))
        for btn in self._buttons.values():
            btn.refresh_theme()
