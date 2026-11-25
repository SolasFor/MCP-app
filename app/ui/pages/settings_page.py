"""Settings page: Dark/Light/System theme, RU/EN language, sidebar, startup, and storage."""
from __future__ import annotations

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from app import __version__
from app.config import Settings
from app.core import autostart
from app.paths import user_data_dir
from app.ui import theme
from app.ui.components.cards import Card, Divider
from app.ui.i18n import LANG_EN, LANG_RU, tr
from app.ui.pages.base import PageScaffold


class SettingsPage(PageScaffold):
    theme_mode_selected = pyqtSignal(str)
    language_selected = pyqtSignal(str)
    sidebar_compact_toggled = pyqtSignal(bool)
    autostart_toggled = pyqtSignal(bool)
    start_on_launch_toggled = pyqtSignal(bool)
    minimize_toggled = pyqtSignal(bool)
    auto_restart_toggled = pyqtSignal(bool)

    def __init__(self, settings: Settings, cloudflared_path: str | None, tray_available: bool,
                 parent: QWidget | None = None) -> None:
        super().__init__(scroll=True, parent=parent)
        self.settings = settings
        self._tray_available = tray_available

        # --- Appearance & Language
        app_card = Card(spacing=10)
        self.appearance_title = QLabel()
        self.appearance_title.setObjectName("SectionTitle")
        app_card.body.addWidget(self.appearance_title)

        theme_row = QHBoxLayout()
        self.theme_label = QLabel()
        self.theme_label.setObjectName("FieldLabel")
        theme_row.addWidget(self.theme_label, 1)
        theme_seg = QFrame()
        theme_seg.setObjectName("SegmentGroup")
        t_box = QHBoxLayout(theme_seg)
        t_box.setContentsMargins(3, 3, 3, 3)
        t_box.setSpacing(2)
        self._theme_group = QButtonGroup(self)
        self._theme_group.setExclusive(True)
        self.theme_buttons: dict[str, QPushButton] = {}
        for mode in (theme.THEME_SYSTEM, theme.THEME_DARK, theme.THEME_LIGHT):
            btn = QPushButton()
            btn.setObjectName("Segment")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, m=mode: self.theme_mode_selected.emit(m))
            self._theme_group.addButton(btn)
            self.theme_buttons[mode] = btn
            t_box.addWidget(btn)
        theme_row.addWidget(theme_seg)
        app_card.body.addLayout(theme_row)

        lang_row = QHBoxLayout()
        self.lang_label = QLabel()
        self.lang_label.setObjectName("FieldLabel")
        lang_row.addWidget(self.lang_label, 1)
        lang_seg = QFrame()
        lang_seg.setObjectName("SegmentGroup")
        l_box = QHBoxLayout(lang_seg)
        l_box.setContentsMargins(3, 3, 3, 3)
        l_box.setSpacing(2)
        self._lang_group = QButtonGroup(self)
        self._lang_group.setExclusive(True)
        self.lang_buttons: dict[str, QPushButton] = {}
        for lang in (LANG_RU, LANG_EN):
            btn = QPushButton()
            btn.setObjectName("Segment")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, code=lang: self.language_selected.emit(code))
            self._lang_group.addButton(btn)
            self.lang_buttons[lang] = btn
            l_box.addWidget(btn)
        lang_row.addWidget(lang_seg)
        app_card.body.addLayout(lang_row)

        app_card.body.addWidget(Divider())
        self.compact_check = QCheckBox()
        self.compact_check.setCursor(Qt.CursorShape.PointingHandCursor)
        self.compact_check.setChecked(settings.sidebar_collapsed)
        self.compact_check.toggled.connect(self.sidebar_compact_toggled.emit)
        app_card.body.addWidget(self.compact_check)
        self.content.addWidget(app_card)

        # --- Startup & Behavior
        start_card = Card(spacing=6)
        self.startup_title = QLabel()
        self.startup_title.setObjectName("SectionTitle")
        start_card.body.addWidget(self.startup_title)

        self.autostart = QCheckBox()
        self.autostart.setEnabled(autostart.is_supported())
        self.autostart.setChecked(autostart.is_enabled())
        self.autostart.toggled.connect(self.autostart_toggled.emit)

        self.start_on_launch = QCheckBox()
        self.start_on_launch.setChecked(settings.start_services_on_launch)
        self.start_on_launch.toggled.connect(self.start_on_launch_toggled.emit)

        self.minimize = QCheckBox()
        self.minimize.setEnabled(tray_available)
        self.minimize.setChecked(tray_available and settings.minimize_to_tray_on_close)
        self.minimize.toggled.connect(self.minimize_toggled.emit)

        self.auto_restart = QCheckBox()
        self.auto_restart.setChecked(settings.auto_restart)
        self.auto_restart.toggled.connect(self.auto_restart_toggled.emit)

        for check in (self.autostart, self.start_on_launch, self.minimize, self.auto_restart):
            check.setCursor(Qt.CursorShape.PointingHandCursor)
            start_card.body.addWidget(check)
        self.content.addWidget(start_card)

        # --- Components & Storage
        comp_card = Card()
        self.components_title = QLabel()
        self.components_title.setObjectName("SectionTitle")
        comp_card.body.addWidget(self.components_title)

        cf_lbl = QLabel("cloudflared")
        cf_lbl.setObjectName("FieldLabel")
        comp_card.body.addWidget(cf_lbl)
        cf_val = QLabel(cloudflared_path or "not found")
        cf_val.setObjectName("ServiceDetail")
        cf_val.setWordWrap(True)
        cf_val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        comp_card.body.addWidget(cf_val)

        data_dir = user_data_dir()
        data_row = QHBoxLayout()
        data_label = QLabel(str(data_dir))
        data_label.setObjectName("ServiceDetail")
        data_label.setWordWrap(True)
        data_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data_row.addWidget(data_label, 1)
        self.open_folder_btn = QPushButton()
        self.open_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_btn.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(data_dir)))
        )
        data_row.addWidget(self.open_folder_btn)
        comp_card.body.addLayout(data_row)

        ver = QLabel(f"MCP app {__version__}")
        ver.setObjectName("Hint")
        comp_card.body.addWidget(ver)
        self.content.addWidget(comp_card)

        self.content.addStretch(1)
        self.sync_selections(settings.theme_mode, settings.language, settings.sidebar_collapsed)
        self.retranslate()

    def sync_selections(self, theme_mode: str, language: str, sidebar_collapsed: bool) -> None:
        if theme_mode in self.theme_buttons:
            self.theme_buttons[theme_mode].setChecked(True)
        if language in self.lang_buttons:
            self.lang_buttons[language].setChecked(True)
        self.compact_check.blockSignals(True)
        self.compact_check.setChecked(sidebar_collapsed)
        self.compact_check.blockSignals(False)

    def retranslate(self) -> None:
        self.set_header(tr("settings.title"), tr("settings.lead"))
        self.appearance_title.setText(tr("settings.appearance.title"))
        self.theme_label.setText(tr("settings.theme.label"))
        for mode in (theme.THEME_SYSTEM, theme.THEME_DARK, theme.THEME_LIGHT):
            self.theme_buttons[mode].setText(tr(f"settings.theme.{mode}"))
        self.lang_label.setText(tr("settings.lang.label"))
        self.lang_buttons[LANG_RU].setText(tr("settings.lang.ru"))
        self.lang_buttons[LANG_EN].setText(tr("settings.lang.en"))
        self.compact_check.setText(tr("settings.sidebar_compact"))

        self.startup_title.setText(tr("settings.startup.title"))
        self.autostart.setText(tr("settings.autostart"))
        self.start_on_launch.setText(tr("settings.start_on_launch"))
        self.minimize.setText(tr("settings.minimize"))
        self.auto_restart.setText(tr("settings.auto_restart"))

        self.components_title.setText(tr("settings.components.title"))
        self.open_folder_btn.setText(tr("settings.open_folder"))
