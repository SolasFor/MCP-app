"""Settings page: flat hairline sections with SettingRow controls."""
from __future__ import annotations

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QWidget,
)

from app import __version__
from app.config import LOG_LEVEL_NAMES, Settings
from app.core import autostart
from app.core.logging_manager import get_logging_manager
from app.paths import user_data_dir
from app.ui import theme
from app.ui.components.cards import Divider, Section, SettingRow
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.toggle_switch import ToggleSwitch
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
    logging_settings_changed = pyqtSignal(dict)

    def __init__(
        self,
        settings: Settings,
        cloudflared_path: str | None,
        tray_available: bool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=True, parent=parent)
        self.settings = settings
        self._tray_available = tray_available

        # --- Section 1: Appearance & Language
        app_sec = Section(spacing=4)
        self.appearance_title = app_sec.header.title_label

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
        self._theme_row = SettingRow("", theme_seg)
        self.theme_label = self._theme_row.title_label
        app_sec.body.addWidget(self._theme_row)
        app_sec.body.addWidget(Divider())

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
        self._lang_row = SettingRow("", lang_seg)
        self.lang_label = self._lang_row.title_label
        app_sec.body.addWidget(self._lang_row)
        app_sec.body.addWidget(Divider())

        self.compact_check = ToggleSwitch()
        self.compact_check.setChecked(settings.sidebar_collapsed)
        self.compact_check.toggled.connect(self.sidebar_compact_toggled.emit)
        self._compact_row = SettingRow("", self.compact_check)
        app_sec.body.addWidget(self._compact_row)
        self.content.addWidget(app_sec)

        self.content.addWidget(Divider())

        # --- Section 2: Startup & Behavior
        start_sec = Section(spacing=4)
        self.startup_title = start_sec.header.title_label

        self.autostart = ToggleSwitch()
        self.autostart.setEnabled(autostart.is_supported())
        self.autostart.setChecked(autostart.is_enabled())
        self.autostart.toggled.connect(self.autostart_toggled.emit)

        self.start_on_launch = ToggleSwitch()
        self.start_on_launch.setChecked(settings.start_services_on_launch)
        self.start_on_launch.toggled.connect(self.start_on_launch_toggled.emit)

        self.minimize = ToggleSwitch()
        self.minimize.setEnabled(tray_available)
        self.minimize.setChecked(tray_available and settings.minimize_to_tray_on_close)
        self.minimize.toggled.connect(self.minimize_toggled.emit)

        self.auto_restart = ToggleSwitch()
        self.auto_restart.setChecked(settings.auto_restart)
        self.auto_restart.toggled.connect(self.auto_restart_toggled.emit)

        self._autostart_row = SettingRow("", self.autostart)
        self._start_launch_row = SettingRow("", self.start_on_launch)
        self._minimize_row = SettingRow("", self.minimize)
        self._auto_restart_row = SettingRow("", self.auto_restart)
        for idx, r in enumerate((
            self._autostart_row,
            self._start_launch_row,
            self._minimize_row,
            self._auto_restart_row,
        )):
            if idx > 0:
                start_sec.body.addWidget(Divider())
            start_sec.body.addWidget(r)
        self.content.addWidget(start_sec)

        self.content.addWidget(Divider())

        # --- Section 3: Persistent Logging
        log_sec = Section(spacing=6)
        self.logging_title = log_sec.header.title_label

        self.logging_enabled = ToggleSwitch()
        self.logging_auto_rotate = ToggleSwitch()
        self.logging_archive_enabled = ToggleSwitch()
        for sw in (self.logging_enabled, self.logging_auto_rotate, self.logging_archive_enabled):
            sw.toggled.connect(lambda _v: self._emit_logging_settings())

        self._log_enabled_row = SettingRow("", self.logging_enabled)
        self._log_rotate_row = SettingRow("", self.logging_auto_rotate)
        self._log_archive_row = SettingRow("", self.logging_archive_enabled)
        log_sec.body.addWidget(self._log_enabled_row)
        log_sec.body.addWidget(Divider())
        log_sec.body.addWidget(self._log_rotate_row)
        log_sec.body.addWidget(Divider())
        log_sec.body.addWidget(self._log_archive_row)
        log_sec.body.addSpacing(4)

        log_form = QFormLayout()
        log_form.setSpacing(8)
        self.logging_level_combo = SafeComboBox()
        for lvl in LOG_LEVEL_NAMES:
            self.logging_level_combo.addItem(lvl, lvl)
        self.logging_level_combo.currentIndexChanged.connect(lambda _i: self._emit_logging_settings())

        self.logging_max_file_spin = QSpinBox()
        self.logging_max_file_spin.setRange(1, 512)
        self.logging_max_file_spin.setObjectName("UiInput")
        self.logging_max_file_spin.valueChanged.connect(lambda _v: self._emit_logging_settings())

        self.logging_retention_spin = QSpinBox()
        self.logging_retention_spin.setRange(1, 3650)
        self.logging_retention_spin.setObjectName("UiInput")
        self.logging_retention_spin.valueChanged.connect(lambda _v: self._emit_logging_settings())

        self.logging_max_total_spin = QSpinBox()
        self.logging_max_total_spin.setRange(10, 10240)
        self.logging_max_total_spin.setObjectName("UiInput")
        self.logging_max_total_spin.valueChanged.connect(lambda _v: self._emit_logging_settings())

        log_form.addRow(QLabel(), self.logging_level_combo)
        log_form.addRow(QLabel(), self.logging_max_file_spin)
        log_form.addRow(QLabel(), self.logging_retention_spin)
        log_form.addRow(QLabel(), self.logging_max_total_spin)
        self._logging_level_lbl = log_form.labelForField(self.logging_level_combo)
        self._logging_max_file_lbl = log_form.labelForField(self.logging_max_file_spin)
        self._logging_retention_lbl = log_form.labelForField(self.logging_retention_spin)
        self._logging_max_total_lbl = log_form.labelForField(self.logging_max_total_spin)
        for lbl in (
            self._logging_level_lbl,
            self._logging_max_file_lbl,
            self._logging_retention_lbl,
            self._logging_max_total_lbl,
        ):
            if isinstance(lbl, QLabel):
                lbl.setObjectName("FieldLabel")
        log_sec.body.addLayout(log_form)

        log_dir = str(get_logging_manager().base_dir)
        log_path_row = QHBoxLayout()
        log_path_row.setSpacing(8)
        log_path_lbl = QLabel(log_dir)
        log_path_lbl.setObjectName("ServiceDetail")
        log_path_lbl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        log_path_lbl.setToolTip(log_dir)
        log_path_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        log_path_row.addWidget(log_path_lbl, 1)
        self.open_logs_folder_btn = QPushButton()
        self.open_logs_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_logs_folder_btn.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(get_logging_manager().base_dir)))
        )
        log_path_row.addWidget(self.open_logs_folder_btn)
        log_sec.body.addLayout(log_path_row)
        self.content.addWidget(log_sec)

        self.content.addWidget(Divider())

        # --- Section 4: Components & Data
        comp_sec = Section(spacing=6)
        self.components_title = comp_sec.header.title_label

        cf_row = QHBoxLayout()
        cf_row.setSpacing(10)
        cf_lbl = QLabel("cloudflared")
        cf_lbl.setObjectName("FieldLabel")
        cf_val = QLabel(cloudflared_path or "not found")
        cf_val.setObjectName("ServiceDetail")
        cf_val.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        cf_val.setToolTip(cloudflared_path or "not found")
        cf_val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cf_row.addWidget(cf_lbl, 0)
        cf_row.addWidget(cf_val, 1)
        comp_sec.body.addLayout(cf_row)

        data_dir = str(user_data_dir())
        data_row = QHBoxLayout()
        data_row.setSpacing(8)
        data_label = QLabel(data_dir)
        data_label.setObjectName("ServiceDetail")
        data_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        data_label.setToolTip(data_dir)
        data_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data_row.addWidget(data_label, 1)
        self.open_folder_btn = QPushButton()
        self.open_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_btn.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(data_dir))
        )
        data_row.addWidget(self.open_folder_btn)
        comp_sec.body.addLayout(data_row)

        ver = QLabel(f"MCP app {__version__}")
        ver.setObjectName("Caption")
        comp_sec.body.addWidget(ver)
        self.content.addWidget(comp_sec)

        self.content.addStretch(1)
        self.sync_selections(settings.theme_mode, settings.language, settings.sidebar_collapsed)
        self.sync_logging_settings(settings)
        self.retranslate()

    def _emit_logging_settings(self) -> None:
        self.logging_settings_changed.emit({
            "logging_enabled": self.logging_enabled.isChecked(),
            "logging_level": str(self.logging_level_combo.currentData() or "INFO"),
            "logging_max_file_mb": int(self.logging_max_file_spin.value()),
            "logging_retention_days": int(self.logging_retention_spin.value()),
            "logging_max_total_mb": int(self.logging_max_total_spin.value()),
            "logging_auto_rotate": self.logging_auto_rotate.isChecked(),
            "logging_archive_enabled": self.logging_archive_enabled.isChecked(),
        })

    def sync_logging_settings(self, settings: Settings) -> None:
        widgets = (
            self.logging_enabled,
            self.logging_auto_rotate,
            self.logging_archive_enabled,
            self.logging_level_combo,
            self.logging_max_file_spin,
            self.logging_retention_spin,
            self.logging_max_total_spin,
        )
        for w in widgets:
            w.blockSignals(True)
        try:
            self.logging_enabled.setChecked(bool(getattr(settings, "logging_enabled", True)))
            self.logging_auto_rotate.setChecked(bool(getattr(settings, "logging_auto_rotate", True)))
            self.logging_archive_enabled.setChecked(bool(getattr(settings, "logging_archive_enabled", True)))
            idx = self.logging_level_combo.findData(str(getattr(settings, "logging_level", "INFO")).upper())
            if idx >= 0:
                self.logging_level_combo.setCurrentIndex(idx)
            self.logging_max_file_spin.setValue(int(getattr(settings, "logging_max_file_mb", 10)))
            self.logging_retention_spin.setValue(int(getattr(settings, "logging_retention_days", 30)))
            self.logging_max_total_spin.setValue(int(getattr(settings, "logging_max_total_mb", 200)))
        finally:
            for w in widgets:
                w.blockSignals(False)

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
        self._compact_row.set_texts(tr("settings.sidebar_compact"))

        self.startup_title.setText(tr("settings.startup.title"))
        self._autostart_row.set_texts(tr("settings.autostart"))
        self._start_launch_row.set_texts(tr("settings.start_on_launch"))
        self._minimize_row.set_texts(tr("settings.minimize"))
        self._auto_restart_row.set_texts(tr("settings.auto_restart"))

        self.logging_title.setText(tr("settings.logging.title"))
        self._log_enabled_row.set_texts(tr("settings.logging.enabled"))
        self._log_rotate_row.set_texts(tr("settings.logging.auto_rotate"))
        self._log_archive_row.set_texts(tr("settings.logging.archive_enabled"))
        if isinstance(self._logging_level_lbl, QLabel):
            self._logging_level_lbl.setText(tr("settings.logging.level"))
        if isinstance(self._logging_max_file_lbl, QLabel):
            self._logging_max_file_lbl.setText(tr("settings.logging.max_file_mb"))
        if isinstance(self._logging_retention_lbl, QLabel):
            self._logging_retention_lbl.setText(tr("settings.logging.retention_days"))
        if isinstance(self._logging_max_total_lbl, QLabel):
            self._logging_max_total_lbl.setText(tr("settings.logging.max_total_mb"))
        self.open_logs_folder_btn.setText(tr("logs.open_folder"))

        self.components_title.setText(tr("settings.components.title"))
        self.open_folder_btn.setText(tr("settings.open_folder"))

    def apply_theme(self) -> None:
        for sw in (
            self.compact_check,
            self.autostart,
            self.start_on_launch,
            self.minimize,
            self.auto_restart,
            self.logging_enabled,
            self.logging_auto_rotate,
            self.logging_archive_enabled,
        ):
            sw.apply_theme()
