"""Compact structured log viewer panel backed by %APPDATA%\\MCPApp\\logs\\."""
from __future__ import annotations

import threading

from PyQt6.QtCore import QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QLabel,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.core.logging_manager import LOG_COMPONENTS, LOG_LEVELS, get_logging_manager
from app.ui import icons, theme
from app.ui.components.cards import Badge, FlowLayout
from app.ui.components.safe_combo import SafeComboBox
from app.ui.i18n import tr
from app.ui.widgets import LogView


class LogViewerWidget(QWidget):
    """Compact structured log viewer maximizing vertical space for log output."""

    copy_requested = pyqtSignal(str, object)
    _page_loaded = pyqtSignal(int, list, int, bool)  # token, records, next_offset, has_more

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._load_token = 0
        self._next_offset = 0
        self._has_more = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        # One compact toolbar with distinct filter and action groups.
        toolbar = QFrame()
        toolbar.setObjectName("LogToolbar")
        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 9, 10, 9)
        toolbar_layout.setSpacing(9)
        root.addWidget(toolbar)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("LogFilterInput")
        self.search_edit.setFixedHeight(36)
        self._search_icon = QAction(self.search_edit)
        self.search_edit.addAction(self._search_icon, QLineEdit.ActionPosition.LeadingPosition)
        self.search_edit.setMinimumWidth(100)
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.search_edit.textChanged.connect(lambda txt: self.log_view.set_filters(query=txt))
        search_group = QVBoxLayout()
        search_group.setSpacing(3)
        self.search_label = QLabel()
        self.search_label.setObjectName("Hint")
        self.search_label.setBuddy(self.search_edit)
        search_group.addWidget(self.search_label)
        search_group.addWidget(self.search_edit)
        top.addLayout(search_group, 1)

        self.component_combo = SafeComboBox()
        self.component_combo.setMinimumWidth(100)
        self.component_combo.setFixedHeight(36)
        self.component_combo.setObjectName("LogFilterCombo")
        self.component_combo.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.component_combo.addItem("", "all")
        for comp in LOG_COMPONENTS:
            self.component_combo.addItem(f"{comp}.log", comp)
        self.component_combo.currentIndexChanged.connect(self._on_component_changed)
        source_group = QVBoxLayout()
        source_group.setSpacing(3)
        self.source_label = QLabel()
        self.source_label.setObjectName("Hint")
        self.source_label.setBuddy(self.component_combo)
        source_group.addWidget(self.source_label)
        source_group.addWidget(self.component_combo)
        top.addLayout(source_group, 1)

        self.level_combo = SafeComboBox()
        self.level_combo.setMinimumWidth(100)
        self.level_combo.setFixedHeight(36)
        self.level_combo.setObjectName("LogFilterCombo")
        self.level_combo.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.level_combo.addItem("", "ALL")
        for lvl in LOG_LEVELS:
            self.level_combo.addItem(lvl, lvl)
        self.level_combo.currentIndexChanged.connect(self._on_level_changed)
        level_group = QVBoxLayout()
        level_group.setSpacing(3)
        self.level_label = QLabel()
        self.level_label.setObjectName("Hint")
        self.level_label.setBuddy(self.level_combo)
        level_group.addWidget(self.level_label)
        level_group.addWidget(self.level_combo)
        top.addLayout(level_group, 1)
        toolbar_layout.addLayout(top)
        toolbar_layout.addSpacing(15)

        # Compact actions + counts row (wraps cleanly at 800px)
        actions_bar = QHBoxLayout()
        actions_bar.setSpacing(8)
        actions = FlowLayout(spacing=6)

        self.auto_scroll_check = QCheckBox()
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.toggled.connect(self.log_view_auto_scroll)

        self.open_folder_btn = QPushButton()
        self.open_folder_btn.setObjectName("LogAction")
        self.open_folder_btn.clicked.connect(self.open_logs_folder)

        self.copy_btn = QPushButton()
        self.copy_btn.setObjectName("LogAction")
        self.copy_btn.clicked.connect(
            lambda: self.copy_requested.emit(self.log_view.plain_text(), self.copy_btn)
        )

        self.clear_btn = QPushButton()
        self.clear_btn.setObjectName("LogClearAction")
        self.clear_btn.clicked.connect(self.clear_logs)

        self.load_more_btn = QPushButton()
        self.load_more_btn.setObjectName("LogAction")
        self.load_more_btn.clicked.connect(self.load_more)
        self.load_more_btn.hide()

        for btn in (
            self.open_folder_btn,
            self.copy_btn,
            self.clear_btn,
            self.load_more_btn,
        ):
            btn.setFixedHeight(25)
            actions.addWidget(btn)
        actions_bar.addLayout(actions, 1)
        actions_bar.addWidget(self.auto_scroll_check)

        badges = QHBoxLayout()
        badges.setSpacing(6)
        self.errors_badge = Badge("", variant="neutral")
        self.count_badge = Badge("", variant="neutral")
        self.errors_badge.setObjectName("LogCount")
        self.count_badge.setObjectName("LogCount")
        badges.addStretch(1)
        badges.addWidget(self.errors_badge)
        badges.addWidget(self.count_badge)
        toolbar_layout.addLayout(actions_bar)
        toolbar_layout.addLayout(badges)

        self.log_view = LogView()
        self.log_view.counts_changed.connect(self._update_count)
        root.addWidget(self.log_view, 1)

        self._page_loaded.connect(self._apply_loaded_page)
        self.retranslate()
        self._update_count(0, 0)
        self.apply_theme()

    def log_view_auto_scroll(self, enabled: bool) -> None:
        self.log_view.set_auto_scroll(enabled)

    def _on_component_changed(self, _index: int) -> None:
        comp = str(self.component_combo.currentData() or "all")
        self.log_view.set_filters(source=comp)
        self.reload_from_disk(comp)

    def _on_level_changed(self, _index: int) -> None:
        lvl = str(self.level_combo.currentData() or "ALL")
        self.log_view.set_filters(level=lvl)

    def reload_from_disk(self, component: str | None = None) -> None:
        comp = component or str(self.component_combo.currentData() or "all")
        self._load_token += 1
        tok = self._load_token
        self._next_offset = 0
        self._has_more = False
        self.load_more_btn.hide()

        def worker() -> None:
            lm = get_logging_manager()
            lm.flush(timeout=0.5)
            records, next_off, has_more = lm.read_tail_page(comp, offset_from_end=0, max_lines=400)
            self._page_loaded.emit(tok, records, next_off, has_more)

        threading.Thread(target=worker, name="log-tail-loader", daemon=True).start()

    def load_more(self) -> None:
        if not self._has_more:
            return
        comp = str(self.component_combo.currentData() or "all")
        tok = self._load_token
        offset = self._next_offset
        self.load_more_btn.setEnabled(False)

        def worker() -> None:
            lm = get_logging_manager()
            records, next_off, has_more = lm.read_tail_page(
                comp,
                offset_from_end=offset,
                max_lines=400,
            )
            self._page_loaded.emit(-tok, records, next_off, has_more)

        threading.Thread(target=worker, name="log-page-loader", daemon=True).start()

    def _apply_loaded_page(self, tok: int, records: list, next_off: int, has_more: bool) -> None:
        prepend = tok < 0
        if abs(tok) != self._load_token:
            return
        self._next_offset = next_off
        self._has_more = has_more
        self.load_more_btn.setEnabled(True)
        self.load_more_btn.setVisible(bool(has_more))
        if records or not prepend:
            if prepend:
                self.log_view.load_records(records, prepend=True)
            elif not self.log_view.plain_text().strip() or self.component_combo.currentData() != "all":
                self.log_view.load_records(records, prepend=False)

    def _update_count(self, shown: int, total: int) -> None:
        self.count_badge.setText(tr("logs.count", shown=shown, total=total))
        err_cnt = self.log_view.error_count()
        self.errors_badge.setText(tr("logs.errors_count", count=err_cnt))
        self.errors_badge.set_variant("err" if err_cnt > 0 else "neutral")

    def open_logs_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(get_logging_manager().base_dir)))

    def clear_logs(self) -> None:
        comp = str(self.component_combo.currentData() or "all")
        get_logging_manager().clear_normal_logs(comp)
        self.log_view.clear_log()

    def retranslate(self) -> None:
        self.search_label.setText(tr("logs.filter.search"))
        self.source_label.setText(tr("logs.filter.source"))
        self.level_label.setText(tr("logs.filter.level"))
        self.search_edit.setPlaceholderText(tr("logs.search"))
        self.auto_scroll_check.setText(tr("logs.autoscroll"))
        self.open_folder_btn.setText(tr("logs.open_folder"))
        self.copy_btn.setText(tr("logs.copy"))
        self.clear_btn.setText(tr("logs.clear"))
        self.load_more_btn.setText(tr("logs.load_more"))
        if self.component_combo.count() > 0:
            self.component_combo.setItemText(0, tr("logs.source.all"))
        if self.level_combo.count() > 0:
            self.level_combo.setItemText(0, tr("logs.level.all"))
        shown, total = self.log_view.records_count()
        self._update_count(shown, total)
        self.log_view.re_render()

    def apply_theme(self) -> None:
        self._search_icon.setIcon(icons.vector_icon("search", theme.TEXT_MUTED, 14))
        self.log_view.re_render()
        err_cnt = self.log_view.error_count()
        self.errors_badge.set_variant("err" if err_cnt > 0 else "neutral")
        self.count_badge.set_variant("neutral")
