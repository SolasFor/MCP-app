"""Structured log viewer panel backed by %APPDATA%\\MCPApp\\logs\\."""
from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core.logging_manager import LOG_COMPONENTS, LOG_LEVELS, get_logging_manager
from app.paths import user_data_dir
from app.ui.components.cards import Badge
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import tr
from app.ui.widgets import LogView


class LogViewerWidget(QWidget):
    """Structured log viewer with component/level selectors, paging, folder open, and log export."""

    copy_requested = pyqtSignal(str, object)
    exported = pyqtSignal(str)
    _page_loaded = pyqtSignal(int, list, int, bool)  # token, records, next_offset, has_more

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._load_token = 0
        self._next_offset = 0
        self._has_more = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        # Toolbar row 1: search + action buttons
        top = QHBoxLayout()
        top.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda txt: self.log_view.set_filters(query=txt))
        top.addWidget(self.search_edit, 1)

        self.auto_scroll_check = QCheckBox()
        self.auto_scroll_check.setChecked(True)
        self.auto_scroll_check.setCursor(Qt.CursorShape.PointingHandCursor)
        self.auto_scroll_check.toggled.connect(self.log_view_auto_scroll)
        top.addWidget(self.auto_scroll_check)

        self.open_folder_btn = QPushButton()
        self.open_folder_btn.setObjectName("Ghost")
        self.open_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_btn.clicked.connect(self.open_logs_folder)

        self.copy_btn = QPushButton()
        self.copy_btn.setObjectName("Ghost")
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_btn.clicked.connect(
            lambda: self.copy_requested.emit(self.log_view.plain_text(), self.copy_btn)
        )
        self.export_btn = QPushButton()
        self.export_btn.setObjectName("Ghost")
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_log)

        self.clear_btn = QPushButton()
        self.clear_btn.setObjectName("Ghost")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.clicked.connect(self.clear_logs)

        for btn in (self.open_folder_btn, self.copy_btn, self.export_btn, self.clear_btn):
            top.addWidget(btn)
        root.addLayout(top)

        # Toolbar row 2: Component selector + Level selector + Load Earlier + Error & Line count badges
        filters = QHBoxLayout()
        filters.setSpacing(8)

        self.component_combo = SafeComboBox()
        self.component_combo.setMinimumWidth(175)
        self.component_combo.addItem("", "all")
        for comp in LOG_COMPONENTS:
            self.component_combo.addItem(f"{comp}.log", comp)
        self.component_combo.currentIndexChanged.connect(self._on_component_changed)
        filters.addWidget(self.component_combo)

        self.level_combo = SafeComboBox()
        self.level_combo.setMinimumWidth(135)
        self.level_combo.addItem("", "ALL")
        for lvl in LOG_LEVELS:
            self.level_combo.addItem(lvl, lvl)
        self.level_combo.currentIndexChanged.connect(self._on_level_changed)
        filters.addWidget(self.level_combo)

        self.load_more_btn = QPushButton()
        self.load_more_btn.setObjectName("Ghost")
        self.load_more_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.load_more_btn.clicked.connect(self.load_more)
        self.load_more_btn.hide()
        filters.addWidget(self.load_more_btn)

        filters.addStretch(1)
        self.errors_badge = Badge("", variant="neutral")
        self.count_badge = Badge("", variant="neutral")
        filters.addWidget(self.errors_badge)
        filters.addWidget(self.count_badge)
        root.addLayout(filters)

        self.log_view = LogView()
        self.log_view.counts_changed.connect(self._update_count)
        root.addWidget(self.log_view, 1)

        self._page_loaded.connect(self._apply_loaded_page)
        self.retranslate()
        self._update_count(0, 0)

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

    def export_log(self) -> None:
        comp = str(self.component_combo.currentData() or "all")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"mcp-app-{comp if comp != 'all' else 'logs'}-{stamp}.log"
        default_path = str(user_data_dir() / default_name)
        dest, _ = QFileDialog.getSaveFileName(
            self,
            tr("logs.export"),
            default_path,
            "Log (*.log *.txt);;All Files (*)",
        )
        if not dest:
            return
        try:
            Path(dest).write_text(self.log_view.plain_text(), encoding="utf-8")
        except OSError as exc:
            SilentMessageBox.warning(self, tr("logs.export"), f"{type(exc).__name__}: {exc}")
            return
        self.exported.emit(tr("toast.exported"))

    def retranslate(self) -> None:
        self.search_edit.setPlaceholderText(tr("logs.search"))
        self.auto_scroll_check.setText(tr("logs.autoscroll"))
        self.open_folder_btn.setText(tr("logs.open_folder"))
        self.copy_btn.setText(tr("logs.copy"))
        self.export_btn.setText(tr("logs.export"))
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
        self.log_view.re_render()
        err_cnt = self.log_view.error_count()
        self.errors_badge.set_variant("err" if err_cnt > 0 else "neutral")
        self.count_badge.set_variant("neutral")
