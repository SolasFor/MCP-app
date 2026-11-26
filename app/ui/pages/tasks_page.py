"""Tasks Manager page: active/queue/history view, context menus, and inactive task purge."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QPoint, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.logging_manager import get_logging_manager
from app.core.redaction import SecretRedactor
from app.paths import user_data_dir
from app.ui import tokens
from app.ui.components.cards import EmptyState, SectionHeader
from app.ui.components.context_menu import AppContextMenu, MenuActionSpec, make_toolbar_menu_button
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.output_stream import OutputSpoolManager
from backend.tasks.models import (
    ALL_STATUSES,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    TERMINAL_STATUSES,
    TaskRecord,
)
from backend.tasks.store import TaskStore


class TasksPage(PageScaffold):
    """GUI view of durable background tasks, output streams, artifacts, context actions & history purge."""

    task_finished = pyqtSignal(str, str, str)  # task_id, title, status
    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        spool_dir: Path | None = None,
        artifacts_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        base_dir = user_data_dir() / "tasks"
        self._db_path = db_path or (base_dir / "tasks.sqlite3")
        self._spool_dir = spool_dir or (base_dir / "spool")
        self._artifacts_dir = artifacts_dir or (base_dir / "artifacts")
        self._redactor = redactor or SecretRedactor()
        self._scope = "all"  # all | active | history
        self._records: dict[str, TaskRecord] = {}
        self._row_task_ids: list[str] = []
        self._known_statuses: dict[str, str] = {}

        # Clean top bar: scope filter, status combo, search, refresh, global list menu
        top_bar = QHBoxLayout()
        top_bar.setSpacing(6)

        self._scope_group = QButtonGroup(self)
        self._scope_group.setExclusive(True)
        self.scope_all_btn = self._make_scope_btn("all")
        self.scope_active_btn = self._make_scope_btn("active")
        self.scope_history_btn = self._make_scope_btn("history")
        self.scope_all_btn.setChecked(True)
        for btn in (self.scope_all_btn, self.scope_active_btn, self.scope_history_btn):
            top_bar.addWidget(btn)

        self.status_combo = SafeComboBox()
        self.status_combo.addItem("", "")
        for st in (
            STATUS_QUEUED,
            STATUS_RUNNING,
            STATUS_SUCCEEDED,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_INTERRUPTED,
        ):
            self.status_combo.addItem(st, st)
        self.status_combo.currentIndexChanged.connect(lambda *_: self.reload())
        top_bar.addWidget(self.status_combo)

        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))
        top_bar.addWidget(self.search_edit, 1)

        self.refresh_btn = self._make_action_btn(self.reload, obj="Ghost")
        self.list_menu_btn = make_toolbar_menu_button(parent=self)
        self.list_menu_btn.clicked.connect(self._open_list_menu)
        top_bar.addWidget(self.refresh_btn)
        top_bar.addWidget(self.list_menu_btn)
        self.content.addLayout(top_bar)

        self.table_card = QWidget()
        table_lay = QVBoxLayout(self.table_card)
        table_lay.setContentsMargins(0, 0, 0, 0)
        table_lay.setSpacing(0)
        self.table = DataTable(["", "", "", "", "", "", "", "", ""])
        self.table.setMinimumHeight(130)
        self.table.set_row_menu_provider(self._build_row_menu)
        self.table.itemSelectionChanged.connect(self._on_selected)
        table_lay.addWidget(self.table, 1)
        self.content.addWidget(self.table_card, 1)

        self.empty_state = EmptyState("tasks")
        self.content.addWidget(self.empty_state, 1)

        # Bottom splitter: live redacted spool logs + artifact inspector
        splitter = QSplitter(Qt.Orientation.Horizontal)

        logs_pane = QWidget()
        logs_lay = QVBoxLayout(logs_pane)
        logs_lay.setContentsMargins(0, 4, 8, 0)
        logs_lay.setSpacing(6)
        self.logs_header = SectionHeader()
        self.stream_combo = SafeComboBox()
        self.stream_combo.addItem("stdout", "stdout")
        self.stream_combo.addItem("stderr", "stderr")
        self.stream_combo.currentIndexChanged.connect(lambda *_: self._refresh_details())
        self.logs_header.right_box.addWidget(self.stream_combo)
        logs_lay.addWidget(self.logs_header)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        logs_lay.addWidget(self.logs_view, 1)
        splitter.addWidget(logs_pane)

        art_pane = QWidget()
        art_lay = QVBoxLayout(art_pane)
        art_lay.setContentsMargins(8, 4, 0, 0)
        art_lay.setSpacing(6)
        self.art_header = SectionHeader()
        self.artifact_combo = SafeComboBox()
        self.artifact_combo.currentIndexChanged.connect(lambda *_: self._refresh_artifact_preview())
        self.art_header.right_box.addWidget(self.artifact_combo)
        art_lay.addWidget(self.art_header)
        self.artifact_view = QPlainTextEdit()
        self.artifact_view.setReadOnly(True)
        art_lay.addWidget(self.artifact_view, 1)
        splitter.addWidget(art_pane)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        self.content.addWidget(splitter, 1)

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._on_poll)
        self._poll_timer.start()

        self.retranslate()
        self.reload()

    def _make_scope_btn(self, scope: str) -> QPushButton:
        btn = QPushButton()
        btn.setCheckable(True)
        btn.setProperty("seg", True)
        btn.clicked.connect(lambda _c=False, s=scope: self._set_scope(s))
        self._scope_group.addButton(btn)
        return btn

    def _make_action_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.clicked.connect(slot)
        return btn

    def _set_scope(self, scope: str) -> None:
        self._scope = scope
        self.reload()

    def set_paths(
        self,
        *,
        db_path: Path,
        spool_dir: Path,
        artifacts_dir: Path,
    ) -> None:
        self._db_path = db_path
        self._spool_dir = spool_dir
        self._artifacts_dir = artifacts_dir
        self._known_statuses.clear()
        self.reload()

    def _open_store(self) -> TaskStore | None:
        if not self._db_path.is_file():
            return None
        return TaskStore(self._db_path)

    def _selected_task_id(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return None
        val = item.data(Qt.ItemDataRole.UserRole)
        return str(val) if val else None

    def _record_at_row(self, row: int) -> TaskRecord | None:
        if 0 <= row < len(self._row_task_ids):
            return self._records.get(self._row_task_ids[row])
        return None

    # ------------------------------------------------------------------ context menus
    def build_list_menu_specs(self) -> list[MenuActionSpec]:
        purge_sub = [
            MenuActionSpec(
                key="purge_7d",
                label=tr("tasks.purge.7d"),
                icon_name="trash",
                callback=lambda: self.purge_old_tasks(older_than_days=7),
            ),
            MenuActionSpec(
                key="purge_30d",
                label=tr("tasks.purge.30d"),
                icon_name="trash",
                callback=lambda: self.purge_old_tasks(older_than_days=30),
            ),
            MenuActionSpec(
                key="purge_90d",
                label=tr("tasks.purge.90d"),
                icon_name="trash",
                callback=lambda: self.purge_old_tasks(older_than_days=90),
            ),
            MenuActionSpec(
                key="purge_all_inactive",
                label=tr("tasks.purge.all"),
                icon_name="trash",
                danger=True,
                separator_before=True,
                callback=lambda: self.purge_old_tasks(older_than_days=None),
            ),
        ]
        return [
            MenuActionSpec(
                key="refresh",
                label=tr("clients.refresh"),
                icon_name="refresh",
                callback=self.reload,
            ),
            MenuActionSpec(
                key="clear_old",
                label=tr("tasks.purge.menu"),
                icon_name="trash",
                separator_before=True,
                submenu=purge_sub,
            ),
        ]

    def _open_list_menu(self) -> None:
        menu = AppContextMenu.from_specs(self.build_list_menu_specs(), self)
        pos = self.list_menu_btn.mapToGlobal(QPoint(self.list_menu_btn.width(), self.list_menu_btn.height()))
        menu.exec_clamped(pos)

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        rec = self._record_at_row(row)
        if rec is None:
            return []
        tid = rec.task_id
        is_active = rec.status in (STATUS_QUEUED, STATUS_RUNNING) and not rec.cancel_requested
        is_terminal = rec.status in TERMINAL_STATUSES
        has_artifacts = bool(rec.artifact_refs)

        return [
            MenuActionSpec(
                key="details",
                label=tr("tasks.menu.details"),
                icon_name="info",
                callback=lambda t=tid: self._show_task_details(t),
            ),
            MenuActionSpec(
                key="logs",
                label=tr("tasks.menu.view_log"),
                icon_name="terminal",
                callback=lambda t=tid: self._focus_task_log(t),
            ),
            MenuActionSpec(
                key="stop",
                label=tr("tasks.btn.cancel"),
                icon_name="stop",
                enabled=is_active,
                separator_before=True,
                callback=lambda t=tid: self.cancel_task(t),
            ),
            MenuActionSpec(
                key="restart",
                label=tr("tasks.btn.restart"),
                icon_name="refresh",
                enabled=is_terminal,
                callback=lambda t=tid: self.restart_task(t),
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("tasks.menu.copy_id"),
                icon_name="copy",
                separator_before=True,
                callback=lambda t=tid: self._copy_task_id(t),
            ),
            MenuActionSpec(
                key="export",
                label=tr("tasks.btn.export"),
                icon_name="export",
                enabled=has_artifacts,
                callback=lambda t=tid: self.export_task_artifact(t),
            ),
            MenuActionSpec(
                key="delete",
                label=tr("tasks.menu.delete"),
                icon_name="trash",
                enabled=is_terminal,
                danger=True,
                separator_before=True,
                callback=lambda t=tid: self.delete_inactive_task(t),
            ),
        ]

    # ------------------------------------------------------------------ refresh
    def _on_poll(self) -> None:
        if self.isVisible() or any(
            st in (STATUS_QUEUED, STATUS_RUNNING) for st in self._known_statuses.values()
        ):
            self.reload()

    def reload(self) -> None:
        store = self._open_store()
        if store is None:
            self._records = {}
            self._row_task_ids = []
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.show()
            self._on_selected()
            return

        # Track terminal transitions across all tasks for tray notifications
        try:
            all_rows = store.list_tasks(limit=200)
        except Exception:
            all_rows = []

        for rec in all_rows:
            prev = self._known_statuses.get(rec.task_id)
            if (
                prev in (STATUS_QUEUED, STATUS_RUNNING)
                and rec.status in TERMINAL_STATUSES
            ):
                self.task_finished.emit(rec.task_id, rec.title, rec.status)
            self._known_statuses[rec.task_id] = rec.status

        selected_status = str(self.status_combo.currentData() or "")
        if selected_status and selected_status not in ALL_STATUSES:
            selected_status = ""
        records = store.list_tasks(
            status=selected_status or None,
            active_only=(self._scope == "active"),
            history_only=(self._scope == "history"),
            limit=200,
        )
        self._records = {r.task_id: r for r in records}
        self._row_task_ids = [r.task_id for r in records]

        if not records:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.show()
            self._on_selected()
            return

        self.empty_state.hide()
        self.table_card.show()
        selected_id = self._selected_task_id()
        self.table.setRowCount(len(records))
        restore_row = 0

        for idx, rec in enumerate(records):
            id_item = QTableWidgetItem(rec.task_id[:12])
            id_item.setData(Qt.ItemDataRole.UserRole, rec.task_id)
            id_item.setToolTip(rec.task_id)
            title_clean = self._redactor.redact_text(rec.title)
            status_text = tr(f"tasks.status.{rec.status}")
            progress_text = f"{rec.progress_percent}%" if rec.progress_percent is not None else "—"
            elapsed_text = f"{rec.elapsed_seconds():.1f}s"
            exit_text = str(rec.exit_code) if rec.exit_code is not None else "—"

            self.table.setItem(idx, 0, id_item)
            self.table.setItem(idx, 1, QTableWidgetItem(title_clean))
            self.table.setItem(idx, 2, QTableWidgetItem(rec.owner_client_id[:14]))
            self.table.setItem(idx, 3, QTableWidgetItem(status_text))
            self.table.setItem(idx, 4, QTableWidgetItem(str(rec.priority)))
            self.table.setItem(idx, 5, QTableWidgetItem(progress_text))
            self.table.setItem(idx, 6, QTableWidgetItem(elapsed_text))
            self.table.setItem(idx, 7, QTableWidgetItem(exit_text))
            self.table.set_row_actions_cell(idx, 8, tooltip=tr("common.actions"))
            if selected_id and rec.task_id == selected_id:
                restore_row = idx

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(8, 42)
        self.table.filter_rows(self.search_edit.text())
        if self.table.rowCount() > 0:
            self.table.selectRow(restore_row)
        self._on_selected()

    def _on_selected(self) -> None:
        self._refresh_details()

    def _refresh_details(self) -> None:
        tid = self._selected_task_id()
        rec = self._records.get(tid) if tid else None
        if rec is None:
            self.logs_view.setPlainText(tr("tasks.details.no_output"))
            self.artifact_combo.clear()
            self.artifact_view.setPlainText(tr("tasks.details.no_artifacts"))
            return

        stream = "stderr" if self.stream_combo.currentData() == "stderr" else "stdout"
        out_text = ""
        if rec.spool_run_id and self._spool_dir.is_dir():
            spool = OutputSpoolManager(self._spool_dir)
            page = spool.read_page(
                rec.spool_run_id,
                "stderr" if stream == "stderr" else "stdout",
                offset=0,
                limit=32000,
                redactor=self._redactor,
            )
            out_text = page.text
        if not out_text and rec.error:
            out_text = self._redactor.redact_text(rec.error)
        self.logs_view.setPlainText(out_text or tr("tasks.details.no_output"))

        prev_name = str(self.artifact_combo.currentData() or "")
        self.artifact_combo.blockSignals(True)
        self.artifact_combo.clear()
        for ref in rec.artifact_refs:
            name = str(ref.get("name") or "")
            if name:
                self.artifact_combo.addItem(name, name)
        if prev_name:
            idx = self.artifact_combo.findData(prev_name)
            if idx >= 0:
                self.artifact_combo.setCurrentIndex(idx)
        self.artifact_combo.blockSignals(False)
        self._refresh_artifact_preview()

    def _refresh_artifact_preview(self) -> None:
        tid = self._selected_task_id()
        name = str(self.artifact_combo.currentData() or "")
        if not tid or not name:
            self.artifact_view.setPlainText(tr("tasks.details.no_artifacts"))
            return
        target = (self._artifacts_dir / tid / Path(name).name).resolve()
        expected_dir = (self._artifacts_dir / tid).resolve()
        if target.parent != expected_dir or not target.is_file():
            self.artifact_view.setPlainText(tr("tasks.details.no_artifacts"))
            return
        raw = target.read_text(encoding="utf-8", errors="replace")[:32000]
        self.artifact_view.setPlainText(self._redactor.redact_text(raw))

    # ------------------------------------------------------------------ actions
    def _select_task_row(self, task_id: str) -> None:
        if task_id in self._row_task_ids:
            self.table.selectRow(self._row_task_ids.index(task_id))

    def _show_task_details(self, task_id: str) -> None:
        self._select_task_row(task_id)
        rec = self._records.get(task_id)
        if rec is None:
            return
        created = datetime.fromtimestamp(rec.created_at).strftime("%d.%m.%Y %H:%M:%S")
        finished = (
            datetime.fromtimestamp(rec.finished_at).strftime("%d.%m.%Y %H:%M:%S")
            if rec.finished_at
            else "—"
        )
        body = tr(
            "tasks.details.popup_body",
            task_id=rec.task_id,
            title=self._redactor.redact_text(rec.title),
            client=rec.owner_client_id,
            status=tr(f"tasks.status.{rec.status}"),
            profile=rec.profile,
            kind=rec.kind,
            created=created,
            finished=finished,
            exit_code=str(rec.exit_code) if rec.exit_code is not None else "—",
            error=self._redactor.redact_text(rec.error) or "—",
        )
        SilentMessageBox.information(self, tr("tasks.menu.details"), body)

    def _focus_task_log(self, task_id: str) -> None:
        self._select_task_row(task_id)
        self.logs_view.setFocus()

    def _copy_task_id(self, task_id: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(task_id)
        self.status_message.emit(tr("toast.copied"), "ok")

    def cancel_task(self, tid: str) -> None:
        store = self._open_store()
        if not tid or store is None:
            return
        try:
            store.request_cancel(tid)
            self.status_message.emit(tr("tasks.toast.cancelled", task_id=tid[:12]), "info")
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("tasks.title"), str(exc))

    def cancel_selected(self) -> None:
        tid = self._selected_task_id()
        if tid:
            self.cancel_task(tid)

    def restart_task(self, tid: str) -> None:
        store = self._open_store()
        if not tid or store is None:
            return
        try:
            created = store.create_restart_task(tid)
            if created is not None:
                self.status_message.emit(tr("tasks.toast.restarted", task_id=created.task_id[:12]), "ok")
                self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("tasks.title"), str(exc))

    def restart_selected(self) -> None:
        tid = self._selected_task_id()
        if tid:
            self.restart_task(tid)

    def export_task_artifact(self, tid: str) -> None:
        self._select_task_row(tid)
        self.export_selected_artifact()

    def export_selected_artifact(self) -> None:
        text = self.artifact_view.toPlainText()
        if not text:
            return
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)
        name = str(self.artifact_combo.currentData() or "artifact.json")
        path, _ = QFileDialog.getSaveFileName(self, tr("tasks.btn.export"), name, "All Files (*)")
        if path:
            Path(path).write_text(text, encoding="utf-8")
        self.status_message.emit(tr("tasks.toast.exported"), "ok")

    def delete_inactive_task(self, tid: str, *, confirm: bool = True) -> dict | None:
        store = self._open_store()
        if store is None or not tid:
            return None
        rec = self._records.get(tid) or store.get_task(tid)
        if rec is None or rec.status not in TERMINAL_STATUSES:
            SilentMessageBox.warning(self, tr("tasks.title"), tr("tasks.purge.refused_active"))
            return None
        if confirm:
            ans = SilentMessageBox.question(
                self,
                tr("tasks.menu.delete"),
                tr("tasks.delete.confirm", task_id=tid[:12]),
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            if ans != SilentMessageBox.StandardButton.Yes:
                return None
        spool_mgr = OutputSpoolManager(self._spool_dir)
        res = store.delete_inactive_tasks(
            task_ids=[tid],
            spool_manager=spool_mgr,
            artifacts_dir=self._artifacts_dir,
        )
        try:
            get_logging_manager().info(
                "tasks",
                f"GUI deleted inactive task task_id={tid} deleted={res['deleted_count']}",
                event_code="task_deleted_gui",
            )
        except Exception:  # noqa: BLE001
            pass
        self._known_statuses.pop(tid, None)
        self.status_message.emit(tr("tasks.toast.deleted", count=res["deleted_count"]), "ok")
        self.reload()
        return res

    def purge_old_tasks(self, *, older_than_days: int | None = None, confirm: bool = True) -> dict | None:
        store = self._open_store()
        if store is None:
            return None
        count = store.count_purgeable_inactive(older_than_days=older_than_days)
        if count == 0:
            SilentMessageBox.information(self, tr("tasks.purge.menu"), tr("tasks.purge.none"))
            return {"deleted_count": 0, "deleted_task_ids": [], "cleaned_dirs": 0}
        if confirm:
            scope_txt = (
                tr("tasks.purge.scope_days", days=older_than_days)
                if older_than_days is not None
                else tr("tasks.purge.scope_all")
            )
            ans = SilentMessageBox.question(
                self,
                tr("tasks.purge.menu"),
                tr("tasks.purge.confirm", count=count, scope=scope_txt),
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            if ans != SilentMessageBox.StandardButton.Yes:
                return None
        spool_mgr = OutputSpoolManager(self._spool_dir)
        res = store.delete_inactive_tasks(
            older_than_days=older_than_days,
            spool_manager=spool_mgr,
            artifacts_dir=self._artifacts_dir,
        )
        for tid in res["deleted_task_ids"]:
            self._known_statuses.pop(tid, None)
        try:
            get_logging_manager().info(
                "tasks",
                f"GUI purged inactive tasks older_than_days={older_than_days} deleted={res['deleted_count']} cleaned_dirs={res['cleaned_dirs']}",
                event_code="tasks_purged_gui",
            )
        except Exception:  # noqa: BLE001
            pass
        self.status_message.emit(tr("tasks.toast.deleted", count=res["deleted_count"]), "ok")
        self.reload()
        return res

    def retranslate(self) -> None:
        self.set_header(tr("tasks.title"), tr("tasks.lead"))
        self.scope_all_btn.setText(tr("tasks.scope.all"))
        self.scope_active_btn.setText(tr("tasks.scope.active"))
        self.scope_history_btn.setText(tr("tasks.scope.history"))
        self.search_edit.setPlaceholderText(tr("tasks.search"))
        self.refresh_btn.setText(tr("clients.refresh"))
        self.list_menu_btn.setToolTip(tr("tasks.purge.menu"))

        cur_status = self.status_combo.currentData()
        self.status_combo.blockSignals(True)
        self.status_combo.setItemText(0, tr("tasks.status.all"))
        for i in range(1, self.status_combo.count()):
            st = str(self.status_combo.itemData(i) or "")
            self.status_combo.setItemText(i, tr(f"tasks.status.{st}"))
        if cur_status:
            idx = self.status_combo.findData(cur_status)
            if idx >= 0:
                self.status_combo.setCurrentIndex(idx)
        self.status_combo.blockSignals(False)

        self.table.setHorizontalHeaderLabels(
            [
                tr("tasks.col.id"),
                tr("tasks.col.title"),
                tr("tasks.col.owner"),
                tr("tasks.col.status"),
                tr("tasks.col.priority"),
                tr("tasks.col.progress"),
                tr("tasks.col.elapsed"),
                tr("tasks.col.exit"),
                "",
            ]
        )
        self.empty_state.set_content(tr("tasks.empty.title"), tr("tasks.empty.desc"))
        self.logs_header.set_texts(tr("tasks.details.output_title"))
        self.art_header.set_texts(tr("tasks.details.artifacts_title"))
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
        mono = tokens.FONT_MONO
        for view in (self.logs_view, self.artifact_view):
            view.setStyleSheet(f"font-family: {mono}; font-size: 11px;")
