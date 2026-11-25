"""Tasks Manager page: active/queue/history view, live redacted spool output, artifacts, cancel/restart."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QWidget,
)

from app.core.redaction import SecretRedactor
from app.paths import user_data_dir
from app.ui import tokens
from app.ui.components.cards import Card, EmptyState, SectionHeader
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
    """GUI view of durable background tasks, output streams, artifacts, and cancel/restart actions."""

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
        self._known_statuses: dict[str, str] = {}

        # Filter & action bar
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

        self.status_combo = QComboBox()
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

        self.refresh_btn = self._make_action_btn(self.reload)
        self.cancel_btn = self._make_action_btn(self.cancel_selected, obj="Danger")
        self.restart_btn = self._make_action_btn(self.restart_selected, obj="Accent")
        self.export_btn = self._make_action_btn(self.export_selected_artifact)
        for btn in (self.refresh_btn, self.cancel_btn, self.restart_btn, self.export_btn):
            top_bar.addWidget(btn)
        self.content.addLayout(top_bar)

        self.table_card = Card(margins=(12, 12, 12, 12))
        self.table = DataTable(["", "", "", "", "", "", "", ""])
        self.table.itemSelectionChanged.connect(self._on_selected)
        self.table_card.body.addWidget(self.table, 1)
        self.content.addWidget(self.table_card, 1)

        self.empty_state = EmptyState("tasks")
        self.content.addWidget(self.empty_state, 1)

        # Bottom splitter: live redacted spool logs + artifact inspector
        splitter = QSplitter(Qt.Orientation.Horizontal)

        logs_card = Card(margins=(12, 12, 12, 12))
        self.logs_header = SectionHeader()
        self.stream_combo = QComboBox()
        self.stream_combo.addItem("stdout", "stdout")
        self.stream_combo.addItem("stderr", "stderr")
        self.stream_combo.currentIndexChanged.connect(lambda *_: self._refresh_details())
        self.logs_header.right_box.addWidget(self.stream_combo)
        logs_card.body.addWidget(self.logs_header)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        logs_card.body.addWidget(self.logs_view, 1)
        splitter.addWidget(logs_card)

        art_card = Card(margins=(12, 12, 12, 12))
        self.art_header = SectionHeader()
        self.artifact_combo = QComboBox()
        self.artifact_combo.currentIndexChanged.connect(lambda *_: self._refresh_artifact_preview())
        self.art_header.right_box.addWidget(self.artifact_combo)
        art_card.body.addWidget(self.art_header)
        self.artifact_view = QPlainTextEdit()
        self.artifact_view.setReadOnly(True)
        art_card.body.addWidget(self.artifact_view, 1)
        splitter.addWidget(art_card)
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
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda _c=False, s=scope: self._set_scope(s))
        self._scope_group.addButton(btn)
        return btn

    def _make_action_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
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

    def _on_poll(self) -> None:
        if self.isVisible() or any(
            st in (STATUS_QUEUED, STATUS_RUNNING) for st in self._known_statuses.values()
        ):
            self.reload()

    def reload(self) -> None:
        store = self._open_store()
        if store is None:
            self._records = {}
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
            if selected_id and rec.task_id == selected_id:
                restore_row = idx

        self.table.filter_rows(self.search_edit.text())
        if self.table.rowCount() > 0:
            self.table.selectRow(restore_row)
        self._on_selected()

    def _on_selected(self) -> None:
        tid = self._selected_task_id()
        rec = self._records.get(tid) if tid else None
        is_active = bool(rec and rec.status in (STATUS_QUEUED, STATUS_RUNNING))
        is_terminal = bool(rec and rec.status in TERMINAL_STATUSES)
        self.cancel_btn.setEnabled(is_active)
        self.restart_btn.setEnabled(is_terminal)
        self.export_btn.setEnabled(bool(rec and rec.artifact_refs))
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

    def cancel_selected(self) -> None:
        tid = self._selected_task_id()
        store = self._open_store()
        if not tid or store is None:
            return
        try:
            store.request_cancel(tid)
            self.status_message.emit(tr("tasks.toast.cancelled", task_id=tid[:12]), "info")
            self.reload()
        except Exception as exc:
            QMessageBox.warning(self, tr("tasks.title"), str(exc))

    def restart_selected(self) -> None:
        tid = self._selected_task_id()
        store = self._open_store()
        if not tid or store is None:
            return
        try:
            created = store.create_restart_task(tid)
            if created is not None:
                self.status_message.emit(tr("tasks.toast.restarted", task_id=created.task_id[:12]), "ok")
                self.reload()
        except Exception as exc:
            QMessageBox.warning(self, tr("tasks.title"), str(exc))

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

    def retranslate(self) -> None:
        self.set_header(tr("tasks.title"), tr("tasks.lead"))
        self.scope_all_btn.setText(tr("tasks.scope.all"))
        self.scope_active_btn.setText(tr("tasks.scope.active"))
        self.scope_history_btn.setText(tr("tasks.scope.history"))
        self.search_edit.setPlaceholderText(tr("tasks.search"))
        self.refresh_btn.setText(tr("clients.refresh"))
        self.cancel_btn.setText(tr("tasks.btn.cancel"))
        self.restart_btn.setText(tr("tasks.btn.restart"))
        self.export_btn.setText(tr("tasks.btn.export"))

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
