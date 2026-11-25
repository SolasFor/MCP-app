"""MCP Gateway page: manage upstream stdio / Streamable HTTP / SSE MCP servers and permissions."""
from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.redaction import SecretRedactor
from app.paths import user_data_dir
from app.ui import tokens
from app.ui.components.cards import Card, EmptyState, SectionHeader
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_HEADERS,
    AUTH_NONE,
    ISOLATION_PER_CLIENT,
    ISOLATION_SHARED,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    GatewayServerStatus,
    ImportPreviewItem,
    UpstreamServerProfile,
    UpstreamToolEntry,
)
from backend.gateway.router import GatewayRouter
from backend.gateway.store import GatewayConfigStore, solidworks_mcp_template


def _parse_kv_lines(raw: str, sep: str = "=") -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if sep not in stripped:
            continue
        k, v = stripped.split(sep, 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _parse_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


class GatewayServerDialog(QDialog):
    """Create or edit an upstream MCP server profile without exposing stored secrets."""

    def __init__(
        self,
        store: GatewayConfigStore,
        *,
        existing: UpstreamServerProfile | None = None,
        is_new: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._base = existing or UpstreamServerProfile(server_id="", name="")
        self._is_new = is_new
        self.saved_profile: UpstreamServerProfile | None = None

        self.setWindowTitle(tr("gateway.dlg.title_add" if is_new else "gateway.dlg.title_edit"))
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self.id_edit = QLineEdit(self._base.server_id)
        self.id_edit.setObjectName("UiInput")
        self.id_edit.setReadOnly(not is_new)
        form.addRow(tr("gateway.dlg.id"), self.id_edit)

        self.name_edit = QLineEdit(self._base.name)
        self.name_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.name"), self.name_edit)

        self.transport_combo = QComboBox()
        for tid in (TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP, TRANSPORT_SSE):
            self.transport_combo.addItem(tid, tid)
        self.transport_combo.setCurrentIndex(max(self.transport_combo.findData(self._base.transport), 0))
        self.transport_combo.currentIndexChanged.connect(self._sync_transport_fields)
        form.addRow(tr("gateway.dlg.transport"), self.transport_combo)

        # stdio fields
        self.cmd_edit = QLineEdit(self._base.command)
        self.cmd_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.command"), self.cmd_edit)

        self.args_edit = QLineEdit(shlex.join(self._base.args) if self._base.args else "")
        self.args_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.args"), self.args_edit)

        self.cwd_edit = QLineEdit(self._base.cwd)
        self.cwd_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.cwd"), self.cwd_edit)

        self.plain_env_edit = QPlainTextEdit(
            "\n".join(f"{k}={v}" for k, v in sorted(self._base.env.items()))
        )
        self.plain_env_edit.setMaximumHeight(64)
        form.addRow(tr("gateway.dlg.plain_env"), self.plain_env_edit)

        self.secret_env_edit = QPlainTextEdit()
        self.secret_env_edit.setMaximumHeight(58)
        self.secret_env_edit.setPlaceholderText(tr("gateway.dlg.secret_hint"))
        form.addRow(tr("gateway.dlg.secret_env"), self.secret_env_edit)

        # HTTP / SSE fields
        self.url_edit = QLineEdit(self._base.url)
        self.url_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.url"), self.url_edit)

        self.allow_local_chk = QCheckBox(tr("gateway.dlg.allow_local"))
        self.allow_local_chk.setChecked(self._base.allow_local_endpoint)
        form.addRow("", self.allow_local_chk)

        self.allow_redirects_chk = QCheckBox(tr("gateway.dlg.allow_redirects"))
        self.allow_redirects_chk.setChecked(self._base.allow_redirects)
        form.addRow("", self.allow_redirects_chk)

        self.auth_combo = QComboBox()
        for aid in (AUTH_NONE, AUTH_BEARER, AUTH_HEADERS):
            self.auth_combo.addItem(aid, aid)
        self.auth_combo.setCurrentIndex(max(self.auth_combo.findData(self._base.auth_mode), 0))
        form.addRow(tr("gateway.dlg.auth_mode"), self.auth_combo)

        self.bearer_edit = QLineEdit()
        self.bearer_edit.setObjectName("UiInput")
        self.bearer_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.bearer_edit.setPlaceholderText(tr("gateway.dlg.secret_hint"))
        form.addRow(tr("gateway.dlg.bearer_token"), self.bearer_edit)

        self.secret_headers_edit = QPlainTextEdit()
        self.secret_headers_edit.setMaximumHeight(58)
        self.secret_headers_edit.setPlaceholderText(tr("gateway.dlg.secret_hint"))
        form.addRow(tr("gateway.dlg.secret_headers"), self.secret_headers_edit)

        # Access policy & lifecycle
        self.profile_combo = QComboBox()
        for pid in ("safe", "allowlist", "full"):
            self.profile_combo.addItem(tr(f"clients.role.{pid}"), pid)
        self.profile_combo.setCurrentIndex(max(self.profile_combo.findData(self._base.min_profile), 0))
        form.addRow(tr("gateway.dlg.min_profile"), self.profile_combo)

        self.isolation_combo = QComboBox()
        for iid in (ISOLATION_PER_CLIENT, ISOLATION_SHARED):
            self.isolation_combo.addItem(tr(f"gateway.isolation.{iid}"), iid)
        self.isolation_combo.setCurrentIndex(
            max(self.isolation_combo.findData(self._base.session_isolation), 0)
        )
        form.addRow(tr("gateway.dlg.isolation"), self.isolation_combo)

        self.allowed_tools_edit = QLineEdit(", ".join(self._base.allowed_tools))
        self.allowed_tools_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.allowed_tools"), self.allowed_tools_edit)

        self.denied_tools_edit = QLineEdit(", ".join(self._base.denied_tools))
        self.denied_tools_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.denied_tools"), self.denied_tools_edit)

        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(1.0, 600.0)
        self.timeout_spin.setValue(float(self._base.timeout_seconds))
        form.addRow(tr("gateway.dlg.timeout"), self.timeout_spin)

        self.enabled_chk = QCheckBox(tr("gateway.dlg.enabled"))
        self.enabled_chk.setChecked(self._base.enabled)
        self.autostart_chk = QCheckBox(tr("gateway.dlg.autostart"))
        self.autostart_chk.setChecked(self._base.autostart)
        self.approved_chk = QCheckBox(tr("gateway.dlg.approved"))
        self.approved_chk.setChecked(self._base.approved_by_owner)
        flags_row = QHBoxLayout()
        flags_row.addWidget(self.enabled_chk)
        flags_row.addWidget(self.autostart_chk)
        flags_row.addWidget(self.approved_chk)
        form.addRow("", flags_row)

        self.notes_edit = QLineEdit(self._base.notes)
        self.notes_edit.setObjectName("UiInput")
        form.addRow(tr("gateway.dlg.notes"), self.notes_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._sync_transport_fields()

    def _sync_transport_fields(self) -> None:
        is_stdio = self.transport_combo.currentData() == TRANSPORT_STDIO
        for w in (self.cmd_edit, self.args_edit, self.cwd_edit, self.plain_env_edit, self.secret_env_edit):
            w.setEnabled(is_stdio)
        for w in (
            self.url_edit,
            self.allow_local_chk,
            self.allow_redirects_chk,
            self.auth_combo,
            self.bearer_edit,
            self.secret_headers_edit,
        ):
            w.setEnabled(not is_stdio)

    def _on_accept(self) -> None:
        raw_args = self.args_edit.text().strip()
        try:
            args = tuple(shlex.split(raw_args, posix=False)) if raw_args else ()
        except ValueError:
            args = tuple(raw_args.split())

        profile = UpstreamServerProfile(
            server_id=self.id_edit.text().strip().lower(),
            name=self.name_edit.text().strip(),
            transport=str(self.transport_combo.currentData()),
            enabled=self.enabled_chk.isChecked(),
            autostart=self.autostart_chk.isChecked(),
            command=self.cmd_edit.text().strip(),
            args=args,
            cwd=self.cwd_edit.text().strip(),
            env=_parse_kv_lines(self.plain_env_edit.toPlainText(), "="),
            env_secret_refs=dict(self._base.env_secret_refs),
            url=self.url_edit.text().strip(),
            auth_mode=str(self.auth_combo.currentData()),
            auth_secret_ref=self._base.auth_secret_ref,
            headers_secret_refs=dict(self._base.headers_secret_refs),
            allow_local_endpoint=self.allow_local_chk.isChecked(),
            allow_redirects=self.allow_redirects_chk.isChecked(),
            session_isolation=str(self.isolation_combo.currentData()),
            min_profile=str(self.profile_combo.currentData()),
            allowed_tools=_parse_csv(self.allowed_tools_edit.text()),
            denied_tools=_parse_csv(self.denied_tools_edit.text()),
            timeout_seconds=float(self.timeout_spin.value()),
            max_response_bytes=self._base.max_response_bytes,
            approved_by_owner=self.approved_chk.isChecked(),
            notes=self.notes_edit.text().strip(),
        )
        secret_env = _parse_kv_lines(self.secret_env_edit.toPlainText(), "=")
        bearer = self.bearer_edit.text().strip() or None
        secret_headers = _parse_kv_lines(self.secret_headers_edit.toPlainText(), ":")
        errors = self._store.upsert(
            profile,
            secret_env=secret_env or None,
            bearer_token=bearer,
            secret_headers=secret_headers or None,
        )
        if errors:
            QMessageBox.warning(self, self.windowTitle(), "\n".join(errors))
            return
        self.saved_profile = self._store.get(profile.server_id)
        self.accept()


class GatewayImportPreviewDialog(QDialog):
    """Owner-confirmation preview dialog for imported `mcpServers` JSON configurations."""

    def __init__(self, items: list[ImportPreviewItem], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("gateway.import.preview_title"))
        self.setMinimumWidth(540)

        layout = QVBoxLayout(self)
        summary = QPlainTextEdit()
        summary.setReadOnly(True)
        lines: list[str] = []
        for item in items:
            p = item.profile
            target = f"{p.command} {' '.join(p.args)}".strip() if p.transport == TRANSPORT_STDIO else p.url
            lines.append(f"[{p.server_id}] {p.name} ({p.transport}) -> {target}")
            if item.inline_secrets:
                lines.append(f"  secrets -> SecretStore: {', '.join(sorted(item.inline_secrets))}")
            for warn in item.warnings:
                lines.append(f"  ! {warn}")
        summary.setPlainText("\n".join(lines))
        layout.addWidget(summary)

        self.approve_chk = QCheckBox(tr("gateway.import.approve_check"))
        self.approve_chk.setChecked(False)
        self.enable_chk = QCheckBox(tr("gateway.import.enable_check"))
        self.enable_chk.setChecked(True)
        layout.addWidget(self.approve_chk)
        layout.addWidget(self.enable_chk)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        assert ok_btn is not None
        ok_btn.setEnabled(False)
        self.approve_chk.toggled.connect(ok_btn.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)


class GatewayPage(PageScaffold):
    """Universal MCP Gateway manager page."""

    config_changed = pyqtSignal()
    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self._config_path = config_path or (user_data_dir() / "gateway" / "servers.json")
        self.store = GatewayConfigStore(self._config_path)
        self._statuses: dict[str, GatewayServerStatus] = {}
        self._catalog_by_server: dict[str, list[UpstreamToolEntry]] = {}

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda q: self.server_table.filter_rows(q))
        toolbar.addWidget(self.search_edit, 1)

        self.add_btn = self._make_btn(self._open_add_dialog, obj="Accent")
        self.solidworks_btn = self._make_btn(self._open_solidworks_preset)
        self.import_btn = self._make_btn(self._open_import_flow)
        self.export_btn = self._make_btn(self._export_redacted)
        self.refresh_btn = self._make_btn(lambda: self.refresh_servers_sync())
        for btn in (self.add_btn, self.solidworks_btn, self.import_btn, self.export_btn, self.refresh_btn):
            toolbar.addWidget(btn)
        self.content.addLayout(toolbar)

        action_bar = QHBoxLayout()
        action_bar.setSpacing(6)
        self.edit_btn = self._make_btn(self._open_edit_dialog)
        self.toggle_btn = self._make_btn(self._toggle_selected)
        self.delete_btn = self._make_btn(self._delete_selected, obj="Danger")
        for btn in (self.edit_btn, self.toggle_btn, self.delete_btn):
            btn.setEnabled(False)
            action_bar.addWidget(btn)
        action_bar.addStretch(1)
        self.content.addLayout(action_bar)

        self.table_card = Card(margins=(12, 12, 12, 12))
        self.server_table = DataTable(["", "", "", "", "", ""])
        self.server_table.itemSelectionChanged.connect(self._on_server_selected)
        self.table_card.body.addWidget(self.server_table, 1)
        self.content.addWidget(self.table_card, 1)

        self.empty_state = EmptyState("gateway")
        self.content.addWidget(self.empty_state, 1)

        # Details splitter: Tools/Schemas on left, Logs/Health on right
        splitter = QSplitter(Qt.Orientation.Horizontal)

        tools_card = Card(margins=(12, 12, 12, 12))
        self.tools_header = SectionHeader()
        tools_card.body.addWidget(self.tools_header)
        self.tools_table = DataTable(["", "", ""])
        self.tools_table.itemSelectionChanged.connect(self._on_tool_selected)
        tools_card.body.addWidget(self.tools_table, 1)
        self.schema_view = QPlainTextEdit()
        self.schema_view.setReadOnly(True)
        self.schema_view.setMaximumHeight(110)
        tools_card.body.addWidget(self.schema_view)
        splitter.addWidget(tools_card)

        logs_card = Card(margins=(12, 12, 12, 12))
        self.logs_header = SectionHeader()
        logs_card.body.addWidget(self.logs_header)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        logs_card.body.addWidget(self.logs_view, 1)
        splitter.addWidget(logs_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        self.content.addWidget(splitter, 1)

        self.retranslate()
        self.reload()

    def _make_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(slot)
        return btn

    def _selected_server_id(self) -> str | None:
        row = self.server_table.currentRow()
        item = self.server_table.item(row, 0) if row >= 0 else None
        if item is None:
            return None
        val = item.data(Qt.ItemDataRole.UserRole)
        return str(val) if val else None

    def reload(self) -> None:
        self.store.load()
        profiles = self.store.list_profiles()
        if not profiles:
            self.table_card.hide()
            self.empty_state.show()
            self.server_table.setRowCount(0)
            self._on_server_selected()
            return

        self.empty_state.hide()
        self.table_card.show()
        selected_id = self._selected_server_id()
        self.server_table.setRowCount(len(profiles))
        restore_row = 0
        for row, prof in enumerate(profiles):
            st = self._statuses.get(prof.server_id)
            if not prof.approved_by_owner:
                status_text = tr("gateway.status.unapproved")
            elif not prof.enabled:
                status_text = tr("gateway.status.disabled")
            elif st is not None:
                status_text = tr(f"gateway.status.{st.health}")
            else:
                status_text = tr("gateway.status.stopped")

            tools_count = len(self._catalog_by_server.get(prof.server_id, ()))
            if st is not None and st.tool_count > tools_count:
                tools_count = st.tool_count

            name_item = QTableWidgetItem(f"{prof.name} ({prof.server_id})")
            name_item.setData(Qt.ItemDataRole.UserRole, prof.server_id)
            self.server_table.setItem(row, 0, name_item)
            self.server_table.setItem(row, 1, QTableWidgetItem(prof.transport))
            self.server_table.setItem(row, 2, QTableWidgetItem(status_text))
            self.server_table.setItem(row, 3, QTableWidgetItem(str(tools_count)))
            self.server_table.setItem(row, 4, QTableWidgetItem(tr(f"clients.role.{prof.min_profile}")))
            self.server_table.setItem(
                row, 5, QTableWidgetItem(tr(f"gateway.isolation.{prof.session_isolation}"))
            )
            if selected_id and prof.server_id == selected_id:
                restore_row = row

        self.server_table.filter_rows(self.search_edit.text())
        if self.server_table.rowCount() > 0:
            self.server_table.selectRow(restore_row)
        self._on_server_selected()

    def _on_server_selected(self) -> None:
        sid = self._selected_server_id()
        has_sel = sid is not None
        self.edit_btn.setEnabled(has_sel)
        self.toggle_btn.setEnabled(has_sel)
        self.delete_btn.setEnabled(has_sel)
        if not sid:
            self.tools_table.setRowCount(0)
            self.schema_view.setPlainText(tr("gateway.details.schema_placeholder"))
            self.logs_view.setPlainText(tr("gateway.details.no_logs"))
            return

        entries = self._catalog_by_server.get(sid, [])
        self.tools_table.setRowCount(len(entries))
        for idx, entry in enumerate(entries):
            item = QTableWidgetItem(entry.namespaced_name)
            item.setData(Qt.ItemDataRole.UserRole, entry.input_schema)
            self.tools_table.setItem(idx, 0, item)
            self.tools_table.setItem(idx, 1, QTableWidgetItem(entry.raw_name))
            self.tools_table.setItem(idx, 2, QTableWidgetItem(entry.description))
        if entries:
            self.tools_table.selectRow(0)
        else:
            self.schema_view.setPlainText(tr("gateway.details.schema_placeholder"))

        st = self._statuses.get(sid)
        lines: list[str] = []
        if st is not None:
            if st.capabilities:
                lines.append(f"capabilities: {', '.join(st.capabilities)}")
            if st.last_error:
                lines.append(f"error: {st.last_error}")
            lines.extend(st.logs)
        self.logs_view.setPlainText("\n".join(lines) if lines else tr("gateway.details.no_logs"))

    def _on_tool_selected(self) -> None:
        row = self.tools_table.currentRow()
        item = self.tools_table.item(row, 0) if row >= 0 else None
        if item is None:
            self.schema_view.setPlainText(tr("gateway.details.schema_placeholder"))
            return
        schema = item.data(Qt.ItemDataRole.UserRole) or {}
        self.schema_view.setPlainText(json.dumps(schema, indent=2, ensure_ascii=False))

    def _open_add_dialog(self) -> None:
        dlg = GatewayServerDialog(self.store, is_new=True, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.reload()
            self.config_changed.emit()

    def _open_solidworks_preset(self) -> None:
        template = solidworks_mcp_template()
        dlg = GatewayServerDialog(self.store, existing=template, is_new=True, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.reload()
            self.config_changed.emit()

    def _open_edit_dialog(self) -> None:
        sid = self._selected_server_id()
        prof = self.store.get(sid) if sid else None
        if prof is None:
            return
        dlg = GatewayServerDialog(self.store, existing=prof, is_new=False, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.reload()
            self.config_changed.emit()

    def _toggle_selected(self) -> None:
        sid = self._selected_server_id()
        prof = self.store.get(sid) if sid else None
        if prof is None:
            return
        updated = UpstreamServerProfile.from_dict({**prof.to_dict(), "enabled": not prof.enabled})
        self.store.upsert(updated)
        self.reload()
        self.config_changed.emit()

    def _delete_selected(self) -> None:
        sid = self._selected_server_id()
        prof = self.store.get(sid) if sid else None
        if prof is None:
            return
        answer = QMessageBox.question(
            self,
            tr("gateway.btn.delete"),
            tr("gateway.delete.confirm", name=prof.name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.store.delete(prof.server_id)
        self._statuses.pop(prof.server_id, None)
        self._catalog_by_server.pop(prof.server_id, None)
        self.reload()
        self.config_changed.emit()

    def import_json_with_preview(self, raw_json: str) -> list[str]:
        """Parse standard MCP JSON, require owner confirmation, and persist."""
        items = self.store.preview_standard_mcp_json(raw_json)
        if not items:
            QMessageBox.information(self, tr("gateway.import.title"), tr("gateway.import.no_servers"))
            return []
        preview = GatewayImportPreviewDialog(items, parent=self)
        if preview.exec() != QDialog.DialogCode.Accepted or not preview.approve_chk.isChecked():
            return []
        imported = self.store.commit_import(
            items,
            approved_by_owner=True,
            enable_imported=preview.enable_chk.isChecked(),
        )
        self.reload()
        self.config_changed.emit()
        self.status_message.emit(tr("gateway.import.done", count=len(imported)), "ok")
        return imported

    def _open_import_flow(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(tr("gateway.import.title"))
        dlg.setMinimumWidth(520)
        box = QVBoxLayout(dlg)
        editor = QPlainTextEdit()
        editor.setPlaceholderText(tr("gateway.import.placeholder"))
        editor.setMinimumHeight(200)
        file_btn = QPushButton(tr("gateway.import.load_file"))

        def _pick_file() -> None:
            path, _ = QFileDialog.getOpenFileName(
                dlg, tr("gateway.import.load_file"), "", "JSON Files (*.json);;All Files (*)"
            )
            if path:
                editor.setPlainText(Path(path).read_text(encoding="utf-8", errors="replace"))

        file_btn.clicked.connect(_pick_file)
        box.addWidget(file_btn)
        box.addWidget(editor)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        box.addWidget(buttons)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.import_json_with_preview(editor.toPlainText())
        except (ValueError, PermissionError, OSError) as exc:
            QMessageBox.warning(self, tr("gateway.import.title"), str(exc))

    def export_redacted_text(self) -> str:
        """Return redacted gateway config JSON containing zero plaintext secrets."""
        return self.store.export_redacted_json()

    def _export_redacted(self) -> None:
        payload = self.export_redacted_text()
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(payload)
        path, _ = QFileDialog.getSaveFileName(
            self, tr("gateway.btn.export"), "mcp-gateway-export.json", "JSON Files (*.json)"
        )
        if path:
            Path(path).write_text(payload, encoding="utf-8")
        self.status_message.emit(tr("gateway.export.done"), "ok")

    def refresh_servers_sync(self, server_id: str | None = None) -> list[GatewayServerStatus]:
        """Run one isolated discovery pass for upstream status + tool schemas and close cleanly."""

        async def _discover() -> tuple[list[GatewayServerStatus], dict[str, list[UpstreamToolEntry]]]:
            router = GatewayRouter(self.store, redactor=SecretRedactor())
            try:
                if server_id is not None:
                    statuses = [await router.refresh_server(server_id)]
                else:
                    statuses = await router.refresh_all()
                by_server: dict[str, list[UpstreamToolEntry]] = {}
                for entry in router.catalog_entries():
                    by_server.setdefault(entry.server_id, []).append(entry)
                return statuses, by_server
            finally:
                await router.close_all()

        self.store.load()
        statuses, by_server = asyncio.run(_discover())
        if server_id is None:
            self._statuses = {st.server_id: st for st in statuses}
            self._catalog_by_server = by_server
        else:
            for st in statuses:
                self._statuses[st.server_id] = st
            self._catalog_by_server[server_id] = by_server.get(server_id, [])
        self.reload()
        self.status_message.emit(tr("gateway.refreshed"), "info")
        return statuses

    def retranslate(self) -> None:
        self.set_header(tr("gateway.title"), tr("gateway.lead"))
        self.search_edit.setPlaceholderText(tr("gateway.search"))
        self.add_btn.setText(tr("gateway.btn.add"))
        self.solidworks_btn.setText(tr("gateway.btn.solidworks"))
        self.import_btn.setText(tr("gateway.btn.import"))
        self.export_btn.setText(tr("gateway.btn.export"))
        self.refresh_btn.setText(tr("gateway.btn.refresh"))
        self.edit_btn.setText(tr("gateway.btn.edit"))
        self.toggle_btn.setText(tr("gateway.btn.toggle"))
        self.delete_btn.setText(tr("gateway.btn.delete"))
        self.server_table.setHorizontalHeaderLabels(
            [
                tr("gateway.col.name"),
                tr("gateway.col.transport"),
                tr("gateway.col.status"),
                tr("gateway.col.tools"),
                tr("gateway.col.profile"),
                tr("gateway.col.isolation"),
            ]
        )
        self.empty_state.set_content(tr("gateway.empty.title"), tr("gateway.empty.desc"))
        self.tools_header.set_texts(tr("gateway.details.tools_title"))
        self.logs_header.set_texts(tr("gateway.details.logs_title"))
        self.tools_table.setHorizontalHeaderLabels(
            [
                tr("gateway.tools.col.name"),
                tr("gateway.tools.col.raw"),
                tr("gateway.tools.col.desc"),
            ]
        )
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
        mono = tokens.FONT_MONO
        for view in (self.schema_view, self.logs_view):
            view.setStyleSheet(f"font-family: {mono}; font-size: 11px;")
