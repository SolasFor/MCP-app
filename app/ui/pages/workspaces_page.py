"""Workspaces GUI page: registry, auto-detection, file tree, text search, Git status, and quick tasks."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.ui import tokens
from app.ui.components.cards import EmptyState, SectionHeader
from app.ui.components.management_layout import ManagementTabs, management_list, management_split, management_toolbar
from app.ui.components.context_menu import AppContextMenu, MenuActionSpec, make_toolbar_menu_button
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import (
    WORKSPACE_MIN_PROFILES,
    WorkspacePermissions,
    WorkspaceProfile,
)
from backend.workspaces.store import WorkspaceStore, detect_workspace_metadata


def _parse_kv_lines(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _parse_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


class WorkspaceProfileDialog(SilentDialog):
    """Create or edit a WorkspaceProfile with granular permissions and SecretStore refs."""

    def __init__(
        self,
        store: WorkspaceStore,
        *,
        existing: WorkspaceProfile | None = None,
        is_new: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._base = existing or WorkspaceProfile(workspace_id="", name="", root_path="")
        self._is_new = is_new
        self.saved_profile: WorkspaceProfile | None = None

        self.setWindowTitle(tr("workspaces.dlg.title_add" if is_new else "workspaces.dlg.title_edit"))
        self.setMinimumWidth(620)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self.id_edit = QLineEdit(self._base.workspace_id)
        self.id_edit.setObjectName("UiInput")
        self.id_edit.setReadOnly(not is_new)
        form.addRow(tr("workspaces.dlg.id"), self.id_edit)

        self.name_edit = QLineEdit(self._base.name)
        self.name_edit.setObjectName("UiInput")
        form.addRow(tr("workspaces.dlg.name"), self.name_edit)

        root_row = QHBoxLayout()
        self.root_edit = QLineEdit(self._base.root_path)
        self.root_edit.setObjectName("UiInput")
        self.browse_btn = QPushButton(tr("workspaces.dlg.browse"))
        self.browse_btn.clicked.connect(self._browse_root)
        self.detect_btn = QPushButton(tr("workspaces.dlg.autodetect"))
        self.detect_btn.clicked.connect(self.auto_detect_fields)
        root_row.addWidget(self.root_edit, 1)
        root_row.addWidget(self.browse_btn)
        root_row.addWidget(self.detect_btn)
        form.addRow(tr("workspaces.dlg.root"), root_row)

        meta_row = QHBoxLayout()
        self.lang_edit = QLineEdit(self._base.language)
        self.lang_edit.setObjectName("UiInput")
        self.git_root_edit = QLineEdit(self._base.git_root)
        self.git_root_edit.setObjectName("UiInput")
        meta_row.addWidget(self.lang_edit, 1)
        meta_row.addWidget(self.git_root_edit, 2)
        form.addRow(f"{tr('workspaces.dlg.lang')} / {tr('workspaces.dlg.git_root')}", meta_row)

        env_paths = QHBoxLayout()
        self.venv_edit = QLineEdit(self._base.python_venv)
        self.venv_edit.setObjectName("UiInput")
        self.node_edit = QLineEdit(self._base.node_path)
        self.node_edit.setObjectName("UiInput")
        env_paths.addWidget(self.venv_edit, 1)
        env_paths.addWidget(self.node_edit, 1)
        form.addRow(f"{tr('workspaces.dlg.venv')} / {tr('workspaces.dlg.node')}", env_paths)

        self.commands_edit = QPlainTextEdit(
            "\n".join(f"{k}={v}" for k, v in sorted(self._base.commands.items()))
        )
        self.commands_edit.setFixedHeight(58)
        form.addRow(tr("workspaces.dlg.commands"), self.commands_edit)

        self.excludes_edit = QLineEdit(", ".join(self._base.exclude_patterns))
        self.excludes_edit.setObjectName("UiInput")
        form.addRow(tr("workspaces.dlg.excludes"), self.excludes_edit)

        self.linked_servers_edit = QLineEdit(", ".join(self._base.linked_servers))
        self.linked_servers_edit.setObjectName("UiInput")
        form.addRow(tr("workspaces.dlg.linked_servers"), self.linked_servers_edit)

        perm_row = QHBoxLayout()
        self.perm_read = QCheckBox(tr("workspaces.dlg.perm_read"))
        self.perm_read.setChecked(self._base.permissions.read)
        self.perm_write = QCheckBox(tr("workspaces.dlg.perm_write"))
        self.perm_write.setChecked(self._base.permissions.write)
        self.perm_delete = QCheckBox(tr("workspaces.dlg.perm_delete"))
        self.perm_delete.setChecked(self._base.permissions.delete)
        self.perm_execute = QCheckBox(tr("workspaces.dlg.perm_execute"))
        self.perm_execute.setChecked(self._base.permissions.execute)
        self.perm_git = QCheckBox(tr("workspaces.dlg.perm_git"))
        self.perm_git.setChecked(self._base.permissions.git)
        for cb in (self.perm_read, self.perm_write, self.perm_delete, self.perm_execute, self.perm_git):
            perm_row.addWidget(cb)
        form.addRow("", perm_row)

        opts_row = QHBoxLayout()
        self.trust_hooks_check = QCheckBox(tr("workspaces.dlg.trust_hooks"))
        self.trust_hooks_check.setChecked(self._base.trust_git_hooks)
        self.enabled_check = QCheckBox(tr("workspaces.dlg.enabled"))
        self.enabled_check.setChecked(self._base.enabled)
        opts_row.addWidget(self.trust_hooks_check)
        opts_row.addWidget(self.enabled_check)
        opts_row.addStretch(1)
        form.addRow("", opts_row)

        access_row = QHBoxLayout()
        self.min_profile_combo = SafeComboBox()
        for mp in WORKSPACE_MIN_PROFILES:
            self.min_profile_combo.addItem(mp, mp)
        self.min_profile_combo.setCurrentIndex(
            max(self.min_profile_combo.findData(self._base.min_profile), 0)
        )
        self.allowed_clients_edit = QLineEdit(", ".join(self._base.allowed_clients))
        self.allowed_clients_edit.setObjectName("UiInput")
        access_row.addWidget(self.min_profile_combo, 1)
        access_row.addWidget(self.allowed_clients_edit, 2)
        form.addRow(
            f"{tr('workspaces.dlg.min_profile')} / {tr('workspaces.dlg.allowed_clients')}",
            access_row,
        )

        self.plain_env_edit = QPlainTextEdit(
            "\n".join(f"{k}={v}" for k, v in sorted(self._base.env.items()))
        )
        self.plain_env_edit.setFixedHeight(48)
        form.addRow(tr("workspaces.dlg.plain_env"), self.plain_env_edit)

        self.secret_env_edit = QPlainTextEdit()
        self.secret_env_edit.setFixedHeight(48)
        existing_secrets = sorted(self._base.env_secret_refs)
        self.secret_env_edit.setPlaceholderText(
            f"{tr('workspaces.dlg.secret_hint')} ({', '.join(existing_secrets)})"
            if existing_secrets
            else tr("workspaces.dlg.secret_hint")
        )
        form.addRow(tr("workspaces.dlg.secret_env"), self.secret_env_edit)

        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_root(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("workspaces.dlg.root"))
        if path:
            self.root_edit.setText(path)
            self.auto_detect_fields()

    def auto_detect_fields(self) -> None:
        root = self.root_edit.text().strip()
        if not root:
            return
        try:
            meta = detect_workspace_metadata(root)
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))
            return
        if not self.id_edit.isReadOnly() and not self.id_edit.text().strip():
            clean_id = "".join(ch if (ch.isalnum() or ch in "_.-") else "_" for ch in str(meta["name"]))
            self.id_edit.setText(clean_id[:64] or "workspace")
        if not self.name_edit.text().strip():
            self.name_edit.setText(str(meta["name"]))
        self.lang_edit.setText(str(meta["language"]))
        self.git_root_edit.setText(str(meta["git_root"]))
        self.venv_edit.setText(str(meta["python_venv"]))
        self.node_edit.setText(str(meta["node_path"]))
        if not self.commands_edit.toPlainText().strip() and meta["commands"]:
            self.commands_edit.setPlainText(
                "\n".join(f"{k}={v}" for k, v in sorted(meta["commands"].items()))
            )

    def _on_accept(self) -> None:
        wid = self.id_edit.text().strip()
        try:
            secret_refs = dict(self._base.env_secret_refs)
            for k, v in _parse_kv_lines(self.secret_env_edit.toPlainText()).items():
                secret_refs[k] = self._store.set_env_secret(wid, k, v)
            perms = WorkspacePermissions(
                read=self.perm_read.isChecked(),
                write=self.perm_write.isChecked(),
                delete=self.perm_delete.isChecked(),
                execute=self.perm_execute.isChecked(),
                git=self.perm_git.isChecked(),
            )
            profile = WorkspaceProfile(
                workspace_id=wid,
                name=self.name_edit.text().strip() or wid,
                root_path=self.root_edit.text().strip(),
                language=self.lang_edit.text().strip(),
                git_root=self.git_root_edit.text().strip(),
                python_venv=self.venv_edit.text().strip(),
                node_path=self.node_edit.text().strip(),
                commands=_parse_kv_lines(self.commands_edit.toPlainText()),
                env=_parse_kv_lines(self.plain_env_edit.toPlainText()),
                env_secret_refs=secret_refs,
                linked_servers=_parse_csv(self.linked_servers_edit.text()),
                exclude_patterns=_parse_csv(self.excludes_edit.text()),
                permissions=perms,
                client_permissions=dict(self._base.client_permissions),
                allowed_clients=_parse_csv(self.allowed_clients_edit.text()),
                min_profile=str(self.min_profile_combo.currentData() or "allowlist"),
                trust_git_hooks=self.trust_hooks_check.isChecked(),
                enabled=self.enabled_check.isChecked(),
            )
            profile.validate()
            if self._is_new and wid in self._store.load_workspaces():
                raise ValueError(f"Workspace '{wid}' already exists")
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))
            return
        self.saved_profile = profile
        self.accept()


class WorkspacesPage(PageScaffold):
    """GUI view of registered project workspaces, file trees, search, Git status, and tasks."""

    config_changed = pyqtSignal()
    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        history_dir: Path | None = None,
        secrets_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self.content.setSpacing(10)
        base = user_data_dir() / "workspaces"
        self._config_path = config_path or (base / "workspaces.json")
        self._history_dir = history_dir or (base / "history")
        secret_store = SecretStore(secrets_dir) if secrets_dir is not None else None
        self._redactor = redactor or SecretRedactor()
        self.store = WorkspaceStore(self._config_path, secret_store=secret_store)
        self.history = WorkspaceHistory(self._history_dir)
        self.manager = WorkspaceManager(self.store, self.history, redactor=self._redactor)
        self._profiles: dict[str, WorkspaceProfile] = {}

        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))

        self.add_btn = self._make_btn(self.add_workspace, obj="Accent")
        self.run_task_btn = self._make_btn(self.run_selected_task, obj="Accent")
        self.refresh_btn = self._make_btn(self.reload)
        self.list_menu_btn = make_toolbar_menu_button(tr("common.actions"), parent=self)
        self.list_menu_btn.clicked.connect(self._open_list_menu)
        self.content.addWidget(management_toolbar(self.search_edit, (self.add_btn, self.refresh_btn, self.list_menu_btn)))

        self.table_card = QWidget()
        table_lay = QVBoxLayout(self.table_card)
        table_lay.setContentsMargins(0, 0, 0, 0)
        table_lay.setSpacing(0)
        self.table = DataTable(["", "", "", "", "", "", ""])
        self.table.setMinimumHeight(130)
        self.table.itemSelectionChanged.connect(self._on_selected)
        self.table.set_row_menu_provider(self._build_row_menu)
        table_lay.addWidget(self.table, 1)

        self.empty_state = EmptyState("workspaces")
        list_panel = management_list(self.table_card, self.empty_state)

        self.detail_tabs = ManagementTabs()

        tree_pane = QWidget()
        tree_lay = QVBoxLayout(tree_pane)
        tree_lay.setContentsMargins(10, 10, 10, 10)
        tree_lay.setSpacing(6)
        self.tree_header = SectionHeader()
        tree_lay.addWidget(self.tree_header)
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)
        tree_lay.addWidget(self.tree_widget, 1)
        self.detail_tabs.add_section(tree_pane, "workspaces.details.tree_title", self.tree_header)

        git_pane = QWidget()
        git_lay = QVBoxLayout(git_pane)
        git_lay.setContentsMargins(10, 10, 10, 10)
        git_lay.setSpacing(6)
        self.git_header = SectionHeader()
        git_lay.addWidget(self.git_header)
        git_tools = QHBoxLayout()
        git_tools.setSpacing(6)
        self.file_search_edit = QLineEdit()
        self.file_search_edit.setObjectName("UiInput")
        self.file_search_btn = self._make_btn(self.search_in_selected_workspace)
        self.cmd_combo = SafeComboBox()
        git_tools.addWidget(self.file_search_edit, 1)
        git_tools.addWidget(self.file_search_btn)
        git_lay.addLayout(git_tools)
        command_row = QHBoxLayout()
        command_row.setSpacing(6)
        command_row.addWidget(self.cmd_combo, 1)
        command_row.addWidget(self.run_task_btn)
        git_lay.addLayout(command_row)
        self.file_search_edit.setClearButtonEnabled(True)
        self.details_view = QPlainTextEdit()
        self.details_view.setObjectName("ConsoleLog")
        self.details_view.setReadOnly(True)
        git_lay.addWidget(self.details_view, 1)
        self.detail_tabs.add_section(git_pane, "workspaces.details.git_title", self.git_header)

        self.content.addWidget(management_split(list_panel, self.detail_tabs), 1)

        self.retranslate()
        self.apply_theme()
        self.reload()

    def _make_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.clicked.connect(slot)
        return btn

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return None
        val = item.data(Qt.ItemDataRole.UserRole)
        return str(val) if val else None

    def reload(self) -> None:
        try:
            self._profiles = self.store.load_workspaces()
        except Exception:
            self._profiles = {}
        for secret in self.store.collect_secret_values():
            self._redactor.register(secret)

        if not self._profiles:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.show()
            self._on_selected()
            return

        self.empty_state.hide()
        self.table_card.show()
        selected = self._selected_id()
        wids = sorted(self._profiles)
        self.table.setRowCount(len(wids))
        restore_row = 0

        for idx, wid in enumerate(wids):
            prof = self._profiles[wid]
            name_item = QTableWidgetItem(f"{prof.name} ({prof.workspace_id})")
            name_item.setData(Qt.ItemDataRole.UserRole, prof.workspace_id)
            p = prof.permissions
            perm_text = "".join([
                "R" if p.read else "-",
                "W" if p.write else "-",
                "D" if p.delete else "-",
                "X" if p.execute else "-",
                "G" if p.git else "-",
            ])
            git_text = "Git" if prof.git_root else "—"
            self.table.setItem(idx, 0, name_item)
            self.table.setItem(idx, 1, QTableWidgetItem(prof.language or "—"))
            self.table.setItem(idx, 2, QTableWidgetItem(prof.root_path))
            self.table.setItem(idx, 3, QTableWidgetItem(git_text))
            self.table.setItem(idx, 4, QTableWidgetItem(perm_text))
            self.table.setItem(idx, 5, QTableWidgetItem(", ".join(sorted(prof.commands)) or "—"))
            self.table.set_row_actions_cell(idx, 6, tooltip=tr("common.actions"))
            if selected and wid == selected:
                restore_row = idx

        self.table.filter_rows(self.search_edit.text())
        if self.table.rowCount() > 0:
            self.table.selectRow(restore_row)
        self._on_selected()

    def _row_id(self, row: int) -> str | None:
        item = self.table.item(row, 0) if 0 <= row < self.table.rowCount() else None
        if item is None:
            return None
        val = item.data(Qt.ItemDataRole.UserRole)
        return str(val) if val else None

    def _on_selected(self) -> None:
        wid = self._selected_id()
        prof = self._profiles.get(wid or "")
        has_sel = prof is not None
        self.cmd_combo.clear()
        if prof is not None:
            for cname in sorted(prof.commands):
                self.cmd_combo.addItem(cname, cname)
        self.run_task_btn.setEnabled(has_sel and bool(prof and prof.commands))
        self.file_search_btn.setEnabled(has_sel)
        self._refresh_details()

    def _open_list_menu(self) -> None:
        specs = [
            MenuActionSpec(
                key="import",
                label=tr("workspaces.btn.import"),
                callback=self.import_json,
                icon_name="import",
            ),
            MenuActionSpec(
                key="export",
                label=tr("workspaces.btn.export"),
                callback=self.export_json,
                icon_name="export",
            ),
        ]
        AppContextMenu.from_specs(specs, parent=self).exec_clamped(
            self.list_menu_btn.mapToGlobal(self.list_menu_btn.rect().bottomLeft())
        )

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        wid = self._row_id(row)
        if not wid or wid not in self._profiles:
            return []
        return [
            MenuActionSpec(
                key="edit",
                label=tr("workspaces.btn.edit"),
                callback=lambda w=wid: self._edit_workspace(w),
                icon_name="edit",
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("common.copy_id"),
                callback=lambda w=wid: self._copy_workspace_id(w),
                icon_name="copy",
            ),
            MenuActionSpec(
                key="delete",
                label=tr("workspaces.btn.delete"),
                callback=lambda w=wid: self._delete_workspace(w),
                icon_name="trash",
                danger=True,
                separator_before=True,
            ),
        ]

    def _copy_workspace_id(self, wid: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(wid)
        self.status_message.emit(tr("common.copied_id", item_id=wid), "info")

    def _refresh_details(self) -> None:
        wid = self._selected_id()
        self.tree_widget.clear()
        if not wid or wid not in self._profiles:
            self.details_view.setPlainText(tr("workspaces.details.no_git"))
            return
        try:
            tree = self.manager.workspace_tree(wid, max_depth=3, client_id="owner")
            nodes: dict[str, QTreeWidgetItem] = {}
            for entry in tree.get("entries", []):
                rel = str(entry["path"])
                parts = rel.split("/")
                parent_item: QTreeWidgetItem | None = None
                for i in range(len(parts) - 1):
                    prefix = "/".join(parts[: i + 1])
                    if prefix not in nodes:
                        it = QTreeWidgetItem([parts[i]])
                        if parent_item is None:
                            self.tree_widget.addTopLevelItem(it)
                        else:
                            parent_item.addChild(it)
                        nodes[prefix] = it
                    parent_item = nodes[prefix]
                leaf = QTreeWidgetItem([parts[-1]])
                if parent_item is None:
                    self.tree_widget.addTopLevelItem(leaf)
                else:
                    parent_item.addChild(leaf)
                if entry["type"] == "dir":
                    nodes[rel] = leaf
        except Exception as exc:
            self.tree_widget.addTopLevelItem(QTreeWidgetItem([f"Error: {exc}"]))

        info = self.manager.workspace_info(wid, client_id="owner")
        git_block: dict[str, object]
        try:
            st = self.manager.git_status(wid, client_id="owner")
            lg = self.manager.git_log(wid, limit=5, client_id="owner")
            git_block = {"status": st, "recent_commits": lg.get("commits", [])}
        except Exception as exc:
            git_block = {"status_note": str(exc)}
        self.details_view.setPlainText(
            self._redactor.redact_text(
                json.dumps({"workspace": info, "git": git_block}, indent=2, ensure_ascii=False)
            )
        )

    def add_workspace(self) -> None:
        dlg = WorkspaceProfileDialog(self.store, is_new=True, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def save_profile(self, profile: WorkspaceProfile) -> None:
        self.store.upsert_workspace(profile)
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.saved", name=profile.name), "ok")
        self.reload()

    def _edit_workspace(self, wid: str) -> None:
        if wid not in self._profiles:
            return
        dlg = WorkspaceProfileDialog(
            self.store, existing=self._profiles[wid], is_new=False, parent=self
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def edit_selected(self) -> None:
        wid = self._selected_id()
        if wid:
            self._edit_workspace(wid)

    def _delete_workspace(self, wid: str) -> None:
        ans = SilentMessageBox.question(
            self,
            tr("workspaces.title"),
            tr("workspaces.delete.confirm", name=wid),
            SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            SilentMessageBox.StandardButton.No,
        )
        if ans != SilentMessageBox.StandardButton.Yes:
            return
        self.store.delete_workspace(wid)
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.deleted", name=wid), "info")
        self.reload()

    def delete_selected(self) -> None:
        wid = self._selected_id()
        if wid:
            self._delete_workspace(wid)

    def export_json(self) -> None:
        payload = self.store.export_redacted()
        text = self._redactor.redact_text(json.dumps(payload, indent=2, ensure_ascii=False))
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)
        self.status_message.emit(tr("workspaces.toast.exported"), "ok")

    def import_json(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("workspaces.btn.import"), "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            res = self.store.import_redacted(payload)
            self.config_changed.emit()
            self.status_message.emit(
                tr("workspaces.toast.imported", count=len(res.get("imported", []))), "ok"
            )
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))

    def search_in_selected_workspace(self) -> None:
        wid = self._selected_id()
        query = self.file_search_edit.text().strip()
        if not wid or not query:
            return
        try:
            res = self.manager.search_files(wid, query, client_id="owner")
            self.details_view.setPlainText(
                self._redactor.redact_text(json.dumps(res, indent=2, ensure_ascii=False))
            )
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))

    def run_selected_task(self) -> None:
        wid = self._selected_id()
        cname = str(self.cmd_combo.currentData() or "")
        if not wid or not cname:
            return
        try:
            res = asyncio.run(self.manager.run_workspace_task(wid, cname, client_id="owner"))
            self.details_view.setPlainText(
                self._redactor.redact_text(json.dumps(res, indent=2, ensure_ascii=False))
            )
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), self._redactor.redact_text(str(exc)))

    def shutdown(self) -> None:
        self.manager.close()

    def retranslate(self) -> None:
        self.set_header(tr("workspaces.title"), tr("workspaces.lead"))
        self.detail_tabs.retranslate()
        self.search_edit.setPlaceholderText(tr("workspaces.search"))
        self.add_btn.setText(tr("workspaces.btn.add"))
        self.run_task_btn.setText(tr("workspaces.btn.run_task"))
        self.file_search_btn.setText(tr("workspaces.btn.search_files"))
        self.refresh_btn.setText(tr("workspaces.btn.refresh"))
        self.list_menu_btn.setToolTip(tr("common.actions"))
        self.file_search_edit.setPlaceholderText(tr("workspaces.details.file_search_ph"))
        self.table.setHorizontalHeaderLabels([
            tr("workspaces.col.name"),
            tr("workspaces.col.lang"),
            tr("workspaces.col.root"),
            tr("workspaces.col.git"),
            tr("workspaces.col.perms"),
            tr("workspaces.col.commands"),
            "",
        ])
        self.empty_state.set_content(tr("workspaces.empty.title"), tr("workspaces.empty.desc"))
        self.tree_header.set_texts(tr("workspaces.details.tree_title"))
        self.git_header.set_texts(tr("workspaces.details.git_title"))
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
        mono = tokens.FONT_MONO
        self.details_view.setStyleSheet(f"font-family: {mono}; font-size: 11px;")
