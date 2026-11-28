"""Unified Workspaces GUI page: projects, guarded files, Git, tasks, and managed local servers."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.admin_client import (
    AdminBackendUnavailableError,
    AdminRequestAmbiguousError,
    LocalAdminClient,
)
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.ui import tokens
from app.ui.components.cards import EmptyState, SectionHeader
from app.ui.components.context_menu import AppContextMenu, MenuActionSpec, make_toolbar_menu_button
from app.ui.components.management_layout import ManagementTabs, management_list, management_split, management_toolbar
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from app.ui.workspace_wizard import WorkspaceWizardDialog
from app.ui.pages.servers_page import (
    LinkServerDialog,
    RenameServerDialog,
    ServerProfileDialog,
    TemplateWizardDialog,
    fetch_server_logs_text,
    format_server_details,
    populate_server_rows,
)
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.store import TaskStore
from backend.workspaces.discovery import ManifestDriftError, verify_manifest_digests
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import (
    WORKSPACE_MIN_PROFILES,
    WorkspacePermissions,
    WorkspaceProfile,
)
from backend.workspaces.server_links import WorkspaceServerCoordinator, WorkspaceServersSnapshot
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


def _populate_tree_widget(tree_widget: QTreeWidget, entries: list[dict[str, Any]]) -> None:
    nodes: dict[str, QTreeWidgetItem] = {}
    for entry in entries:
        rel = str(entry["path"])
        parts = rel.split("/")
        parent_item: QTreeWidgetItem | None = None
        for i in range(len(parts) - 1):
            prefix = "/".join(parts[: i + 1])
            if prefix not in nodes:
                it = QTreeWidgetItem([parts[i]])
                if parent_item is None:
                    tree_widget.addTopLevelItem(it)
                else:
                    parent_item.addChild(it)
                nodes[prefix] = it
            parent_item = nodes[prefix]
        leaf = QTreeWidgetItem([parts[-1]])
        if parent_item is None:
            tree_widget.addTopLevelItem(leaf)
        else:
            parent_item.addChild(leaf)
        if entry["type"] == "dir":
            nodes[rel] = leaf


def _build_git_block(manager: WorkspaceManager, wid: str) -> dict[str, object]:
    try:
        st = manager.git_status(wid, client_id="owner")
        lg = manager.git_log(wid, limit=5, client_id="owner")
        return {"status": st, "recent_commits": lg.get("commits", [])}
    except Exception as exc:
        return {"status_note": str(exc)}


def _build_recent_tasks_block(task_store: TaskStore, linked_tasks: tuple[str, ...]) -> list[dict[str, Any]]:
    if not linked_tasks:
        return []
    wanted = set(linked_tasks[-20:])
    out: list[dict[str, Any]] = []
    for rec in task_store.list_tasks(limit=50):
        if rec.task_id in wanted:
            out.append(
                {
                    "task_id": rec.task_id,
                    "title": rec.title,
                    "status": rec.status,
                    "exit_code": rec.exit_code,
                    "finished_at": rec.finished_at,
                }
            )
    return out


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
        self._base = existing or WorkspaceProfile(
            workspace_id="",
            name="",
            root_path="",
            allow_oauth_clients=False,
        )
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

        self.allow_oauth_check = QCheckBox(tr("workspaces.dlg.allow_oauth_clients"))
        self.allow_oauth_check.setChecked(self._base.allow_oauth_clients)
        form.addRow("", self.allow_oauth_check)

        access_row = QHBoxLayout()
        self.min_profile_combo = SafeComboBox()
        for mp in WORKSPACE_MIN_PROFILES:
            self.min_profile_combo.addItem(mp, mp)
        self.min_profile_combo.setCurrentIndex(
            max(self.min_profile_combo.findData(self._base.min_profile), 0)
        )
        self.allowed_clients_edit = QLineEdit(", ".join(self._base.allowed_clients))
        self.allowed_clients_edit.setObjectName("UiInput")
        self.allowed_clients_edit.setPlaceholderText(tr("workspaces.dlg.allowed_clients_ph"))
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
                linked_tasks=self._base.linked_tasks,
                linked_extensions=self._base.linked_extensions,
                exclude_patterns=_parse_csv(self.excludes_edit.text()),
                permissions=perms,
                client_permissions=dict(self._base.client_permissions),
                allowed_clients=_parse_csv(self.allowed_clients_edit.text()),
                min_profile=str(self.min_profile_combo.currentData() or "allowlist"),
                allow_oauth_clients=self.allow_oauth_check.isChecked(),
                manifest_digests=dict(self._base.manifest_digests),
                trust_git_hooks=self.trust_hooks_check.isChecked(),
                enabled=self.enabled_check.isChecked(),
                description=self._base.description,
            )
            profile.validate()
            if self._is_new and wid in self._store.load_workspaces():
                raise ValueError(f"Workspace '{wid}' already exists")
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))
            return
        self.saved_profile = profile
        self.accept()


class _ServerRuntimeProxy:
    """Delegates server runtime calls to backend Admin API when running, else local ServerManager."""

    def __init__(
        self,
        local_manager: ServerManager,
        get_admin_client: Callable[[], LocalAdminClient | None],
        is_backend_stopped: Callable[[], bool] | None = None,
    ) -> None:
        self._local = local_manager
        self._get_client = get_admin_client
        self._is_backend_stopped = is_backend_stopped or (lambda: True)

    def _call(
        self,
        remote_fn: Callable[[LocalAdminClient], Any],
        local_fn: Callable[[], Any],
        *,
        mutating: bool,
    ) -> Any:
        client = self._get_client()
        if client is not None:
            try:
                return remote_fn(client)
            except AdminRequestAmbiguousError:
                if mutating:
                    raise
            except AdminBackendUnavailableError:
                if mutating and not self._is_backend_stopped():
                    raise
        elif mutating and not self._is_backend_stopped():
            raise AdminBackendUnavailableError(
                "Backend is active but Local Admin API is unavailable; refusing local state mutation"
            )
        return local_fn()

    def list_servers(self, *, client_id: str | None = "owner", workspace_id: str = "") -> list[dict[str, Any]]:
        return list(
            self._call(
                lambda c: c.list_servers(),
                lambda: self._local.list_servers(client_id=client_id, workspace_id=workspace_id),
                mutating=False,
            )
        )

    def status_server(self, name: str, *, client_id: str | None = "owner", workspace_id: str = "") -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.server_status(name),
                lambda: self._local.status_server(name, client_id=client_id, workspace_id=workspace_id),
                mutating=False,
            )
        )

    def start_server(
        self, name: str, *, client_id: str | None = "owner", wait_readiness: bool = True, workspace_id: str = ""
    ) -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.start_server(name, workspace_id=workspace_id, wait_readiness=wait_readiness),
                lambda: self._local.start_server(
                    name, client_id=client_id, wait_readiness=wait_readiness, workspace_id=workspace_id
                ),
                mutating=True,
            )
        )

    def stop_server(self, name: str, *, client_id: str | None = "owner", workspace_id: str = "") -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.stop_server(name),
                lambda: self._local.stop_server(name, client_id=client_id, workspace_id=workspace_id),
                mutating=True,
            )
        )

    def restart_server(
        self, name: str, *, client_id: str | None = "owner", wait_readiness: bool = True, workspace_id: str = ""
    ) -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.restart_server(name, workspace_id=workspace_id, wait_readiness=wait_readiness),
                lambda: self._local.restart_server(
                    name, client_id=client_id, wait_readiness=wait_readiness, workspace_id=workspace_id
                ),
                mutating=True,
            )
        )

    def health_server(
        self, name: str, *, client_id: str | None = "owner", run_probe: bool = True, workspace_id: str = ""
    ) -> dict[str, Any]:
        def _remote(c: LocalAdminClient) -> dict[str, Any]:
            return c.health_server(name) if run_probe else c.server_status(name)

        return dict(
            self._call(
                _remote,
                lambda: self._local.health_server(
                    name, client_id=client_id, run_probe=run_probe, workspace_id=workspace_id
                ),
                mutating=bool(run_probe),
            )
        )

    def logs_server(
        self,
        name: str,
        *,
        client_id: str | None = "owner",
        stream: Literal["stdout", "stderr"] = "stdout",
        offset: int = 0,
        limit: int = 8000,
    ) -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.server_logs(name, stream=stream, offset=offset, limit=limit),
                lambda: self._local.logs_server(
                    name, client_id=client_id, stream=stream, offset=offset, limit=limit
                ),
                mutating=False,
            )
        )

    def metrics_server(self, name: str, *, client_id: str | None = "owner") -> dict[str, Any]:
        return dict(
            self._call(
                lambda c: c.server_metrics(name),
                lambda: self._local.metrics_server(name, client_id=client_id),
                mutating=False,
            )
        )

    def start_autostart_servers(self) -> list[dict[str, Any]]:
        return list(
            self._call(
                lambda c: c.autostart_servers(),
                lambda: self._local.start_autostart_servers(),
                mutating=True,
            )
        )


class WorkspacesPage(PageScaffold):
    """Unified Workspaces + Managed Servers page with linked & unlinked server parity."""

    config_changed = pyqtSignal()
    status_message = pyqtSignal(str, str)
    _op_finished = pyqtSignal(str, object, str, str)

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        history_dir: Path | None = None,
        secrets_dir: Path | None = None,
        servers_config_path: Path | None = None,
        servers_secrets_dir: Path | None = None,
        tasks_db_path: Path | None = None,
        tasks_spool_dir: Path | None = None,
        tasks_artifacts_dir: Path | None = None,
        automation_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
        admin_client_provider: Callable[[], LocalAdminClient | None] | None = None,
        backend_running_checker: Callable[[], bool] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self.content.setSpacing(10)
        ws_base = user_data_dir() / "workspaces"
        self._config_path = config_path or (ws_base / "workspaces.json")
        self._history_dir = history_dir or (ws_base / "history")
        self._servers_config_path = servers_config_path or (user_data_dir() / "servers" / "managed_servers.json")
        self._tasks_db_path = tasks_db_path or (user_data_dir() / "tasks" / "tasks.sqlite3")
        resolved_spool = tasks_spool_dir or (self._tasks_db_path.parent / "spool")
        resolved_artifacts = tasks_artifacts_dir or (self._tasks_db_path.parent / "artifacts")
        self._redactor = redactor or SecretRedactor()
        self._admin_client_provider = admin_client_provider
        self._backend_running_checker = backend_running_checker

        ws_secret_store = SecretStore(secrets_dir) if secrets_dir is not None else None
        srv_secret_store = SecretStore(servers_secrets_dir) if servers_secrets_dir is not None else None
        self.store = WorkspaceStore(self._config_path, secret_store=ws_secret_store)
        self.server_store = ServerConfigStore(self._servers_config_path, secret_store=srv_secret_store)
        self.history = WorkspaceHistory(self._history_dir)
        self.task_store = TaskStore(self._tasks_db_path)
        self.coordinator = WorkspaceServerCoordinator(
            self.store,
            self.server_store,
            automation_dir=automation_dir,
        )
        self._config_error = ""
        self._try_initial_migration()

        self._local_runner = ProcessRunner(spool_dir=resolved_spool, redactor=self._redactor)
        self.server_manager = ServerManager(
            self.server_store,
            runner=self._local_runner,
            redactor=self._redactor,
            task_store=self.task_store,
            workspace_authorizer=self.coordinator.authorize_server_operation,
        )
        self.runtime_proxy = _ServerRuntimeProxy(
            self.server_manager,
            self._get_admin_client,
            self._is_backend_confirmed_stopped,
        )
        self.manager = WorkspaceManager(
            self.store,
            self.history,
            runner=self._local_runner,
            redactor=self._redactor,
            task_store=self.task_store,
            spool_dir=resolved_spool,
            artifacts_dir=resolved_artifacts,
            coordinator=self.coordinator,
            server_manager=self.server_manager,
        )
        self._profiles: dict[str, WorkspaceProfile] = {}
        self._server_profiles: dict[str, ServerProfile] = {}
        self._snapshot: WorkspaceServersSnapshot | None = None
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._active_server_name: str | None = None
        self._pending_threads: set[threading.Thread] = set()

        self._op_finished.connect(self._on_op_finished)
        self._build_ui()

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._on_poll)
        self._poll_timer.start()

        self.retranslate()
        self.apply_theme()
        self.reload()

    def _is_backend_confirmed_stopped(self) -> bool:
        if self._backend_running_checker is None:
            return True
        return not bool(self._backend_running_checker())

    def _get_admin_client(self) -> LocalAdminClient | None:
        if self._backend_running_checker is not None and self._is_backend_confirmed_stopped():
            return None
        if self._admin_client_provider is None:
            return None
        return self._admin_client_provider()

    def _try_initial_migration(self) -> None:
        try:
            self.coordinator.ensure_migrated()
            self._config_error = ""
        except Exception as exc:  # noqa: BLE001
            self._config_error = str(exc)

    def _build_ui(self) -> None:
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._apply_search_filter)

        self.add_btn = self._make_btn(self.add_workspace, obj="Accent")
        self.add_server_btn = self._make_btn(self.add_server)
        self.run_task_btn = self._make_btn(self.run_selected_task, obj="Accent")
        self.refresh_btn = self._make_btn(self.reload)
        self.list_menu_btn = make_toolbar_menu_button(tr("common.actions"), parent=self)
        self.list_menu_btn.clicked.connect(self._open_list_menu)
        self.content.addWidget(
            management_toolbar(
                self.search_edit,
                (self.add_btn, self.add_server_btn, self.refresh_btn, self.list_menu_btn),
            )
        )

        self.corrupt_banner = QLabel()
        self.corrupt_banner.setObjectName("WarnBanner")
        self.corrupt_banner.setWordWrap(True)
        self.corrupt_banner.hide()
        self.content.addWidget(self.corrupt_banner)

        list_panel = self._build_collection_tabs()
        self.detail_tabs = ManagementTabs()
        self._build_detail_tabs()
        self.content.addWidget(management_split(list_panel, self.detail_tabs), 1)

    def _build_collection_tabs(self) -> ManagementTabs:
        self.collection_tabs = ManagementTabs()

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
        self.collection_tabs.addTab(
            management_list(self.table_card, self.empty_state), tr("workspaces.tab.projects")
        )

        self.unlinked_table_card = QWidget()
        unlinked_lay = QVBoxLayout(self.unlinked_table_card)
        unlinked_lay.setContentsMargins(0, 0, 0, 0)
        unlinked_lay.setSpacing(0)
        self.unlinked_table = DataTable(["", "", "", "", "", "", "", "", ""])
        self.unlinked_table.setMinimumHeight(130)
        self.unlinked_table.itemSelectionChanged.connect(self._on_unlinked_server_selected)
        self.unlinked_table.set_row_menu_provider(self._build_unlinked_server_menu)
        unlinked_lay.addWidget(self.unlinked_table, 1)
        self.unlinked_empty_state = EmptyState("servers")
        self.collection_tabs.addTab(
            management_list(self.unlinked_table_card, self.unlinked_empty_state),
            tr("workspaces.tab.unlinked"),
        )
        return self.collection_tabs

    def _build_detail_tabs(self) -> None:
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
        self.file_search_edit.setClearButtonEnabled(True)
        self.file_search_btn = self._make_btn(self.search_in_selected_workspace)
        git_tools.addWidget(self.file_search_edit, 1)
        git_tools.addWidget(self.file_search_btn)
        git_lay.addLayout(git_tools)

        self.cmd_combo = SafeComboBox()
        self.task_combo = self.cmd_combo
        command_row = QHBoxLayout()
        command_row.setSpacing(6)
        command_row.addWidget(self.cmd_combo, 1)
        command_row.addWidget(self.run_task_btn)
        git_lay.addLayout(command_row)

        self.details_view = QPlainTextEdit()
        self.details_view.setObjectName("ConsoleLog")
        self.details_view.setReadOnly(True)
        self.git_view = self.details_view
        self.task_output_view = self.details_view
        git_lay.addWidget(self.details_view, 1)
        self.detail_tabs.add_section(git_pane, "workspaces.details.git_title", self.git_header)

        ws_srv_pane = QWidget()
        ws_srv_lay = QVBoxLayout(ws_srv_pane)
        ws_srv_lay.setContentsMargins(10, 10, 10, 10)
        ws_srv_lay.setSpacing(6)
        self.servers_header = SectionHeader()
        self.ws_add_server_btn = self._make_btn(self.add_server_for_selected_workspace, obj="Accent")
        self.ws_tpl_server_btn = self._make_btn(self.add_template_server_for_selected_workspace)
        self.ws_link_server_btn = self._make_btn(self.prompt_link_server_to_selected_workspace)
        self.servers_header.right_box.addWidget(self.ws_add_server_btn)
        self.servers_header.right_box.addWidget(self.ws_tpl_server_btn)
        self.servers_header.right_box.addWidget(self.ws_link_server_btn)
        ws_srv_lay.addWidget(self.servers_header)
        self.ws_servers_card = QWidget()
        ws_card_lay = QVBoxLayout(self.ws_servers_card)
        ws_card_lay.setContentsMargins(0, 0, 0, 0)
        ws_card_lay.setSpacing(0)
        self.ws_servers_table = DataTable(["", "", "", "", "", "", "", "", ""])
        self.ws_servers_table.setMinimumHeight(110)
        self.ws_servers_table.itemSelectionChanged.connect(self._on_ws_server_selected)
        self.ws_servers_table.set_row_menu_provider(self._build_ws_server_menu)
        ws_card_lay.addWidget(self.ws_servers_table, 1)
        self.ws_servers_empty = EmptyState("servers")
        ws_srv_lay.addWidget(management_list(self.ws_servers_card, self.ws_servers_empty), 1)
        self.detail_tabs.add_section(ws_srv_pane, "workspaces.details.servers_title", self.servers_header, controls=True)

        logs_pane = QWidget()
        logs_lay = QVBoxLayout(logs_pane)
        logs_lay.setContentsMargins(10, 10, 10, 10)
        logs_lay.setSpacing(6)
        self.logs_header = SectionHeader()
        self.stream_combo = SafeComboBox()
        self.stream_combo.addItem("stdout", "stdout")
        self.stream_combo.addItem("stderr", "stderr")
        self.stream_combo.currentIndexChanged.connect(lambda *_: self._refresh_server_details())
        self.logs_header.right_box.addWidget(self.stream_combo)
        logs_lay.addWidget(self.logs_header)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setObjectName("ConsoleLog")
        self.logs_view.setReadOnly(True)
        logs_lay.addWidget(self.logs_view, 1)
        self.detail_tabs.add_section(logs_pane, "workspaces.details.server_logs_title", self.logs_header, controls=True)

        info_pane = QWidget()
        info_lay = QVBoxLayout(info_pane)
        info_lay.setContentsMargins(10, 10, 10, 10)
        info_lay.setSpacing(6)
        self.info_header = SectionHeader()
        info_lay.addWidget(self.info_header)
        self.info_view = QPlainTextEdit()
        self.info_view.setObjectName("ConsoleLog")
        self.info_view.setReadOnly(True)
        info_lay.addWidget(self.info_view, 1)
        self.detail_tabs.add_section(info_pane, "workspaces.details.server_info_title", self.info_header)

    def _make_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.clicked.connect(slot)
        return btn

    def _selected_id(self) -> str | None:
        return self._row_id(self.table.currentRow())

    def _row_id(self, row: int) -> str | None:
        item = self.table.item(row, 0) if 0 <= row < self.table.rowCount() else None
        val = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return str(val) if val else None

    @staticmethod
    def _server_row_info(table: DataTable, row: int) -> tuple[str | None, bool]:
        item = table.item(row, 0) if 0 <= row < table.rowCount() else None
        if item is None:
            return None, False
        val = item.data(Qt.ItemDataRole.UserRole)
        missing = bool(item.data(Qt.ItemDataRole.UserRole + 1))
        return (str(val) if val else None), missing

    def _apply_search_filter(self, query: str) -> None:
        self.table.filter_rows(query)
        self.unlinked_table.filter_rows(query)
        self.ws_servers_table.filter_rows(query)

    def _on_poll(self) -> None:
        has_live = any(
            snap.get("running") or snap.get("status") == "restarting"
            for snap in self._snapshots.values()
        )
        if self.isVisible() or has_live or self._pending_threads:
            self.reload()

    def reload(self) -> None:
        self._load_state_safely()
        self._populate_workspaces_table()
        self._populate_unlinked_servers_table()
        self._on_selected()

    def _load_state_safely(self) -> None:
        try:
            snap = self.coordinator.partition_servers()
            self._snapshot = snap
            self._profiles = snap.workspaces
            self._server_profiles = snap.servers
            self._config_error = ""
            self.corrupt_banner.hide()
        except Exception as exc:  # noqa: BLE001
            self._config_error = str(exc)
            self.corrupt_banner.setText(tr("workspaces.corrupt_banner", error=self._config_error))
            self.corrupt_banner.show()
            if self._snapshot is None:
                self._profiles = {}
                self._server_profiles = {}
        for secret in self.store.collect_secret_values():
            self._redactor.register(secret)
        for secret in self.server_store.collect_secret_values():
            self._redactor.register(secret)
        try:
            items = self.runtime_proxy.list_servers(client_id="owner")
            self._snapshots = {str(item["name"]): item for item in items}
        except Exception:  # noqa: BLE001
            self._snapshots = {}

    def _populate_workspaces_table(self) -> None:
        if not self._profiles:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.show()
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
            perm_text = "".join(
                ch if allowed else "-"
                for ch, allowed in (("R", p.read), ("W", p.write), ("D", p.delete), ("X", p.execute), ("G", p.git))
            )
            self.table.setItem(idx, 0, name_item)
            self.table.setItem(idx, 1, QTableWidgetItem(prof.language or "—"))
            self.table.setItem(idx, 2, QTableWidgetItem(prof.root_path))
            self.table.setItem(idx, 3, QTableWidgetItem("Git" if prof.git_root else "—"))
            self.table.setItem(idx, 4, QTableWidgetItem(perm_text))
            self.table.setItem(idx, 5, QTableWidgetItem(", ".join(sorted(prof.commands)) or "—"))
            self.table.set_row_actions_cell(idx, 6, tooltip=tr("common.actions"))
            if selected and wid == selected:
                restore_row = idx
        self.table.filter_rows(self.search_edit.text())
        if self.table.rowCount() > 0:
            self.table.selectRow(restore_row)

    def _populate_unlinked_servers_table(self) -> None:
        unlinked = self._snapshot.unlinked_servers if self._snapshot else []
        if not unlinked:
            self.unlinked_table.setRowCount(0)
            self.unlinked_table_card.hide()
            self.unlinked_empty_state.show()
            return
        self.unlinked_empty_state.hide()
        self.unlinked_table_card.show()
        restore = populate_server_rows(
            self.unlinked_table,
            unlinked,
            self._snapshots,
            self.runtime_proxy,
            selected_name=self._active_server_name,
        )
        self.unlinked_table.filter_rows(self.search_edit.text())
        if self.unlinked_table.rowCount() > 0 and self._active_server_name in {p.name for p in unlinked}:
            self.unlinked_table.selectRow(restore)

    def _populate_workspace_servers_table(self, wid: str | None) -> None:
        snap = self._snapshot
        if not wid or wid not in self._profiles or snap is None:
            self.ws_servers_table.setRowCount(0)
            self.ws_servers_card.hide()
            self.ws_servers_empty.show()
            return
        linked = snap.linked_by_workspace.get(wid, [])
        missing = snap.missing_by_workspace.get(wid, ())
        if not linked and not missing:
            self.ws_servers_table.setRowCount(0)
            self.ws_servers_card.hide()
            self.ws_servers_empty.show()
            return
        self.ws_servers_empty.hide()
        self.ws_servers_card.show()
        restore = populate_server_rows(
            self.ws_servers_table,
            linked,
            self._snapshots,
            self.runtime_proxy,
            missing_names=missing,
            linked_map=snap.server_to_workspaces,
            selected_name=self._active_server_name,
        )
        self.ws_servers_table.filter_rows(self.search_edit.text())
        if self.ws_servers_table.rowCount() > 0:
            self.ws_servers_table.selectRow(restore)
            if not self._active_server_name or self._active_server_name not in self._server_profiles:
                chosen, is_missing = self._server_row_info(self.ws_servers_table, restore)
                if chosen and not is_missing:
                    self._active_server_name = chosen

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
        self.ws_add_server_btn.setEnabled(has_sel)
        self.ws_tpl_server_btn.setEnabled(has_sel)
        self.ws_link_server_btn.setEnabled(has_sel and self._has_linkable_servers(wid))
        self._populate_workspace_servers_table(wid)
        self._refresh_details()
        self._refresh_server_details()

    def _has_linkable_servers(self, wid: str | None) -> bool:
        if not wid or wid not in self._profiles:
            return False
        already = set(self._profiles[wid].linked_servers)
        return any(name not in already for name in self._server_profiles)

    def _on_ws_server_selected(self) -> None:
        name, is_missing = self._server_row_info(self.ws_servers_table, self.ws_servers_table.currentRow())
        if name and not is_missing:
            self._active_server_name = name
            self._refresh_server_details()

    def _on_unlinked_server_selected(self) -> None:
        name, _ = self._server_row_info(self.unlinked_table, self.unlinked_table.currentRow())
        if name:
            self._active_server_name = name
            self._refresh_server_details()

    def select_workspace(self, wid: str) -> bool:
        for row in range(self.table.rowCount()):
            if self._row_id(row) == wid:
                self.table.selectRow(row)
                self._on_selected()
                return True
        return False

    def select_server(self, name: str) -> bool:
        for table in (self.ws_servers_table, self.unlinked_table):
            for row in range(table.rowCount()):
                rname, is_missing = self._server_row_info(table, row)
                if rname == name and not is_missing:
                    table.selectRow(row)
                    self._active_server_name = name
                    self._refresh_server_details()
                    return True
        if name in self._server_profiles:
            self._active_server_name = name
            self._refresh_server_details()
            return True
        return False

    def _open_list_menu(self) -> None:
        specs = [
            MenuActionSpec(
                key="add_manual",
                label=tr("workspaces.btn.add_manual"),
                callback=self.add_workspace_manual,
                icon_name="plus",
            ),
            MenuActionSpec(
                key="template_server",
                label=tr("workspaces.btn.template_server"),
                callback=self.add_server_from_template,
                icon_name="plus",
            ),
            MenuActionSpec(
                key="import",
                label=tr("workspaces.btn.import"),
                callback=self.import_json,
                icon_name="import",
                separator_before=True,
            ),
            MenuActionSpec(
                key="export",
                label=tr("workspaces.btn.export"),
                callback=self.export_json,
                icon_name="export",
            ),
            MenuActionSpec(
                key="import_servers",
                label=tr("workspaces.btn.import_servers"),
                callback=self.import_servers_json,
                icon_name="import",
            ),
        ]
        AppContextMenu.from_specs(specs, parent=self).exec_clamped(
            self.list_menu_btn.mapToGlobal(self.list_menu_btn.rect().bottomLeft())
        )

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        wid = self._row_id(row)
        if not wid or wid not in self._profiles:
            return []
        prof = self._profiles[wid]
        specs = [
            MenuActionSpec(
                key="edit",
                label=tr("workspaces.btn.edit"),
                callback=lambda w=wid: self._edit_workspace(w),
                icon_name="edit",
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("common.copy_id"),
                callback=lambda w=wid: self._copy_item_id(w),
                icon_name="copy",
            ),
        ]
        if prof.manifest_digests:
            specs.append(
                MenuActionSpec(
                    key="reapprove_manifests",
                    label=tr("workspaces.btn.reapprove_manifests"),
                    callback=lambda w=wid: self._reapprove_workspace_manifests(w),
                    icon_name="shield",
                )
            )
        specs.append(
            MenuActionSpec(
                key="delete",
                label=tr("workspaces.btn.delete"),
                callback=lambda w=wid: self._delete_workspace(w),
                icon_name="trash",
                danger=True,
                separator_before=True,
            )
        )
        return specs

    def _build_ws_server_menu(self, row: int) -> list[MenuActionSpec]:
        name, is_missing = self._server_row_info(self.ws_servers_table, row)
        wid = self._selected_id()
        if not name:
            return []
        if is_missing or name not in self._server_profiles:
            specs: list[MenuActionSpec] = []
            if wid:
                specs.append(
                    MenuActionSpec(
                        key="unlink",
                        label=tr("workspaces.btn.unlink_server"),
                        callback=lambda w=wid, n=name: self.unlink_server_from_workspace(w, n),
                        icon_name="trash",
                    )
                )
            specs.append(
                MenuActionSpec(
                    key="copy_id",
                    label=tr("common.copy_id"),
                    callback=lambda n=name: self._copy_item_id(n),
                    icon_name="copy",
                )
            )
            return specs
        return self._server_menu_specs(name, workspace_id=wid, unlinked=False)

    def _build_unlinked_server_menu(self, row: int) -> list[MenuActionSpec]:
        name, _ = self._server_row_info(self.unlinked_table, row)
        if not name or name not in self._server_profiles:
            return []
        return self._server_menu_specs(name, workspace_id=self._selected_id(), unlinked=True)

    def _server_menu_specs(self, name: str, *, workspace_id: str | None, unlinked: bool) -> list[MenuActionSpec]:
        running = bool(self._snapshots.get(name, {}).get("running"))
        specs = [
            MenuActionSpec(key="start", label=tr("servers.btn.start"), callback=lambda n=name: self._run_server_op("start", n), icon_name="play", enabled=not running),
            MenuActionSpec(key="stop", label=tr("servers.btn.stop"), callback=lambda n=name: self._run_server_op("stop", n), icon_name="stop", enabled=running),
            MenuActionSpec(key="restart", label=tr("servers.btn.restart"), callback=lambda n=name: self._run_server_op("restart", n), icon_name="refresh"),
            MenuActionSpec(key="health", label=tr("servers.btn.health"), callback=lambda n=name: self._run_server_op("health", n), icon_name="shield", enabled=running),
        ]
        if unlinked and workspace_id and workspace_id in self._profiles:
            specs.append(
                MenuActionSpec(
                    key="link",
                    label=tr("workspaces.btn.link_server"),
                    callback=lambda w=workspace_id, n=name: self.link_server_to_workspace(w, n),
                    icon_name="plus",
                    separator_before=True,
                )
            )
        elif not unlinked and workspace_id and workspace_id in self._profiles:
            specs.append(
                MenuActionSpec(
                    key="unlink",
                    label=tr("workspaces.btn.unlink_server"),
                    callback=lambda w=workspace_id, n=name: self.unlink_server_from_workspace(w, n),
                    icon_name="edit",
                    separator_before=True,
                )
            )
        specs.extend(
            [
                MenuActionSpec(key="edit", label=tr("servers.btn.edit"), callback=lambda n=name: self._edit_server(n), icon_name="edit", separator_before=True),
                MenuActionSpec(key="rename", label=tr("workspaces.btn.rename_server"), callback=lambda n=name: self._prompt_rename_server(n), icon_name="edit", enabled=not running),
                MenuActionSpec(key="copy_id", label=tr("common.copy_id"), callback=lambda n=name: self._copy_item_id(n), icon_name="copy"),
                MenuActionSpec(key="delete", label=tr("servers.btn.delete"), callback=lambda n=name: self._delete_server(n), icon_name="trash", enabled=not running, danger=True, separator_before=True),
            ]
        )
        return specs

    def _copy_item_id(self, item_id: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(item_id)
        self.status_message.emit(tr("common.copied_id", item_id=item_id), "info")

    def _refresh_details(self) -> None:
        wid = self._selected_id()
        self.tree_widget.clear()
        if not wid or wid not in self._profiles:
            self.details_view.setPlainText(tr("workspaces.details.no_git"))
            return
        try:
            tree = self.manager.workspace_tree(wid, max_depth=3, client_id="owner")
            _populate_tree_widget(self.tree_widget, tree.get("entries", []))
        except Exception as exc:
            self.tree_widget.addTopLevelItem(QTreeWidgetItem([f"Error: {exc}"]))

        info = self.manager.workspace_info(wid, client_id="owner")
        git_block = _build_git_block(self.manager, wid)
        recent_tasks = _build_recent_tasks_block(self.task_store, self._profiles[wid].linked_tasks)
        self.details_view.setPlainText(
            self._redactor.redact_text(
                json.dumps(
                    {"workspace": info, "git": git_block, "recent_tasks": recent_tasks},
                    indent=2,
                    ensure_ascii=False,
                )
            )
        )

    def _refresh_server_details(self) -> None:
        name = self._active_server_name
        if not name or name not in self._server_profiles:
            self.logs_view.setPlainText(tr("servers.details.no_logs"))
            self.info_view.setPlainText(tr("servers.details.no_info"))
            return
        stream: Literal["stdout", "stderr"] = "stderr" if self.stream_combo.currentData() == "stderr" else "stdout"
        self.logs_view.setPlainText(fetch_server_logs_text(name, stream, self.runtime_proxy))
        prof = self._server_profiles[name]
        snap = self._snapshots.get(name, {})
        linked = self._snapshot.server_to_workspaces.get(name, []) if self._snapshot else []
        self.info_view.setPlainText(
            format_server_details(
                prof,
                snap,
                self.runtime_proxy,
                self._redactor,
                linked_workspaces=linked,
            )
        )

    # ------------------------------ Workspace CRUD ------------------------------
    def add_workspace(self) -> None:
        dlg = WorkspaceWizardDialog(
            self.store,
            self.server_store,
            self.coordinator,
            parent=self,
        )
        accepted = dlg.exec()
        if accepted and dlg.committed_workspace_id:
            wid = dlg.committed_workspace_id
            prof = self.store.get_workspace(wid)
            label = prof.name if prof is not None else wid
            self.config_changed.emit()
            self.status_message.emit(tr("workspaces.toast.saved", name=label), "ok")
            self.reload()
            self.select_workspace(wid)
        elif dlg.manual_requested:
            self.add_workspace_manual()

    def add_workspace_manual(self) -> None:
        dlg = WorkspaceProfileDialog(self.store, is_new=True, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)
            self.select_workspace(dlg.saved_profile.workspace_id)

    def _reapprove_workspace_manifests(self, wid: str) -> None:
        try:
            updated = self.store.refresh_manifest_digests(wid)
            self.config_changed.emit()
            self.status_message.emit(
                tr("workspaces.toast.manifests_reapproved", name=updated.name), "ok"
            )
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("workspaces.title"), str(exc))

    def save_profile(self, profile: WorkspaceProfile) -> None:
        self.store.upsert_workspace(profile)
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.saved", name=profile.name), "ok")
        self.reload()

    def _edit_workspace(self, wid: str) -> None:
        if wid not in self._profiles:
            return
        dlg = WorkspaceProfileDialog(self.store, existing=self._profiles[wid], is_new=False, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def edit_selected(self) -> None:
        wid = self._selected_id()
        if wid:
            self._edit_workspace(wid)

    def delete_workspace_by_id(self, wid: str) -> bool:
        """Remove a workspace registry entry without stopping or deleting any servers."""
        removed = self.coordinator.delete_workspace_preserving_servers(wid)
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.deleted", name=wid), "info")
        self.reload()
        return removed

    def _delete_workspace(self, wid: str) -> None:
        ans = SilentMessageBox.question(
            self,
            tr("workspaces.title"),
            tr("workspaces.delete.confirm", name=wid),
            SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            SilentMessageBox.StandardButton.No,
        )
        if ans == SilentMessageBox.StandardButton.Yes:
            self.delete_workspace_by_id(wid)

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

    def import_servers_json(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("workspaces.btn.import_servers"), "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            res = self.server_store.migrate_legacy_file(Path(path), create_backup=False)
            self.config_changed.emit()
            self.status_message.emit(
                tr("servers.toast.imported", count=len(res.get("imported", []))), "ok"
            )
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), str(exc))

    # ------------------------------ Server CRUD & Linking ------------------------------
    def save_server_profile(
        self,
        profile: ServerProfile,
        *,
        link_to_workspaces: tuple[str, ...] = (),
    ) -> None:
        self.server_store.upsert_profile(profile)
        for wid in link_to_workspaces:
            if wid in self._profiles:
                self.coordinator.link_server(wid, profile.name)
        self._active_server_name = profile.name
        self.config_changed.emit()
        self.status_message.emit(tr("servers.toast.saved", name=profile.name), "ok")
        self.reload()

    def add_server(self) -> None:
        dlg = ServerProfileDialog(
            self.server_store,
            is_new=True,
            workspaces=self._profiles,
            selected_workspaces=(),
            parent=self,
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_server_profile(dlg.saved_profile, link_to_workspaces=dlg.selected_workspaces)

    def add_server_for_selected_workspace(self) -> None:
        wid = self._selected_id()
        prof = self._profiles.get(wid or "")
        dlg = ServerProfileDialog(
            self.server_store,
            is_new=True,
            default_cwd=prof.root_path if prof else "",
            workspaces=self._profiles,
            selected_workspaces=(wid,) if wid and prof else (),
            parent=self,
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_server_profile(dlg.saved_profile, link_to_workspaces=dlg.selected_workspaces)

    def add_server_from_template(self) -> None:
        dlg = TemplateWizardDialog(self.server_store, workspaces=self._profiles, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_server_profile(dlg.saved_profile, link_to_workspaces=dlg.selected_workspaces)

    def add_template_server_for_selected_workspace(self) -> None:
        wid = self._selected_id()
        prof = self._profiles.get(wid or "")
        dlg = TemplateWizardDialog(
            self.server_store,
            default_cwd=prof.root_path if prof else "",
            workspaces=self._profiles,
            selected_workspaces=(wid,) if wid and prof else (),
            parent=self,
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_server_profile(dlg.saved_profile, link_to_workspaces=dlg.selected_workspaces)

    def _edit_server(self, name: str) -> None:
        if name not in self._server_profiles:
            return
        linked = tuple(self._snapshot.server_to_workspaces.get(name, [])) if self._snapshot else ()
        dlg = ServerProfileDialog(
            self.server_store,
            existing=self._server_profiles[name],
            is_new=False,
            workspaces=self._profiles,
            selected_workspaces=linked,
            parent=self,
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_server_profile(dlg.saved_profile)
            self._sync_server_workspace_links(
                dlg.saved_profile.name,
                dlg.selected_workspaces,
                allow_unscoped_access=not dlg.saved_profile.workspace_scoped,
            )

    def _sync_server_workspace_links(
        self,
        server_name: str,
        target_workspaces: tuple[str, ...],
        *,
        allow_unscoped_access: bool = False,
    ) -> None:
        target_set = set(target_workspaces)
        changed = False
        for wid, ws in list(self._profiles.items()):
            if wid in target_set and server_name not in ws.linked_servers:
                self.coordinator.link_server(wid, server_name)
                changed = True
            elif wid not in target_set and server_name in ws.linked_servers:
                self.coordinator.unlink_server(
                    wid, server_name, allow_unscoped_access=allow_unscoped_access
                )
                changed = True
        if changed:
            self.config_changed.emit()
            self.reload()

    def rename_server_profile(self, old_name: str, new_name: str) -> ServerProfile:
        renamed = self.coordinator.rename_server(old_name, new_name, server_manager=self.runtime_proxy)
        if self._active_server_name == old_name:
            self._active_server_name = new_name
        self.config_changed.emit()
        self.status_message.emit(tr("servers.toast.renamed", old=old_name, new=new_name), "ok")
        self.reload()
        return renamed

    def _prompt_rename_server(self, name: str) -> None:
        dlg = RenameServerDialog(name, set(self._server_profiles), parent=self)
        if dlg.exec() and dlg.new_name:
            try:
                self.rename_server_profile(name, dlg.new_name)
            except Exception as exc:
                SilentMessageBox.warning(self, tr("servers.title"), str(exc))

    def link_server_to_workspace(self, wid: str, server_name: str) -> WorkspaceProfile:
        updated = self.coordinator.link_server(wid, server_name)
        self._active_server_name = server_name
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.linked", server=server_name, workspace=wid), "ok")
        self.reload()
        return updated

    def unlink_server_from_workspace(self, wid: str, server_name: str) -> WorkspaceProfile:
        updated = self.coordinator.unlink_server(wid, server_name)
        self.config_changed.emit()
        self.status_message.emit(tr("workspaces.toast.unlinked", server=server_name, workspace=wid), "info")
        self.reload()
        return updated

    def prompt_link_server_to_selected_workspace(self) -> None:
        wid = self._selected_id()
        if not wid or wid not in self._profiles:
            return
        already = set(self._profiles[wid].linked_servers)
        available = [p for name, p in self._server_profiles.items() if name not in already]
        if not available:
            return
        dlg = LinkServerDialog(available, parent=self)
        if dlg.exec() and dlg.selected_server:
            self.link_server_to_workspace(wid, dlg.selected_server)

    def _delete_server(self, name: str) -> None:
        ans = SilentMessageBox.question(
            self,
            tr("servers.title"),
            tr("servers.delete.confirm", name=name),
            SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            SilentMessageBox.StandardButton.No,
        )
        if ans != SilentMessageBox.StandardButton.Yes:
            return
        try:
            self.coordinator.delete_server_and_unlink(name, server_manager=self.runtime_proxy)
            if self._active_server_name == name:
                self._active_server_name = None
            self.config_changed.emit()
            self.status_message.emit(tr("servers.toast.deleted", name=name), "info")
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), str(exc))

    # ------------------------------ Non-Blocking Background Execution ------------------------------
    def _spawn_op(self, kind: str, target_name: str, fn) -> None:  # noqa: ANN001
        holder: list[threading.Thread] = []

        def _worker() -> None:
            try:
                res = fn()
                err = ""
            except Exception as exc:  # noqa: BLE001
                res = None
                err = self._redactor.redact_text(str(exc)) or type(exc).__name__
            finally:
                if holder:
                    self._pending_threads.discard(holder[0])
            self._op_finished.emit(kind, res, err, target_name)

        t = threading.Thread(target=_worker, daemon=True, name=f"mcp-ws-ui-{kind}")
        holder.append(t)
        self._pending_threads.add(t)
        t.start()

    def _on_op_finished(self, kind: str, result: object, err: str, target_name: str) -> None:
        if err:
            SilentMessageBox.warning(self, tr("workspaces.title"), err)
            self.reload()
            return
        res = result if isinstance(result, dict) else {}
        if kind == "task":
            self.reload()
            self.details_view.setPlainText(
                self._redactor.redact_text(json.dumps(res, indent=2, ensure_ascii=False))
            )
            return
        self._emit_server_op_toast(kind, res, target_name)
        self.reload()

    def _emit_server_op_toast(self, kind: str, res: dict[str, Any], name: str) -> None:
        if kind == "start":
            self.status_message.emit(tr("servers.toast.started", name=name), "ok")
        elif kind == "stop":
            key = "servers.toast.independent_kept" if res.get("lifecycle") == "independent" else "servers.toast.stopped"
            self.status_message.emit(tr(key, name=name), "info")
        elif kind == "restart":
            self.status_message.emit(tr("servers.toast.restarted", name=name), "ok")
        elif kind == "health":
            lvl = "ok" if res.get("healthy") else "warn"
            self.status_message.emit(f"{name}: {res.get('detail', res.get('status'))}", lvl)

    def _run_server_op(self, kind: str, name: str) -> None:
        self._active_server_name = name
        wid = self._selected_id() or ""
        ops = {
            "start": lambda: self.runtime_proxy.start_server(
                name, client_id="owner", wait_readiness=True, workspace_id=wid
            ),
            "stop": lambda: self.runtime_proxy.stop_server(name, client_id="owner"),
            "restart": lambda: self.runtime_proxy.restart_server(
                name, client_id="owner", wait_readiness=True, workspace_id=wid
            ),
            "health": lambda: self.runtime_proxy.health_server(name, client_id="owner", run_probe=True),
        }
        fn = ops.get(kind)
        if fn is not None:
            self._spawn_op(kind, name, fn)

    def start_selected_server(self) -> None:
        if self._active_server_name:
            self._run_server_op("start", self._active_server_name)

    def stop_selected_server(self) -> None:
        if self._active_server_name:
            self._run_server_op("stop", self._active_server_name)

    def restart_selected_server(self) -> None:
        if self._active_server_name:
            self._run_server_op("restart", self._active_server_name)

    def check_health_selected_server(self) -> None:
        if self._active_server_name:
            self._run_server_op("health", self._active_server_name)

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

    def _run_workspace_task_via_admin_or_local(self, wid: str, cname: str) -> dict[str, Any]:
        client = self._get_admin_client()
        if client is not None:
            try:
                return client.run_workspace_task(wid, cname)
            except AdminRequestAmbiguousError:
                raise
            except AdminBackendUnavailableError:
                if not self._is_backend_confirmed_stopped():
                    raise
        elif not self._is_backend_confirmed_stopped():
            raise AdminBackendUnavailableError(
                "Backend is active but Local Admin API is unavailable; refusing duplicate local task run"
            )
        return asyncio.run(self.manager.run_workspace_task(wid, cname, client_id="owner"))

    def _confirm_task_execution_prerequisites(self, wid: str, cname: str) -> bool:
        prof = self._profiles.get(wid)
        if prof is None:
            return False
        if prof.manifest_digests:
            try:
                verify_manifest_digests(Path(prof.root_path), prof.manifest_digests)
            except ManifestDriftError:
                ans = SilentMessageBox.question(
                    self,
                    tr("workspaces.exec_confirm.title"),
                    tr("workspaces.exec_confirm.drift_body", name=prof.name, cmd_name=cname),
                    SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                    SilentMessageBox.StandardButton.No,
                )
                if ans != SilentMessageBox.StandardButton.Yes:
                    return False
                prof = self.store.refresh_manifest_digests(wid)
                self.reload()
        if not prof.permissions.execute:
            ans = SilentMessageBox.question(
                self,
                tr("workspaces.exec_confirm.title"),
                tr(
                    "workspaces.exec_confirm.body",
                    cmd_name=cname,
                    root=prof.root_path,
                    command=prof.commands.get(cname, ""),
                ),
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            if ans != SilentMessageBox.StandardButton.Yes:
                return False
            updated = replace(prof, permissions=replace(prof.permissions, execute=True))
            self.save_profile(updated)
            self.select_workspace(wid)
        return True

    def run_selected_task(self) -> None:
        wid = self._selected_id()
        cname = str(self.cmd_combo.currentData() or "")
        if not wid or not cname:
            return
        if not self._confirm_task_execution_prerequisites(wid, cname):
            return
        self._spawn_op(
            "task",
            f"{wid}:{cname}",
            lambda: self._run_workspace_task_via_admin_or_local(wid, cname),
        )

    def wait_for_pending_ops(self, timeout: float = 10.0) -> bool:
        """Pump Qt events until background UI server/task operations finish."""
        deadline = time.monotonic() + timeout
        app = QApplication.instance()
        while self._pending_threads and time.monotonic() < deadline:
            if app is not None:
                app.processEvents()
            time.sleep(0.01)
        if app is not None:
            app.processEvents()
        return not self._pending_threads

    def start_autostart_servers(self) -> None:
        self.runtime_proxy.start_autostart_servers()
        self.reload()

    def shutdown(self) -> None:
        self._poll_timer.stop()
        self.wait_for_pending_ops(timeout=3.0)
        self.server_manager.close()
        self.manager.close()
        self._local_runner.close()

    # ------------------------------ i18n & Theme ------------------------------
    def retranslate(self) -> None:
        self.set_header(tr("workspaces.title"), tr("workspaces.lead"))
        self.search_edit.setPlaceholderText(tr("workspaces.search"))
        self.add_btn.setText(tr("workspaces.btn.add"))
        self.add_server_btn.setText(tr("workspaces.btn.add_server"))
        self.run_task_btn.setText(tr("workspaces.btn.run_task"))
        self.file_search_btn.setText(tr("workspaces.btn.search_files"))
        self.refresh_btn.setText(tr("workspaces.btn.refresh"))
        self.list_menu_btn.setToolTip(tr("common.actions"))
        self.file_search_edit.setPlaceholderText(tr("workspaces.details.file_search_ph"))
        self.ws_add_server_btn.setText(tr("workspaces.btn.add_server"))
        self.ws_tpl_server_btn.setText(tr("workspaces.btn.template_server"))
        self.ws_link_server_btn.setText(tr("workspaces.btn.link_server"))

        self.collection_tabs.setTabText(0, tr("workspaces.tab.projects"))
        self.collection_tabs.setTabText(1, tr("workspaces.tab.unlinked"))
        self.table.setHorizontalHeaderLabels(
            [
                tr("workspaces.col.name"),
                tr("workspaces.col.lang"),
                tr("workspaces.col.root"),
                tr("workspaces.col.git"),
                tr("workspaces.col.perms"),
                tr("workspaces.col.commands"),
                "",
            ]
        )
        server_cols = [
            tr("servers.col.name"),
            tr("servers.col.template"),
            tr("servers.col.lifecycle"),
            tr("servers.col.status"),
            tr("servers.col.endpoint"),
            tr("servers.col.metrics"),
            tr("servers.col.deps"),
            tr("servers.col.access"),
            "",
        ]
        self.unlinked_table.setHorizontalHeaderLabels(server_cols)
        self.ws_servers_table.setHorizontalHeaderLabels(server_cols)

        self.empty_state.set_content(tr("workspaces.empty.title"), tr("workspaces.empty.desc"))
        self.unlinked_empty_state.set_content(tr("workspaces.unlinked.empty_title"), tr("workspaces.unlinked.empty_desc"))
        self.ws_servers_empty.set_content(tr("workspaces.servers.empty_title"), tr("workspaces.servers.empty_desc"))
        self.tree_header.set_texts(tr("workspaces.details.tree_title"))
        self.git_header.set_texts(tr("workspaces.details.git_title"))
        self.servers_header.set_texts(tr("workspaces.details.servers_title"))
        self.logs_header.set_texts(tr("workspaces.details.server_logs_title"))
        self.info_header.set_texts(tr("workspaces.details.server_info_title"))
        self.detail_tabs.retranslate()
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
        self.unlinked_empty_state.apply_theme()
        self.ws_servers_empty.apply_theme()
        mono = tokens.FONT_MONO
        for view in (self.details_view, self.logs_view, self.info_view):
            view.setStyleSheet(f"font-family: {mono}; font-size: 11px;")
