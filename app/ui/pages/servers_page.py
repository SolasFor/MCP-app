"""Server Manager page: profile registry, templates, readiness health, metrics, and redacted logs."""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
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
from app.ui.components.safe_spin import SafeDoubleSpinBox, SafeSpinBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.servers.manager import ServerManager
from backend.servers.models import (
    LIFECYCLES,
    READINESS_KINDS,
    RESTART_POLICIES,
    SERVER_MIN_PROFILES,
    TEMPLATES,
    ReadinessConfig,
    RestartConfig,
    ServerProfile,
)
from backend.servers.store import ServerConfigStore, validate_dependencies
from backend.servers.templates import build_profile_from_template, list_templates
from backend.tasks.store import TaskStore


def _parse_env_lines(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        k, v = stripped.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _parse_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


class ServerProfileDialog(SilentDialog):
    """Create or edit a managed ServerProfile without revealing saved SecretStore values."""

    def __init__(
        self,
        store: ServerConfigStore,
        *,
        existing: ServerProfile | None = None,
        is_new: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._base = existing or ServerProfile(name="")
        self._is_new = is_new
        self.saved_profile: ServerProfile | None = None

        self.setWindowTitle(tr("servers.dlg.title_add" if is_new else "servers.dlg.title_edit"))
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self.name_edit = QLineEdit(self._base.name)
        self.name_edit.setObjectName("UiInput")
        self.name_edit.setReadOnly(not is_new)
        form.addRow(tr("servers.dlg.name"), self.name_edit)

        self.display_edit = QLineEdit(self._base.display_name)
        self.display_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.display_name"), self.display_edit)

        self.template_combo = SafeComboBox()
        for tid in TEMPLATES:
            self.template_combo.addItem(tid, tid)
        self.template_combo.setCurrentIndex(max(self.template_combo.findData(self._base.template), 0))
        form.addRow(tr("servers.dlg.template"), self.template_combo)

        exe_row = QHBoxLayout()
        self.exe_edit = QLineEdit(self._base.argv[0] if self._base.argv else sys.executable)
        self.exe_edit.setObjectName("UiInput")
        self.exe_browse_btn = QPushButton(tr("servers.dlg.browse"))
        self.exe_browse_btn.clicked.connect(self._browse_exe)
        exe_row.addWidget(self.exe_edit, 1)
        exe_row.addWidget(self.exe_browse_btn)
        form.addRow(tr("servers.dlg.executable"), exe_row)

        args_str = shlex.join(self._base.argv[1:]) if len(self._base.argv) > 1 else ""
        self.args_edit = QLineEdit(args_str)
        self.args_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.args"), self.args_edit)

        cwd_row = QHBoxLayout()
        self.cwd_edit = QLineEdit(self._base.cwd)
        self.cwd_edit.setObjectName("UiInput")
        self.cwd_browse_btn = QPushButton(tr("servers.dlg.browse"))
        self.cwd_browse_btn.clicked.connect(self._browse_cwd)
        cwd_row.addWidget(self.cwd_edit, 1)
        cwd_row.addWidget(self.cwd_browse_btn)
        form.addRow(tr("servers.dlg.cwd"), cwd_row)

        net_row = QHBoxLayout()
        self.host_edit = QLineEdit(self._base.host or "127.0.0.1")
        self.host_edit.setObjectName("UiInput")
        self.port_spin = SafeSpinBox()
        self.port_spin.setRange(0, 65535)
        self.port_spin.setSpecialValueText("—")
        self.port_spin.setValue(int(self._base.port or 0))
        net_row.addWidget(self.host_edit, 2)
        net_row.addWidget(self.port_spin, 1)
        form.addRow(f"{tr('servers.dlg.host')} / {tr('servers.dlg.port')}", net_row)

        self.expose_check = QCheckBox(tr("servers.dlg.expose"))
        self.expose_check.setChecked(self._base.expose_externally)
        form.addRow("", self.expose_check)

        self.lifecycle_combo = SafeComboBox()
        for lc in LIFECYCLES:
            self.lifecycle_combo.addItem(lc, lc)
        self.lifecycle_combo.setCurrentIndex(max(self.lifecycle_combo.findData(self._base.lifecycle), 0))
        form.addRow(tr("servers.dlg.lifecycle"), self.lifecycle_combo)

        probe_row = QHBoxLayout()
        self.readiness_combo = SafeComboBox()
        for rk in READINESS_KINDS:
            self.readiness_combo.addItem(rk, rk)
        self.readiness_combo.setCurrentIndex(
            max(self.readiness_combo.findData(self._base.readiness.kind), 0)
        )
        self.health_path_edit = QLineEdit(self._base.readiness.http_path)
        self.health_path_edit.setObjectName("UiInput")
        self.readiness_timeout_spin = SafeDoubleSpinBox()
        self.readiness_timeout_spin.setRange(1.0, 300.0)
        self.readiness_timeout_spin.setValue(self._base.readiness.timeout_seconds)
        probe_row.addWidget(self.readiness_combo, 1)
        probe_row.addWidget(self.health_path_edit, 2)
        probe_row.addWidget(self.readiness_timeout_spin, 1)
        form.addRow(tr("servers.dlg.readiness_kind"), probe_row)

        restart_row = QHBoxLayout()
        self.restart_combo = SafeComboBox()
        for rp in RESTART_POLICIES:
            self.restart_combo.addItem(rp, rp)
        self.restart_combo.setCurrentIndex(max(self.restart_combo.findData(self._base.restart.policy), 0))
        self.max_restarts_spin = SafeSpinBox()
        self.max_restarts_spin.setRange(0, 50)
        self.max_restarts_spin.setValue(self._base.restart.max_attempts)
        self.backoff_spin = SafeDoubleSpinBox()
        self.backoff_spin.setRange(0.2, 60.0)
        self.backoff_spin.setValue(self._base.restart.base_backoff_seconds)
        restart_row.addWidget(self.restart_combo, 2)
        restart_row.addWidget(self.max_restarts_spin, 1)
        restart_row.addWidget(self.backoff_spin, 1)
        form.addRow(tr("servers.dlg.restart_policy"), restart_row)

        self.deps_edit = QLineEdit(", ".join(self._base.depends_on))
        self.deps_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.deps"), self.deps_edit)

        self.min_profile_combo = SafeComboBox()
        for mp in SERVER_MIN_PROFILES:
            self.min_profile_combo.addItem(mp, mp)
        self.min_profile_combo.setCurrentIndex(
            max(self.min_profile_combo.findData(self._base.min_profile), 0)
        )
        form.addRow(tr("servers.dlg.min_profile"), self.min_profile_combo)

        self.allowed_clients_edit = QLineEdit(", ".join(self._base.allowed_clients))
        self.allowed_clients_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.allowed_clients"), self.allowed_clients_edit)

        self.pre_start_edit = QLineEdit(self._base.pre_start_task_command)
        self.pre_start_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.pre_start_task"), self.pre_start_edit)

        self.plain_env_edit = QPlainTextEdit(
            "\n".join(f"{k}={v}" for k, v in sorted(self._base.env.items()))
        )
        self.plain_env_edit.setFixedHeight(56)
        form.addRow(tr("servers.dlg.plain_env"), self.plain_env_edit)

        self.secret_env_edit = QPlainTextEdit()
        self.secret_env_edit.setFixedHeight(56)
        existing_keys = sorted(self._base.env_secret_refs)
        hint = (
            f"{tr('servers.dlg.secret_hint')} ({', '.join(existing_keys)})"
            if existing_keys
            else tr("servers.dlg.secret_hint")
        )
        self.secret_env_edit.setPlaceholderText(hint)
        form.addRow(tr("servers.dlg.secret_env"), self.secret_env_edit)

        flags_row = QHBoxLayout()
        self.enabled_check = QCheckBox(tr("servers.dlg.enabled"))
        self.enabled_check.setChecked(self._base.enabled)
        self.autostart_check = QCheckBox(tr("servers.dlg.autostart"))
        self.autostart_check.setChecked(self._base.autostart)
        flags_row.addWidget(self.enabled_check)
        flags_row.addWidget(self.autostart_check)
        flags_row.addStretch(1)
        form.addRow("", flags_row)

        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_exe(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, tr("servers.dlg.executable"))
        if path:
            self.exe_edit.setText(path)

    def _browse_cwd(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("servers.dlg.cwd"))
        if path:
            self.cwd_edit.setText(path)

    def _on_accept(self) -> None:
        name = self.name_edit.text().strip()
        exe = self.exe_edit.text().strip()
        try:
            extra_args = shlex.split(self.args_edit.text().strip()) if self.args_edit.text().strip() else []
            port_val = int(self.port_spin.value()) or None
            host = self.host_edit.text().strip() or "127.0.0.1"
            readiness_kind = str(self.readiness_combo.currentData() or "none")
            probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
            readiness = ReadinessConfig(
                kind=readiness_kind,
                host=probe_host,
                port=port_val,
                http_path=self.health_path_edit.text().strip() or "/health",
                timeout_seconds=float(self.readiness_timeout_spin.value()),
            )
            restart = RestartConfig(
                policy=str(self.restart_combo.currentData() or "never"),
                max_attempts=int(self.max_restarts_spin.value()),
                base_backoff_seconds=float(self.backoff_spin.value()),
                max_backoff_seconds=max(float(self.backoff_spin.value()) * 4.0, 30.0),
            )
            secret_refs = dict(self._base.env_secret_refs)
            secret_updates = _parse_env_lines(self.secret_env_edit.toPlainText())
            for k, v in secret_updates.items():
                secret_refs[k] = self._store.set_env_secret(name, k, v)

            profile = ServerProfile(
                name=name,
                display_name=self.display_edit.text().strip() or name,
                template=str(self.template_combo.currentData() or "custom"),
                argv=tuple([exe, *extra_args]) if exe else (),
                cwd=self.cwd_edit.text().strip(),
                env=_parse_env_lines(self.plain_env_edit.toPlainText()),
                env_secret_refs=secret_refs,
                lifecycle=str(self.lifecycle_combo.currentData() or "controlled"),
                host=host,
                port=port_val,
                expose_externally=self.expose_check.isChecked(),
                readiness=readiness,
                depends_on=_parse_csv(self.deps_edit.text()),
                restart=restart,
                autostart=self.autostart_check.isChecked(),
                enabled=self.enabled_check.isChecked(),
                min_profile=str(self.min_profile_combo.currentData() or "full"),
                allowed_clients=_parse_csv(self.allowed_clients_edit.text()),
                pre_start_task_command=self.pre_start_edit.text().strip(),
            )
            profile.validate()
            profiles = self._store.load_profiles(strict=False)
            if self._is_new and profile.name in profiles:
                raise ValueError(f"Server '{profile.name}' already exists")
            profiles[profile.name] = profile
            validate_dependencies(profiles)
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), str(exc))
            return
        self.saved_profile = profile
        self.accept()


class TemplateWizardDialog(SilentDialog):
    """Create a validated ServerProfile from one of the safe built-in templates."""

    def __init__(self, store: ServerConfigStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store
        self.saved_profile: ServerProfile | None = None
        self._templates = {item["template"]: item for item in list_templates() if item["template"] != "custom"}

        self.setWindowTitle(tr("servers.tpl.title"))
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self.name_edit = QLineEdit()
        self.name_edit.setObjectName("UiInput")
        form.addRow(tr("servers.dlg.name"), self.name_edit)

        self.template_combo = SafeComboBox()
        for tid, meta in self._templates.items():
            self.template_combo.addItem(str(meta["title"]), tid)
        self.template_combo.currentIndexChanged.connect(self._on_template_changed)
        form.addRow(tr("servers.dlg.template"), self.template_combo)

        cwd_row = QHBoxLayout()
        self.cwd_edit = QLineEdit()
        self.cwd_edit.setObjectName("UiInput")
        self.cwd_edit.textChanged.connect(self._update_preview)
        browse_cwd = QPushButton(tr("servers.dlg.browse"))
        browse_cwd.clicked.connect(self._browse_cwd)
        cwd_row.addWidget(self.cwd_edit, 1)
        cwd_row.addWidget(browse_cwd)
        form.addRow(tr("servers.dlg.cwd"), cwd_row)

        self.exe_edit = QLineEdit()
        self.exe_edit.setObjectName("UiInput")
        self.exe_edit.textChanged.connect(self._update_preview)
        form.addRow(tr("servers.dlg.executable"), self.exe_edit)

        self.entrypoint_edit = QLineEdit()
        self.entrypoint_edit.setObjectName("UiInput")
        self.entrypoint_edit.textChanged.connect(self._update_preview)
        form.addRow(tr("servers.tpl.entrypoint"), self.entrypoint_edit)

        net_row = QHBoxLayout()
        self.host_edit = QLineEdit("127.0.0.1")
        self.host_edit.setObjectName("UiInput")
        self.host_edit.textChanged.connect(self._update_preview)
        self.port_spin = SafeSpinBox()
        self.port_spin.setRange(0, 65535)
        self.port_spin.setSpecialValueText("—")
        self.port_spin.valueChanged.connect(self._update_preview)
        net_row.addWidget(self.host_edit, 2)
        net_row.addWidget(self.port_spin, 1)
        form.addRow(f"{tr('servers.dlg.host')} / {tr('servers.dlg.port')}", net_row)

        self.preview_edit = QLineEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setObjectName("UiInput")
        form.addRow(tr("servers.tpl.preview"), self.preview_edit)

        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._on_template_changed()

    def _browse_cwd(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("servers.dlg.cwd"))
        if path:
            self.cwd_edit.setText(path)

    def _on_template_changed(self) -> None:
        tid = str(self.template_combo.currentData() or "python_fastapi")
        meta = self._templates.get(tid, {})
        self.entrypoint_edit.setText(str(meta.get("default_entrypoint") or ""))
        self.port_spin.setValue(int(meta.get("default_port") or 0))
        self.exe_edit.setText(sys.executable if tid.startswith("python_") or tid == "static_http" else "")
        self._update_preview()

    def _build_candidate(self) -> ServerProfile:
        tid = str(self.template_combo.currentData() or "python_fastapi")
        port_val = int(self.port_spin.value()) or None
        return build_profile_from_template(
            name=self.name_edit.text().strip() or "preview_server",
            template=tid,
            cwd=self.cwd_edit.text().strip() or str(Path.cwd()),
            host=self.host_edit.text().strip() or "127.0.0.1",
            port=port_val,
            executable=self.exe_edit.text().strip(),
            entrypoint=self.entrypoint_edit.text().strip(),
        )

    def _update_preview(self) -> None:
        try:
            prof = self._build_candidate()
            self.preview_edit.setText(shlex.join(prof.argv))
        except Exception as exc:
            self.preview_edit.setText(f"[{type(exc).__name__}] {exc}")

    def _on_accept(self) -> None:
        try:
            name = self.name_edit.text().strip()
            if not name:
                raise ValueError("Server name is required")
            prof = self._build_candidate()
            profiles = self._store.load_profiles(strict=False)
            if prof.name in profiles:
                raise ValueError(f"Server '{prof.name}' already exists")
            profiles[prof.name] = prof
            validate_dependencies(profiles)
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.tpl.title"), str(exc))
            return
        self.saved_profile = prof
        self.accept()


class ServersPage(PageScaffold):
    """GUI management page for local servers, templates, dependencies, readiness, metrics, and logs."""

    config_changed = pyqtSignal()
    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        secrets_dir: Path | None = None,
        tasks_db_path: Path | None = None,
        redactor: SecretRedactor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self.content.setSpacing(10)
        self._config_path = config_path or (user_data_dir() / "servers" / "managed_servers.json")
        secret_store = SecretStore(secrets_dir) if secrets_dir is not None else None
        self._redactor = redactor or SecretRedactor()
        self._tasks_db_path = tasks_db_path
        task_store = TaskStore(tasks_db_path) if (tasks_db_path and tasks_db_path.is_file()) else None
        self.store = ServerConfigStore(self._config_path, secret_store=secret_store)
        self.server_manager = ServerManager(
            self.store,
            redactor=self._redactor,
            task_store=task_store,
        )
        self._profiles: dict[str, ServerProfile] = {}
        self._snapshots: dict[str, dict[str, Any]] = {}

        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))

        self.add_btn = self._make_btn(self.add_server, obj="Accent")
        self.refresh_btn = self._make_btn(self.reload)
        self.list_menu_btn = make_toolbar_menu_button(tr("common.actions"), parent=self)
        self.list_menu_btn.clicked.connect(self._open_list_menu)
        self.content.addWidget(management_toolbar(self.search_edit, (self.add_btn, self.refresh_btn, self.list_menu_btn)))

        self.table_card = QWidget()
        table_lay = QVBoxLayout(self.table_card)
        table_lay.setContentsMargins(0, 0, 0, 0)
        table_lay.setSpacing(0)
        self.table = DataTable(["", "", "", "", "", "", "", "", ""])
        self.table.setMinimumHeight(130)
        self.table.itemSelectionChanged.connect(self._on_selected)
        self.table.set_row_menu_provider(self._build_row_menu)
        table_lay.addWidget(self.table, 1)

        self.empty_state = EmptyState("servers")
        list_panel = management_list(self.table_card, self.empty_state)

        self.detail_tabs = ManagementTabs()

        logs_pane = QWidget()
        logs_lay = QVBoxLayout(logs_pane)
        logs_lay.setContentsMargins(10, 10, 10, 10)
        logs_lay.setSpacing(6)
        self.logs_header = SectionHeader()
        self.stream_combo = SafeComboBox()
        self.stream_combo.addItem("stdout", "stdout")
        self.stream_combo.addItem("stderr", "stderr")
        self.stream_combo.currentIndexChanged.connect(lambda *_: self._refresh_details())
        self.logs_header.right_box.addWidget(self.stream_combo)
        logs_lay.addWidget(self.logs_header)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setObjectName("ConsoleLog")
        self.logs_view.setReadOnly(True)
        logs_lay.addWidget(self.logs_view, 1)
        self.detail_tabs.add_section(logs_pane, "servers.details.logs_title", self.logs_header, controls=True)

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
        self.detail_tabs.add_section(info_pane, "servers.details.info_title", self.info_header)

        self.content.addWidget(management_split(list_panel, self.detail_tabs), 1)

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._on_poll)
        self._poll_timer.start()

        self.retranslate()
        self.apply_theme()
        self.reload()

    def _make_btn(self, slot, obj: str | None = None) -> QPushButton:  # noqa: ANN001
        btn = QPushButton()
        if obj:
            btn.setObjectName(obj)
        btn.clicked.connect(slot)
        return btn

    def _row_name(self, row: int) -> str | None:
        item = self.table.item(row, 0) if 0 <= row < self.table.rowCount() else None
        if item is None:
            return None
        val = item.data(Qt.ItemDataRole.UserRole)
        return str(val) if val else None

    def _selected_name(self) -> str | None:
        return self._row_name(self.table.currentRow())

    def _on_poll(self) -> None:
        if self.isVisible() or any(snap.get("running") or snap.get("status") == "restarting" for snap in self._snapshots.values()):
            self.reload()

    def reload(self) -> None:
        try:
            self._profiles = self.store.load_profiles(strict=False)
        except Exception:
            self._profiles = {}
        for secret in self.store.collect_secret_values():
            self._redactor.register(secret)
        items = self.server_manager.list_servers(client_id="owner")
        self._snapshots = {str(item["name"]): item for item in items}

        if not self._profiles:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.show()
            self._on_selected()
            return

        self.empty_state.hide()
        self.table_card.show()
        selected_name = self._selected_name()
        names = sorted(self._profiles)
        self.table.setRowCount(len(names))
        restore_row = 0

        for idx, name in enumerate(names):
            prof = self._profiles[name]
            snap = self._snapshots.get(name, {})
            name_item = QTableWidgetItem(prof.display_name or prof.name)
            name_item.setData(Qt.ItemDataRole.UserRole, prof.name)
            name_item.setToolTip(prof.name)

            status_key = str(snap.get("status") or "stopped")
            status_label = tr(f"servers.status.{status_key}")
            if snap.get("running") and prof.readiness.kind != "none":
                health_suffix = "✓" if snap.get("healthy") else "!"
                status_label = f"{status_label} [{health_suffix}]"

            endpoint = f"{prof.host}:{prof.port}" if prof.port else prof.host
            metrics_text = "—"
            if snap.get("running"):
                m = self.server_manager.metrics_server(name, client_id="owner")
                metrics_text = f"{m.get('cpu_percent', 0.0):.1f}% / {m.get('memory_mb', 0.0):.1f} MB"
            deps_text = ", ".join(prof.depends_on) or "—"
            access_text = prof.min_profile if prof.enabled else "disabled"

            self.table.setItem(idx, 0, name_item)
            self.table.setItem(idx, 1, QTableWidgetItem(prof.template))
            self.table.setItem(idx, 2, QTableWidgetItem(prof.lifecycle))
            self.table.setItem(idx, 3, QTableWidgetItem(status_label))
            self.table.setItem(idx, 4, QTableWidgetItem(endpoint))
            self.table.setItem(idx, 5, QTableWidgetItem(metrics_text))
            self.table.setItem(idx, 6, QTableWidgetItem(deps_text))
            self.table.setItem(idx, 7, QTableWidgetItem(access_text))
            self.table.set_row_actions_cell(idx, 8, tooltip=tr("common.actions"))
            if selected_name and name == selected_name:
                restore_row = idx

        self.table.filter_rows(self.search_edit.text())
        if self.table.rowCount() > 0:
            self.table.selectRow(restore_row)
        self._on_selected()

    def _on_selected(self) -> None:
        self._refresh_details()

    def _open_list_menu(self) -> None:
        specs = [
            MenuActionSpec(
                key="template",
                label=tr("servers.btn.template"),
                callback=self.add_from_template,
                icon_name="plus",
            ),
            MenuActionSpec(
                key="import",
                label=tr("servers.btn.import"),
                callback=self.import_legacy_json,
                icon_name="import",
            ),
        ]
        AppContextMenu.from_specs(specs, parent=self).exec_clamped(
            self.list_menu_btn.mapToGlobal(self.list_menu_btn.rect().bottomLeft())
        )

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        name = self._row_name(row)
        if not name or name not in self._profiles:
            return []
        running = bool(self._snapshots.get(name, {}).get("running"))
        return [
            MenuActionSpec(
                key="start",
                label=tr("servers.btn.start"),
                callback=lambda n=name: self._start_server(n),
                icon_name="play",
                enabled=not running,
            ),
            MenuActionSpec(
                key="stop",
                label=tr("servers.btn.stop"),
                callback=lambda n=name: self._stop_server(n),
                icon_name="stop",
                enabled=running,
            ),
            MenuActionSpec(
                key="restart",
                label=tr("servers.btn.restart"),
                callback=lambda n=name: self._restart_server(n),
                icon_name="refresh",
            ),
            MenuActionSpec(
                key="health",
                label=tr("servers.btn.health"),
                callback=lambda n=name: self._check_health_server(n),
                icon_name="shield",
                enabled=running,
            ),
            MenuActionSpec(
                key="edit",
                label=tr("servers.btn.edit"),
                callback=lambda n=name: self._edit_server(n),
                icon_name="edit",
                separator_before=True,
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("common.copy_id"),
                callback=lambda n=name: self._copy_server_id(n),
                icon_name="copy",
            ),
            MenuActionSpec(
                key="delete",
                label=tr("servers.btn.delete"),
                callback=lambda n=name: self._delete_server(n),
                icon_name="trash",
                enabled=not running,
                danger=True,
                separator_before=True,
            ),
        ]

    def _copy_server_id(self, name: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(name)
        self.status_message.emit(tr("common.copied_id", item_id=name), "info")

    def _refresh_details(self) -> None:
        name = self._selected_name()
        if not name or name not in self._profiles:
            self.logs_view.setPlainText(tr("servers.details.no_logs"))
            self.info_view.setPlainText(tr("servers.details.no_info"))
            return
        stream = "stderr" if self.stream_combo.currentData() == "stderr" else "stdout"
        try:
            logs_res = self.server_manager.logs_server(
                name, client_id="owner", stream=stream, offset=0, limit=16000
            )
            self.logs_view.setPlainText(logs_res.get("text") or tr("servers.details.no_logs"))
        except Exception:
            self.logs_view.setPlainText(tr("servers.details.no_logs"))

        prof = self._profiles[name]
        snap = self._snapshots.get(name, {})
        metrics = self.server_manager.metrics_server(name, client_id="owner")
        health = self.server_manager.health_server(name, client_id="owner", run_probe=False)
        summary = {
            "name": prof.name,
            "template": prof.template,
            "lifecycle": prof.lifecycle,
            "argv_executable": prof.argv[0] if prof.argv else "",
            "cwd": prof.cwd,
            "status": snap.get("status", "stopped"),
            "pid": snap.get("pid"),
            "exit_code": snap.get("exit_code"),
            "restart_count": snap.get("restart_count", 0),
            "readiness": prof.readiness.to_dict(),
            "health": health,
            "metrics": metrics,
            "secret_env_refs": list(prof.env_secret_refs.values()),
            "last_error": snap.get("last_error", ""),
        }
        self.info_view.setPlainText(
            self._redactor.redact_text(json.dumps(summary, indent=2, ensure_ascii=False))
        )

    def add_server(self) -> None:
        dlg = ServerProfileDialog(self.store, is_new=True, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def add_from_template(self) -> None:
        dlg = TemplateWizardDialog(self.store, parent=self)
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def save_profile(self, profile: ServerProfile) -> None:
        self.store.upsert_profile(profile)
        self.config_changed.emit()
        self.status_message.emit(tr("servers.toast.saved", name=profile.name), "ok")
        self.reload()

    def _edit_server(self, name: str) -> None:
        if name not in self._profiles:
            return
        dlg = ServerProfileDialog(
            self.store, existing=self._profiles[name], is_new=False, parent=self
        )
        if dlg.exec() and dlg.saved_profile is not None:
            self.save_profile(dlg.saved_profile)

    def edit_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._edit_server(name)

    def _delete_server(self, name: str) -> None:
        answer = SilentMessageBox.question(
            self,
            tr("servers.title"),
            tr("servers.delete.confirm", name=name),
            SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            SilentMessageBox.StandardButton.No,
        )
        if answer != SilentMessageBox.StandardButton.Yes:
            return
        try:
            self.store.delete_profile(name)
            self.config_changed.emit()
            self.status_message.emit(tr("servers.toast.deleted", name=name), "info")
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), str(exc))

    def delete_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._delete_server(name)

    def import_legacy_json(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("servers.btn.import"), "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        try:
            res = self.store.migrate_legacy_file(Path(path), create_backup=False)
            self.config_changed.emit()
            self.status_message.emit(
                tr("servers.toast.imported", count=len(res.get("imported", []))), "ok"
            )
            self.reload()
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), str(exc))

    def _start_server(self, name: str) -> None:
        try:
            self.server_manager.start_server(name, client_id="owner", wait_readiness=True)
            self.status_message.emit(tr("servers.toast.started", name=name), "ok")
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), self._redactor.redact_text(str(exc)))
        self.reload()

    def start_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._start_server(name)

    def _stop_server(self, name: str) -> None:
        try:
            res = self.server_manager.stop_server(name, client_id="owner")
            if res.get("lifecycle") == "independent":
                self.status_message.emit(tr("servers.toast.independent_kept", name=name), "info")
            else:
                self.status_message.emit(tr("servers.toast.stopped", name=name), "info")
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), self._redactor.redact_text(str(exc)))
        self.reload()

    def stop_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._stop_server(name)

    def _restart_server(self, name: str) -> None:
        try:
            self.server_manager.restart_server(name, client_id="owner", wait_readiness=True)
            self.status_message.emit(tr("servers.toast.restarted", name=name), "ok")
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), self._redactor.redact_text(str(exc)))
        self.reload()

    def restart_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._restart_server(name)

    def _check_health_server(self, name: str) -> None:
        try:
            res = self.server_manager.health_server(name, client_id="owner", run_probe=True)
            lvl = "ok" if res.get("healthy") else "warn"
            self.status_message.emit(f"{name}: {res.get('detail', res.get('status'))}", lvl)
        except Exception as exc:
            SilentMessageBox.warning(self, tr("servers.title"), self._redactor.redact_text(str(exc)))
        self.reload()

    def check_health_selected(self) -> None:
        name = self._selected_name()
        if name:
            self._check_health_server(name)

    def start_autostart_servers(self) -> None:
        self.server_manager.start_autostart_servers()
        self.reload()

    def shutdown(self) -> None:
        self._poll_timer.stop()
        self.server_manager.close()

    def retranslate(self) -> None:
        self.set_header(tr("servers.title"), tr("servers.lead"))
        self.detail_tabs.retranslate()
        self.search_edit.setPlaceholderText(tr("servers.search"))
        self.add_btn.setText(tr("servers.btn.add"))
        self.refresh_btn.setText(tr("servers.btn.refresh"))
        self.list_menu_btn.setToolTip(tr("common.actions"))
        self.table.setHorizontalHeaderLabels(
            [
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
        )
        self.empty_state.set_content(tr("servers.empty.title"), tr("servers.empty.desc"))
        self.logs_header.set_texts(tr("servers.details.logs_title"))
        self.info_header.set_texts(tr("servers.details.info_title"))
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
        mono = tokens.FONT_MONO
        for view in (self.logs_view, self.info_view):
            view.setStyleSheet(f"font-family: {mono}; font-size: 11px;")
