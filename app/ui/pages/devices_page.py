"""Devices GUI page: SSH/SFTP profiles, ~/.ssh/config import, strict host keys, health, metrics & SFTP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.ui.components.cards import Divider, EmptyState, SectionHeader
from app.ui.components.context_menu import MenuActionSpec
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.safe_spin import SafeSpinBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.remote.manager import RemoteManager
from backend.remote.models import DevicePermissions, DeviceProfile
from backend.remote.store import DeviceStore, import_ssh_config


def _parse_csv(raw: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in raw.split(",") if x.strip())


def _parse_lines(raw: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in raw.splitlines() if line.strip())


class DeviceProfileDialog(SilentDialog):
    """Create or edit an SSH/SFTP DeviceProfile with strict host-key verification and SecretStore refs."""

    def __init__(
        self,
        store: DeviceStore,
        *,
        existing: DeviceProfile | None = None,
        is_new: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._base = existing or DeviceProfile(device_id="srv1", name="Server 1", host="127.0.0.1")
        self._is_new = is_new
        self.saved_profile: DeviceProfile | None = None

        self.setWindowTitle(tr("devices.dlg.title"))
        self.setMinimumWidth(580)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(6)

        self.id_edit = QLineEdit(self._base.device_id if existing else "")
        self.id_edit.setObjectName("UiInput")
        self.id_edit.setReadOnly(not is_new)
        self.name_edit = QLineEdit(self._base.name if existing else "")
        self.name_edit.setObjectName("UiInput")
        self.group_edit = QLineEdit(self._base.group)
        self.group_edit.setObjectName("UiInput")
        self.host_edit = QLineEdit(self._base.host if existing else "")
        self.host_edit.setObjectName("UiInput")
        self.port_spin = SafeSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(self._base.port)
        self.user_edit = QLineEdit(self._base.username)
        self.user_edit.setObjectName("UiInput")

        self.auth_combo = SafeComboBox()
        for mode in ("agent", "key", "password_ref"):
            self.auth_combo.addItem(mode, mode)
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(self._base.auth_method)))

        self.key_path_edit = QLineEdit(self._base.key_path)
        self.key_path_edit.setObjectName("UiInput")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setObjectName("UiInput")
        self.password_edit.setPlaceholderText(tr("devices.dlg.password_hint"))
        self.known_hosts_edit = QLineEdit(self._base.known_hosts_path)
        self.known_hosts_edit.setObjectName("UiInput")
        self.sftp_roots_edit = QLineEdit(", ".join(self._base.allowed_sftp_roots))
        self.sftp_roots_edit.setObjectName("UiInput")
        self.commands_edit = QPlainTextEdit("\n".join(self._base.allowed_commands))
        self.commands_edit.setMaximumHeight(54)
        self.services_edit = QLineEdit(", ".join(self._base.allowed_services))
        self.services_edit.setObjectName("UiInput")
        self.clients_edit = QLineEdit(", ".join(self._base.allowed_clients))
        self.clients_edit.setObjectName("UiInput")

        self.min_profile_combo = SafeComboBox()
        self.min_profile_combo.addItem("Allowlist", "allowlist")
        self.min_profile_combo.addItem("Full Access", "full")
        self.min_profile_combo.setCurrentIndex(max(0, self.min_profile_combo.findData(self._base.min_profile)))

        perms = self._base.permissions
        self.perm_exec = QCheckBox("Execute")
        self.perm_exec.setChecked(perms.execute)
        self.perm_sftp_r = QCheckBox("SFTP Read")
        self.perm_sftp_r.setChecked(perms.sftp_read)
        self.perm_sftp_w = QCheckBox("SFTP Write")
        self.perm_sftp_w.setChecked(perms.sftp_write)
        self.perm_svc = QCheckBox("Services")
        self.perm_svc.setChecked(perms.service_control)
        self.perm_metrics = QCheckBox("Metrics")
        self.perm_metrics.setChecked(perms.metrics)
        self.enabled_chk = QCheckBox(tr("devices.dlg.enabled"))
        self.enabled_chk.setChecked(self._base.enabled)

        perm_row = QHBoxLayout()
        for chk in (
            self.perm_exec,
            self.perm_sftp_r,
            self.perm_sftp_w,
            self.perm_svc,
            self.perm_metrics,
            self.enabled_chk,
        ):
            perm_row.addWidget(chk)

        form.addRow(tr("devices.dlg.id"), self.id_edit)
        form.addRow(tr("devices.dlg.name"), self.name_edit)
        form.addRow(tr("devices.dlg.group"), self.group_edit)
        form.addRow(tr("devices.dlg.host"), self.host_edit)
        form.addRow(tr("devices.dlg.port"), self.port_spin)
        form.addRow(tr("devices.dlg.user"), self.user_edit)
        form.addRow(tr("devices.dlg.auth"), self.auth_combo)
        form.addRow(tr("devices.dlg.key_path"), self.key_path_edit)
        form.addRow(tr("devices.dlg.password"), self.password_edit)
        form.addRow(tr("devices.dlg.known_hosts"), self.known_hosts_edit)
        form.addRow(tr("devices.dlg.sftp_roots"), self.sftp_roots_edit)
        form.addRow(tr("devices.dlg.commands"), self.commands_edit)
        form.addRow(tr("devices.dlg.services"), self.services_edit)
        form.addRow(tr("devices.dlg.min_profile"), self.min_profile_combo)
        form.addRow(tr("devices.dlg.clients"), self.clients_edit)
        form.addRow(tr("devices.dlg.perms"), perm_row)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        try:
            dev_id = self.id_edit.text().strip()
            pwd_ref = self._base.password_ref
            raw_pwd = self.password_edit.text()
            if raw_pwd:
                pwd_ref = self._store.set_secret(dev_id, "password", raw_pwd)
            prof = DeviceProfile(
                device_id=dev_id,
                name=self.name_edit.text().strip() or dev_id,
                host=self.host_edit.text().strip(),
                port=int(self.port_spin.value()),
                username=self.user_edit.text().strip(),
                group=self.group_edit.text().strip() or "default",
                auth_method=str(self.auth_combo.currentData() or "agent"),
                key_path=self.key_path_edit.text().strip(),
                password_ref=pwd_ref,
                passphrase_ref=self._base.passphrase_ref,
                known_hosts_path=self.known_hosts_edit.text().strip(),
                strict_host_key=True,
                allowed_sftp_roots=_parse_csv(self.sftp_roots_edit.text()),
                allowed_commands=_parse_lines(self.commands_edit.toPlainText()),
                allowed_services=_parse_csv(self.services_edit.text()),
                min_profile=str(self.min_profile_combo.currentData() or "allowlist"),
                allowed_clients=_parse_csv(self.clients_edit.text()),
                permissions=DevicePermissions(
                    execute=self.perm_exec.isChecked(),
                    sftp_read=self.perm_sftp_r.isChecked(),
                    sftp_write=self.perm_sftp_w.isChecked(),
                    service_control=self.perm_svc.isChecked(),
                    metrics=self.perm_metrics.isChecked(),
                ),
                enabled=self.enabled_chk.isChecked(),
            )
            if self._is_new and prof.device_id in self._store.load_all():
                raise ValueError(f"Device '{prof.device_id}' already exists")
        except Exception as exc:  # noqa: BLE001
            SilentMessageBox.warning(self, tr("devices.title"), str(exc))
            return
        self.saved_profile = prof
        self.accept()


class DevicesPage(PageScaffold):
    """GUI manager for remote SSH/SFTP servers, known_hosts trust, metrics, SFTP & logs."""

    toast_requested = pyqtSignal(str)

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        secrets_dir: Path | None = None,
        redactor: SecretRedactor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self._redactor = redactor or SecretRedactor()
        sec_store = SecretStore(secrets_dir) if secrets_dir is not None else None
        self.store = DeviceStore(config_path or (user_data_dir() / "remote" / "devices.json"), secret_store=sec_store)
        self.manager = RemoteManager(self.store, redactor=self._redactor)
        self._devices: list[dict[str, Any]] = []

        self.set_header(tr("devices.title"), tr("devices.lead"))

        self._notice_lbl = QLabel(tr("devices.security_notice"))
        self._notice_lbl.setWordWrap(True)
        self._notice_lbl.setObjectName("Hint")
        self.content.addWidget(self._notice_lbl)
        self.content.addWidget(Divider())

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("UiInput")
        self.search_input.setPlaceholderText(tr("devices.search"))
        self.search_input.textChanged.connect(self.refresh_all)
        toolbar.addWidget(self.search_input, 1)

        self.add_btn = QPushButton(tr("devices.btn.add"))
        self.add_btn.setObjectName("Accent")
        self.add_btn.clicked.connect(self.add_device)
        self.import_btn = QPushButton(tr("devices.btn.import"))
        self.import_btn.setObjectName("Ghost")
        self.import_btn.clicked.connect(lambda: self.import_from_ssh_config(None))
        self.refresh_btn = QPushButton(tr("devices.btn.refresh"))
        self.refresh_btn.setObjectName("Ghost")
        self.refresh_btn.clicked.connect(self.refresh_all)
        toolbar.addWidget(self.add_btn)
        toolbar.addWidget(self.import_btn)
        toolbar.addWidget(self.refresh_btn)
        self.content.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        top_pane = QWidget()
        top_lay = QVBoxLayout(top_pane)
        top_lay.setContentsMargins(0, 0, 0, 6)
        top_lay.setSpacing(6)
        self._table_hdr = SectionHeader(tr("devices.table.title"))
        top_lay.addWidget(self._table_hdr)
        self.table = DataTable([
            tr("devices.col.id"),
            tr("devices.col.name"),
            tr("devices.col.host"),
            tr("devices.col.group"),
            tr("devices.col.auth"),
            tr("devices.col.perms"),
            "",
        ])
        self.table.setMinimumHeight(130)
        self.table.itemSelectionChanged.connect(self._refresh_details)
        self.table.set_row_menu_provider(self._build_row_menu)
        top_lay.addWidget(self.table, 1)
        self.empty_state = EmptyState("devices", tr("devices.empty.title"), tr("devices.empty.desc"))
        top_lay.addWidget(self.empty_state)
        splitter.addWidget(top_pane)

        bottom_pane = QWidget()
        bottom_lay = QVBoxLayout(bottom_pane)
        bottom_lay.setContentsMargins(0, 6, 0, 0)
        bottom_lay.setSpacing(6)
        self._output_hdr = SectionHeader(tr("devices.details.output"))
        bottom_lay.addWidget(self._output_hdr)
        self.output_view = QPlainTextEdit()
        self.output_view.setObjectName("ConsoleLog")
        self.output_view.setReadOnly(True)
        bottom_lay.addWidget(self.output_view, 1)
        splitter.addWidget(bottom_pane)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([280, 160])

        self.content.addWidget(splitter, 1)
        self.refresh_all()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()

    def refresh_all(self) -> None:
        q = self.search_input.text().strip().lower()
        all_rows = self.manager.list_devices()["devices"]
        self._devices = [
            d
            for d in all_rows
            if not q or q in d["device_id"].lower() or q in d["name"].lower() or q in d["host"].lower() or q in d["group"].lower()
        ]
        has_rows = bool(self._devices)
        self.table.setVisible(has_rows)
        self.empty_state.setVisible(not has_rows)
        self.table.setRowCount(len(self._devices))
        for row, dev in enumerate(self._devices):
            enabled_perms = [k for k, v in dev["permissions"].items() if v]
            cells = [
                dev["device_id"],
                dev["name"],
                f"{dev['username']}@{dev['host']}:{dev['port']}" if dev["username"] else f"{dev['host']}:{dev['port']}",
                dev["group"],
                dev["auth_method"],
                ", ".join(enabled_perms) or "read-only",
            ]
            for col, val in enumerate(cells):
                self.table.setItem(row, col, QTableWidgetItem(val))
            self.table.set_row_actions_cell(row, 6, tooltip=tr("common.actions"))
        self.table.resizeColumnsToContents()
        self._refresh_details()

    def _row_id(self, row: int) -> str | None:
        if 0 <= row < len(self._devices):
            return str(self._devices[row]["device_id"])
        return None

    def _selected_id(self) -> str | None:
        return self._row_id(self.table.currentRow())

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        dev_id = self._row_id(row)
        if not dev_id:
            return []
        return [
            MenuActionSpec(
                key="health",
                label=tr("devices.btn.health"),
                callback=lambda d=dev_id: self._check_device_health(d),
                icon_name="shield",
            ),
            MenuActionSpec(
                key="metrics",
                label=tr("devices.btn.metrics"),
                callback=lambda d=dev_id: self._fetch_device_metrics(d),
                icon_name="eye",
            ),
            MenuActionSpec(
                key="edit",
                label=tr("devices.btn.edit"),
                callback=lambda d=dev_id: self._edit_device(d),
                icon_name="edit",
                separator_before=True,
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("common.copy_id"),
                callback=lambda d=dev_id: self._copy_device_id(d),
                icon_name="copy",
            ),
            MenuActionSpec(
                key="delete",
                label=tr("devices.btn.delete"),
                callback=lambda d=dev_id: self._delete_device(d),
                icon_name="trash",
                danger=True,
                separator_before=True,
            ),
        ]

    def _copy_device_id(self, dev_id: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(dev_id)
        self.toast_requested.emit(tr("common.copied_id", item_id=dev_id))

    def _refresh_details(self) -> None:
        dev_id = self._selected_id()
        if not dev_id:
            self.output_view.setPlainText("")
            return
        logs = self.manager.get_logs(dev_id)
        if logs:
            self.output_view.setPlainText("\n".join(logs))

    def add_device(self) -> None:
        dlg = DeviceProfileDialog(self.store, is_new=True, parent=self)
        if dlg.exec() == SilentDialog.DialogCode.Accepted and dlg.saved_profile is not None:
            self.store.upsert(dlg.saved_profile)
            self.manager._register_secrets()
            self.toast_requested.emit(tr("devices.toast.saved", name=dlg.saved_profile.name))
            self.refresh_all()

    def _edit_device(self, dev_id: str) -> None:
        existing = self.store.get(dev_id)
        if existing is None:
            return
        dlg = DeviceProfileDialog(self.store, existing=existing, is_new=False, parent=self)
        if dlg.exec() == SilentDialog.DialogCode.Accepted and dlg.saved_profile is not None:
            self.store.upsert(dlg.saved_profile)
            self.manager._register_secrets()
            self.toast_requested.emit(tr("devices.toast.saved", name=dlg.saved_profile.name))
            self.refresh_all()

    def edit_selected(self) -> None:
        dev_id = self._selected_id()
        if dev_id:
            self._edit_device(dev_id)

    def import_from_ssh_config(self, config_path: Path | None = None) -> int:
        imported = import_ssh_config(config_path)
        count = 0
        for prof in imported:
            if self.store.get(prof.device_id) is None:
                self.store.upsert(prof)
                count += 1
        self.toast_requested.emit(tr("devices.toast.imported", count=count))
        self.refresh_all()
        return count

    def _check_device_health(self, dev_id: str) -> None:
        try:
            res = self.manager.device_health(dev_id)
            self.output_view.setPlainText(json.dumps(res, indent=2, ensure_ascii=False))
        except Exception as exc:  # noqa: BLE001
            self.output_view.setPlainText(f"Health probe denied/failed: {exc}")

    def check_selected_health(self) -> None:
        dev_id = self._selected_id()
        if dev_id:
            self._check_device_health(dev_id)

    def _fetch_device_metrics(self, dev_id: str) -> None:
        try:
            res = self.manager.remote_metrics(dev_id)
            self.output_view.setPlainText(json.dumps(res, indent=2, ensure_ascii=False))
        except Exception as exc:  # noqa: BLE001
            self.output_view.setPlainText(f"Metrics denied/failed: {exc}")

    def fetch_selected_metrics(self) -> None:
        dev_id = self._selected_id()
        if dev_id:
            self._fetch_device_metrics(dev_id)

    def _delete_device(self, dev_id: str) -> None:
        self.store.remove(dev_id)
        self.toast_requested.emit(tr("devices.toast.deleted", name=dev_id))
        self.refresh_all()

    def delete_selected(self) -> None:
        dev_id = self._selected_id()
        if dev_id:
            self._delete_device(dev_id)

    def shutdown(self) -> None:
        self.manager.close()

    def retranslate(self) -> None:
        self.set_header(tr("devices.title"), tr("devices.lead"))
        self._notice_lbl.setText(tr("devices.security_notice"))
        self.search_input.setPlaceholderText(tr("devices.search"))
        self.add_btn.setText(tr("devices.btn.add"))
        self.import_btn.setText(tr("devices.btn.import"))
        self.refresh_btn.setText(tr("devices.btn.refresh"))
        self._table_hdr.set_texts(tr("devices.table.title"))
        self._output_hdr.set_texts(tr("devices.details.output"))
        self.empty_state.set_content(tr("devices.empty.title"), tr("devices.empty.desc"))
        self.table.setHorizontalHeaderLabels([
            tr("devices.col.id"),
            tr("devices.col.name"),
            tr("devices.col.host"),
            tr("devices.col.group"),
            tr("devices.col.auth"),
            tr("devices.col.perms"),
            "",
        ])
        self.refresh_all()
