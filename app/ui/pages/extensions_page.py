"""Extensions GUI page: local catalog, signed/pinned ZIP install, permissions, declarative UI, rollback & logs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
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
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.ui import theme
from app.ui.components.cards import Card, EmptyState, SectionHeader
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.extensions.manager import ExtensionManager
from backend.extensions.store import ExtensionStore


class InstallZipDialog(QDialog):
    """Prompt owner for ZIP archive path, optional expected SHA-256 pin, and explicit confirmation."""

    def __init__(self, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("extensions.dlg.zip_title"))
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setObjectName("UiInput")
        browse_btn = QPushButton("…")
        browse_btn.setObjectName("Ghost")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse_btn)

        self.sha_edit = QLineEdit()
        self.sha_edit.setObjectName("UiInput")
        self.sha_edit.setPlaceholderText("64 hex chars (optional when signed with trusted Ed25519 key)")

        self.confirm_chk = QCheckBox(tr("extensions.dlg.zip_confirm"))
        form.addRow(tr("extensions.dlg.zip_path"), row)
        form.addRow(tr("extensions.dlg.zip_sha"), self.sha_edit)
        form.addRow("", self.confirm_chk)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, tr("extensions.dlg.zip_title"), "", "ZIP (*.zip);;All Files (*.*)"
        )
        if chosen:
            self.path_edit.setText(chosen)


class ExtensionPermissionsDialog(QDialog):
    """Edit granted permissions, allowed clients, and approved mutating tools for an extension."""

    def __init__(self, info: dict[str, Any], *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{tr('extensions.dlg.perms_title')} — {info['name']}")
        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        self._perm_checks: dict[str, QCheckBox] = {}
        granted = set(info.get("granted_permissions") or [])
        for perm in info.get("requested_permissions") or []:
            chk = QCheckBox(perm)
            chk.setChecked(perm in granted)
            self._perm_checks[perm] = chk
            layout.addWidget(chk)

        form = QFormLayout()
        self.clients_edit = QLineEdit(", ".join(info.get("allowed_clients") or []))
        self.clients_edit.setObjectName("UiInput")
        self.tools_edit = QLineEdit(", ".join(info.get("approved_tools") or []))
        self.tools_edit.setObjectName("UiInput")
        form.addRow(tr("extensions.dlg.perms_clients"), self.clients_edit)
        form.addRow(tr("extensions.dlg.perms_tools"), self.tools_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_permissions(self) -> tuple[str, ...]:
        return tuple(p for p, chk in self._perm_checks.items() if chk.isChecked())

    def allowed_clients(self) -> tuple[str, ...]:
        return tuple(x.strip() for x in self.clients_edit.text().split(",") if x.strip())

    def approved_tools(self) -> tuple[str, ...]:
        return tuple(x.strip() for x in self.tools_edit.text().split(",") if x.strip())


class ExtensionsPage(PageScaffold):
    """Local Extensions catalog, verified package installation, permissions, UI, rollback & logs."""

    toast_requested = pyqtSignal(str)

    def __init__(
        self,
        *,
        extensions_dir: Path | None = None,
        catalog_dir: Path | None = None,
        secret_store: SecretStore | None = None,
        redactor: SecretRedactor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self._base_dir = extensions_dir or (user_data_dir() / "extensions")
        self._redactor = redactor or SecretRedactor()
        self._store = ExtensionStore(
            self._base_dir,
            secret_store=secret_store or SecretStore(self._base_dir.parent / "secrets"),
        )
        self.manager = ExtensionManager(self._store, catalog_dir=catalog_dir, redactor=self._redactor)

        self._installed_cache: list[dict[str, Any]] = []
        self._catalog_cache: list[dict[str, Any]] = []
        self._selected_id: str | None = None

        self.set_header(tr("extensions.title"), tr("extensions.lead"))

        self._notice_card = Card()
        self._notice_lbl = QLabel(tr("extensions.isolation_notice"))
        self._notice_lbl.setWordWrap(True)
        self._notice_lbl.setObjectName("Hint")
        self._notice_card.body.addWidget(self._notice_lbl)
        self.content.addWidget(self._notice_card)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("UiInput")
        self.search_input.setPlaceholderText(tr("extensions.search"))
        self.search_input.textChanged.connect(self.refresh_all)
        toolbar.addWidget(self.search_input, 1)

        self.install_zip_btn = QPushButton(tr("extensions.btn.install_zip"))
        self.install_zip_btn.setObjectName("Accent")
        self.install_zip_btn.clicked.connect(self.install_zip_interactive)
        self.install_official_btn = QPushButton(tr("extensions.btn.install_official"))
        self.install_official_btn.setObjectName("Ghost")
        self.install_official_btn.clicked.connect(self.install_selected_catalog)
        self.toggle_btn = QPushButton(tr("extensions.btn.toggle"))
        self.toggle_btn.setObjectName("Ghost")
        self.toggle_btn.clicked.connect(self.toggle_selected)
        self.perms_btn = QPushButton(tr("extensions.btn.perms"))
        self.perms_btn.setObjectName("Ghost")
        self.perms_btn.clicked.connect(self.edit_permissions_selected)
        self.update_btn = QPushButton(tr("extensions.btn.update"))
        self.update_btn.setObjectName("Ghost")
        self.update_btn.clicked.connect(self.update_selected_zip)
        self.rollback_btn = QPushButton(tr("extensions.btn.rollback"))
        self.rollback_btn.setObjectName("Ghost")
        self.rollback_btn.clicked.connect(self.rollback_selected)
        self.uninstall_btn = QPushButton(tr("extensions.btn.uninstall"))
        self.uninstall_btn.setObjectName("Danger")
        self.uninstall_btn.clicked.connect(self.uninstall_selected)
        self.refresh_btn = QPushButton(tr("extensions.btn.refresh"))
        self.refresh_btn.setObjectName("Ghost")
        self.refresh_btn.clicked.connect(self.refresh_all)
        for btn in (
            self.install_zip_btn,
            self.install_official_btn,
            self.toggle_btn,
            self.perms_btn,
            self.update_btn,
            self.rollback_btn,
            self.uninstall_btn,
            self.refresh_btn,
        ):
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            toolbar.addWidget(btn)
        self.content.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        top_widget = QWidget()
        top_lay = QVBoxLayout(top_widget)
        top_lay.setContentsMargins(0, 0, 0, 0)
        top_lay.setSpacing(8)

        self._installed_hdr = SectionHeader(tr("extensions.installed.title"))
        top_lay.addWidget(self._installed_hdr)
        self.installed_table = DataTable([
            tr("extensions.col.id"),
            tr("extensions.col.name"),
            tr("extensions.col.version"),
            tr("extensions.col.status"),
            tr("extensions.col.trust"),
            tr("extensions.col.perms"),
        ])
        self.installed_table.setMinimumHeight(130)
        self.installed_table.itemSelectionChanged.connect(self._on_installed_selected)
        top_lay.addWidget(self.installed_table, 1)

        self.empty_state = EmptyState("extensions", tr("extensions.empty.title"), tr("extensions.empty.desc"))
        top_lay.addWidget(self.empty_state)

        self._catalog_hdr = SectionHeader(tr("extensions.catalog.title"))
        top_lay.addWidget(self._catalog_hdr)
        self.catalog_table = DataTable([
            tr("extensions.col.id"),
            tr("extensions.col.name"),
            tr("extensions.col.version"),
            tr("extensions.col.perms"),
            tr("extensions.col.desc"),
        ])
        self.catalog_table.setMinimumHeight(120)
        top_lay.addWidget(self.catalog_table, 1)
        splitter.addWidget(top_widget)

        bottom_card = Card(margins=(12, 12, 12, 12))
        self._ui_hdr = SectionHeader(tr("extensions.details.ui"))
        bottom_card.body.addWidget(self._ui_hdr)
        self.ui_preview = QPlainTextEdit()
        self.ui_preview.setObjectName("ConsoleLog")
        self.ui_preview.setReadOnly(True)
        self.ui_preview.setMaximumHeight(95)
        bottom_card.body.addWidget(self.ui_preview)

        self._logs_hdr = SectionHeader(tr("extensions.details.logs"))
        bottom_card.body.addWidget(self._logs_hdr)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setObjectName("ConsoleLog")
        self.logs_view.setReadOnly(True)
        self.logs_view.setMinimumHeight(110)
        bottom_card.body.addWidget(self.logs_view, 1)
        splitter.addWidget(bottom_card)

        self.content.addWidget(splitter, 1)
        self.refresh_all()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()

    def refresh_all(self) -> None:
        query = self.search_input.text().strip()
        self._installed_cache = self.manager.list_extensions(query=query)
        self._catalog_cache = self.manager.list_catalog(query=query)

        has_inst = bool(self._installed_cache)
        self.installed_table.setVisible(has_inst)
        self.empty_state.setVisible(not has_inst)

        self.installed_table.setRowCount(len(self._installed_cache))
        for row, item in enumerate(self._installed_cache):
            st = item["runtime"]["state"]
            cells = [
                item["id"],
                item["name"],
                item["version"],
                tr(f"extensions.status.{st}"),
                item["verified_by"] or item["source"],
                ", ".join(item["granted_permissions"]) or "—",
            ]
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                if col == 3:
                    color = theme.OK if st == "running" else (theme.ERR if st == "crashed" else theme.IDLE)
                    cell.setData(Qt.ItemDataRole.UserRole, color)
                self.installed_table.setItem(row, col, cell)
        self.installed_table.resizeColumnsToContents()

        self.catalog_table.setRowCount(len(self._catalog_cache))
        for row, cat in enumerate(self._catalog_cache):
            tag = " [installed]" if cat["installed"] else ""
            cells = [
                cat["id"],
                cat["name"] + tag,
                cat["version"],
                ", ".join(cat["permissions"]) or "—",
                cat["description"],
            ]
            for col, text in enumerate(cells):
                self.catalog_table.setItem(row, col, QTableWidgetItem(text))
        self.catalog_table.resizeColumnsToContents()
        self._refresh_details()

    def _selected_installed(self) -> dict[str, Any] | None:
        row = self.installed_table.currentRow()
        if 0 <= row < len(self._installed_cache):
            return self._installed_cache[row]
        if self._selected_id:
            return next((x for x in self._installed_cache if x["id"] == self._selected_id), None)
        return None

    def _on_installed_selected(self) -> None:
        item = self._selected_installed()
        self._selected_id = item["id"] if item else None
        self._refresh_details()

    def _refresh_details(self) -> None:
        item = self._selected_installed()
        if not item:
            self.ui_preview.setPlainText("—")
            self.logs_view.setPlainText("")
            return
        ext_id = item["id"]
        try:
            ui = self.manager.get_ui(ext_id)
            self.ui_preview.setPlainText(json.dumps(ui, indent=2, ensure_ascii=False))
        except Exception as exc:  # noqa: BLE001
            self.ui_preview.setPlainText(str(exc))
        lines = self.manager.get_logs(ext_id, tail=100)
        self.logs_view.setPlainText("\n".join(lines))

    def install_zip_interactive(self) -> None:
        dlg = InstallZipDialog(parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            res = self.manager.install_zip(
                Path(dlg.path_edit.text().strip()),
                expected_sha256=dlg.sha_edit.text().strip(),
                owner_confirmed=dlg.confirm_chk.isChecked(),
            )
            self._selected_id = res["id"]
            self.toast_requested.emit(tr("extensions.toast.installed", name=res["name"]))
            self.refresh_all()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("extensions.title"), str(exc))

    def install_selected_catalog(self) -> None:
        row = self.catalog_table.currentRow()
        if not (0 <= row < len(self._catalog_cache)):
            return
        ext_id = self._catalog_cache[row]["id"]
        try:
            res = self.manager.install_official(ext_id, enable_after_install=False)
            self._selected_id = res["id"]
            self.toast_requested.emit(tr("extensions.toast.installed", name=res["name"]))
            self.refresh_all()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("extensions.title"), str(exc))

    def toggle_selected(self) -> None:
        item = self._selected_installed()
        if not item:
            return
        try:
            if item["enabled"]:
                self.manager.disable(item["id"])
            else:
                self.manager.enable(item["id"])
            self.refresh_all()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("extensions.title"), str(exc))

    def edit_permissions_selected(self) -> None:
        item = self._selected_installed()
        if not item:
            return
        dlg = ExtensionPermissionsDialog(item, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self.manager.set_permissions(
            item["id"],
            dlg.selected_permissions(),
            allowed_clients=dlg.allowed_clients(),
            approved_tools=dlg.approved_tools(),
        )
        self.toast_requested.emit(tr("extensions.toast.saved"))
        self.refresh_all()

    def update_selected_zip(self) -> None:
        item = self._selected_installed()
        if not item:
            return
        dlg = InstallZipDialog(parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            res = self.manager.update_zip(
                item["id"],
                Path(dlg.path_edit.text().strip()),
                expected_sha256=dlg.sha_edit.text().strip(),
                owner_confirmed=dlg.confirm_chk.isChecked(),
            )
            self.toast_requested.emit(tr("extensions.toast.updated", name=res["name"]))
            self.refresh_all()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("extensions.title"), str(exc))

    def rollback_selected(self) -> None:
        item = self._selected_installed()
        if not item:
            return
        try:
            res = self.manager.rollback(item["id"])
            self.toast_requested.emit(tr("extensions.toast.rolled_back", name=res["name"]))
            self.refresh_all()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, tr("extensions.title"), str(exc))

    def uninstall_selected(self) -> None:
        item = self._selected_installed()
        if not item:
            return
        self.manager.uninstall(item["id"], keep_data=True)
        self._selected_id = None
        self.toast_requested.emit(tr("extensions.toast.removed", name=item["name"]))
        self.refresh_all()

    def shutdown(self) -> None:
        self.manager.shutdown_all()

    def retranslate(self) -> None:
        self.set_header(tr("extensions.title"), tr("extensions.lead"))
        self._notice_lbl.setText(tr("extensions.isolation_notice"))
        self.search_input.setPlaceholderText(tr("extensions.search"))
        self.install_zip_btn.setText(tr("extensions.btn.install_zip"))
        self.install_official_btn.setText(tr("extensions.btn.install_official"))
        self.toggle_btn.setText(tr("extensions.btn.toggle"))
        self.perms_btn.setText(tr("extensions.btn.perms"))
        self.update_btn.setText(tr("extensions.btn.update"))
        self.rollback_btn.setText(tr("extensions.btn.rollback"))
        self.uninstall_btn.setText(tr("extensions.btn.uninstall"))
        self.refresh_btn.setText(tr("extensions.btn.refresh"))
        self._installed_hdr.set_texts(tr("extensions.installed.title"))
        self._catalog_hdr.set_texts(tr("extensions.catalog.title"))
        self._ui_hdr.set_texts(tr("extensions.details.ui"))
        self._logs_hdr.set_texts(tr("extensions.details.logs"))
        self.empty_state.set_content(tr("extensions.empty.title"), tr("extensions.empty.desc"))
        self.installed_table.setHorizontalHeaderLabels([
            tr("extensions.col.id"),
            tr("extensions.col.name"),
            tr("extensions.col.version"),
            tr("extensions.col.status"),
            tr("extensions.col.trust"),
            tr("extensions.col.perms"),
        ])
        self.catalog_table.setHorizontalHeaderLabels([
            tr("extensions.col.id"),
            tr("extensions.col.name"),
            tr("extensions.col.version"),
            tr("extensions.col.perms"),
            tr("extensions.col.desc"),
        ])
        self.refresh_all()
