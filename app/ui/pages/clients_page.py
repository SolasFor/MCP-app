"""AI Clients page: inline OAuth client management, search filter, per-client roles, and revocation."""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QMessageBox, QPushButton, QTableWidgetItem

from app.ui.components.cards import Card, EmptyState
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore, default_store_path


class ClientsPage(PageScaffold):
    """Full-page OAuth client manager with live search and per-client execution rights."""

    allowlist_requested = pyqtSignal()
    clients_updated = pyqtSignal(list)

    def __init__(self, parent=None) -> None:  # noqa: ANN001
        super().__init__(scroll=False, parent=parent)
        self._public_url = ""
        self._store: OAuthStore | None = None
        self._execution: ExecutionApprovals | None = None

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))
        toolbar.addWidget(self.search_edit, 1)

        self.refresh_button = QPushButton()
        self.refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_button.clicked.connect(self.reload)
        self.allowlist_button = QPushButton()
        self.allowlist_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.allowlist_button.clicked.connect(self.allowlist_requested.emit)
        self.revoke_button = QPushButton()
        self.revoke_button.setObjectName("Danger")
        self.revoke_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.revoke_button.setEnabled(False)
        self.revoke_button.clicked.connect(self.revoke_selected)

        for btn in (self.refresh_button, self.allowlist_button, self.revoke_button):
            toolbar.addWidget(btn)
        self.content.addLayout(toolbar)

        self.table_card = Card(margins=(12, 12, 12, 12))
        self.table = DataTable(["", "", "", ""])
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table_card.body.addWidget(self.table, 1)
        self.content.addWidget(self.table_card, 1)

        self.empty_state = EmptyState("clients")
        self.content.addWidget(self.empty_state, 1)

        self.retranslate()
        self.reload()

    def set_public_url(self, public_url: str) -> None:
        self._public_url = public_url.strip()
        self.reload()

    def client_summaries(self) -> list[tuple[str, str, str]]:
        if not self._public_url or self._store is None or self._execution is None:
            return []
        try:
            clients = self._store.list_clients()
        except Exception:
            return []
        out: list[tuple[str, str, str]] = []
        for entry in clients:
            approved = bool(entry["approved_at"])
            status = tr("clients.status.approved" if approved else "clients.status.registered")
            if approved:
                role = self._execution.profile_for(entry["client_id"])
                rights = tr(f"clients.role.{role}")
            else:
                rights = tr("clients.no_access")
            out.append((entry["client_name"], status, rights))
        return out

    def reload(self) -> None:
        self._store = None
        self._execution = None
        if not self._public_url:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.set_content(
                tr("clients.empty.no_server_title"),
                tr("clients.empty.no_server_desc"),
            )
            self.empty_state.show()
            self.revoke_button.setEnabled(False)
            self.clients_updated.emit([])
            return

        parts = urlsplit(self._public_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            self.table_card.hide()
            self.empty_state.show()
            self.clients_updated.emit([])
            return

        issuer = f"{parts.scheme}://{parts.netloc}"
        try:
            self._store = OAuthStore(default_store_path(), issuer, self._public_url)
            self._execution = ExecutionApprovals(self._store)
            clients = self._store.list_clients()
        except Exception:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.set_content(
                tr("clients.empty.none_title"),
                tr("clients.empty.none_desc"),
            )
            self.empty_state.show()
            self.clients_updated.emit([])
            return

        if not clients:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.set_content(
                tr("clients.empty.none_title"),
                tr("clients.empty.none_desc"),
            )
            self.empty_state.show()
            self.revoke_button.setEnabled(False)
            self.clients_updated.emit([])
            return

        self.empty_state.hide()
        self.table_card.show()
        self.table.setRowCount(len(clients))
        for idx, entry in enumerate(clients):
            approved = entry["approved_at"]
            when = datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M") if approved else "—"
            name = QTableWidgetItem(entry["client_name"])
            client_id = entry["client_id"]
            name.setData(Qt.ItemDataRole.UserRole, client_id)
            name.setToolTip(f"ID: {client_id}")
            self.table.setItem(idx, 0, name)
            self.table.setItem(
                idx,
                1,
                QTableWidgetItem(tr("clients.status.approved" if approved else "clients.status.registered")),
            )
            if approved and self._execution is not None:
                selector = QComboBox(self.table)
                selector.setMinimumWidth(190)
                for key in ("safe", "allowlist", "full"):
                    selector.addItem(tr(f"clients.role.{key}"), key)
                mode = self._execution.profile_for(client_id)
                selector.setCurrentIndex(max(selector.findData(mode), 0))
                selector.currentIndexChanged.connect(
                    lambda _index, cid=client_id, combo=selector: self._change_client_profile(cid, combo)
                )
                self.table.setCellWidget(idx, 2, selector)
            else:
                self.table.setItem(idx, 2, QTableWidgetItem(tr("clients.no_access")))
            self.table.setItem(idx, 3, QTableWidgetItem(when))

        self.table.setColumnWidth(2, 210)
        self.table.filter_rows(self.search_edit.text())
        self._selection_changed()
        self.clients_updated.emit(self.client_summaries())

    def _change_client_profile(self, client_id: str, combo: QComboBox) -> None:
        if self._execution is None:
            return
        try:
            previous = self._execution.profile_for(client_id)
            selected = combo.currentData()
            if selected == previous:
                return
            if selected == "full":
                answer = QMessageBox.warning(
                    self,
                    tr("clients.role.full"),
                    tr("home.access.hint.full"),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    combo.blockSignals(True)
                    combo.setCurrentIndex(combo.findData(previous))
                    combo.blockSignals(False)
                    return
            self._execution.set_client_profile(client_id, selected)
            self.clients_updated.emit(self.client_summaries())
        except (ValueError, OSError, RuntimeError) as exc:
            combo.blockSignals(True)
            combo.setCurrentIndex(max(combo.findData(self._execution.profile_for(client_id)), 0))
            combo.blockSignals(False)
            QMessageBox.warning(self, tr("clients.title"), str(type(exc).__name__))

    def _selection_changed(self) -> None:
        row = self.table.currentRow()
        self.revoke_button.setEnabled(row >= 0 and self.table.item(row, 0) is not None)

    def revoke_selected(self) -> None:
        if self._store is None:
            return
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        client_id = item.data(Qt.ItemDataRole.UserRole)
        if (
            QMessageBox.question(
                self,
                tr("clients.revoke"),
                f"{item.text()}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._store.revoke_client(client_id)
        self.reload()

    def retranslate(self) -> None:
        self.set_header(tr("clients.title"), tr("clients.lead"))
        self.search_edit.setPlaceholderText(tr("clients.search"))
        self.refresh_button.setText(tr("clients.refresh"))
        self.allowlist_button.setText(tr("home.access.allowlist_btn"))
        self.revoke_button.setText(tr("clients.revoke"))
        self.table.setHorizontalHeaderLabels(
            [
                tr("clients.col.name"),
                tr("clients.col.status"),
                tr("clients.col.rights"),
                tr("clients.col.date"),
            ]
        )
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
