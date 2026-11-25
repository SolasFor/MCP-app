"""AI Clients page: flat DataTable with search, per-client execution rights, and revocation."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import EmptyState, FlowLayout
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.table import DataTable
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore, canonical_oauth_urls, default_store_path


class ClientsPage(PageScaffold):
    """Full-page OAuth client manager with live search and per-client execution rights."""

    allowlist_requested = pyqtSignal()
    clients_updated = pyqtSignal(list)
    status_message = pyqtSignal(str, str)

    def __init__(
        self,
        parent=None,  # noqa: ANN001
        *,
        store_path_fn: Callable[[], Path] | None = None,
    ) -> None:
        super().__init__(scroll=False, parent=parent)
        self._public_url = ""
        self._store_path_fn = store_path_fn or default_store_path
        self._store: OAuthStore | None = None
        self._execution: ExecutionApprovals | None = None

        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.setMinimumWidth(160)
        self.search_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))
        search_row.addWidget(self.search_edit, 1)

        actions = FlowLayout(spacing=6)
        self.refresh_button = QPushButton()
        self.refresh_button.setObjectName("Ghost")
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
            actions.addWidget(btn)
        self.content.addLayout(search_row)
        self.content.addLayout(actions)

        self.table_card = QWidget()
        tbl_lay = QVBoxLayout(self.table_card)
        tbl_lay.setContentsMargins(0, 0, 0, 0)
        self.table = DataTable(["", "", "", ""])
        self.table.itemSelectionChanged.connect(self._selection_changed)
        tbl_lay.addWidget(self.table, 1)
        self.content.addWidget(self.table_card, 1)

        self.empty_state = EmptyState("clients")
        self.content.addWidget(self.empty_state, 1)

        self.refresh_hint = QLabel()
        self.refresh_hint.setObjectName("Hint")
        self.refresh_hint.setWordWrap(True)
        self.content.addWidget(self.refresh_hint)

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

        issuer, resource_url = canonical_oauth_urls(self._public_url)
        try:
            self._store = OAuthStore(self._store_path_fn(), issuer, resource_url)
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
            cname = str(entry["client_name"] or entry["client_id"])
            name = QTableWidgetItem(cname)
            client_id = entry["client_id"]
            name.setData(Qt.ItemDataRole.UserRole, client_id)
            name.setToolTip(f"{cname}\nID: {client_id}")
            self.table.setItem(idx, 0, name)
            self.table.setItem(
                idx,
                1,
                QTableWidgetItem(tr("clients.status.approved" if approved else "clients.status.registered")),
            )
            if approved and self._execution is not None:
                selector = SafeComboBox(self.table)
                selector.setMinimumWidth(160)
                selector.setFixedHeight(28)
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

        self.table.setColumnWidth(2, 180)
        self.table.filter_rows(self.search_edit.text())
        self._selection_changed()
        self.clients_updated.emit(self.client_summaries())

    def _change_client_profile(self, client_id: str, combo: SafeComboBox) -> None:
        if self._execution is None:
            return
        try:
            previous = self._execution.profile_for(client_id)
            selected = combo.currentData()
            if selected == previous:
                return
            if selected == "full":
                answer = SilentMessageBox.warning(
                    self,
                    tr("clients.role.full"),
                    tr("home.access.hint.full"),
                    SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                    SilentMessageBox.StandardButton.No,
                )
                if answer != SilentMessageBox.StandardButton.Yes:
                    combo.blockSignals(True)
                    combo.setCurrentIndex(combo.findData(previous))
                    combo.blockSignals(False)
                    return
            self._execution.set_client_profile(client_id, selected)
            try:
                from app.core.logging_manager import get_logging_manager

                get_logging_manager().info(
                    "oauth",
                    f"Client execution profile updated: client_id={client_id} {previous} -> {selected}",
                    event_code="oauth_client_profile_changed",
                )
            except Exception:  # noqa: BLE001
                pass
            self.clients_updated.emit(self.client_summaries())
            self.status_message.emit(
                tr("clients.role_saved", role=tr(f"clients.role.{selected}")),
                "ok",
            )
        except (ValueError, OSError, RuntimeError) as exc:
            combo.blockSignals(True)
            combo.setCurrentIndex(max(combo.findData(self._execution.profile_for(client_id)), 0))
            combo.blockSignals(False)
            SilentMessageBox.warning(self, tr("clients.title"), str(type(exc).__name__))

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
            SilentMessageBox.question(
                self,
                tr("clients.revoke"),
                f"{item.text()}?",
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            != SilentMessageBox.StandardButton.Yes
        ):
            return
        self._store.revoke_client(client_id)
        try:
            from app.core.logging_manager import get_logging_manager

            get_logging_manager().warning(
                "oauth",
                f"OAuth client revoked by owner: client_id={client_id}",
                event_code="oauth_client_revoked",
            )
        except Exception:  # noqa: BLE001
            pass
        self.reload()

    def retranslate(self) -> None:
        self.set_header(tr("clients.title"), tr("clients.lead"))
        self.search_edit.setPlaceholderText(tr("clients.search"))
        self.refresh_button.setText(tr("clients.refresh"))
        self.allowlist_button.setText(tr("home.access.allowlist_btn"))
        self.revoke_button.setText(tr("clients.revoke"))
        self.refresh_hint.setText(tr("clients.tools_refresh_hint"))
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
