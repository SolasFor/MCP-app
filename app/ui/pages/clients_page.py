"""AI Clients page: aligned DataTable with inline access combo and per-row context menus."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import EmptyState
from app.ui.components.context_menu import MenuActionSpec
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.table import DataTable, TableCellCombo
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore, canonical_oauth_urls, default_store_path


class ClientsPage(PageScaffold):
    """Full-page OAuth client manager with live search, inline scenario selector, and row context menu."""

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
        self._entries: list[dict] = []

        top_row = QHBoxLayout()
        top_row.setSpacing(6)
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("UiInput")
        self.search_edit.setMinimumWidth(160)
        self.search_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.search_edit.textChanged.connect(lambda q: self.table.filter_rows(q))
        top_row.addWidget(self.search_edit, 1)

        self.allowlist_button = QPushButton()
        self.allowlist_button.clicked.connect(self.allowlist_requested.emit)
        self.refresh_button = QPushButton()
        self.refresh_button.setObjectName("Ghost")
        self.refresh_button.clicked.connect(self.reload)
        top_row.addWidget(self.allowlist_button)
        top_row.addWidget(self.refresh_button)
        self.content.addLayout(top_row)

        self.table_card = QWidget()
        tbl_lay = QVBoxLayout(self.table_card)
        tbl_lay.setContentsMargins(0, 0, 0, 0)
        self.table = DataTable(["", "", "", "", ""])
        self.table.set_row_menu_provider(self._build_row_menu)
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

    def _entry_at_row(self, row: int) -> dict | None:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def _build_row_menu(self, row: int) -> list[MenuActionSpec]:
        entry = self._entry_at_row(row)
        if entry is None:
            return []
        cid = str(entry["client_id"])
        cname = str(entry.get("client_name") or cid)
        approved = bool(entry.get("approved_at"))
        has_custom = False
        if approved and self._execution is not None:
            try:
                has_custom = cid in self._execution.client_profiles()
            except Exception:
                has_custom = False

        return [
            MenuActionSpec(
                key="details",
                label=tr("clients.menu.details"),
                icon_name="info",
                callback=lambda c=entry: self._show_client_details(c),
            ),
            MenuActionSpec(
                key="copy_id",
                label=tr("clients.menu.copy_id"),
                icon_name="copy",
                callback=lambda client_id=cid: self._copy_client_id(client_id),
            ),
            MenuActionSpec(
                key="reset_custom",
                label=tr("clients.menu.reset_custom"),
                icon_name="refresh",
                enabled=has_custom,
                callback=lambda client_id=cid: self._reset_custom_profile(client_id),
            ),
            MenuActionSpec(
                key="revoke",
                label=tr("clients.revoke"),
                icon_name="trash",
                danger=True,
                separator_before=True,
                callback=lambda client_id=cid, client_name=cname: self.revoke_client(client_id, client_name),
            ),
        ]

    def reload(self) -> None:
        self._store = None
        self._execution = None
        self._entries = []
        if not self._public_url:
            self.table.setRowCount(0)
            self.table_card.hide()
            self.empty_state.set_content(
                tr("clients.empty.no_server_title"),
                tr("clients.empty.no_server_desc"),
            )
            self.empty_state.show()
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
            self.clients_updated.emit([])
            return

        self._entries = list(clients)
        self.empty_state.hide()
        self.table_card.show()
        self.table.clear_cell_widgets()
        self.table.setRowCount(0)
        self.table.setRowCount(len(clients))

        max_combo_w = max(
            180,
            self.table.fontMetrics().horizontalAdvance(tr("clients.col.rights")) + 28,
            max(
                self.table.fontMetrics().horizontalAdvance(tr(f"clients.role.{k}")) + 64
                for k in ("safe", "allowlist", "full")
            ),
        )
        max_row_h = max(38, self.table.fontMetrics().height() + 22)

        for idx, entry in enumerate(clients):
            approved = entry["approved_at"]
            when = datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M") if approved else "—"
            cname = str(entry["client_name"] or entry["client_id"])
            name = QTableWidgetItem(cname)
            client_id = str(entry["client_id"])
            name.setData(Qt.ItemDataRole.UserRole, client_id)
            name.setToolTip(f"{cname}\nID: {client_id}")
            self.table.setItem(idx, 0, name)
            self.table.setItem(
                idx,
                1,
                QTableWidgetItem(tr("clients.status.approved" if approved else "clients.status.registered")),
            )
            self.table.setItem(idx, 2, QTableWidgetItem(""))
            if approved and self._execution is not None:
                selector = TableCellCombo()
                for key in ("safe", "allowlist", "full"):
                    selector.addItem(tr(f"clients.role.{key}"), key)
                mode = self._execution.profile_for(client_id)
                selector.setCurrentIndex(max(selector.findData(mode), 0))
                selector.currentIndexChanged.connect(
                    lambda _index, cid=client_id, combo=selector: self._change_client_profile(cid, combo)
                )
                max_combo_w = max(max_combo_w, selector.sizeHint().width() + 12)
                max_row_h = max(max_row_h, selector.sizeHint().height() + 6)
                self.table.setCellWidget(idx, 2, selector)
            else:
                self.table.setItem(idx, 2, QTableWidgetItem(tr("clients.no_access")))
            self.table.setItem(idx, 3, QTableWidgetItem(when))
            self.table.set_row_actions_cell(idx, 4, tooltip=tr("common.actions"))

        self.table.verticalHeader().setDefaultSectionSize(max_row_h)
        for row_i in range(self.table.rowCount()):
            self.table.setRowHeight(row_i, max_row_h)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, max_combo_w)
        self.table.setColumnWidth(4, 42)
        self.table.resizeColumnToContents(1)
        self.table.resizeColumnToContents(3)
        self.table.filter_rows(self.search_edit.text())
        self.clients_updated.emit(self.client_summaries())

    def _change_client_profile(self, client_id: str, combo: TableCellCombo) -> None:
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

    def _copy_client_id(self, client_id: str) -> None:
        cb = QGuiApplication.clipboard()
        if cb is not None and client_id:
            cb.setText(client_id)
        self.status_message.emit(tr("toast.copied"), "ok")

    def _show_client_details(self, entry: dict) -> None:
        cid = str(entry.get("client_id") or "")
        cname = str(entry.get("client_name") or cid)
        approved = entry.get("approved_at")
        when = datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M") if approved else "—"
        role_txt = tr("clients.no_access")
        if approved and self._execution is not None:
            role_txt = tr(f"clients.role.{self._execution.profile_for(cid)}")
        extra_uris = ""
        if self._store is not None:
            try:
                info = self._store.get_client(cid)
                if info is not None and info.redirect_uris:
                    extra_uris = "\n" + tr(
                        "clients.details.redirects",
                        uris=", ".join(str(u) for u in info.redirect_uris),
                    )
            except Exception:
                pass
        body = tr(
            "clients.details.body",
            name=cname,
            client_id=cid,
            status=tr("clients.status.approved" if approved else "clients.status.registered"),
            role=role_txt,
            approved_at=when,
        ) + extra_uris
        SilentMessageBox.information(self, tr("clients.menu.details"), body)

    def _reset_custom_profile(self, client_id: str) -> None:
        if self._execution is None:
            return
        self._execution.clear_client_profile(client_id)
        self._execution.clear_client_allowlist(client_id)
        label = client_id
        for entry in self._entries:
            if str(entry.get("client_id") or "") == client_id:
                label = str(entry.get("client_name") or client_id)
                break
        self.reload()
        self.status_message.emit(tr("clients.toast.reset_custom", name=label), "info")

    def revoke_client(self, client_id: str, display_name: str = "") -> bool:
        if self._store is None or not client_id:
            return False
        label = display_name or client_id
        if (
            SilentMessageBox.question(
                self,
                tr("clients.revoke"),
                f"{label}?",
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            != SilentMessageBox.StandardButton.Yes
        ):
            return False
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
        return True

    def revoke_selected(self) -> None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        client_id = str(item.data(Qt.ItemDataRole.UserRole) or "")
        self.revoke_client(client_id, item.text())

    def retranslate(self) -> None:
        self.set_header(tr("clients.title"), tr("clients.lead"))
        self.search_edit.setPlaceholderText(tr("clients.search"))
        self.refresh_button.setText(tr("clients.refresh"))
        self.allowlist_button.setText(tr("home.access.allowlist_btn"))
        self.refresh_hint.setText(tr("clients.tools_refresh_hint"))
        self.table.setHorizontalHeaderLabels(
            [
                tr("clients.col.name"),
                tr("clients.col.status"),
                tr("clients.col.rights"),
                tr("clients.col.date"),
                "",
            ]
        )
        self.reload()

    def apply_theme(self) -> None:
        self.empty_state.apply_theme()
