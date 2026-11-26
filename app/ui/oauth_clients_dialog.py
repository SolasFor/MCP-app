"""Local OAuth client management with an individual access mode per client.

Owner-only GUI controls change encrypted permissions in SQLite. Changes are
checked on each MCP call; OAuth clients have no network admin route.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.ui.components.cards import EmptyState
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.components.table import TableCellCombo
from backend.oauth_store import OAuthStore, default_store_path
from backend.oauth_execution import ExecutionApprovals


class OAuthClientsDialog(SilentDialog):
    def __init__(self, public_url: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        parts = urlsplit(public_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("A valid server URL is required")
        issuer = f"{parts.scheme}://{parts.netloc}"
        self.store = OAuthStore(default_store_path(), issuer, public_url)
        self.execution = ExecutionApprovals(self.store)
        self.setWindowTitle("OAuth-клиенты MCP app")
        self.setMinimumSize(680, 400)
        self.resize(780, 470)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)
        title = QLabel("OAuth-клиенты")
        title.setObjectName("SectionTitle")
        root.addWidget(title)

        explanation = QLabel(
            "Выберите сценарий доступа отдельно для каждого подтверждённого "
            "OAuth-клиента в колонке «Права». Изменения вступают в силу сразу. "
            "По умолчанию используется режим с главной страницы, пока для "
            "клиента не выбран свой. Команды из белого списка и полного "
            "доступа выполняются без отдельного подтверждения."
        )
        explanation.setObjectName("Hint")
        explanation.setWordWrap(True)
        root.addWidget(explanation)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Клиент", "Состояние", "Права", "Дата разрешения"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        fm_h = self.table.fontMetrics().height()
        self.table.verticalHeader().setMinimumSectionSize(max(32, fm_h + 16))
        self.table.verticalHeader().setDefaultSectionSize(max(38, fm_h + 22))
        self.table.itemSelectionChanged.connect(self._selection_changed)
        root.addWidget(self.table, 1)

        self.empty_state = EmptyState(
            "clients",
            "Нет зарегистрированных OAuth-клиентов",
            "Клиенты появятся здесь после регистрации и подтверждения доступа.",
        )
        self.empty_state.hide()
        root.addWidget(self.empty_state, 1)

        footer = QHBoxLayout()
        footer.setSpacing(6)
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.setObjectName("Ghost")
        self.refresh_button.clicked.connect(self.reload)
        self.revoke_button = QPushButton("Отозвать OAuth-доступ")
        self.revoke_button.setObjectName("Danger")
        self.revoke_button.setEnabled(False)
        self.revoke_button.clicked.connect(self.revoke_selected)
        close_button = QPushButton("Закрыть")
        close_button.setObjectName("Ghost")
        close_button.clicked.connect(self.accept)
        for btn in (
            self.refresh_button, self.revoke_button,
        ):
            footer.addWidget(btn)
        footer.addStretch(1)
        footer.addWidget(close_button)
        root.addLayout(footer)
        self.reload()

    def reload(self) -> None:
        try:
            clients = self.store.list_clients()
        except Exception as exc:
            SilentMessageBox.warning(
                self, "OAuth", f"Не удалось прочитать хранилище: {type(exc).__name__}"
            )
            return
        has_clients = bool(clients)
        self.table.setVisible(has_clients)
        self.empty_state.setVisible(not has_clients)
        for r in range(self.table.rowCount()):
            for c in range(self.table.columnCount()):
                w = self.table.cellWidget(r, c)
                if w is not None:
                    self.table.removeCellWidget(r, c)
                    w.hide()
                    w.setParent(None)
                    w.deleteLater()
        self.table.setRowCount(0)
        self.table.setRowCount(len(clients))
        for idx, entry in enumerate(clients):
            approved = entry["approved_at"]
            when = (
                datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M")
                if approved else "—"
            )
            name = QTableWidgetItem(entry["client_name"])
            client_id = entry["client_id"]
            name.setData(Qt.ItemDataRole.UserRole, client_id)
            name.setToolTip("ID: " + client_id)
            self.table.setItem(idx, 0, name)
            self.table.setItem(
                idx, 1, QTableWidgetItem("Разрешён" if approved else "Зарегистрирован")
            )
            self.table.setItem(idx, 2, QTableWidgetItem(""))
            if approved:
                selector = TableCellCombo()
                selector.addItem("Безопасный", "safe")
                selector.addItem("Белый список", "allowlist")
                selector.addItem("Полный доступ", "full")
                selector.setToolTip(
                    "Индивидуальные права OAuth-клиента. "
                    "Белый список настраивается на главной странице."
                )
                mode = self.execution.profile_for(client_id)
                selector.setCurrentIndex(max(selector.findData(mode), 0))
                selector.currentIndexChanged.connect(
                    lambda _index, cid=client_id, combo=selector:
                        self._change_client_profile(cid, combo)
                )
                self.table.setCellWidget(idx, 2, selector)
            else:
                self.table.setItem(idx, 2, QTableWidgetItem("Нет доступа"))
            self.table.setItem(idx, 3, QTableWidgetItem(when))
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(0, min(260, max(140, self.table.columnWidth(0))))
        col2_w = max(210, self.table.fontMetrics().horizontalAdvance("Полный доступ") + 64)
        self.table.setColumnWidth(2, col2_w)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._selection_changed()

    def _change_client_profile(self, client_id: str, combo: TableCellCombo) -> None:
        try:
            previous = self.execution.profile_for(client_id)
            selected = combo.currentData()
            if selected == previous:
                return
            if selected == "full":
                answer = SilentMessageBox.warning(
                    self,
                    "Полный доступ для OAuth-клиента",
                    "Вы даёте выбранному клиенту возможность сразу выполнять "
                    "произвольные Windows-команды и SSH-команды без "
                    "подтверждения каждого запуска. Это высокий риск: "
                    "действия выполняются с правами пользователя Windows "
                    "или SSH-учётной записи.\n\nПродолжить?",
                    SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                    SilentMessageBox.StandardButton.No,
                )
                if answer != SilentMessageBox.StandardButton.Yes:
                    combo.blockSignals(True)
                    combo.setCurrentIndex(combo.findData(previous))
                    combo.blockSignals(False)
                    return
            self.execution.set_client_profile(client_id, selected)
        except (ValueError, OSError, RuntimeError) as exc:
            combo.blockSignals(True)
            combo.setCurrentIndex(max(combo.findData(self.execution.profile_for(client_id)), 0))
            combo.blockSignals(False)
            SilentMessageBox.warning(
                self, "Права OAuth-клиента",
                f"Не удалось сохранить сценарий доступа: {type(exc).__name__}"
            )

    def _selection_changed(self) -> None:
        self.revoke_button.setEnabled(
            self.table.currentRow() >= 0 and self.table.item(self.table.currentRow(), 0) is not None
        )

    def revoke_selected(self) -> None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        client_id = item.data(Qt.ItemDataRole.UserRole)
        if SilentMessageBox.question(
            self, "Отозвать OAuth-доступ?",
            f"Удалить регистрацию «{item.text()}» и все её OAuth-токены?\n"
            "Для повторного подключения потребуется новая авторизация.",
            SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            SilentMessageBox.StandardButton.No,
        ) != SilentMessageBox.StandardButton.Yes:
            return
        try:
            self.store.revoke_client(client_id)
        except Exception as exc:
            SilentMessageBox.warning(
                self, "OAuth", f"Не удалось отозвать доступ: {type(exc).__name__}"
            )
            return
        self.reload()
