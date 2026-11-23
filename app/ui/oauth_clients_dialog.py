"""Local OAuth client management for one global owner-chosen access mode.

Clients cannot choose or change this global mode. Each is separately OAuth
authorized and can be revoked. No public administrative HTTP endpoint exists.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QDialog, QHBoxLayout, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from backend.oauth_store import OAuthStore, default_store_path
from backend.oauth_execution import ExecutionApprovals
from app.ui.oauth_execution_dialogs import ExecutionPolicyDialog


class OAuthClientsDialog(QDialog):
    def __init__(self, public_url: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        parts = urlsplit(public_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("A valid server URL is required")
        issuer = f"{parts.scheme}://{parts.netloc}"
        self.store = OAuthStore(default_store_path(), issuer, public_url)
        self.execution = ExecutionApprovals(self.store)
        self.setWindowTitle("OAuth-клиенты MCP app")
        self.setMinimumSize(700, 420)
        self.resize(820, 490)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)
        title = QLabel("OAuth-клиенты")
        title.setObjectName("SectionTitle")
        root.addWidget(title)

        explanation = QLabel(
            "Все подтверждённые OAuth-клиенты используют режим доступа, "
            "выбранный владельцем на главной странице. Нет отдельных прав "
            "для каждого клиента. В режимах «Белый список» и «Полный доступ» "
            "команды выполняются сразу, без подтверждения каждого вызова."
        )
        explanation.setWordWrap(True)
        root.addWidget(explanation)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Клиент", "Состояние", "Права", "Дата разрешения"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        root.addWidget(self.table, 1)

        footer = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.clicked.connect(self.reload)
        self.policy_button = QPushButton("Разрешённые команды и хосты…")
        self.policy_button.clicked.connect(self._open_execution_policy)
        self.revoke_button = QPushButton("Отозвать OAuth-доступ")
        self.revoke_button.setEnabled(False)
        self.revoke_button.clicked.connect(self.revoke_selected)
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.accept)
        for btn in (
            self.refresh_button, self.policy_button, self.revoke_button,
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
            QMessageBox.warning(
                self, "OAuth", f"Не удалось прочитать хранилище: {type(exc).__name__}"
            )
            return
        self.table.setRowCount(len(clients))
        mode_name = {
            "safe": "Безопасный (только server_info)",
            "allowlist": "Windows + SSH (белый список)",
            "full": "Полный Windows + SSH",
        }.get(self.execution.profile(), "Безопасный")
        for idx, entry in enumerate(clients):
            approved = entry["approved_at"]
            when = (
                datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M")
                if approved else "—"
            )
            name = QTableWidgetItem(entry["client_name"])
            name.setData(Qt.ItemDataRole.UserRole, entry["client_id"])
            name.setToolTip("ID: " + entry["client_id"])
            items = (
                name,
                QTableWidgetItem("Разрешён" if approved else "Зарегистрирован"),
                QTableWidgetItem(mode_name if approved else "Нет"),
                QTableWidgetItem(when),
            )
            for col, item in enumerate(items):
                self.table.setItem(idx, col, item)
        self.table.resizeColumnsToContents()
        self._selection_changed()

    def _selection_changed(self) -> None:
        self.revoke_button.setEnabled(
            self.table.currentRow() >= 0 and self.table.item(self.table.currentRow(), 0) is not None
        )

    def _open_execution_policy(self) -> None:
        ExecutionPolicyDialog(self.execution, self).exec()

    def revoke_selected(self) -> None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        client_id = item.data(Qt.ItemDataRole.UserRole)
        if QMessageBox.question(
            self, "Отозвать OAuth-доступ?",
            f"Удалить регистрацию «{item.text()}» и все её OAuth-токены?\n"
            "Для повторного подключения потребуется новая авторизация.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.revoke_client(client_id)
        except Exception as exc:
            QMessageBox.warning(
                self, "OAuth", f"Не удалось отозвать доступ: {type(exc).__name__}"
            )
            return
        self.reload()
