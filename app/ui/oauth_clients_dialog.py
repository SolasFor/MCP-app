"""Local-only OAuth client management dialog.

Reads the same encrypted SQLite store as the backend. No public admin routes
are added to the Cloudflare tunnel. Revocation is effective immediately
because backend token validation always consults the database.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QHBoxLayout, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from backend.oauth_store import OAuthStore, default_store_path
from backend.shared_notes import SharedNotes, default_notes_dir


class OAuthClientsDialog(QDialog):
    def __init__(self, public_url: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from urllib.parse import urlsplit
        parts = urlsplit(public_url)
        issuer = f"{parts.scheme}://{parts.netloc}"
        if parts.scheme not in ("http", "https") or not parts.netloc or not public_url:
            raise ValueError("Server URL is required to manage OAuth connections")

        self.store = OAuthStore(default_store_path(), issuer, public_url)
        self._clients: dict[str, dict] = {}
        self._updating_checks = False
        self.setWindowTitle("OAuth-клиенты MCP app")
        self.setMinimumSize(670, 410)
        self.resize(760, 460)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)
        title = QLabel("Подключённые OAuth-клиенты")
        title.setObjectName("SectionTitle")
        root.addWidget(title)
        note = QLabel(
            "Здесь видны только регистрации для текущего публичного адреса. "
            "Отзыв удаляет клиент и все его OAuth-токены сразу, без перезапуска сервера. "
            "Общий токен владельца здесь не показывается и не изменяется."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Клиент", "Доступ", "Последнее разрешение"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        root.addWidget(self.table, 1)

        permissions = QHBoxLayout()
        self.read_notes_check = QCheckBox("Чтение общих заметок")
        self.write_notes_check = QCheckBox("Запись общих заметок")
        self.read_notes_check.toggled.connect(self._save_permissions)
        self.write_notes_check.toggled.connect(self._save_permissions)
        permissions.addWidget(self.read_notes_check)
        permissions.addWidget(self.write_notes_check)
        permissions.addStretch(1)
        root.addLayout(permissions)
        help_text = QLabel(
            "Разрешения действуют отдельно для каждого OAuth-клиента и только "
            "после вашего подтверждения его подключения. По умолчанию оба выключены. "
            "Заметки: только небольшие .md/.txt файлы в отдельной папке."
        )
        help_text.setWordWrap(True)
        root.addWidget(help_text)

        footer = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.clicked.connect(self.reload)
        self.notes_button = QPushButton("Открыть папку заметок")
        self.notes_button.clicked.connect(self._open_notes_folder)
        self.revoke_button = QPushButton("Отозвать доступ")
        self.revoke_button.setEnabled(False)
        self.revoke_button.clicked.connect(self.revoke_selected)
        self.close_button = QPushButton("Закрыть")
        self.close_button.clicked.connect(self.accept)
        footer.addWidget(self.refresh_button)
        footer.addWidget(self.notes_button)
        footer.addWidget(self.revoke_button)
        footer.addStretch(1)
        footer.addWidget(self.close_button)
        root.addLayout(footer)
        self.reload()

    def reload(self) -> None:
        try:
            clients = self.store.list_clients()
        except Exception as exc:
            QMessageBox.warning(self, "OAuth", f"Не удалось прочитать хранилище: {type(exc).__name__}")
            return
        self._clients = {entry["client_id"]: entry for entry in clients}
        self.table.setRowCount(len(clients))
        for index, item in enumerate(clients):
            approved = item["approved_at"]
            when = datetime.fromtimestamp(approved).strftime("%d.%m.%Y %H:%M") if approved else "—"
            name = QTableWidgetItem(item["client_name"])
            name.setData(Qt.ItemDataRole.UserRole, item["client_id"])
            name.setToolTip("ID: " + item["client_id"])
            self.table.setItem(index, 0, name)
            self.table.setItem(index, 1, QTableWidgetItem("Разрешён" if approved else "Зарегистрирован"))
            self.table.setItem(index, 2, QTableWidgetItem(when))
        self.table.resizeColumnsToContents()
        self._selection_changed()

    def _selection_changed(self) -> None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        client = self._clients.get(item.data(Qt.ItemDataRole.UserRole), {}) if item else {}
        enabled = bool(client.get("approved_at"))
        self.revoke_button.setEnabled(bool(item))
        self._updating_checks = True
        try:
            self.read_notes_check.setChecked(bool(client.get("can_read_notes")))
            self.write_notes_check.setChecked(bool(client.get("can_write_notes")))
            self.read_notes_check.setEnabled(enabled)
            self.write_notes_check.setEnabled(enabled)
        finally:
            self._updating_checks = False

    def _save_permissions(self, _checked: bool) -> None:
        if self._updating_checks:
            return
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        client_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            self.store.set_note_permissions(
                client_id,
                read=self.read_notes_check.isChecked(),
                write=self.write_notes_check.isChecked(),
            )
            self._clients[client_id]["can_read_notes"] = self.read_notes_check.isChecked()
            self._clients[client_id]["can_write_notes"] = self.write_notes_check.isChecked()
        except (OSError, ValueError, RuntimeError) as exc:
            QMessageBox.warning(
                self, "OAuth", f"Не удалось сохранить разрешения: {type(exc).__name__}"
            )
            self._selection_changed()

    def _open_notes_folder(self) -> None:
        try:
            folder = SharedNotes(default_notes_dir()).directory
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "OAuth", f"Не удалось открыть папку: {type(exc).__name__}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def revoke_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        name = self.table.item(row, 0)
        if name is None:
            return
        client_id = name.data(Qt.ItemDataRole.UserRole)
        if QMessageBox.question(
            self, "Отозвать OAuth-доступ?",
            f"Удалить регистрацию «{name.text()}» и немедленно отозвать её токены?\n"
            "Для повторного подключения потребуется новая авторизация.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.revoke_client(client_id)
        except Exception as exc:
            QMessageBox.warning(self, "OAuth", f"Не удалось отозвать доступ: {type(exc).__name__}")
            return
        self.reload()
