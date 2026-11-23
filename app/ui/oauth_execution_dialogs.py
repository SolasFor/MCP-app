"""Local-only dialogs for OAuth Windows/SSH allowlists and one-use approvals.

Never exposed over Cloudflare or MCP tools. The owner reads exact command,
remote host/user/port and requesting OAuth client before approving.
"""
from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout,
    QLabel, QMessageBox, QPlainTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from backend.oauth_execution import ExecutionApprovals


class ExecutionPolicyDialog(QDialog):
    def __init__(self, approvals: ExecutionApprovals, parent: QWidget | None = None):
        super().__init__(parent)
        self.approvals = approvals
        self.setWindowTitle("Разрешённые Windows и SSH-команды")
        self.resize(660, 570)
        root = QVBoxLayout(self)
        warning = QLabel(
            "ВНИМАНИЕ: Windows и SSH выполняют настоящие команды на вашем компьютере "
            "или удалённом сервере. Указывайте только доверенные, ТОЧНО совпадающие "
            "команды. Даже после выдачи разрешений каждый вызов требует вашего "
            "отдельного одобрения, действующего только один раз."
        )
        warning.setWordWrap(True)
        root.addWidget(warning)
        policy = approvals.policy()
        self.windows = QPlainTextEdit("\n".join(policy["windows"]))
        self.windows.setPlaceholderText("Например:\nwhoami.exe\nhostname.exe")
        self.hosts = QPlainTextEdit("\n".join(policy["hosts"]))
        self.hosts.setPlaceholderText("SSH-хосты или алиасы, по одному в строке")
        self.ssh_commands = QPlainTextEdit("\n".join(policy["ssh_commands"]))
        self.ssh_commands.setPlaceholderText("Точные удалённые команды:\nuptime\nhostname")
        for label, widget in (
            ("Windows: точные команды с аргументами (по строкам)", self.windows),
            ("SSH: точные разрешённые имена хостов/алиасы", self.hosts),
            ("SSH: точные команды (по строкам)", self.ssh_commands),
        ):
            root.addWidget(QLabel(label))
            root.addWidget(widget)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def save(self) -> None:
        try:
            self.approvals.set_policy(
                windows=self.windows.toPlainText(),
                hosts=self.hosts.toPlainText(),
                ssh_commands=self.ssh_commands.toPlainText(),
            )
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Разрешённые команды",
                                f"Некорректный список: {exc}")
            return
        self.accept()


class ExecutionQueueDialog(QDialog):
    def __init__(self, approvals: ExecutionApprovals, parent: QWidget | None = None):
        super().__init__(parent)
        self.approvals = approvals
        self.setWindowTitle("Подтверждение команд OAuth")
        self.resize(810, 480)
        root = QVBoxLayout(self)
        note = QLabel(
            "Запросы действуют 3 минуты и могут быть использованы только один раз. "
            "Убедитесь, что доверяете OAuth-клиенту, команде и SSH-хосту. "
            "Если сомневаетесь — отклоните. Не разрешайте действия, которые вы "
            "сами не собирались запускать."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Клиент", "Тип", "Цель", "Команда", "Состояние"]
        )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить")
        self.refresh_button.clicked.connect(self.reload)
        self.approve_button = QPushButton("Просмотреть и разрешить")
        self.approve_button.clicked.connect(self.approve_selected)
        self.deny_button = QPushButton("Отклонить")
        self.deny_button.clicked.connect(self.deny_selected)
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(self.accept)
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.approve_button)
        buttons.addWidget(self.deny_button)
        buttons.addStretch(1)
        buttons.addWidget(close_button)
        root.addLayout(buttons)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self._requests: dict[str, dict] = {}
        self.reload()

    def reload(self):
        items = self.approvals.pending()
        self._requests = {item["ticket_hash"]: item for item in items}
        self.table.setRowCount(len(items))
        for index, item in enumerate(items):
            client = self.approvals.store.get_client(item["client_id"])
            client_name = (client.client_name if client else None) or item["client_id"]
            fields = (
                client_name, "Windows" if item["kind"] == "windows" else "SSH",
                f'{item["user"] + "@" if item["user"] else ""}{item["host"]}:{item["port"]}'
                if item["kind"] == "ssh" else "Этот компьютер",
                item["command"],
                "Одобрено — ожидает повторного вызова" if item["approved"] else "Ожидает решения",
            )
            for col, value in enumerate(fields):
                cell = QTableWidgetItem(value)
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item["ticket_hash"])
                cell.setToolTip(value)
                self.table.setItem(index, col, cell)
        self.table.resizeColumnsToContents()
        self._update_buttons()

    def _selected(self) -> dict | None:
        row = self.table.currentRow()
        cell = self.table.item(row, 0) if row >= 0 else None
        if cell is None:
            return None
        return self._requests.get(cell.data(Qt.ItemDataRole.UserRole))

    def _update_buttons(self):
        item = self._selected()
        self.approve_button.setEnabled(item is not None and not item["approved"])
        self.deny_button.setEnabled(item is not None)

    def _confirm_exact(self, item: dict) -> bool:
        dialog = QDialog(self)
        dialog.setWindowTitle("Точное подтверждение команды")
        dialog.resize(660, 350)
        layout = QVBoxLayout(dialog)
        client = self.approvals.store.get_client(item["client_id"])
        name = (client.client_name if client else "") or item["client_id"]
        info = QLabel(
            f"OAuth-клиент: {name}\n"
            f"Тип: {item['kind']}\n"
            f"Цель: {item['user'] + '@' if item['user'] else ''}{item['host']} "
            f"(порт {item['port']})\n"
            "Вы подтверждаете ОДИН запуск ровно этой команды:"
        )
        info.setWordWrap(True)
        layout.addWidget(info)
        command_view = QPlainTextEdit(item["command"])
        command_view.setReadOnly(True)
        layout.addWidget(command_view)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes |
            QDialogButtonBox.StandardButton.Cancel
        )
        yes = buttons.button(QDialogButtonBox.StandardButton.Yes)
        yes.setText("Разрешить ОДИН раз")
        yes.setAutoDefault(False)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        return dialog.exec() == QDialog.DialogCode.Accepted

    def approve_selected(self):
        item = self._selected()
        if item is None or item["approved"]:
            return
        if not self._confirm_exact(item):
            return
        if not self.approvals.decision(item["ticket_hash"], approve=True):
            QMessageBox.warning(self, "Подтверждение", "Запрос истёк или права были изменены.")
        self.reload()

    def deny_selected(self):
        item = self._selected()
        if item is None:
            return
        self.approvals.decision(item["ticket_hash"], approve=False)
        self.reload()
