"""Local-only allowlist editor for OAuth Windows/SSH execution scenarios.

There is no per-action approval queue. The settings are protected by the
Windows user's encrypted OAuth database and not exposed through Cloudflare.
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
        self.setWindowTitle("Белые списки Windows и SSH")
        self.resize(660, 570)
        root = QVBoxLayout(self)
        warning = QLabel(
            "Режим «Белый список»: команды выполняются БЕЗ дополнительного "
            "подтверждения, но только при точном совпадении с этими строками. "
            "Режим «Полный доступ» игнорирует эти списки. "
            "Списки сохраняются локально и не предоставляются клиенту для изменения."
        )
        warning.setWordWrap(True)
        root.addWidget(warning)
        policy = approvals.policy()
        self.windows = QPlainTextEdit("\n".join(policy["windows"]))
        self.windows.setPlaceholderText("Например:\nwhoami\nipconfig\nsysteminfo\ndir\nls\npwd\necho")
        self.hosts = QPlainTextEdit("\n".join(policy["hosts"]))
        self.hosts.setPlaceholderText("SSH-хосты или алиасы, по одному в строке")
        self.ssh_commands = QPlainTextEdit("\n".join(policy["ssh_commands"]))
        self.ssh_commands.setPlaceholderText("Точные удалённые команды:\nuptime\nhostname")
        for label, widget in (
            ("Windows: точные команды, по одной в строке", self.windows),
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


