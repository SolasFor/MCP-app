"""Local-only allowlist editor for OAuth Windows/SSH execution scenarios.

There is no per-action approval queue. The settings are protected by the
Windows user's encrypted OAuth database and not exposed through Cloudflare.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from backend.oauth_execution import ExecutionApprovals, DEFAULT_WINDOWS_ALLOWLIST


class ExecutionPolicyDialog(SilentDialog):
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
        self.windows.setPlaceholderText("\n".join(DEFAULT_WINDOWS_ALLOWLIST))
        self.hosts = QPlainTextEdit("\n".join(policy["hosts"]))
        self.hosts.setPlaceholderText("SSH-хосты или алиасы, по одному в строке")
        self.ssh_commands = QPlainTextEdit("\n".join(policy["ssh_commands"]))
        self.ssh_commands.setPlaceholderText("Точные удалённые команды:\nuptime\nhostname")
        root.addWidget(QLabel("Windows: точные команды, по одной в строке"))
        root.addWidget(self.windows)
        reset_row = QHBoxLayout()
        self.reset_windows = QPushButton("Восстановить базовые команды")
        self.reset_windows.setToolTip(
            "ls, pwd, dir, echo, whoami, ipconfig, systeminfo. "
            "Изменение сохранится только после нажатия «Сохранить»."
        )
        self.reset_windows.clicked.connect(
            lambda: self.windows.setPlainText("\n".join(DEFAULT_WINDOWS_ALLOWLIST))
        )
        reset_row.addWidget(self.reset_windows)
        reset_row.addStretch(1)
        root.addLayout(reset_row)
        for label, widget in (
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
            SilentMessageBox.warning(
                self, "Разрешённые команды", f"Некорректный список: {exc}"
            )
            return
        self.accept()


