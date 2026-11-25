"""Local-only allowlist editor for OAuth Windows/SSH execution scenarios.

There is no per-action approval queue. The settings are protected by the
Windows user's encrypted OAuth database and not exposed through Cloudflare.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
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
        self.setMinimumSize(520, 480)
        self.resize(620, 540)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)
        warning = QLabel(
            "Режим «Белый список»: команды выполняются БЕЗ дополнительного "
            "подтверждения, но только при точном совпадении с этими строками. "
            "Режим «Полный доступ» игнорирует эти списки. "
            "Списки сохраняются локально и не предоставляются клиенту для изменения."
        )
        warning.setObjectName("Hint")
        warning.setWordWrap(True)
        root.addWidget(warning)
        policy = approvals.policy()
        self.windows = QPlainTextEdit("\n".join(policy["windows"]))
        self.windows.setObjectName("ConsoleLog")
        self.windows.setPlaceholderText("\n".join(DEFAULT_WINDOWS_ALLOWLIST))
        self.hosts = QPlainTextEdit("\n".join(policy["hosts"]))
        self.hosts.setObjectName("ConsoleLog")
        self.hosts.setPlaceholderText("SSH-хосты или алиасы, по одному в строке")
        self.ssh_commands = QPlainTextEdit("\n".join(policy["ssh_commands"]))
        self.ssh_commands.setObjectName("ConsoleLog")
        self.ssh_commands.setPlaceholderText("Точные удалённые команды:\nuptime\nhostname")
        win_lbl = QLabel("Windows: точные команды, по одной в строке")
        win_lbl.setObjectName("FieldLabel")
        root.addWidget(win_lbl)
        root.addWidget(self.windows, 1)
        reset_row = QHBoxLayout()
        self.reset_windows = QPushButton("Восстановить базовые команды")
        self.reset_windows.setObjectName("Ghost")
        self.reset_windows.setCursor(Qt.CursorShape.PointingHandCursor)
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
            lbl = QLabel(label)
            lbl.setObjectName("FieldLabel")
            root.addWidget(lbl)
            root.addWidget(widget, 1)
        footer = QHBoxLayout()
        footer.setSpacing(6)
        footer.addStretch(1)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.setObjectName("Ghost")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Сохранить")
        save_btn.setObjectName("Accent")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.setDefault(True)
        save_btn.clicked.connect(self.save)
        footer.addWidget(cancel_btn)
        footer.addWidget(save_btn)
        root.addLayout(footer)

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


