"""Local-only allowlist editor for OAuth Windows/SSH execution scenarios.

There is no per-action approval queue. The settings are protected by the
Windows user's encrypted OAuth database and not exposed through Cloudflare.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.silent_dialog import SilentDialog, SilentMessageBox
from app.ui.i18n import tr
from backend.desktop.models import DesktopPolicyStore
from backend.oauth_execution import DEFAULT_WINDOWS_ALLOWLIST, ExecutionApprovals


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
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Сохранить")
        save_btn.setObjectName("Accent")
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


class ClientPermissionsDialog(SilentDialog):
    """Per-client access scenario, custom Windows/SSH allowlist, Computer Use, and blocked tools editor."""

    def __init__(
        self,
        approvals: ExecutionApprovals,
        client_id: str,
        client_name: str,
        *,
        desktop_store: DesktopPolicyStore | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.approvals = approvals
        self.client_id = client_id
        self.client_name = client_name or client_id
        self.desktop_store = desktop_store

        self.setWindowTitle(tr("clients.perms.title", name=self.client_name))
        self.setMinimumSize(540, 520)
        self.resize(620, 580)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(8)

        lead = QLabel(tr("clients.perms.lead", client_id=self.client_id))
        lead.setObjectName("Hint")
        lead.setWordWrap(True)
        root.addWidget(lead)

        # 1. Scenario selector (inherit global vs explicit override)
        scen_lbl = QLabel(tr("clients.perms.scenario"))
        scen_lbl.setObjectName("FieldLabel")
        root.addWidget(scen_lbl)
        self.scenario_combo = SafeComboBox()
        self.scenario_combo.addItem(
            tr("clients.perms.inherit_default", role=tr(f"clients.role.{approvals.profile()}")),
            "inherit",
        )
        for key in ("safe", "allowlist", "full"):
            self.scenario_combo.addItem(tr(f"clients.role.{key}"), key)
        explicit_profiles = approvals.client_profiles()
        initial_scen = explicit_profiles.get(client_id, "inherit")
        self.scenario_combo.setCurrentIndex(max(self.scenario_combo.findData(initial_scen), 0))
        root.addWidget(self.scenario_combo)

        # 2. Per-client Computer Use mode
        dt_lbl = QLabel(tr("clients.perms.desktop"))
        dt_lbl.setObjectName("FieldLabel")
        root.addWidget(dt_lbl)
        self.desktop_combo = SafeComboBox()
        for mode_key in ("inherit", "disabled", "view", "control"):
            self.desktop_combo.addItem(tr(f"clients.perms.desktop.{mode_key}"), mode_key)
        current_dt = "inherit"
        if self.desktop_store is not None:
            try:
                current_dt = self.desktop_store.load().client_overrides.get(client_id, "inherit")
            except Exception:  # noqa: BLE001
                current_dt = "inherit"
        else:
            self.desktop_combo.setEnabled(False)
        self.desktop_combo.setCurrentIndex(max(self.desktop_combo.findData(current_dt), 0))
        root.addWidget(self.desktop_combo)

        # 3. Custom per-client Windows / SSH allowlist
        custom_al = approvals.client_allowlist(client_id)
        base_pol = approvals.policy()
        self.use_custom_allowlist = QCheckBox(tr("clients.perms.custom_allowlist"))
        self.use_custom_allowlist.setChecked(custom_al is not None)
        root.addWidget(self.use_custom_allowlist)

        al_src = custom_al if custom_al is not None else base_pol
        self.windows_edit = QPlainTextEdit("\n".join(al_src["windows"]))
        self.windows_edit.setObjectName("ConsoleLog")
        self.windows_edit.setMaximumHeight(82)
        self.windows_edit.setPlaceholderText("\n".join(DEFAULT_WINDOWS_ALLOWLIST))

        self.hosts_edit = QPlainTextEdit("\n".join(al_src["hosts"]))
        self.hosts_edit.setObjectName("ConsoleLog")
        self.hosts_edit.setMaximumHeight(56)
        self.hosts_edit.setPlaceholderText("SSH host / alias")

        self.ssh_edit = QPlainTextEdit("\n".join(al_src["ssh_commands"]))
        self.ssh_edit.setObjectName("ConsoleLog")
        self.ssh_edit.setMaximumHeight(56)
        self.ssh_edit.setPlaceholderText("uptime\nhostname")

        for w in (self.windows_edit, self.hosts_edit, self.ssh_edit):
            w.setEnabled(self.use_custom_allowlist.isChecked())
        self.use_custom_allowlist.toggled.connect(self._toggle_allowlist_fields)

        win_lbl = QLabel(tr("clients.perms.win_cmds"))
        win_lbl.setObjectName("FieldLabel")
        root.addWidget(win_lbl)
        root.addWidget(self.windows_edit)

        ssh_row = QHBoxLayout()
        ssh_row.setSpacing(8)
        hosts_col = QVBoxLayout()
        h_lbl = QLabel(tr("clients.perms.ssh_hosts"))
        h_lbl.setObjectName("FieldLabel")
        hosts_col.addWidget(h_lbl)
        hosts_col.addWidget(self.hosts_edit)
        cmds_col = QVBoxLayout()
        c_lbl = QLabel(tr("clients.perms.ssh_cmds"))
        c_lbl.setObjectName("FieldLabel")
        cmds_col.addWidget(c_lbl)
        cmds_col.addWidget(self.ssh_edit)
        ssh_row.addLayout(hosts_col, 1)
        ssh_row.addLayout(cmds_col, 1)
        root.addLayout(ssh_row)

        # 4. Per-client denied MCP tools
        tool_pol = approvals.client_tool_policy(client_id)
        denied_lbl = QLabel(tr("clients.perms.denied_tools"))
        denied_lbl.setObjectName("FieldLabel")
        root.addWidget(denied_lbl)
        self.denied_tools_edit = QPlainTextEdit("\n".join(tool_pol.get("denied_tools", ())))
        self.denied_tools_edit.setObjectName("ConsoleLog")
        self.denied_tools_edit.setMaximumHeight(68)
        self.denied_tools_edit.setPlaceholderText("workspace_delete_file, git_commit")
        root.addWidget(self.denied_tools_edit)

        footer = QHBoxLayout()
        footer.setSpacing(6)
        footer.addStretch(1)
        cancel_btn = QPushButton(tr("common.cancel"))
        cancel_btn.setObjectName("Ghost")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton(tr("common.save"))
        save_btn.setObjectName("Accent")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self.save)
        footer.addWidget(cancel_btn)
        footer.addWidget(save_btn)
        root.addLayout(footer)

    def _toggle_allowlist_fields(self, checked: bool) -> None:
        for w in (self.windows_edit, self.hosts_edit, self.ssh_edit):
            w.setEnabled(checked)

    def save(self) -> None:
        selected_scen = str(self.scenario_combo.currentData() or "inherit")
        prev_explicit = self.approvals.client_profiles().get(self.client_id, "inherit")
        if selected_scen == "full" and prev_explicit != "full":
            answer = SilentMessageBox.warning(
                self,
                tr("clients.role.full"),
                tr("home.access.hint.full"),
                SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
                SilentMessageBox.StandardButton.No,
            )
            if answer != SilentMessageBox.StandardButton.Yes:
                return

        try:
            if selected_scen == "inherit":
                self.approvals.clear_client_profile(self.client_id)
            else:
                self.approvals.set_client_profile(self.client_id, selected_scen)

            if self.use_custom_allowlist.isChecked():
                self.approvals.set_client_allowlist(
                    self.client_id,
                    windows=self.windows_edit.toPlainText(),
                    hosts=self.hosts_edit.toPlainText(),
                    ssh_commands=self.ssh_edit.toPlainText(),
                )
            else:
                self.approvals.clear_client_allowlist(self.client_id)

            raw_denied = self.denied_tools_edit.toPlainText().strip()
            self.approvals.set_client_tool_policy(
                self.client_id,
                denied_tools=[raw_denied] if raw_denied else [],
            )

            if self.desktop_store is not None:
                dt_mode = str(self.desktop_combo.currentData() or "inherit")
                self.desktop_store.set_client_override(self.client_id, dt_mode)
        except (ValueError, OSError, RuntimeError) as exc:
            SilentMessageBox.warning(self, tr("clients.title"), str(exc))
            return
        self.accept()


