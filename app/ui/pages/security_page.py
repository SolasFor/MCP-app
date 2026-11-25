"""Security & Boundaries page: access policy, SecretStore, Computer Use toggle auto-save, emergency stop."""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from app.core.logging_manager import get_logging_manager
from app.paths import user_data_dir
from app.ui.components.cards import Badge, Card, SectionHeader
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.components.toggle_switch import ToggleSwitch
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.desktop.models import DesktopPolicy, DesktopPolicyStore, record_desktop_policy_audit


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class SecurityPage(PageScaffold):
    """Central view of access profiles, DPAPI secret storage, and auto-saved Computer Use toggles."""

    allowlist_requested = pyqtSignal()
    clients_requested = pyqtSignal()
    desktop_policy_changed = pyqtSignal()

    def __init__(
        self,
        *,
        desktop_policy_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(scroll=True, parent=parent)
        self._backend_name = (
            "Windows DPAPI + Credential Manager" if sys.platform == "win32" else "POSIX 0600 Fernet"
        )
        self._active_mode = "allowlist"
        self._loading_desktop = False
        self._desktop_store = DesktopPolicyStore(
            desktop_policy_path or (user_data_dir() / "desktop" / "policy.json")
        )

        # --- Policy Card
        policy_card = Card()
        self.policy_header = SectionHeader()
        self.mode_badge = Badge("safe", variant="ok")
        self.policy_header.right_box.addWidget(self.mode_badge)
        policy_card.body.addWidget(self.policy_header)

        p_row = QHBoxLayout()
        p_row.setSpacing(8)
        self.allowlist_btn = _button("")
        self.allowlist_btn.clicked.connect(self.allowlist_requested.emit)
        self.clients_btn = _button("", "Accent")
        self.clients_btn.clicked.connect(self.clients_requested.emit)
        p_row.addWidget(self.allowlist_btn)
        p_row.addWidget(self.clients_btn)
        p_row.addStretch(1)
        policy_card.body.addLayout(p_row)
        self.content.addWidget(policy_card)

        # --- Computer Use Opt-In Card (ToggleSwitch + immediate auto-save, default OFF)
        desktop_card = Card()
        self.desktop_header = SectionHeader()
        self.desktop_badge = Badge("", variant="ok")
        self.desktop_header.right_box.addWidget(self.desktop_badge)
        desktop_card.body.addWidget(self.desktop_header)

        self.desktop_enabled_sw = ToggleSwitch()
        self.desktop_screen_sw = ToggleSwitch()
        self.desktop_control_sw = ToggleSwitch()
        self.desktop_secrets_sw = ToggleSwitch()
        # Backwards-compatible aliases (QAbstractButton API: isChecked/setChecked/toggled)
        self.desktop_enabled_chk = self.desktop_enabled_sw
        self.desktop_screen_chk = self.desktop_screen_sw
        self.desktop_control_chk = self.desktop_control_sw
        self.desktop_secrets_chk = self.desktop_secrets_sw

        for sw in (
            self.desktop_enabled_sw,
            self.desktop_screen_sw,
            self.desktop_control_sw,
            self.desktop_secrets_sw,
        ):
            sw.toggled.connect(self._on_desktop_control_changed)
            desktop_card.body.addWidget(sw)

        d_form = QFormLayout()
        d_form.setSpacing(6)
        self.desktop_clients_edit = QLineEdit()
        self.desktop_clients_edit.setObjectName("UiInput")
        self.desktop_clients_edit.editingFinished.connect(self._on_desktop_control_changed)
        self.desktop_apps_edit = QLineEdit()
        self.desktop_apps_edit.setObjectName("UiInput")
        self.desktop_apps_edit.editingFinished.connect(self._on_desktop_control_changed)
        d_form.addRow(QLabel(), self.desktop_clients_edit)
        d_form.addRow(QLabel(), self.desktop_apps_edit)
        self._desktop_clients_lbl = d_form.labelForField(self.desktop_clients_edit)
        self._desktop_apps_lbl = d_form.labelForField(self.desktop_apps_edit)
        desktop_card.body.addLayout(d_form)

        d_row = QHBoxLayout()
        d_row.setSpacing(8)
        self.desktop_stop_btn = _button("", "Danger")
        self.desktop_stop_btn.clicked.connect(self.stop_computer_use)
        self.desktop_clear_stop_btn = _button("", "Secondary")
        self.desktop_clear_stop_btn.clicked.connect(self.clear_emergency_stop)
        self.desktop_clear_stop_btn.hide()
        d_row.addWidget(self.desktop_stop_btn)
        d_row.addWidget(self.desktop_clear_stop_btn)
        d_row.addStretch(1)
        desktop_card.body.addLayout(d_row)

        self.desktop_refresh_hint = QLabel()
        self.desktop_refresh_hint.setObjectName("Hint")
        self.desktop_refresh_hint.setWordWrap(True)
        desktop_card.body.addWidget(self.desktop_refresh_hint)
        self.content.addWidget(desktop_card)

        # --- Secret Storage & Honest Sandbox Notice Card
        secret_card = Card()
        self.secret_header = SectionHeader()
        secret_card.body.addWidget(self.secret_header)
        self.secret_desc = QLabel()
        self.secret_desc.setObjectName("Hint")
        self.secret_desc.setWordWrap(True)
        secret_card.body.addWidget(self.secret_desc)
        self.content.addWidget(secret_card)

        self.content.addStretch(1)
        self.reload_desktop_policy()
        self.retranslate()

    def reload_desktop_policy(self) -> DesktopPolicy:
        pol = self._desktop_store.load()
        self._loading_desktop = True
        widgets = (
            self.desktop_enabled_sw,
            self.desktop_screen_sw,
            self.desktop_control_sw,
            self.desktop_secrets_sw,
            self.desktop_clients_edit,
            self.desktop_apps_edit,
        )
        for w in widgets:
            w.blockSignals(True)
        try:
            self.desktop_enabled_sw.setChecked(pol.enabled)
            self.desktop_screen_sw.setChecked(pol.allow_screen_capture)
            self.desktop_control_sw.setChecked(pol.allow_input_control)
            self.desktop_secrets_sw.setChecked(pol.allow_secret_typing)
            self.desktop_clients_edit.setText(", ".join(pol.allowed_clients))
            self.desktop_apps_edit.setText(", ".join(pol.allowed_apps))
        finally:
            for w in widgets:
                w.blockSignals(False)
            self._loading_desktop = False
        self._refresh_desktop_badge(pol)
        return pol

    def _refresh_desktop_badge(self, pol: DesktopPolicy) -> None:
        self.desktop_clear_stop_btn.setVisible(pol.emergency_stop)
        if pol.emergency_stop:
            self.desktop_badge.setText(tr("security.desktop.status.stopped"))
            self.desktop_badge.set_variant("err")
        elif not pol.enabled:
            self.desktop_badge.setText(tr("security.desktop.status.off"))
            self.desktop_badge.set_variant("ok")
        elif pol.allow_input_control:
            self.desktop_badge.setText(tr("security.desktop.status.control"))
            self.desktop_badge.set_variant("err")
        elif pol.allow_screen_capture:
            self.desktop_badge.setText(tr("security.desktop.status.view"))
            self.desktop_badge.set_variant("warn")
        else:
            self.desktop_badge.setText(tr("security.desktop.status.off"))
            self.desktop_badge.set_variant("ok")

    def _on_desktop_control_changed(self, *_args: object) -> None:
        if self._loading_desktop:
            return
        self.save_desktop_policy()

    def save_desktop_policy(self) -> None:
        clients = tuple(dict.fromkeys(c.strip() for c in self.desktop_clients_edit.text().split(",") if c.strip()))
        apps = tuple(dict.fromkeys(a.strip() for a in self.desktop_apps_edit.text().split(",") if a.strip()))
        try:
            prev = self._desktop_store.load()
            pol = self._desktop_store.update(
                enabled=self.desktop_enabled_sw.isChecked(),
                allow_screen_capture=self.desktop_screen_sw.isChecked(),
                allow_input_control=self.desktop_control_sw.isChecked(),
                allow_secret_typing=self.desktop_secrets_sw.isChecked(),
                allowed_clients=clients,
                allowed_apps=apps,
            )
            record_desktop_policy_audit(
                self._desktop_store.path.with_name("desktop_policy_audit.jsonl"),
                prev,
                pol,
                actor="owner",
            )
            get_logging_manager().info(
                "computer_use",
                f"Computer Use policy updated live: enabled={pol.enabled} screen={pol.allow_screen_capture} "
                f"control={pol.allow_input_control} secrets={pol.allow_secret_typing} "
                f"clients={len(pol.allowed_clients)} apps={len(pol.allowed_apps)}",
                event_code="computer_use_policy_updated",
            )
        except Exception as exc:  # noqa: BLE001
            self.reload_desktop_policy()
            SilentMessageBox.warning(self, tr("security.desktop.title"), str(exc))
            return
        self._refresh_desktop_badge(pol)
        self.desktop_policy_changed.emit()

    def stop_computer_use(self) -> None:
        prev = self._desktop_store.load()
        pol = self._desktop_store.set_emergency_stop(True, "Owner stopped Computer Use")
        record_desktop_policy_audit(
            self._desktop_store.path.with_name("desktop_policy_audit.jsonl"),
            prev,
            pol,
            actor="owner",
        )
        get_logging_manager().warning(
            "computer_use",
            "Computer Use emergency stop activated by owner",
            event_code="computer_use_emergency_stop",
        )
        self.reload_desktop_policy()
        self._refresh_desktop_badge(pol)
        self.desktop_policy_changed.emit()

    def clear_emergency_stop(self) -> None:
        prev = self._desktop_store.load()
        pol = self._desktop_store.set_emergency_stop(False, "Owner cleared Computer Use emergency stop")
        record_desktop_policy_audit(
            self._desktop_store.path.with_name("desktop_policy_audit.jsonl"),
            prev,
            pol,
            actor="owner",
        )
        get_logging_manager().info(
            "computer_use",
            "Computer Use emergency stop cleared by owner",
            event_code="computer_use_emergency_cleared",
        )
        self.reload_desktop_policy()
        self._refresh_desktop_badge(pol)
        self.desktop_policy_changed.emit()

    def set_access_mode(self, mode: str) -> None:
        self._active_mode = mode if mode in ("safe", "allowlist", "full") else "safe"
        variant = {"safe": "ok", "allowlist": "warn", "full": "err"}[self._active_mode]
        self.mode_badge.setText(tr(f"clients.role.{self._active_mode}"))
        self.mode_badge.set_variant(variant)

    def retranslate(self) -> None:
        self.set_header(tr("security.title"), tr("security.lead"))
        self.policy_header.set_texts(tr("security.policy.title"), tr("home.access.desc"))
        self.set_access_mode(self._active_mode)
        self.allowlist_btn.setText(tr("home.access.allowlist_btn"))
        self.clients_btn.setText(tr("home.access.clients_btn"))

        self.desktop_header.set_texts(tr("security.desktop.title"), tr("security.desktop.desc"))
        self.desktop_enabled_sw.setText(tr("security.desktop.enabled"))
        self.desktop_screen_sw.setText(tr("security.desktop.screen"))
        self.desktop_control_sw.setText(tr("security.desktop.control"))
        self.desktop_secrets_sw.setText(tr("security.desktop.secrets"))
        if isinstance(self._desktop_clients_lbl, QLabel):
            self._desktop_clients_lbl.setText(tr("security.desktop.clients"))
        if isinstance(self._desktop_apps_lbl, QLabel):
            self._desktop_apps_lbl.setText(tr("security.desktop.apps"))
        self.desktop_stop_btn.setText(tr("security.desktop.stop"))
        self.desktop_clear_stop_btn.setText(tr("security.desktop.clear_stop"))
        self.desktop_refresh_hint.setText(tr("security.desktop.autosave_hint"))

        self.secret_header.set_texts(tr("security.secrets.title"), "")
        self.secret_desc.setText(tr("security.secrets.desc", backend=self._backend_name))

    def apply_theme(self) -> None:
        for sw in (
            self.desktop_enabled_sw,
            self.desktop_screen_sw,
            self.desktop_control_sw,
            self.desktop_secrets_sw,
        ):
            sw.apply_theme()
        self.set_access_mode(self._active_mode)
        self._refresh_desktop_badge(self._desktop_store.load())
