"""Security & Boundaries page: flat hairline sections for access profiles, Computer Use, DPAPI."""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.core.logging_manager import get_logging_manager
from app.paths import user_data_dir
from app.ui.components.cards import Badge, Divider, FlowLayout, Section
from app.ui.components.safe_combo import SafeComboBox
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

    access_profile_changed = pyqtSignal(int)
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

        # --- Section 1: Execution Access Policy
        self.policy_section = Section(spacing=8)
        self.policy_header = self.policy_section.header
        self.mode_badge = Badge("safe", variant="ok")
        self.policy_header.right_box.addWidget(self.mode_badge)

        self.access_label = QLabel()
        self.access_label.setObjectName("FieldLabel")
        self.policy_section.body.addWidget(self.access_label)

        self.access_profile = SafeComboBox()
        self.access_profile.addItem("", "safe")
        self.access_profile.addItem("", "allowlist")
        self.access_profile.addItem("", "full")
        self.access_profile.setCurrentIndex(1)
        self.access_profile.currentIndexChanged.connect(self.access_profile_changed.emit)
        self.policy_section.body.addWidget(self.access_profile)

        self.access_profile_hint = QLabel()
        self.access_profile_hint.setObjectName("Hint")
        self.access_profile_hint.setWordWrap(True)
        self.policy_section.body.addWidget(self.access_profile_hint)

        p_row = FlowLayout(spacing=8)
        self.allowlist_btn = _button("")
        self.allowlist_btn.clicked.connect(self.allowlist_requested.emit)
        self.clients_btn = _button("", "Accent")
        self.clients_btn.clicked.connect(self.clients_requested.emit)
        p_row.addWidget(self.allowlist_btn)
        p_row.addWidget(self.clients_btn)
        self.policy_section.body.addLayout(p_row)
        self.content.addWidget(self.policy_section)

        self.content.addWidget(Divider())

        # --- Section 2: Computer Use Opt-In (master toggle + indented dependent toggles)
        self.desktop_section = Section(spacing=8)
        self.desktop_header = self.desktop_section.header
        self.desktop_badge = Badge("", variant="neutral")
        self.desktop_header.right_box.addWidget(self.desktop_badge)

        self.desktop_enabled_sw = ToggleSwitch()
        self.desktop_screen_sw = ToggleSwitch()
        self.desktop_control_sw = ToggleSwitch()
        self.desktop_secrets_sw = ToggleSwitch()
        # Backwards-compatible aliases
        self.desktop_enabled_chk = self.desktop_enabled_sw
        self.desktop_screen_chk = self.desktop_screen_sw
        self.desktop_control_chk = self.desktop_control_sw
        self.desktop_secrets_chk = self.desktop_secrets_sw

        self.desktop_enabled_sw.toggled.connect(self._on_desktop_control_changed)
        self.desktop_section.body.addWidget(self.desktop_enabled_sw)

        dep_box = QVBoxLayout()
        dep_box.setContentsMargins(20, 2, 0, 2)
        dep_box.setSpacing(6)
        for sw in (
            self.desktop_screen_sw,
            self.desktop_control_sw,
            self.desktop_secrets_sw,
        ):
            sw.toggled.connect(self._on_desktop_control_changed)
            dep_box.addWidget(sw)
        self.desktop_section.body.addLayout(dep_box)

        d_form = QFormLayout()
        d_form.setContentsMargins(0, 4, 0, 0)
        d_form.setSpacing(8)
        self.desktop_clients_edit = QLineEdit()
        self.desktop_clients_edit.setObjectName("UiInput")
        self.desktop_clients_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.desktop_clients_edit.editingFinished.connect(self._on_desktop_control_changed)
        self.desktop_apps_edit = QLineEdit()
        self.desktop_apps_edit.setObjectName("UiInput")
        self.desktop_apps_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.desktop_apps_edit.editingFinished.connect(self._on_desktop_control_changed)
        d_form.addRow(QLabel(), self.desktop_clients_edit)
        d_form.addRow(QLabel(), self.desktop_apps_edit)
        self._desktop_clients_lbl = d_form.labelForField(self.desktop_clients_edit)
        self._desktop_apps_lbl = d_form.labelForField(self.desktop_apps_edit)
        if isinstance(self._desktop_clients_lbl, QLabel):
            self._desktop_clients_lbl.setObjectName("FieldLabel")
        if isinstance(self._desktop_apps_lbl, QLabel):
            self._desktop_apps_lbl.setObjectName("FieldLabel")
        self.desktop_section.body.addLayout(d_form)

        self.desktop_clear_stop_btn = _button("", "Secondary")
        self.desktop_clear_stop_btn.clicked.connect(self.clear_emergency_stop)
        self.desktop_clear_stop_btn.hide()
        self.desktop_section.body.addWidget(self.desktop_clear_stop_btn, 0, Qt.AlignmentFlag.AlignLeft)

        self.desktop_refresh_hint = QLabel()
        self.desktop_refresh_hint.setObjectName("Hint")
        self.desktop_refresh_hint.setWordWrap(True)
        self.desktop_section.body.addWidget(self.desktop_refresh_hint)
        self.content.addWidget(self.desktop_section)

        self.content.addWidget(Divider())

        # --- Section 3: Secret Storage & Honest Sandbox Notice
        self.secret_section = Section(spacing=6)
        self.secret_header = self.secret_section.header
        self.secret_desc = QLabel()
        self.secret_desc.setObjectName("Hint")
        self.secret_desc.setWordWrap(True)
        self.secret_section.body.addWidget(self.secret_desc)
        self.content.addWidget(self.secret_section)

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
        self._sync_desktop_toggle_states()
        self._refresh_desktop_badge(pol)
        return pol

    def _sync_desktop_toggle_states(self) -> None:
        """Disable dependent Computer Use switches visually without erasing saved values."""
        master_on = self.desktop_enabled_sw.isChecked()
        control_on = master_on and self.desktop_control_sw.isChecked()
        self.desktop_screen_sw.setEnabled(master_on)
        self.desktop_control_sw.setEnabled(master_on)
        self.desktop_secrets_sw.setEnabled(control_on)

    def _refresh_desktop_badge(self, pol: DesktopPolicy) -> None:
        self.desktop_clear_stop_btn.setVisible(pol.emergency_stop)
        if pol.emergency_stop:
            self.desktop_badge.setText(tr("security.desktop.status.stopped"))
            self.desktop_badge.set_variant("err")
        elif not pol.enabled:
            self.desktop_badge.setText(tr("security.desktop.status.off"))
            self.desktop_badge.set_variant("neutral")
        elif pol.allow_input_control:
            self.desktop_badge.setText(tr("security.desktop.status.control"))
            self.desktop_badge.set_variant("err")
        elif pol.allow_screen_capture:
            self.desktop_badge.setText(tr("security.desktop.status.view"))
            self.desktop_badge.set_variant("warn")
        else:
            self.desktop_badge.setText(tr("security.desktop.status.off"))
            self.desktop_badge.set_variant("neutral")

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
        self._sync_desktop_toggle_states()
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
        self.access_profile_hint.setText(tr(f"home.access.hint.{self._active_mode}"))

    def retranslate(self) -> None:
        self.set_header(tr("security.title"), tr("security.lead"))
        self.policy_header.set_texts(tr("security.policy.title"), tr("home.access.desc"))
        self.access_label.setText(tr("home.access.label"))
        self.access_profile.blockSignals(True)
        for idx, key in enumerate(("safe", "allowlist", "full")):
            self.access_profile.setItemText(idx, tr(f"home.access.{key}"))
        self.access_profile.blockSignals(False)
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
