"""Security & Boundaries page: access policy, SecretStore, Computer Use opt-in, emergency stop."""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QCheckBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from app.paths import user_data_dir
from app.ui.components.cards import Badge, Card, SectionHeader
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import tr
from app.ui.pages.base import PageScaffold
from backend.desktop.models import DesktopPolicy, DesktopPolicyStore


def _button(text: str = "", obj_name: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    if obj_name:
        btn.setObjectName(obj_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


class SecurityPage(PageScaffold):
    """Central view of access profiles, DPAPI secret storage, and Computer Use opt-in."""

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

        # --- Computer Use Opt-In Card (default OFF, fail closed)
        desktop_card = Card()
        self.desktop_header = SectionHeader()
        self.desktop_badge = Badge("", variant="ok")
        self.desktop_header.right_box.addWidget(self.desktop_badge)
        desktop_card.body.addWidget(self.desktop_header)

        self.desktop_enabled_chk = QCheckBox()
        self.desktop_screen_chk = QCheckBox()
        self.desktop_control_chk = QCheckBox()
        self.desktop_secrets_chk = QCheckBox()
        for chk in (
            self.desktop_enabled_chk,
            self.desktop_screen_chk,
            self.desktop_control_chk,
            self.desktop_secrets_chk,
        ):
            desktop_card.body.addWidget(chk)

        d_form = QFormLayout()
        d_form.setSpacing(6)
        self.desktop_clients_edit = QLineEdit()
        self.desktop_clients_edit.setObjectName("UiInput")
        self.desktop_apps_edit = QLineEdit()
        self.desktop_apps_edit.setObjectName("UiInput")
        d_form.addRow(QLabel(), self.desktop_clients_edit)
        d_form.addRow(QLabel(), self.desktop_apps_edit)
        self._desktop_clients_lbl = d_form.labelForField(self.desktop_clients_edit)
        self._desktop_apps_lbl = d_form.labelForField(self.desktop_apps_edit)
        desktop_card.body.addLayout(d_form)

        d_row = QHBoxLayout()
        d_row.setSpacing(8)
        self.desktop_save_btn = _button("", "Accent")
        self.desktop_save_btn.clicked.connect(self.save_desktop_policy)
        self.desktop_stop_btn = _button("", "Danger")
        self.desktop_stop_btn.clicked.connect(self.stop_computer_use)
        d_row.addWidget(self.desktop_save_btn)
        d_row.addWidget(self.desktop_stop_btn)
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
        self.desktop_enabled_chk.setChecked(pol.enabled)
        self.desktop_screen_chk.setChecked(pol.allow_screen_capture)
        self.desktop_control_chk.setChecked(pol.allow_input_control)
        self.desktop_secrets_chk.setChecked(pol.allow_secret_typing)
        self.desktop_clients_edit.setText(", ".join(pol.allowed_clients))
        self.desktop_apps_edit.setText(", ".join(pol.allowed_apps))
        self._refresh_desktop_badge(pol)
        return pol

    def _refresh_desktop_badge(self, pol: DesktopPolicy) -> None:
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

    def save_desktop_policy(self) -> None:
        clients = tuple(c.strip() for c in self.desktop_clients_edit.text().split(",") if c.strip())
        apps = tuple(a.strip() for a in self.desktop_apps_edit.text().split(",") if a.strip())
        try:
            current = self._desktop_store.load()
            pol = DesktopPolicy(
                enabled=self.desktop_enabled_chk.isChecked(),
                allow_screen_capture=self.desktop_screen_chk.isChecked(),
                allow_input_control=self.desktop_control_chk.isChecked(),
                allow_secret_typing=self.desktop_secrets_chk.isChecked(),
                allowed_clients=clients,
                min_profile=current.min_profile,
                allowed_apps=apps,
                blocked_title_patterns=current.blocked_title_patterns,
                max_image_width=current.max_image_width,
                max_image_bytes=current.max_image_bytes,
                emergency_stop=False,
            )
            self._desktop_store.save(pol)
        except Exception as exc:  # noqa: BLE001
            SilentMessageBox.warning(self, tr("security.desktop.title"), str(exc))
            return
        self._refresh_desktop_badge(pol)
        self.desktop_policy_changed.emit()

    def stop_computer_use(self) -> None:
        pol = self._desktop_store.set_emergency_stop(True, "Owner stopped Computer Use")
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
        self.desktop_enabled_chk.setText(tr("security.desktop.enabled"))
        self.desktop_screen_chk.setText(tr("security.desktop.screen"))
        self.desktop_control_chk.setText(tr("security.desktop.control"))
        self.desktop_secrets_chk.setText(tr("security.desktop.secrets"))
        if isinstance(self._desktop_clients_lbl, QLabel):
            self._desktop_clients_lbl.setText(tr("security.desktop.clients"))
        if isinstance(self._desktop_apps_lbl, QLabel):
            self._desktop_apps_lbl.setText(tr("security.desktop.apps"))
        self.desktop_save_btn.setText(tr("security.desktop.save"))
        self.desktop_stop_btn.setText(tr("security.desktop.stop"))
        self.desktop_refresh_hint.setText(tr("security.desktop.refresh_hint"))
        self._refresh_desktop_badge(self._desktop_store.load())

        self.secret_header.set_texts(tr("security.secrets.title"))
        self.secret_desc.setText(tr("security.secrets.desc", backend=self._backend_name))

    def apply_theme(self) -> None:
        self.mode_badge.set_variant(str(self.mode_badge.property("variant") or "ok"))
        self.desktop_badge.set_variant(str(self.desktop_badge.property("variant") or "ok"))
