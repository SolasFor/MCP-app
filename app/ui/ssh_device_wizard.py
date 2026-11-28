"""Compact 5-step SSH Device Onboarding Wizard (Stage N05)."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.redaction import SecretRedactor
from app.ui.components.cards import Badge, Divider, FlowLayout
from app.ui.components.safe_combo import SafeComboBox
from app.ui.components.safe_spin import SafeSpinBox
from app.ui.components.silent_dialog import SilentDialog
from app.ui.i18n import tr
from app.ui.ssh_device_dialogs import GenerateSSHKeyDialog, SSHSetupGuideDialog
from backend.remote.discovery import (
    DiscoveredSSHEndpoint,
    TailscaleDiscoveryResult,
    discover_ssh_endpoints_in_cidr,
    discover_tailscale_ssh_peers,
)
from backend.remote.host_keys import (
    ApprovedHostKey,
    HostKeyProbeResult,
    probe_ssh_host_key,
    verify_independent_host_key,
)
from backend.remote.models import (
    DevicePermissions,
    DeviceProfile,
    validate_host,
    validate_ssh_username,
)
from backend.remote.onboarding import (
    RemoteCapabilityProbeResult,
    SSHConfigHostCandidate,
    SSHDevicePreview,
    commit_device_wizard_plan,
    inspect_ssh_config,
    prepare_device_wizard_preview,
    probe_remote_os_and_capabilities,
    test_ssh_authentication,
)
from backend.remote.ssh_client import SSHConnectionManager
from backend.remote.store import DeviceStore


def _set_badge(badge: Badge, text: str, variant: str) -> None:
    badge.setText(text)
    badge.set_variant(variant)


def _scroll_wrap(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setObjectName("Page")
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(widget)
    return area


def _parse_ports(raw: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in (raw or "").replace("\n", ",").split(","):
        s = part.strip()
        if not s:
            continue
        if not s.isdigit():
            raise ValueError(f"Invalid port: {s!r}")
        p = int(s)
        if not (1 <= p <= 65535):
            raise ValueError(f"Port out of range: {p}")
        out.append(p)
    return tuple(out or [22])


class _SSHProbeWorker(QThread):
    completed = pyqtSignal(int, str, object, str, arguments=["generation", "kind", "payload", "error"])

    def __init__(
        self,
        generation: int,
        kind: str,
        fn: Any,
        redactor: SecretRedactor,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._generation = generation
        self._kind = kind
        self._fn = fn
        self._redactor = redactor

    def run(self) -> None:
        try:
            res = self._fn()
            self.completed.emit(self._generation, self._kind, res, "")
        except Exception as exc:  # noqa: BLE001
            msg = self._redactor.redact_text(str(exc)) or type(exc).__name__
            self.completed.emit(self._generation, self._kind, None, msg)


class SSHDeviceWizardDialog(SilentDialog):
    """Five-step secure SSH device onboarding wizard with pre-auth host-key verification."""

    def __init__(
        self,
        store: DeviceStore,
        *,
        redactor: SecretRedactor | None = None,
        initial_source: str = "manual",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._redactor = redactor or SecretRedactor()
        self._ssh_mgr = SSHConnectionManager(self._store)

        self.committed_profile: DeviceProfile | None = None
        self.manual_requested: bool = False

        self._generation = 0
        self._worker: _SSHProbeWorker | None = None
        self._retired_workers: list[_SSHProbeWorker] = []
        self._cancel_event: threading.Event | None = None

        self._host_probe: HostKeyProbeResult | None = None
        self._approved_host_key: ApprovedHostKey | None = None
        self._auth_ok: bool = False
        self._capability_probe: RemoteCapabilityProbeResult | None = None
        self._preview: SSHDevicePreview | None = None

        self._config_candidates: list[SSHConfigHostCandidate] = []
        self._cidr_endpoints: list[DiscoveredSSHEndpoint] = []
        self._tailscale_result: TailscaleDiscoveryResult | None = None

        self.setMinimumSize(640, 460)
        self.resize(760, 560)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        top_row = QHBoxLayout()
        self._lead_lbl = QLabel()
        self._lead_lbl.setObjectName("Hint")
        self._lead_lbl.setWordWrap(True)
        self.guide_btn = QPushButton()
        self.guide_btn.setObjectName("Ghost")
        self.guide_btn.clicked.connect(self._open_setup_guide)
        top_row.addWidget(self._lead_lbl, 1)
        top_row.addWidget(self.guide_btn)
        root.addLayout(top_row)

        step_bar = FlowLayout(spacing=6)
        self._step_pills: list[Badge] = []
        for _ in range(5):
            pill = Badge("", variant="neutral")
            self._step_pills.append(pill)
            step_bar.addWidget(pill)
        root.addLayout(step_bar)
        root.addWidget(Divider())

        self.stack = QStackedWidget()
        self.stack.addWidget(_scroll_wrap(self._build_step_source()))
        self.stack.addWidget(_scroll_wrap(self._build_step_host_key()))
        self.stack.addWidget(_scroll_wrap(self._build_step_auth()))
        self.stack.addWidget(_scroll_wrap(self._build_step_os()))
        self.stack.addWidget(_scroll_wrap(self._build_step_access()))
        root.addWidget(self.stack, 1)

        self.step_error_lbl = QLabel()
        self.step_error_lbl.setWordWrap(True)
        self.step_error_lbl.setStyleSheet("color: #f87171; font-weight: 500;")
        self.step_error_lbl.hide()
        root.addWidget(self.step_error_lbl)

        root.addWidget(Divider())
        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.manual_btn = QPushButton()
        self.manual_btn.setObjectName("Ghost")
        self.manual_btn.clicked.connect(self._request_manual_form)
        self.back_btn = QPushButton()
        self.back_btn.clicked.connect(self.go_back)
        self.cancel_btn = QPushButton()
        self.cancel_btn.setObjectName("Ghost")
        self.cancel_btn.clicked.connect(self.reject)
        self.next_btn = QPushButton()
        self.next_btn.setObjectName("Accent")
        self.next_btn.clicked.connect(self._on_primary_clicked)

        footer.addWidget(self.manual_btn)
        footer.addStretch(1)
        footer.addWidget(self.back_btn)
        footer.addWidget(self.cancel_btn)
        footer.addWidget(self.next_btn)
        root.addLayout(footer)

        self.retranslate()
        self._set_source_tab(initial_source)
        self._set_step(0)

    def _build_step_source(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 12, 6)
        lay.setSpacing(8)

        pills = FlowLayout(spacing=6)
        self._src_btns: dict[str, QPushButton] = {}
        for key in ("manual", "ssh_config", "cidr", "tailscale"):
            btn = QPushButton()
            btn.setObjectName("FilterPill")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _c=False, k=key: self._set_source_tab(k))
            self._src_btns[key] = btn
            pills.addWidget(btn)
        lay.addLayout(pills)

        self.source_stack = QStackedWidget()
        self.source_stack.addWidget(self._build_manual_source_pane())
        self.source_stack.addWidget(self._build_ssh_config_pane())
        self.source_stack.addWidget(self._build_cidr_pane())
        self.source_stack.addWidget(self._build_tailscale_pane())
        lay.addWidget(self.source_stack, 1)
        return w

    def _build_manual_source_pane(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setSpacing(6)
        self.id_edit = QLineEdit()
        self.name_edit = QLineEdit()
        self.group_edit = QLineEdit("default")
        self.host_edit = QLineEdit()
        self.port_spin = SafeSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.user_edit = QLineEdit()
        for ed in (self.id_edit, self.name_edit, self.group_edit, self.host_edit, self.user_edit):
            ed.setObjectName("UiInput")
            ed.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.host_edit.textChanged.connect(self._invalidate_host_key)
        self.port_spin.valueChanged.connect(self._invalidate_host_key)
        self.user_edit.textChanged.connect(self._invalidate_auth)

        self._src_labels: dict[str, QLabel] = {}
        for key, widget in (
            ("devices.dlg.id", self.id_edit),
            ("devices.dlg.name", self.name_edit),
            ("devices.dlg.group", self.group_edit),
            ("devices.dlg.host", self.host_edit),
            ("devices.dlg.port", self.port_spin),
            ("devices.dlg.user", self.user_edit),
        ):
            lbl = QLabel()
            lbl.setWordWrap(True)
            lbl.setMaximumWidth(230)
            self._src_labels[key] = lbl
            form.addRow(lbl, widget)
        return w

    def _build_ssh_config_pane(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)
        row = QHBoxLayout()
        self.ssh_cfg_path_edit = QLineEdit()
        self.ssh_cfg_path_edit.setObjectName("UiInput")
        self.ssh_cfg_path_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.ssh_cfg_browse_btn = QPushButton()
        self.ssh_cfg_browse_btn.clicked.connect(self._browse_ssh_config)
        self.ssh_cfg_load_btn = QPushButton()
        self.ssh_cfg_load_btn.clicked.connect(self.load_ssh_config_candidates)
        row.addWidget(self.ssh_cfg_path_edit, 1)
        row.addWidget(self.ssh_cfg_browse_btn)
        row.addWidget(self.ssh_cfg_load_btn)
        lay.addLayout(row)

        self.ssh_cfg_list = QListWidget()
        self.ssh_cfg_list.setMaximumHeight(130)
        self.ssh_cfg_list.itemActivated.connect(self.apply_selected_ssh_config)
        lay.addWidget(self.ssh_cfg_list)

        self.ssh_cfg_diag = QPlainTextEdit()
        self.ssh_cfg_diag.setObjectName("ConsoleLog")
        self.ssh_cfg_diag.setReadOnly(True)
        self.ssh_cfg_diag.setMaximumHeight(72)
        lay.addWidget(self.ssh_cfg_diag)

        self.ssh_cfg_apply_btn = QPushButton()
        self.ssh_cfg_apply_btn.clicked.connect(self.apply_selected_ssh_config)
        lay.addWidget(self.ssh_cfg_apply_btn, 0, Qt.AlignmentFlag.AlignLeft)
        return w

    def _build_cidr_pane(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)
        form = QFormLayout()
        self.cidr_edit = QLineEdit("192.168.1.0/24")
        self.cidr_edit.setObjectName("UiInput")
        self.cidr_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.cidr_ports_edit = QLineEdit("22")
        self.cidr_ports_edit.setObjectName("UiInput")
        self._cidr_lbl = QLabel()
        self._ports_lbl = QLabel()
        form.addRow(self._cidr_lbl, self.cidr_edit)
        form.addRow(self._ports_lbl, self.cidr_ports_edit)
        lay.addLayout(form)

        self.cidr_consent_chk = QCheckBox()
        self.cidr_consent_chk.toggled.connect(lambda ok: self.scan_cidr_btn.setEnabled(ok and not self.is_busy()))
        lay.addWidget(self.cidr_consent_chk)

        btns = FlowLayout(spacing=6)
        self.scan_cidr_btn = QPushButton()
        self.scan_cidr_btn.setEnabled(False)
        self.scan_cidr_btn.clicked.connect(self.start_cidr_scan)
        self.cancel_cidr_btn = QPushButton()
        self.cancel_cidr_btn.hide()
        self.cancel_cidr_btn.clicked.connect(self.cancel_active_worker)
        self.cidr_apply_btn = QPushButton()
        self.cidr_apply_btn.clicked.connect(self.apply_selected_cidr)
        btns.addWidget(self.scan_cidr_btn)
        btns.addWidget(self.cancel_cidr_btn)
        btns.addWidget(self.cidr_apply_btn)
        lay.addLayout(btns)

        self.cidr_list = QListWidget()
        self.cidr_list.setMaximumHeight(120)
        self.cidr_list.itemActivated.connect(self.apply_selected_cidr)
        lay.addWidget(self.cidr_list)
        return w

    def _build_tailscale_pane(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)
        self.ts_consent_chk = QCheckBox()
        self.ts_consent_chk.toggled.connect(lambda ok: self.load_ts_btn.setEnabled(ok and not self.is_busy()))
        lay.addWidget(self.ts_consent_chk)

        row = FlowLayout(spacing=6)
        self.load_ts_btn = QPushButton()
        self.load_ts_btn.setEnabled(False)
        self.load_ts_btn.clicked.connect(self.start_tailscale_discovery)
        self.ts_apply_btn = QPushButton()
        self.ts_apply_btn.clicked.connect(self.apply_selected_tailscale)
        self.ts_status_badge = Badge("OFF", variant="neutral")
        row.addWidget(self.load_ts_btn)
        row.addWidget(self.ts_apply_btn)
        row.addWidget(self.ts_status_badge)
        lay.addLayout(row)

        self.ts_list = QListWidget()
        self.ts_list.setMaximumHeight(130)
        self.ts_list.itemActivated.connect(self.apply_selected_tailscale)
        lay.addWidget(self.ts_list)
        return w

    def _build_step_host_key(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 12, 6)
        lay.setSpacing(8)

        row = FlowLayout(spacing=6)
        self.probe_hk_btn = QPushButton()
        self.probe_hk_btn.setObjectName("Accent")
        self.probe_hk_btn.clicked.connect(self.start_host_key_probe)
        self.cancel_hk_btn = QPushButton()
        self.cancel_hk_btn.hide()
        self.cancel_hk_btn.clicked.connect(self.cancel_active_worker)
        self.hk_status_badge = Badge("unknown", variant="neutral")
        row.addWidget(self.probe_hk_btn)
        row.addWidget(self.cancel_hk_btn)
        row.addWidget(self.hk_status_badge)
        lay.addLayout(row)

        self.hk_details = QPlainTextEdit()
        self.hk_details.setObjectName("ConsoleLog")
        self.hk_details.setReadOnly(True)
        self.hk_details.setMaximumHeight(105)
        lay.addWidget(self.hk_details)

        form = QFormLayout()
        self.expected_fp_edit = QLineEdit()
        self.expected_fp_edit.setObjectName("UiInput")
        self.expected_fp_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.expected_fp_edit.textChanged.connect(self._invalidate_approved_host_key)
        self._fp_lbl = QLabel()
        form.addRow(self._fp_lbl, self.expected_fp_edit)
        lay.addLayout(form)

        self.independent_verify_chk = QCheckBox()
        self.independent_verify_chk.toggled.connect(self._invalidate_approved_host_key)
        lay.addWidget(self.independent_verify_chk)
        lay.addStretch(1)
        return w

    def _build_step_auth(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 12, 6)
        lay.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(6)
        self.auth_combo = SafeComboBox()
        for mode in ("agent", "key", "password_ref"):
            self.auth_combo.addItem(mode, mode)
        self.auth_combo.currentIndexChanged.connect(self._on_auth_method_changed)

        key_row = QHBoxLayout()
        self.key_path_edit = QLineEdit()
        self.key_path_edit.setObjectName("UiInput")
        self.key_path_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.key_path_edit.textChanged.connect(self._invalidate_auth)
        self.key_browse_btn = QPushButton()
        self.key_browse_btn.clicked.connect(self._browse_private_key)
        self.gen_key_btn = QPushButton()
        self.gen_key_btn.clicked.connect(self._open_keygen)
        key_row.addWidget(self.key_path_edit, 1)
        key_row.addWidget(self.key_browse_btn)
        key_row.addWidget(self.gen_key_btn)

        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setObjectName("UiInput")
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_edit.textChanged.connect(self._invalidate_auth)

        self.password_edit = QLineEdit()
        self.password_edit.setObjectName("UiInput")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.textChanged.connect(self._invalidate_auth)

        self._auth_labels: dict[str, QLabel] = {}
        for key, field in (
            ("devices.dlg.auth", self.auth_combo),
            ("devices.dlg.key_path", key_row),
            ("devices.wizard.passphrase", self.passphrase_edit),
            ("devices.dlg.password", self.password_edit),
        ):
            lbl = QLabel()
            lbl.setWordWrap(True)
            lbl.setMaximumWidth(230)
            self._auth_labels[key] = lbl
            form.addRow(lbl, field)
        lay.addLayout(form)

        row = FlowLayout(spacing=6)
        self.test_auth_btn = QPushButton()
        self.test_auth_btn.setObjectName("Accent")
        self.test_auth_btn.clicked.connect(self.start_auth_test)
        self.auth_status_badge = Badge("untested", variant="neutral")
        row.addWidget(self.test_auth_btn)
        row.addWidget(self.auth_status_badge)
        lay.addLayout(row)

        self.auth_diag = QPlainTextEdit()
        self.auth_diag.setObjectName("ConsoleLog")
        self.auth_diag.setReadOnly(True)
        self.auth_diag.setMaximumHeight(90)
        lay.addWidget(self.auth_diag)
        self._sync_auth_fields()
        return w

    def _build_step_os(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 12, 6)
        lay.setSpacing(8)

        row = FlowLayout(spacing=6)
        self.probe_os_btn = QPushButton()
        self.probe_os_btn.setObjectName("Accent")
        self.probe_os_btn.clicked.connect(self.start_os_probe)
        self.os_badge = Badge("unknown", variant="neutral")
        row.addWidget(self.probe_os_btn)
        row.addWidget(self.os_badge)
        lay.addLayout(row)

        self.os_details = QPlainTextEdit()
        self.os_details.setObjectName("ConsoleLog")
        self.os_details.setReadOnly(True)
        lay.addWidget(self.os_details, 1)
        return w

    def _build_step_access(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 6, 12, 6)
        lay.setSpacing(8)

        perm_row = FlowLayout(spacing=8)
        self.perm_exec = QCheckBox("Execute")
        self.perm_sftp_r = QCheckBox("SFTP Read")
        self.perm_sftp_w = QCheckBox("SFTP Write")
        self.perm_svc = QCheckBox("Services")
        self.perm_metrics = QCheckBox("Metrics")
        self.perm_docker = QCheckBox("Docker Read")
        for chk in (self.perm_exec, self.perm_sftp_r, self.perm_sftp_w, self.perm_svc, self.perm_metrics, self.perm_docker):
            chk.setChecked(False)
            chk.toggled.connect(self._refresh_preview)
            perm_row.addWidget(chk)
        lay.addLayout(perm_row)

        self.allow_oauth_chk = QCheckBox()
        self.allow_oauth_chk.setChecked(False)
        self.allow_oauth_chk.toggled.connect(self._refresh_preview)
        lay.addWidget(self.allow_oauth_chk)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self.min_profile_combo = SafeComboBox()
        self.min_profile_combo.addItem("Allowlist", "allowlist")
        self.min_profile_combo.addItem("Full Access", "full")
        self.min_profile_combo.currentIndexChanged.connect(self._refresh_preview)
        self.allowed_clients_edit = QLineEdit()
        self.allowed_clients_edit.setObjectName("UiInput")
        self.allowed_clients_edit.textChanged.connect(self._refresh_preview)
        self.sftp_roots_edit = QLineEdit()
        self.sftp_roots_edit.setObjectName("UiInput")
        self.sftp_roots_edit.textChanged.connect(self._refresh_preview)
        self.commands_edit = QPlainTextEdit()
        self.commands_edit.setMaximumHeight(52)
        self.commands_edit.textChanged.connect(self._refresh_preview)
        self.services_edit = QLineEdit()
        self.services_edit.setObjectName("UiInput")
        self.services_edit.textChanged.connect(self._refresh_preview)
        for ed in (self.min_profile_combo, self.allowed_clients_edit, self.sftp_roots_edit, self.services_edit):
            ed.setMinimumWidth(260)
            ed.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._acc_labels: dict[str, QLabel] = {}
        for key, field in (
            ("devices.dlg.min_profile", self.min_profile_combo),
            ("devices.dlg.clients", self.allowed_clients_edit),
            ("devices.dlg.sftp_roots", self.sftp_roots_edit),
            ("devices.dlg.commands", self.commands_edit),
            ("devices.dlg.services", self.services_edit),
        ):
            lbl = QLabel()
            lbl.setWordWrap(True)
            lbl.setMaximumWidth(230)
            self._acc_labels[key] = lbl
            form.addRow(lbl, field)
        lay.addLayout(form)

        self.preview_title_lbl = QLabel()
        self.preview_title_lbl.setObjectName("FieldLabel")
        lay.addWidget(self.preview_title_lbl)

        self.preview_view = QPlainTextEdit()
        self.preview_view.setObjectName("ConsoleLog")
        self.preview_view.setReadOnly(True)
        self.preview_view.setMinimumHeight(130)
        lay.addWidget(self.preview_view, 1)
        return w

    def _show_error(self, message: str) -> None:
        clean = self._redactor.redact_text((message or "").strip())
        if clean:
            self.step_error_lbl.setText(clean)
            self.step_error_lbl.show()
        else:
            self._clear_error()

    def _clear_error(self) -> None:
        if hasattr(self, "step_error_lbl"):
            self.step_error_lbl.clear()
            self.step_error_lbl.hide()

    def _invalidate_approved_host_key(self) -> None:
        self._approved_host_key = None
        self._clear_error()

    def _set_source_tab(self, key: str) -> None:
        self._clear_error()
        order = ("manual", "ssh_config", "cidr", "tailscale")
        idx = order.index(key) if key in order else 0
        for name, btn in self._src_btns.items():
            btn.setChecked(name == order[idx])
        self.source_stack.setCurrentIndex(idx)

    def _set_step(self, step: int) -> None:
        self._clear_error()
        self.stack.setCurrentIndex(step)
        for idx, pill in enumerate(self._step_pills):
            _set_badge(pill, pill.text(), "ok" if idx < step else ("warn" if idx == step else "neutral"))
        self.back_btn.setEnabled(step > 0)
        self.next_btn.setText(tr("devices.wizard.save") if step == 4 else tr("devices.wizard.next"))
        if step == 3 and self._capability_probe is None and self._auth_ok and not self.is_busy():
            self.start_os_probe()
        if step == 4:
            self._refresh_preview()

    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def _run_worker(self, kind: str, fn: Any) -> None:
        self._clear_error()
        self._generation += 1
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._worker is not None and self._worker.isRunning():
            self._retired_workers.append(self._worker)
        self._cancel_event = threading.Event()
        self._set_busy_controls(True)
        w = _SSHProbeWorker(self._generation, kind, fn, self._redactor, self)
        w.completed.connect(self._on_worker_completed)
        self._worker = w
        w.start()

    def _set_busy_controls(self, busy: bool) -> None:
        self.probe_hk_btn.setEnabled(not busy)
        self.test_auth_btn.setEnabled(not busy)
        self.probe_os_btn.setEnabled(not busy)
        self.scan_cidr_btn.setEnabled((not busy) and self.cidr_consent_chk.isChecked())
        self.load_ts_btn.setEnabled((not busy) and self.ts_consent_chk.isChecked())
        self.cancel_hk_btn.setVisible(busy)
        self.cancel_cidr_btn.setVisible(busy)

    def cancel_active_worker(self) -> None:
        self._generation += 1
        if self._cancel_event is not None:
            self._cancel_event.set()
        self._set_busy_controls(False)

    def _on_worker_completed(self, generation: int, kind: str, payload: object, error: str) -> None:
        self._retired_workers = [w for w in self._retired_workers if w.isRunning()]
        if generation != self._generation:
            return
        self._set_busy_controls(False)
        handlers = {
            "host_key": self._handle_host_key_result,
            "auth": self._handle_auth_dispatch,
            "os": self._handle_os_result,
            "cidr": self._handle_cidr_result,
            "tailscale": self._handle_tailscale_result,
        }
        handler = handlers.get(kind)
        if handler is not None:
            handler(payload, error)

    def _handle_auth_dispatch(self, _payload: object, error: str) -> None:
        self._handle_auth_result(error)

    def _invalidate_host_key(self) -> None:
        self._host_probe = None
        self._approved_host_key = None
        self._clear_error()
        self._invalidate_auth()
        if hasattr(self, "hk_status_badge"):
            _set_badge(self.hk_status_badge, "unknown", "neutral")

    def _invalidate_auth(self) -> None:
        self._auth_ok = False
        self._capability_probe = None
        self._preview = None
        self._clear_error()
        if hasattr(self, "auth_status_badge"):
            _set_badge(self.auth_status_badge, "untested", "neutral")
        if hasattr(self, "os_badge"):
            _set_badge(self.os_badge, "unknown", "neutral")

    def _sync_auth_fields(self) -> None:
        mode = str(self.auth_combo.currentData() or "agent")
        self.key_path_edit.setEnabled(mode == "key")
        self.key_browse_btn.setEnabled(mode == "key")
        self.gen_key_btn.setEnabled(mode == "key")
        self.passphrase_edit.setEnabled(mode == "key")
        self.password_edit.setEnabled(mode == "password_ref")

    def _on_auth_method_changed(self) -> None:
        self._sync_auth_fields()
        self._invalidate_auth()

    def _validated_endpoint(self) -> tuple[str, int, str]:
        host = validate_host(self.host_edit.text().strip())
        port = int(self.port_spin.value())
        user = validate_ssh_username(self.user_edit.text().strip(), required=False)
        return host, port, user

    def _open_setup_guide(self) -> None:
        SSHSetupGuideDialog(self).exec()

    def _browse_ssh_config(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, tr("devices.wizard.src_ssh_config"))
        if chosen:
            self.ssh_cfg_path_edit.setText(chosen)

    def _browse_private_key(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, tr("devices.dlg.key_path"))
        if chosen:
            self.key_path_edit.setText(chosen)

    def _open_keygen(self) -> None:
        dlg = GenerateSSHKeyDialog(parent=self)
        if dlg.exec() == SilentDialog.DialogCode.Accepted and dlg.generated_private_path:
            self.key_path_edit.setText(dlg.generated_private_path)

    def load_ssh_config_candidates(self) -> None:
        raw = self.ssh_cfg_path_edit.text().strip()
        report = inspect_ssh_config(Path(raw) if raw else None, existing_store=self._store)
        self._config_candidates = list(report.candidates)
        self.ssh_cfg_list.clear()
        for cand in self._config_candidates:
            tag = f"[DUP: {cand.duplicate_reason}]" if cand.is_duplicate else "[NEW]"
            item = QListWidgetItem(f"{cand.source_alias} -> {cand.profile.host}:{cand.profile.port} {tag}")
            self.ssh_cfg_list.addItem(item)
        diag_lines = list(report.warnings)
        for cand in self._config_candidates:
            diag_lines.extend(f"{cand.source_alias}: {d}" for d in cand.diagnostics)
        self.ssh_cfg_diag.setPlainText("\n".join(diag_lines) or f"Found {len(self._config_candidates)} Host entries.")

    def apply_selected_ssh_config(self) -> None:
        row = self.ssh_cfg_list.currentRow()
        if not (0 <= row < len(self._config_candidates)):
            return
        prof = self._config_candidates[row].profile
        self.id_edit.setText(prof.device_id)
        self.name_edit.setText(prof.name)
        self.group_edit.setText(prof.group)
        self.host_edit.setText(prof.host)
        self.port_spin.setValue(prof.port)
        self.user_edit.setText(prof.username)
        idx = max(0, self.auth_combo.findData(prof.auth_method))
        self.auth_combo.setCurrentIndex(idx)
        self.key_path_edit.setText(prof.key_path)
        self._set_source_tab("manual")

    def start_cidr_scan(self) -> None:
        if not self.cidr_consent_chk.isChecked():
            return
        scope = self.cidr_edit.text().strip()
        try:
            ports = _parse_ports(self.cidr_ports_edit.text())
        except ValueError as exc:
            self._show_error(str(exc))
            return
        cancel_ev = threading.Event()
        self._run_worker(
            "cidr",
            lambda: discover_ssh_endpoints_in_cidr(scope, ports=ports, owner_consent=True, cancel_event=cancel_ev),
        )
        self._cancel_event = cancel_ev

    def _handle_cidr_result(self, payload: object, error: str) -> None:
        self.cidr_list.clear()
        if error or not isinstance(payload, list):
            self._show_error(error or "CIDR scan failed")
            return
        self._clear_error()
        self._cidr_endpoints = list(payload)
        for ep in self._cidr_endpoints:
            self.cidr_list.addItem(f"{ep.host}:{ep.port} | {ep.banner or 'SSH TCP'} | Not trusted / Not auth")

    def apply_selected_cidr(self) -> None:
        row = self.cidr_list.currentRow()
        if not (0 <= row < len(self._cidr_endpoints)):
            return
        ep = self._cidr_endpoints[row]
        self.host_edit.setText(ep.host)
        self.port_spin.setValue(ep.port)
        if not self.id_edit.text().strip():
            self.id_edit.setText(ep.host.replace(".", "_").replace(":", "_"))
        self._set_source_tab("manual")

    def start_tailscale_discovery(self) -> None:
        if not self.ts_consent_chk.isChecked():
            return
        self._run_worker("tailscale", lambda: discover_tailscale_ssh_peers(owner_consent=True))

    def _handle_tailscale_result(self, payload: object, error: str) -> None:
        self.ts_list.clear()
        if error or not isinstance(payload, TailscaleDiscoveryResult):
            _set_badge(self.ts_status_badge, "error", "err")
            return
        self._tailscale_result = payload
        _set_badge(
            self.ts_status_badge,
            payload.status,
            "ok" if payload.available and payload.status == "ok" else "warn",
        )
        for peer in payload.peers:
            self.ts_list.addItem(
                f"{peer.hostname or peer.dns_name} ({peer.ip}) [{peer.os_name or '?'}] "
                f"{'online' if peer.online else 'offline'} | Not trusted"
            )

    def apply_selected_tailscale(self) -> None:
        if self._tailscale_result is None:
            return
        row = self.ts_list.currentRow()
        if not (0 <= row < len(self._tailscale_result.peers)):
            return
        peer = self._tailscale_result.peers[row]
        self.host_edit.setText(peer.ip)
        self.port_spin.setValue(22)
        if not self.id_edit.text().strip():
            self.id_edit.setText((peer.hostname or peer.ip).replace(".", "_"))
        if not self.name_edit.text().strip():
            self.name_edit.setText(peer.hostname or peer.dns_name or peer.ip)
        self._set_source_tab("manual")

    def start_host_key_probe(self) -> None:
        try:
            host, port, _ = self._validated_endpoint()
        except ValueError as exc:
            self._show_error(str(exc))
            return
        kh = self._store.managed_known_hosts_path
        cancel_ev = threading.Event()
        self._run_worker(
            "host_key",
            lambda: probe_ssh_host_key(
                host,
                port,
                known_hosts_path=kh if kh.is_file() else None,
                include_system_known_hosts=True,
                cancel_event=cancel_ev,
            ),
        )
        self._cancel_event = cancel_ev

    def _handle_host_key_result(self, payload: object, error: str) -> None:
        if error or not isinstance(payload, HostKeyProbeResult):
            _set_badge(self.hk_status_badge, "unreachable", "err")
            self.hk_details.setPlainText(error or "Host key probe failed")
            self._show_error(error or "Host key probe failed")
            return
        self._host_probe = payload
        variant = "ok" if payload.status == "trusted" else ("err" if payload.status == "host_key_changed" else "warn")
        _set_badge(self.hk_status_badge, payload.status, variant)
        self.hk_details.setPlainText(
            f"Endpoint: {payload.host}:{payload.port} ({payload.endpoint_ip or payload.host})\n"
            f"Algorithm: {payload.key_algorithm}\n"
            f"Fingerprint: {payload.fingerprint_sha256}\n"
            f"known_hosts: {payload.status} ({payload.known_hosts_source or 'not yet saved'})"
        )
        if payload.status == "host_key_changed":
            self._show_error(
                f"SSH host key CHANGED for {payload.host}:{payload.port}; onboarding blocked unless rotated explicitly."
            )
        else:
            self._clear_error()

    def _verify_host_key_step(self) -> bool:
        if self._host_probe is None:
            self._show_error("Run the host key probe first")
            return False
        try:
            self._approved_host_key = verify_independent_host_key(
                self._host_probe,
                expected_fingerprint_input=self.expected_fp_edit.text().strip(),
                verified_independently=self.independent_verify_chk.isChecked(),
                allow_rotation=False,
            )
            self._clear_error()
            return True
        except Exception as exc:  # noqa: BLE001
            self._show_error(str(exc))
            return False

    def start_auth_test(self) -> None:
        if self._approved_host_key is None:
            self._show_error("Verify the SSH host key first")
            return
        try:
            host, port, user = self._validated_endpoint()
            user = validate_ssh_username(user, required=True)
        except ValueError as exc:
            self._show_error(str(exc))
            return
        mode = str(self.auth_combo.currentData() or "agent")
        key_path = self.key_path_edit.text().strip()
        pwd = self.password_edit.text()
        passphrase = self.passphrase_edit.text()
        for sec in (pwd, passphrase):
            if sec:
                self._redactor.register(sec)
        approved = self._approved_host_key
        self._run_worker(
            "auth",
            lambda: test_ssh_authentication(
                host,
                port,
                user,
                auth_method=mode,
                approved_host_key=approved,
                key_path=key_path,
                password=pwd,
                passphrase=passphrase,
                known_hosts_path=str(self._store.managed_known_hosts_path),
                ssh_client=self._ssh_mgr,
            ),
        )

    def _handle_auth_result(self, error: str) -> None:
        if error:
            self._auth_ok = False
            _set_badge(self.auth_status_badge, "failed", "err")
            self.auth_diag.setPlainText(error)
            self._show_error(error)
            return
        self._auth_ok = True
        self._clear_error()
        _set_badge(self.auth_status_badge, "ok", "ok")
        self.auth_diag.setPlainText("Authentication succeeded against pinned host key.")

    def start_os_probe(self) -> None:
        if self._approved_host_key is None or not self._auth_ok:
            return
        try:
            host, port, user = self._validated_endpoint()
            user = validate_ssh_username(user, required=True)
        except ValueError as exc:
            self._show_error(str(exc))
            return
        mode = str(self.auth_combo.currentData() or "agent")
        key_path = self.key_path_edit.text().strip()
        pwd = self.password_edit.text()
        passphrase = self.passphrase_edit.text()
        approved = self._approved_host_key
        cancel_ev = threading.Event()
        self._run_worker(
            "os",
            lambda: probe_remote_os_and_capabilities(
                self._ssh_mgr,
                host,
                port,
                user,
                auth_method=mode,
                approved_host_key=approved,
                key_path=key_path,
                password=pwd,
                passphrase=passphrase,
                known_hosts_path=str(self._store.managed_known_hosts_path),
                cancel_event=cancel_ev,
            ),
        )
        self._cancel_event = cancel_ev

    def _handle_os_result(self, payload: object, error: str) -> None:
        if error or not isinstance(payload, RemoteCapabilityProbeResult):
            _set_badge(self.os_badge, "error", "err")
            self.os_details.setPlainText(error or "OS detection failed")
            return
        self._capability_probe = payload
        variant = "ok" if payload.detected_os in ("linux", "windows") else "warn"
        _set_badge(self.os_badge, payload.detected_os, variant)
        self.os_details.setPlainText(
            f"OS: {payload.detected_os} ({payload.os_detail})\n"
            f"Capabilities: {', '.join(payload.capabilities) or 'none'}\n"
            + ("\n".join(payload.warnings) if payload.warnings else "Read-only probe completed (no device changes).")
        )

    @staticmethod
    def _split_csv(text: str) -> tuple[str, ...]:
        return tuple(x.strip() for x in text.split(",") if x.strip())

    def _build_draft_profile(self) -> DeviceProfile:
        host, port, user = self._validated_endpoint()
        dev_id = (self.id_edit.text().strip() or host.replace(".", "_").replace(":", "_"))[:64]
        det_os = self._capability_probe.detected_os if self._capability_probe else ""
        det_caps = self._capability_probe.capabilities if self._capability_probe else ()
        return DeviceProfile(
            device_id=dev_id,
            name=self.name_edit.text().strip() or dev_id,
            host=host,
            port=port,
            username=user,
            group=self.group_edit.text().strip() or "default",
            auth_method=str(self.auth_combo.currentData() or "agent"),
            key_path=self.key_path_edit.text().strip(),
            strict_host_key=True,
            allowed_sftp_roots=self._split_csv(self.sftp_roots_edit.text()),
            allowed_commands=tuple(ln.strip() for ln in self.commands_edit.toPlainText().splitlines() if ln.strip()),
            allowed_services=self._split_csv(self.services_edit.text()),
            min_profile=str(self.min_profile_combo.currentData() or "allowlist"),
            allowed_clients=self._split_csv(self.allowed_clients_edit.text()),
            permissions=DevicePermissions(
                execute=self.perm_exec.isChecked(),
                sftp_read=self.perm_sftp_r.isChecked(),
                sftp_write=self.perm_sftp_w.isChecked(),
                service_control=self.perm_svc.isChecked(),
                metrics=self.perm_metrics.isChecked(),
                docker_read=self.perm_docker.isChecked(),
            ),
            allow_oauth_clients=self.allow_oauth_chk.isChecked(),
            detected_os=det_os,
            detected_capabilities=det_caps,
        )

    def _refresh_preview(self) -> None:
        if self._approved_host_key is None or self.stack.currentIndex() != 4:
            return
        try:
            draft = self._build_draft_profile()
            prev = prepare_device_wizard_preview(
                self._store,
                draft,
                approved_host_key=self._approved_host_key,
                password=self.password_edit.text(),
                passphrase=self.passphrase_edit.text(),
            )
            self._preview = prev
            text = prev.summary_text
            if prev.warnings:
                text += "\n\nWarnings:\n" + "\n".join(f"- {w}" for w in prev.warnings)
            self.preview_view.setPlainText(self._redactor.redact_text(text))
        except Exception as exc:  # noqa: BLE001
            self._preview = None
            self.preview_view.setPlainText(self._redactor.redact_text(str(exc)))

    def go_back(self) -> None:
        cur = self.stack.currentIndex()
        if cur > 0:
            self._set_step(cur - 1)

    def _validate_step0_advance(self) -> bool:
        try:
            self._validated_endpoint()
        except ValueError as exc:
            self._show_error(str(exc))
            return False
        return True

    def _validate_step2_advance(self) -> bool:
        if not self._auth_ok:
            self._show_error("Test SSH authentication before continuing")
            return False
        return True

    def go_next(self) -> None:
        cur = self.stack.currentIndex()
        validators = {
            0: self._validate_step0_advance,
            1: self._verify_host_key_step,
            2: self._validate_step2_advance,
        }
        check = validators.get(cur)
        if check is None or check():
            if cur < 4:
                self._set_step(cur + 1)

    def _on_primary_clicked(self) -> None:
        if self.stack.currentIndex() == 4:
            self.commit_wizard()
        else:
            self.go_next()

    def commit_wizard(self) -> None:
        if self._approved_host_key is None or self._preview is None:
            self._show_error("Complete verification and preview first")
            return
        try:
            draft = self._build_draft_profile()
            saved = commit_device_wizard_plan(
                self._store,
                draft,
                approved_host_key=self._approved_host_key,
                expected_snapshot=self._preview.snapshot,
                password=self.password_edit.text(),
                passphrase=self.passphrase_edit.text(),
            )
        except Exception as exc:  # noqa: BLE001
            self._show_error(str(exc))
            return
        self.committed_profile = saved
        self._clear_transient_secrets()
        self.accept()

    def _clear_transient_secrets(self) -> None:
        self.password_edit.clear()
        self.passphrase_edit.clear()

    def _request_manual_form(self) -> None:
        self.manual_requested = True
        self.reject()

    def reject(self) -> None:
        self.cancel_active_worker()
        for w in [*self._retired_workers, self._worker]:
            if w is not None and w.isRunning():
                w.wait(1000)
        self._clear_transient_secrets()
        super().reject()

    def retranslate(self) -> None:
        self.setWindowTitle(tr("devices.wizard.title"))
        self._lead_lbl.setText(tr("devices.wizard.lead"))
        self.guide_btn.setText(tr("devices.btn.setup_guide"))
        for idx, key in enumerate(("step0", "step1", "step2", "step3", "step4")):
            self._step_pills[idx].setText(tr(f"devices.wizard.{key}"))
        self._src_btns["manual"].setText(tr("devices.wizard.src_manual"))
        self._src_btns["ssh_config"].setText(tr("devices.wizard.src_ssh_config"))
        self._src_btns["cidr"].setText(tr("devices.wizard.src_cidr"))
        self._src_btns["tailscale"].setText(tr("devices.wizard.src_tailscale"))
        for k, lbl in self._src_labels.items():
            lbl.setText(tr(k))
        self.ssh_cfg_browse_btn.setText(tr("devices.wizard.browse"))
        self.ssh_cfg_load_btn.setText(tr("devices.wizard.load_config"))
        self.ssh_cfg_apply_btn.setText(tr("devices.wizard.apply_candidate"))
        self._cidr_lbl.setText(tr("devices.wizard.cidr_label"))
        self._ports_lbl.setText(tr("devices.wizard.ports_label"))
        self.cidr_consent_chk.setText(tr("devices.wizard.cidr_consent"))
        self.scan_cidr_btn.setText(tr("devices.wizard.scan_cidr"))
        self.cancel_cidr_btn.setText(tr("devices.wizard.cancel_op"))
        self.cidr_apply_btn.setText(tr("devices.wizard.apply_candidate"))
        self.ts_consent_chk.setText(tr("devices.wizard.ts_consent"))
        self.load_ts_btn.setText(tr("devices.wizard.load_ts"))
        self.ts_apply_btn.setText(tr("devices.wizard.apply_candidate"))
        self.probe_hk_btn.setText(tr("devices.wizard.probe_host_key"))
        self.cancel_hk_btn.setText(tr("devices.wizard.cancel_op"))
        self._fp_lbl.setText(tr("devices.wizard.expected_fp"))
        self.expected_fp_edit.setPlaceholderText(tr("devices.wizard.expected_fp_ph"))
        self.independent_verify_chk.setText(tr("devices.wizard.independent_chk"))
        for k, lbl in self._auth_labels.items():
            lbl.setText(tr(k))
        self.key_browse_btn.setText(tr("devices.wizard.browse"))
        self.gen_key_btn.setText(tr("devices.wizard.gen_key_btn"))
        self.test_auth_btn.setText(tr("devices.wizard.test_auth_btn"))
        self.probe_os_btn.setText(tr("devices.wizard.probe_os_btn"))
        self.allow_oauth_chk.setText(tr("devices.wizard.allow_oauth_chk"))
        for k, lbl in self._acc_labels.items():
            lbl.setText(tr(k))
        self.preview_title_lbl.setText(tr("devices.wizard.preview_title"))
        self.manual_btn.setText(tr("devices.wizard.manual_btn"))
        self.back_btn.setText(tr("devices.wizard.back"))
        self.cancel_btn.setText(tr("devices.wizard.cancel"))
        self.next_btn.setText(tr("devices.wizard.save") if self.stack.currentIndex() == 4 else tr("devices.wizard.next"))
