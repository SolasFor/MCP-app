"""Auxiliary dialogs for Stage N05 SSH onboarding: contextual OS guide, keygen & key rotation."""
from __future__ import annotations

import threading
from html import escape
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.ui.components.cards import Badge, Divider
from app.ui.components.silent_dialog import SilentDialog
from app.ui.i18n import LANG_RU, i18n, tr
from backend.remote.host_keys import (
    HostKeyProbeResult,
    probe_ssh_host_key,
    verify_independent_host_key,
)
from backend.remote.models import DeviceProfile
from backend.remote.onboarding import generate_ssh_ed25519_keypair, rotate_device_host_key
from backend.remote.store import DeviceStore


def _guide_html(section: str) -> str:
    ru = i18n.language == LANG_RU
    if section == "windows":
        title = "Windows 10 / 11 (OpenSSH Server)"
        steps = (
            "1. Установите OpenSSH Server на целевом ПК (от администратора, вручную):<br>"
            "<code>Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0</code><br>"
            "2. Запустите службу и включите автозапуск вручную:<br>"
            "<code>Start-Service sshd; Set-Service -Name sshd -StartupType Automatic</code><br>"
            "3. Проверьте правило брандмауэра (предпочтительно только локальная/VPN-подсеть):<br>"
            "<code>Get-NetFirewallRule -Name *OpenSSH-Server*</code><br>"
            "4. Ключи: для обычного пользователя <code>%USERPROFILE%\\.ssh\\authorized_keys</code>; "
            "для группы Администраторы <code>%ProgramData%\\ssh\\administrators_authorized_keys</code> (ACL только SYSTEM и Administrators).<br>"
            "5. Получите fingerprint на целевой консоли для независимой сверки:<br>"
            "<code>ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub</code>"
            if ru
            else "1. Install OpenSSH Server on the target PC manually (elevated PowerShell):<br>"
            "<code>Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0</code><br>"
            "2. Start and enable sshd manually:<br>"
            "<code>Start-Service sshd; Set-Service -Name sshd -StartupType Automatic</code><br>"
            "3. Verify firewall rule (prefer Private/VPN profile, not public internet):<br>"
            "<code>Get-NetFirewallRule -Name *OpenSSH-Server*</code><br>"
            "4. Keys: standard users use <code>%USERPROFILE%\\.ssh\\authorized_keys</code>; "
            "Administrators use <code>%ProgramData%\\ssh\\administrators_authorized_keys</code>.<br>"
            "5. Print the host key fingerprint on the target console for independent verification:<br>"
            "<code>ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub</code>"
        )
    elif section == "linux":
        title = "Linux (Debian/Ubuntu, RHEL/Fedora, Arch)"
        steps = (
            "1. Установите пакет OpenSSH Server вручную на целевом хосте:<br>"
            "• Debian/Ubuntu: <code>sudo apt install openssh-server</code><br>"
            "• RHEL/Fedora: <code>sudo dnf install openssh-server</code><br>"
            "• Arch: <code>sudo pacman -S openssh</code><br>"
            "2. Включите службу: <code>sudo systemctl enable --now ssh</code> (или <code>sshd</code>).<br>"
            "3. Права на ключи: <code>chmod 700 ~/.ssh &amp;&amp; chmod 600 ~/.ssh/authorized_keys</code>.<br>"
            "4. Не включайте без необходимости PasswordAuthentication или PermitRootLogin.<br>"
            "5. Получите SHA-256 fingerprint на локальной консоли устройства:<br>"
            "<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>"
            if ru
            else "1. Install OpenSSH Server manually on the target host:<br>"
            "• Debian/Ubuntu: <code>sudo apt install openssh-server</code><br>"
            "• RHEL/Fedora: <code>sudo dnf install openssh-server</code><br>"
            "• Arch: <code>sudo pacman -S openssh</code><br>"
            "2. Enable service: <code>sudo systemctl enable --now ssh</code> (or <code>sshd</code>).<br>"
            "3. Key permissions: <code>chmod 700 ~/.ssh &amp;&amp; chmod 600 ~/.ssh/authorized_keys</code>.<br>"
            "4. Keep PermitRootLogin disabled and prefer key auth over passwords.<br>"
            "5. Read SHA-256 fingerprint on the device's local console:<br>"
            "<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>"
        )
    else:
        title = "LAN / VPN / Tailscale vs MCP Gateway"
        steps = (
            "• SSH обычно используется в локальной сети (LAN) или через VPN (например Tailscale). "
            "Не открывайте порт 22 в публичный интернет без крайней необходимости.<br>"
            "• При доступном SSH на удалённом устройстве устанавливать MCP App на него <b>не требуется</b>.<br>"
            "• Раздел «Устройства (SSH / SFTP)» управляет удалёнными машинами через строгий SSH/Paramiko (RejectPolicy) "
            "и не объединяется с внешними MCP-серверами в «Шлюзе (Gateway)»."
            if ru
            else "• SSH normally operates over LAN or a private VPN (such as Tailscale). "
            "Do not expose TCP port 22 directly to the public internet.<br>"
            "• A remote device does <b>not</b> need MCP App installed when SSH is enabled.<br>"
            "• Remote Devices (SSH/SFTP) use strict Paramiko RejectPolicy and remain architecturally separate from standalone MCP Gateway endpoints."
        )
    return f"<h3>{escape(title)}</h3><p>{steps}</p>"


class SSHSetupGuideDialog(SilentDialog):
    """Contextual manual Windows/Linux/Network OpenSSH setup guide (zero remote automation)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(520, 380)
        self.resize(640, 460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)

        self.tabs = QTabWidget()
        self._win_browser = QTextBrowser()
        self.browser = self._win_browser
        self._linux_browser = QTextBrowser()
        self._net_browser = QTextBrowser()
        for browser in (self._win_browser, self._linux_browser, self._net_browser):
            browser.setOpenExternalLinks(False)
        self.tabs.addTab(self._win_browser, "")
        self.tabs.addTab(self._linux_browser, "")
        self.tabs.addTab(self._net_browser, "")
        lay.addWidget(self.tabs, 1)

        close_btn = QPushButton(tr("management.guide.close"))
        close_btn.clicked.connect(self.accept)
        lay.addWidget(close_btn, 0, Qt.AlignmentFlag.AlignRight)
        self.retranslate()

    def retranslate(self) -> None:
        self.setWindowTitle(tr("devices.setup_guide.title"))
        self.tabs.setTabText(0, tr("devices.setup_guide.win_tab"))
        self.tabs.setTabText(1, tr("devices.setup_guide.linux_tab"))
        self.tabs.setTabText(2, tr("devices.setup_guide.net_tab"))
        self._win_browser.setHtml(_guide_html("windows"))
        self._linux_browser.setHtml(_guide_html("linux"))
        self._net_browser.setHtml(_guide_html("net"))


class GenerateSSHKeyDialog(SilentDialog):
    """Explicitly generate an Ed25519 SSH keypair without overwriting existing files."""

    def __init__(
        self,
        *,
        default_dir: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.generated_private_path: str = ""
        self.generated_public_line: str = ""
        self.setMinimumWidth(520)

        base_dir = default_dir if default_dir is not None else (Path.home() / ".ssh")
        default_path = str(base_dir / "id_ed25519_mcp")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(8)
        form = QFormLayout()
        form.setSpacing(6)

        path_row = QHBoxLayout()
        self.path_edit = QLineEdit(default_path)
        self.path_edit.setObjectName("UiInput")
        self.path_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.browse_btn = QPushButton(tr("devices.wizard.browse"))
        self.browse_btn.clicked.connect(self._browse_target)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.browse_btn)

        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setObjectName("UiInput")
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setObjectName("UiInput")
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.comment_edit = QLineEdit("mcp-app")
        self.comment_edit.setObjectName("UiInput")

        form.addRow(tr("devices.keygen.path"), path_row)
        form.addRow(tr("devices.keygen.passphrase"), self.passphrase_edit)
        form.addRow(tr("devices.keygen.confirm"), self.confirm_edit)
        form.addRow(tr("devices.keygen.comment"), self.comment_edit)
        lay.addLayout(form)

        self.gen_btn = QPushButton(tr("devices.keygen.generate"))
        self.gen_btn.setObjectName("Accent")
        self.gen_btn.clicked.connect(self.generate_key)
        lay.addWidget(self.gen_btn, 0, Qt.AlignmentFlag.AlignLeft)

        self.error_lbl = QLabel()
        self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet("color: #f87171; font-weight: 500;")
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        lay.addWidget(Divider())
        pub_lbl = QLabel(tr("devices.keygen.pub_label"))
        pub_lbl.setObjectName("FieldLabel")
        pub_lbl.setWordWrap(True)
        lay.addWidget(pub_lbl)

        self.pub_output = QPlainTextEdit()
        self.pub_output.setObjectName("ConsoleLog")
        self.pub_output.setReadOnly(True)
        self.pub_output.setMaximumHeight(96)
        lay.addWidget(self.pub_output)

        footer = QHBoxLayout()
        self.copy_btn = QPushButton(tr("devices.keygen.copy_pub"))
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy_public_key)
        self.done_btn = QPushButton(tr("management.guide.close"))
        self.done_btn.clicked.connect(self._on_done)
        footer.addWidget(self.copy_btn)
        footer.addStretch(1)
        footer.addWidget(self.done_btn)
        lay.addLayout(footer)
        self.setWindowTitle(tr("devices.keygen.title"))

    def _browse_target(self) -> None:
        chosen, _ = QFileDialog.getSaveFileName(self, tr("devices.keygen.title"), self.path_edit.text().strip())
        if chosen:
            self.path_edit.setText(chosen)

    def _show_error(self, msg: str) -> None:
        self.error_lbl.setText(msg)
        self.error_lbl.show()

    def _clear_error(self) -> None:
        self.error_lbl.clear()
        self.error_lbl.hide()

    def generate_key(self) -> None:
        self._clear_error()
        pwd = self.passphrase_edit.text()
        if pwd != self.confirm_edit.text():
            self._show_error("Passphrases do not match")
            return
        try:
            res = generate_ssh_ed25519_keypair(
                Path(self.path_edit.text().strip()),
                passphrase=pwd,
                comment=self.comment_edit.text().strip(),
            )
        except Exception as exc:  # noqa: BLE001
            self._show_error(str(exc))
            return
        self.generated_private_path = res.private_key_path
        self.generated_public_line = res.public_key_line
        self.pub_output.setPlainText(f"{res.public_key_line}\n\nFingerprint: {res.fingerprint_sha256}")
        self.copy_btn.setEnabled(True)
        self.passphrase_edit.clear()
        self.confirm_edit.clear()

    def _copy_public_key(self) -> None:
        if not self.generated_public_line:
            return
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(self.generated_public_line)

    def _on_done(self) -> None:
        self.passphrase_edit.clear()
        self.confirm_edit.clear()
        if self.generated_private_path:
            self.accept()
        else:
            self.reject()

    def reject(self) -> None:
        self.passphrase_edit.clear()
        self.confirm_edit.clear()
        super().reject()


class _RotateProbeWorker(QThread):
    finished_probe = pyqtSignal(int, object, str, arguments=["generation", "probe", "error"])

    def __init__(
        self,
        generation: int,
        device: DeviceProfile,
        cancel_event: threading.Event,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._generation = generation
        self._device = device
        self._cancel_event = cancel_event

    def run(self) -> None:
        try:
            pin = (
                (
                    self._device.pinned_host_key_algorithm,
                    self._device.pinned_host_key_sha256,
                    self._device.pinned_host_key_base64,
                )
                if self._device.has_pinned_host_key()
                else None
            )
            res = probe_ssh_host_key(
                self._device.host,
                self._device.port,
                known_hosts_path=self._device.known_hosts_path or None,
                include_system_known_hosts=not bool(self._device.known_hosts_path),
                expected_pin=pin,
                cancel_event=self._cancel_event,
            )
            self.finished_probe.emit(self._generation, res, "")
        except Exception as exc:  # noqa: BLE001
            self.finished_probe.emit(self._generation, None, str(exc) or type(exc).__name__)


class HostKeyRotationDialog(SilentDialog):
    """Explicit host-key rotation workflow requiring independent fingerprint verification."""

    def __init__(
        self,
        store: DeviceStore,
        device: DeviceProfile,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._device = device
        self._generation = 0
        self._worker: _RotateProbeWorker | None = None
        self._retired: list[_RotateProbeWorker] = []
        self._cancel_event: threading.Event | None = None
        self._probe: HostKeyProbeResult | None = None
        self.rotated_profile: DeviceProfile | None = None

        self.setMinimumWidth(560)
        self.setWindowTitle(tr("devices.rotate.title"))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(8)

        warn = QLabel(tr("devices.rotate.warn"))
        warn.setWordWrap(True)
        warn.setObjectName("Hint")
        lay.addWidget(warn)

        row = QHBoxLayout()
        self.status_badge = Badge(device.pinned_host_key_sha256 or "unpinned", variant="warn")
        self.probe_btn = QPushButton(tr("devices.rotate.probe"))
        self.probe_btn.clicked.connect(self.start_probe)
        row.addWidget(self.status_badge, 1)
        row.addWidget(self.probe_btn)
        lay.addLayout(row)

        self.probe_details = QPlainTextEdit()
        self.probe_details.setObjectName("ConsoleLog")
        self.probe_details.setReadOnly(True)
        self.probe_details.setMaximumHeight(90)
        lay.addWidget(self.probe_details)

        form = QFormLayout()
        self.expected_fp_edit = QLineEdit()
        self.expected_fp_edit.setObjectName("UiInput")
        self.expected_fp_edit.setPlaceholderText(tr("devices.wizard.expected_fp_ph"))
        self.expected_fp_edit.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        form.addRow(tr("devices.wizard.expected_fp"), self.expected_fp_edit)
        lay.addLayout(form)

        self.independent_verify_chk = QCheckBox(tr("devices.wizard.independent_chk"))
        lay.addWidget(self.independent_verify_chk)

        self.error_lbl = QLabel()
        self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet("color: #f87171; font-weight: 500;")
        self.error_lbl.hide()
        lay.addWidget(self.error_lbl)

        footer = QHBoxLayout()
        cancel_btn = QPushButton(tr("devices.wizard.cancel"))
        cancel_btn.clicked.connect(self.reject)
        self.apply_btn = QPushButton(tr("devices.rotate.apply"))
        self.apply_btn.setObjectName("Accent")
        self.apply_btn.clicked.connect(self.apply_rotation)
        footer.addStretch(1)
        footer.addWidget(cancel_btn)
        footer.addWidget(self.apply_btn)
        lay.addLayout(footer)

    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def start_probe(self) -> None:
        self._generation += 1
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._worker is not None and self._worker.isRunning():
            self._retired.append(self._worker)
        self._cancel_event = threading.Event()
        self.probe_btn.setEnabled(False)
        worker = _RotateProbeWorker(self._generation, self._device, self._cancel_event, self)
        worker.finished_probe.connect(self._on_probe_done)
        self._worker = worker
        worker.start()

    def _on_probe_done(self, generation: int, probe: object, err: str) -> None:
        self._retired = [w for w in self._retired if w.isRunning()]
        if generation != self._generation:
            return
        self.probe_btn.setEnabled(True)
        if err or not isinstance(probe, HostKeyProbeResult):
            self.status_badge.setText("error")
            self.status_badge.set_variant("err")
            self.probe_details.setPlainText(err or "Probe failed")
            return
        self._probe = probe
        self.status_badge.setText(probe.status)
        self.status_badge.set_variant("warn" if probe.status == "host_key_changed" else "ok")
        self.probe_details.setPlainText(
            f"Endpoint: {probe.host}:{probe.port}\n"
            f"Old Pin: {self._device.pinned_host_key_sha256 or 'none'}\n"
            f"New Key: {probe.key_algorithm} {probe.fingerprint_sha256}"
        )

    def _show_error(self, msg: str) -> None:
        self.error_lbl.setText(msg)
        self.error_lbl.show()

    def _clear_error(self) -> None:
        self.error_lbl.clear()
        self.error_lbl.hide()

    def apply_rotation(self) -> None:
        self._clear_error()
        if self._probe is None:
            self._show_error("Probe the current host key first")
            return
        try:
            approved = verify_independent_host_key(
                self._probe,
                expected_fingerprint_input=self.expected_fp_edit.text().strip(),
                verified_independently=self.independent_verify_chk.isChecked(),
                allow_rotation=True,
            )
            self.rotated_profile = rotate_device_host_key(self._store, self._device.device_id, approved)
        except Exception as exc:  # noqa: BLE001
            self._show_error(str(exc))
            return
        self.accept()

    def reject(self) -> None:
        self._generation += 1
        if self._cancel_event is not None:
            self._cancel_event.set()
        for w in [*self._retired, self._worker]:
            if w is not None and w.isRunning():
                w.wait(1000)
        super().reject()
