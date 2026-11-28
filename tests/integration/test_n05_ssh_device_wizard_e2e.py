"""Headless Qt E2E integration tests for Stage N05 SSH Device Wizard & DevicesPage."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.devices_page import DevicesPage
from app.ui.ssh_device_dialogs import (
    GenerateSSHKeyDialog,
    HostKeyRotationDialog,
    SSHSetupGuideDialog,
)
from app.ui.ssh_device_wizard import SSHDeviceWizardDialog
from backend.remote.host_keys import (
    ApprovedHostKey,
    compute_host_key_sha256,
    upsert_managed_known_host_entry,
)
from backend.remote.models import DeviceProfile
from backend.remote.store import DeviceStore
from tests.fixtures.local_ssh_server import LocalSSHServer


def _pump_until(app: QApplication, predicate, *, timeout_s: float = 8.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.02)
    app.processEvents()
    if not predicate():
        raise AssertionError("Timed out waiting for async Qt wizard state")


class N05SSHDeviceWizardE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home_dir = self.root / "home"
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self._env_patch = patch.dict(
            os.environ,
            {
                "HOME": str(self.home_dir),
                "USERPROFILE": str(self.home_dir),
            },
        )
        self._env_patch.start()
        self.sftp_root = self.root / "sftp"
        self.sftp_root.mkdir()
        self.srv = LocalSSHServer(
            self.sftp_root,
            username="opsuser",
            password="wizard-secret-pass",
            os_flavor="linux",
            enable_sftp=True,
        ).start()
        self.store = DeviceStore(
            self.root / "remote" / "devices.json",
            secret_store=SecretStore(self.root / "secrets"),
        )
        self.redactor = SecretRedactor()
        self.redactor.register("wizard-secret-pass")

    def tearDown(self) -> None:
        self.srv.stop()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self._env_patch.stop()
        self.tmp.cleanup()

    def test_wizard_full_manual_onboarding_deny_by_default_and_rotation(self) -> None:
        wiz = SSHDeviceWizardDialog(self.store, redactor=self.redactor)
        try:
            # Step 0: endpoint entry
            wiz.id_edit.setText("linux_lab")
            wiz.name_edit.setText("Linux Lab")
            wiz.host_edit.setText(self.srv.host)
            wiz.port_spin.setValue(self.srv.port)
            wiz.user_edit.setText("opsuser")
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 1)

            # Step 1: pre-auth host key probe (0 auth attempts), block blind TOFU, verify SHA256
            wiz.start_host_key_probe()
            _pump_until(self.app, lambda: not wiz.is_busy() and wiz._host_probe is not None)
            self.assertEqual(self.srv.auth_attempts, [])
            self.assertEqual(wiz._host_probe.status, "unknown_host")

            # Blind continue without independent fingerprint MUST stay on Step 1
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 1)
            self.assertTrue(bool(wiz.step_error_lbl.text()))

            # Wrong fingerprint blocked
            wiz.expected_fp_edit.setText("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            wiz.independent_verify_chk.setChecked(True)
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 1)
            self.assertIn("match", wiz.step_error_lbl.text().lower())

            # Matching fingerprint advances to Step 2 and clears inline error
            expected_fp = compute_host_key_sha256(self.srv.host_key)
            wiz.expected_fp_edit.setText(expected_fp)
            wiz.independent_verify_chk.setChecked(True)
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 2)
            self.assertEqual(wiz.step_error_lbl.text(), "")

            # Step 2: password auth test
            idx_pw = wiz.auth_combo.findData("password_ref")
            wiz.auth_combo.setCurrentIndex(idx_pw)
            wiz.password_edit.setText("wizard-secret-pass")
            wiz.start_auth_test()
            _pump_until(self.app, lambda: not wiz.is_busy() and wiz._auth_ok)
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 3)

            # Step 3: OS & capability probe
            _pump_until(self.app, lambda: not wiz.is_busy() and wiz._capability_probe is not None)
            self.assertEqual(wiz._capability_probe.detected_os, "linux")
            self.assertIn("sftp", wiz._capability_probe.capabilities)
            wiz.go_next()
            self.assertEqual(wiz.stack.currentIndex(), 4)

            # Step 4: verify deny-by-default & redacted preview, then commit
            self.assertFalse(wiz.allow_oauth_chk.isChecked())
            self.assertFalse(wiz.perm_exec.isChecked())
            self.assertFalse(wiz.perm_sftp_r.isChecked())
            self.assertNotIn("wizard-secret-pass", wiz.preview_view.toPlainText())

            wiz.commit_wizard()
            self.assertIsNotNone(wiz.committed_profile)
            saved = self.store.get("linux_lab", strict=True)
            self.assertIsNotNone(saved)
            assert saved is not None
            self.assertFalse(saved.allow_oauth_clients)
            self.assertEqual(saved.pinned_host_key_sha256, expected_fp)
            self.assertEqual(saved.detected_os, "linux")
            self.assertTrue(self.store.managed_known_hosts_path.is_file())
        finally:
            wiz.close()

        # Host key rotation dialog updates pinned key on server key rotation
        self.srv.rotate_host_key()
        new_fp = compute_host_key_sha256(self.srv.host_key)
        saved_dev = self.store.get("linux_lab", strict=True)
        assert saved_dev is not None
        rot = HostKeyRotationDialog(self.store, saved_dev)
        try:
            rot.start_probe()
            _pump_until(self.app, lambda: not rot.is_busy() and rot._probe is not None)
            self.assertEqual(rot._probe.status, "host_key_changed")
            rot.expected_fp_edit.setText(new_fp)
            rot.independent_verify_chk.setChecked(True)
            rot.apply_rotation()
            self.assertIsNotNone(rot.rotated_profile)
            assert rot.rotated_profile is not None
            self.assertEqual(rot.rotated_profile.pinned_host_key_sha256, new_fp)
        finally:
            rot.close()

    def test_wizard_cancel_writes_nothing_and_opt_in_discovery_gates(self) -> None:
        wiz = SSHDeviceWizardDialog(self.store, redactor=self.redactor)
        try:
            # Opt-in CIDR & Tailscale buttons disabled until explicit consent checked
            self.assertFalse(wiz.cidr_consent_chk.isChecked())
            self.assertFalse(wiz.scan_cidr_btn.isEnabled())
            self.assertFalse(wiz.ts_consent_chk.isChecked())
            self.assertFalse(wiz.load_ts_btn.isEnabled())

            # Enable CIDR consent and scan loopback
            wiz.cidr_consent_chk.setChecked(True)
            self.assertTrue(wiz.scan_cidr_btn.isEnabled())
            wiz.cidr_edit.setText("127.0.0.1/32")
            wiz.cidr_ports_edit.setText(str(self.srv.port))
            wiz.start_cidr_scan()
            _pump_until(self.app, lambda: not wiz.is_busy() and wiz.cidr_list.count() == 1)

            # Tailscale consent + mocked CLI JSON
            ts_json = json.dumps({
                "BackendState": "Running",
                "Peer": {
                    "n1": {
                        "HostName": "win-peer",
                        "DNSName": "win-peer.tailnet.ts.net.",
                        "TailscaleIPs": ["100.64.1.2"],
                        "OS": "windows",
                        "Online": True,
                    }
                },
            })
            from app.core.tunnels.base import BoundedCliResult

            wiz.ts_consent_chk.setChecked(True)
            with patch("backend.remote.discovery._find_tailscale", return_value="tailscale"), patch(
                "backend.remote.discovery.run_cli_capture_bounded",
                return_value=BoundedCliResult(returncode=0, stdout=ts_json, stderr=""),
            ):
                wiz.start_tailscale_discovery()
                _pump_until(self.app, lambda: not wiz.is_busy() and wiz.ts_list.count() == 1)

            # Enter password and cancel -> zero files written, password field cleared
            wiz.id_edit.setText("cancel_me")
            wiz.host_edit.setText(self.srv.host)
            wiz.port_spin.setValue(self.srv.port)
            wiz.password_edit.setText("unsaved-secret-123")
            wiz.reject()
            self.assertEqual(wiz.password_edit.text(), "")
            self.assertFalse(self.store.path.exists())
            self.assertFalse(self.store.managed_known_hosts_path.exists())
        finally:
            wiz.close()

    def test_guides_keygen_and_worst_case_geometry_ru_en_dark_light(self) -> None:
        key_target = self.root / "keys" / "id_ed25519_ui"
        keygen = GenerateSSHKeyDialog(default_dir=self.root / "keys")
        try:
            keygen.path_edit.setText(str(key_target))
            keygen.passphrase_edit.setText("p1")
            keygen.confirm_edit.setText("p1")
            keygen.generate_key()
            self.assertTrue(key_target.is_file())
            self.assertIn("ssh-ed25519 ", keygen.pub_output.toPlainText())
            self.assertNotIn("PRIVATE KEY", keygen.pub_output.toPlainText())
        finally:
            keygen.close()

        guide = SSHSetupGuideDialog()
        try:
            guide.resize(800, 540)
            guide.show()
            self.app.processEvents()
            self.assertGreater(guide.browser.width(), 300)
        finally:
            guide.close()

        # Worst-case realistic hostname / username / narrow 800x540 & 1366x768, RU/EN, Dark/Light
        long_host = "prod-cluster-node-01.eu-central-internal.northwind-holdings.example.com"
        long_user = r"NORTHWIND\Aleksandra.Wisniewska-Kowalczyk"
        page = DevicesPage(
            config_path=self.root / "gui_devices.json",
            secrets_dir=self.root / "gui_secrets",
            redactor=self.redactor,
        )
        try:
            page.store.upsert(
                DeviceProfile(
                    device_id="long_dev_01",
                    name="Aleksandra Long Workstation Profile",
                    host=long_host,
                    port=2222,
                    username=long_user,
                    allow_oauth_clients=False,
                )
            )
            for lang in (LANG_RU, LANG_EN):
                i18n.set_language(lang)
                for th in (theme.THEME_DARK, theme.THEME_LIGHT):
                    theme.apply(self.app, th)
                    page.retranslate()
                    page.resize(800, 540)
                    page.show()
                    self.app.processEvents()
                    self.assertLessEqual(page.table.width(), 800)

                    wiz = SSHDeviceWizardDialog(page.store, redactor=self.redactor, parent=page)
                    wiz.host_edit.setText(long_host)
                    wiz.user_edit.setText(long_user)
                    wiz.resize(800, 540)
                    wiz.show()
                    self.app.processEvents()
                    self.assertLessEqual(wiz.stack.width(), 800)
                    self.assertGreater(wiz.next_btn.width(), 0)
                    wiz.close()
        finally:
            page.shutdown()

    def test_host_key_changed_hard_fail_ssh_config_tab_windows_unknown_and_corrupt_banner(self) -> None:
        # Seed conflicting key in managed known_hosts -> Step 1 must hard-fail even with matching checkbox
        old_key = paramiko_generate_rsa_or_ed()
        upsert_managed_known_host_entry(
            self.store.managed_known_hosts_path,
            ApprovedHostKey(
                host=self.srv.host,
                port=self.srv.port,
                key_algorithm=old_key.get_name(),
                fingerprint_sha256=compute_host_key_sha256(old_key),
                public_key_base64=old_key.get_base64(),
                verified_at=1.0,
            ),
        )
        wiz_hk = SSHDeviceWizardDialog(self.store, redactor=self.redactor)
        try:
            wiz_hk.host_edit.setText(self.srv.host)
            wiz_hk.port_spin.setValue(self.srv.port)
            wiz_hk.user_edit.setText("opsuser")
            wiz_hk.go_next()
            wiz_hk.start_host_key_probe()
            _pump_until(self.app, lambda: not wiz_hk.is_busy() and wiz_hk._host_probe is not None)
            self.assertEqual(wiz_hk._host_probe.status, "host_key_changed")
            self.assertTrue(bool(wiz_hk.step_error_lbl.text()))
            wiz_hk.expected_fp_edit.setText(compute_host_key_sha256(self.srv.host_key))
            wiz_hk.independent_verify_chk.setChecked(True)
            wiz_hk.go_next()
            self.assertEqual(wiz_hk.stack.currentIndex(), 1)
            self.assertIn("changed", wiz_hk.step_error_lbl.text().lower())
        finally:
            wiz_hk.close()
        self.store.managed_known_hosts_path.unlink(missing_ok=True)

        # OpenSSH Config import tab + stale preview rejection + Windows & Unknown OS flows
        cfg_file = self.root / "ssh_config_test"
        cfg_file.write_text(
            f"Host lab-alias\n  HostName {self.srv.host}\n  Port {self.srv.port}\n  User opsuser\n  ProxyCommand evil\n"
            f"Match host *\n  User bad\n",
            encoding="utf-8",
        )
        win_srv = LocalSSHServer(
            self.sftp_root,
            username="opsuser",
            password="wizard-secret-pass",
            os_flavor="windows",
            enable_sftp=True,
        ).start()
        unk_srv = LocalSSHServer(
            self.sftp_root,
            username="opsuser",
            password="wizard-secret-pass",
            os_flavor="unknown",
            enable_sftp=False,
        ).start()
        try:
            wiz_win = SSHDeviceWizardDialog(self.store, redactor=self.redactor, initial_source="ssh_config")
            try:
                wiz_win.ssh_cfg_path_edit.setText(str(cfg_file))
                wiz_win.load_ssh_config_candidates()
                self.assertEqual(wiz_win.ssh_cfg_list.count(), 1)
                self.assertIn("ProxyCommand", wiz_win.ssh_cfg_diag.toPlainText())
                wiz_win.ssh_cfg_list.setCurrentRow(0)
                wiz_win.apply_selected_ssh_config()
                self.assertEqual(wiz_win.host_edit.text(), self.srv.host)

                # Switch endpoint to win_srv and verify Windows OS probe + stale preview block
                wiz_win.id_edit.setText("win_lab")
                wiz_win.host_edit.setText(win_srv.host)
                wiz_win.port_spin.setValue(win_srv.port)
                wiz_win.user_edit.setText("opsuser")
                wiz_win.go_next()
                wiz_win.start_host_key_probe()
                _pump_until(self.app, lambda: not wiz_win.is_busy() and wiz_win._host_probe is not None)
                wiz_win.expected_fp_edit.setText(compute_host_key_sha256(win_srv.host_key))
                wiz_win.independent_verify_chk.setChecked(True)
                wiz_win.go_next()
                wiz_win.auth_combo.setCurrentIndex(wiz_win.auth_combo.findData("password_ref"))
                wiz_win.password_edit.setText("wizard-secret-pass")
                wiz_win.start_auth_test()
                _pump_until(self.app, lambda: not wiz_win.is_busy() and wiz_win._auth_ok)
                wiz_win.go_next()
                _pump_until(self.app, lambda: not wiz_win.is_busy() and wiz_win._capability_probe is not None)
                self.assertEqual(wiz_win._capability_probe.detected_os, "windows")
                self.assertIn("sftp", wiz_win._capability_probe.capabilities)
                wiz_win.go_next()
                self.assertIsNotNone(wiz_win._preview)

                # Mutate store before commit -> stale preview rejected inline
                self.store.upsert(DeviceProfile(device_id="concurrent_dev", name="C", host="127.0.0.2"))
                wiz_win.commit_wizard()
                self.assertIsNone(wiz_win.committed_profile)
                self.assertTrue(bool(wiz_win.step_error_lbl.text()))
            finally:
                wiz_win.close()

            # Unknown OS + no SFTP flow
            wiz_unk = SSHDeviceWizardDialog(self.store, redactor=self.redactor)
            try:
                wiz_unk.id_edit.setText("unk_lab")
                wiz_unk.host_edit.setText(unk_srv.host)
                wiz_unk.port_spin.setValue(unk_srv.port)
                wiz_unk.user_edit.setText("opsuser")
                wiz_unk.go_next()
                wiz_unk.start_host_key_probe()
                _pump_until(self.app, lambda: not wiz_unk.is_busy() and wiz_unk._host_probe is not None)
                wiz_unk.expected_fp_edit.setText(compute_host_key_sha256(unk_srv.host_key))
                wiz_unk.independent_verify_chk.setChecked(True)
                wiz_unk.go_next()
                wiz_unk.auth_combo.setCurrentIndex(wiz_unk.auth_combo.findData("password_ref"))
                wiz_unk.password_edit.setText("wizard-secret-pass")
                wiz_unk.start_auth_test()
                _pump_until(self.app, lambda: not wiz_unk.is_busy() and wiz_unk._auth_ok)
                wiz_unk.go_next()
                _pump_until(self.app, lambda: not wiz_unk.is_busy() and wiz_unk._capability_probe is not None)
                self.assertEqual(wiz_unk._capability_probe.detected_os, "unknown")
                self.assertNotIn("sftp", wiz_unk._capability_probe.capabilities)
                wiz_unk.go_next()
                self.assertIn("unknown", wiz_unk.preview_view.toPlainText().lower())
            finally:
                wiz_unk.close()
        finally:
            win_srv.stop()
            unk_srv.stop()

        # Corrupt devices.json banner check on DevicesPage
        corrupt_cfg = self.root / "corrupt_devices.json"
        corrupt_cfg.write_text("{not-valid-json", encoding="utf-8")
        bad_page = DevicesPage(
            config_path=corrupt_cfg,
            secrets_dir=self.root / "corrupt_secrets",
            redactor=self.redactor,
        )
        try:
            bad_page.show()
            self.app.processEvents()
            self.assertFalse(bad_page.corrupt_banner.isHidden())
            self.assertEqual(bad_page.import_from_ssh_config(cfg_file), 0)
        finally:
            bad_page.shutdown()


def paramiko_generate_rsa_or_ed():
    import paramiko

    return paramiko.RSAKey.generate(2048)


if __name__ == "__main__":
    unittest.main()
