"""TDD integration tests for app.updater lifecycle, transactions, rollback & UI (N02)."""
from __future__ import annotations

import hashlib
import io
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from PyQt6.QtWidgets import QApplication
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import Settings
from app.core.redaction import SecretRedactor
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.automation_page import AutomationPage
from app.updater.detector import InstallEnvironment, detect_install_environment
from app.updater.helper import (
    apply_installed_transaction,
    apply_portable_transaction,
    has_active_tasks,
    recover_interrupted_update_on_boot,
    verify_handoff_token,
)
from app.updater.manager import UpdateManager
from app.updater.models import (
    TrustRootKey,
    UpdateBlockReason,
    UpdateState,
    UpdateTransaction,
)
from app.updater.trust import TrustPolicy
from tools.release_manifest import main as release_manifest_main


def _ensure_qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


class UpdaterLifecycleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = _ensure_qapp()

    def test_detector_distinguishes_dev_portable_and_installed_without_foreign_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Non-frozen defaults to dev blocked mode
            dev_env = detect_install_environment(frozen=False, app_dir=root)
            self.assertEqual(dev_env.install_type, "dev")
            self.assertIn(UpdateBlockReason.DEV_MODE, dev_env.block_reasons)

            # Portable clean directory
            port_dir = root / "PortableApp"
            port_dir.mkdir()
            (port_dir / "MCPApp.exe").write_bytes(b"MZ")
            (port_dir / "_internal").mkdir()
            port_env = detect_install_environment(frozen=True, app_dir=port_dir)
            self.assertEqual(port_env.install_type, "portable")
            self.assertEqual(port_env.block_reasons, ())

            # Foreign folder in portable directory blocks swap
            (port_dir / "MyPersonalStuff").mkdir()
            foreign_env = detect_install_environment(frozen=True, app_dir=port_dir)
            self.assertIn(UpdateBlockReason.FOREIGN_FILES_IN_INSTALL_DIR, foreign_env.block_reasons)

            # Installed mode detected via unins000.exe + unins000.dat
            inst_dir = root / "InstalledApp"
            inst_dir.mkdir()
            (inst_dir / "MCPApp.exe").write_bytes(b"MZ")
            (inst_dir / "unins000.exe").write_bytes(b"MZ")
            (inst_dir / "unins000.dat").write_bytes(b"DAT")
            inst_env = detect_install_environment(frozen=True, app_dir=inst_dir)
            self.assertEqual(inst_env.install_type, "installed")
            # Missing rollback contract blocks automatic install
            self.assertIn(UpdateBlockReason.NO_ROLLBACK_CONTRACT, inst_env.block_reasons)

    def test_active_tasks_and_handoff_token_gate_update_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "tasks.sqlite3"
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT NOT NULL)")
            conn.execute("INSERT INTO tasks VALUES ('t1', 'running')")
            conn.commit()
            conn.close()
            self.assertTrue(has_active_tasks(db))

            conn = sqlite3.connect(db)
            conn.execute("UPDATE tasks SET status = 'succeeded' WHERE id = 't1'")
            conn.commit()
            conn.close()
            self.assertFalse(has_active_tasks(db))

        self.assertTrue(verify_handoff_token("sec-abc", "sec-abc", issued_at=100.0, now=110.0, ttl_seconds=120.0))
        self.assertFalse(verify_handoff_token("sec-abc", "wrong", issued_at=100.0, now=110.0, ttl_seconds=120.0))
        self.assertFalse(verify_handoff_token("sec-abc", "sec-abc", issued_at=100.0, now=300.0, ttl_seconds=120.0))

    def test_portable_swap_verify_success_and_rollback_preserves_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "MCPApp"
            app_dir.mkdir()
            (app_dir / "MCPApp.exe").write_bytes(b"OLD_EXE")
            (app_dir / "_internal").mkdir()
            (app_dir / "_internal" / "mod.txt").write_text("old", encoding="utf-8")

            stage_dir = root / "updates" / "staged"
            stage_dir.mkdir(parents=True)
            (stage_dir / "MCPApp.exe").write_bytes(b"NEW_EXE")
            (stage_dir / "_internal").mkdir()
            (stage_dir / "_internal" / "mod.txt").write_text("new", encoding="utf-8")

            data_dir = root / "APPDATA_MCPApp"
            data_dir.mkdir()
            (data_dir / "token.json").write_text('{"token":"keep-me"}', encoding="utf-8")
            (data_dir / "schedules.json").write_text('[{"id":"s1","enabled":false}]', encoding="utf-8")

            state_path = root / "updates" / "state.json"

            # 1. Failed health check triggers automatic rollback
            tx_fail = apply_portable_transaction(
                tx_id="tx-fail",
                install_dir=app_dir,
                staged_dir=stage_dir,
                expected_hashes=None,
                source_version="1.0.2",
                target_version="1.0.3",
                state_path=state_path,
                data_dir=data_dir,
                verify_callback=lambda target_dir, data: False,
            )
            self.assertEqual(tx_fail.state, UpdateState.ROLLED_BACK)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"OLD_EXE")
            self.assertEqual((data_dir / "token.json").read_text(encoding="utf-8"), '{"token":"keep-me"}')

            # 2. Successful swap commits and removes backup
            tx_ok = apply_portable_transaction(
                tx_id="tx-ok",
                install_dir=app_dir,
                staged_dir=stage_dir,
                expected_hashes=None,
                source_version="1.0.2",
                target_version="1.0.3",
                state_path=state_path,
                data_dir=data_dir,
                verify_callback=lambda target_dir, data: (target_dir / "MCPApp.exe").read_bytes() == b"NEW_EXE",
            )
            self.assertEqual(tx_ok.state, UpdateState.COMMITTED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"NEW_EXE")
            self.assertEqual((data_dir / "schedules.json").read_text(encoding="utf-8"), '[{"id":"s1","enabled":false}]')

    def test_installed_transaction_runs_non_elevated_inno_silent_flags_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "InstalledApp"
            app_dir.mkdir()
            (app_dir / "MCPApp.exe").write_bytes(b"OLD_EXE")
            (app_dir / "unins000.exe").write_bytes(b"UNINS")
            (app_dir / "unins000.dat").write_bytes(b"DAT")

            new_installer = root / "MCPApp-Setup-1.0.3.exe"
            new_installer.write_bytes(b"SETUP_NEW")
            old_installer = root / "MCPApp-Setup-1.0.2.exe"
            old_installer.write_bytes(b"SETUP_OLD")

            recorded_calls: list[tuple[list[str], str]] = []

            def _fake_run(cmd: list[str], env: dict[str, str]):
                recorded_calls.append((cmd, env.get("__COMPAT_LAYER", "")))
                return 0

            tx = apply_installed_transaction(
                tx_id="tx-inst-rollback",
                install_dir=app_dir,
                installer_path=new_installer,
                rollback_installer_path=old_installer,
                source_version="1.0.2",
                target_version="1.0.3",
                state_path=root / "state.json",
                run_installer=_fake_run,
                verify_callback=lambda target_dir, data: False,
            )
            self.assertEqual(tx.state, UpdateState.ROLLED_BACK)
            self.assertEqual(len(recorded_calls), 2)
            for cmd, compat in recorded_calls:
                self.assertIn("/VERYSILENT", cmd)
                self.assertIn("/NORESTART", cmd)
                self.assertEqual(compat, "RunAsInvoker")

    def test_boot_recovery_restores_interrupted_swap_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "MCPApp"
            backup_dir = root / ".MCPApp-old-tx-crash"
            backup_dir.mkdir()
            (backup_dir / "MCPApp.exe").write_bytes(b"RECOVERED_OLD")
            state_path = root / "updates" / "state.json"
            state_path.parent.mkdir(parents=True)
            tx = UpdateTransaction(
                tx_id="tx-crash",
                state=UpdateState.VERIFYING_NEW,
                install_type="portable",
                source_version="1.0.2",
                target_version="1.0.3",
                install_dir=str(app_dir),
                backup_dir=str(backup_dir),
            )
            state_path.write_text(json.dumps({"active_transaction": tx.to_dict()}), encoding="utf-8")

            recovered = recover_interrupted_update_on_boot(state_path, root / "updates")
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.state, UpdateState.ROLLED_BACK)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"RECOVERED_OLD")

    def test_ui_automation_updater_section_controls_cancel_and_i18n_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg"
            cfg.mkdir()
            settings = Settings()
            page = AutomationPage(
                automation_dir=cfg / "automation",
                config_root=cfg,
                redactor=SecretRedactor([]),
                settings=settings,
            )
            try:
                self.assertTrue(hasattr(page, "updater_auto_check_toggle"))
                self.assertTrue(hasattr(page, "updater_auto_download_toggle"))
                self.assertTrue(hasattr(page, "updater_auto_install_toggle"))
                self.assertTrue(hasattr(page, "updater_cancel_btn"))
                self.assertTrue(hasattr(page, "updater_changelog"))
                self.assertTrue(hasattr(page, "updater_progress"))

                # Production build blocks auto_install by default when no trust roots provisioned
                self.assertFalse(settings.update_auto_install)
                i18n.set_language(LANG_EN)
                page.retranslate()
                en_btn = page.updater_check_btn.text()
                i18n.set_language(LANG_RU)
                page.retranslate()
                ru_btn = page.updater_check_btn.text()
                self.assertNotEqual(en_btn, ru_btn)
            finally:
                i18n.set_language(LANG_RU)
                page.shutdown()
                page.close()

    def test_release_manifest_tool_and_update_manager_end_to_end_staging(self) -> None:
        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_b64 = __import__("base64").b64encode(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist_dir = root / "dist"
            dist_dir.mkdir()
            inst = dist_dir / "MCPApp-Setup-1.0.3.exe"
            inst.write_bytes(b"MZ-SETUP-1.0.3")
            port = dist_dir / "MCPApp-1.0.3-portable.zip"
            with zipfile.ZipFile(port, "w") as zf:
                zf.writestr("MCPApp/MCPApp.exe", b"MZ-PORTABLE-1.0.3")
                zf.writestr("MCPApp/_internal/version.txt", b"1.0.3")

            manifest_out = dist_dir / "update-manifest.json"
            with __import__("unittest.mock").mock.patch.dict(
                "os.environ",
                {
                    "MCPAPP_UPDATER_KEY_ID": "test-root-1",
                    "MCPAPP_UPDATER_ED25519_PRIV_B64": __import__("base64").b64encode(priv_raw).decode("ascii"),
                },
            ):
                rc = release_manifest_main(
                    [
                        "--version",
                        "1.0.3",
                        "--installer",
                        str(inst),
                        "--portable",
                        str(port),
                        "--output",
                        str(manifest_out),
                    ]
                )
            self.assertEqual(rc, 0)
            manifest_bytes = manifest_out.read_bytes()
            sig_bytes = (dist_dir / "update-manifest.json.sig").read_bytes()

            app_dir = root / "PortableInstall"
            app_dir.mkdir()
            (app_dir / "MCPApp.exe").write_bytes(b"OLD")
            (app_dir / "_internal").mkdir()
            env = InstallEnvironment(
                install_type="portable",
                install_dir=app_dir,
                exe_path=app_dir / "MCPApp.exe",
                uninstall_exe=None,
                writable=True,
                has_rollback_contract=True,
                rollback_installer=None,
            )
            policy = TrustPolicy(trust_roots=(TrustRootKey("test-root-1", pub_b64),))
            settings = Settings(update_auto_check=True, update_auto_download=False, update_auto_install=False)
            data_dir = root / "data"
            mgr = UpdateManager(settings, data_dir, policy=policy, current_version="1.0.2", environment=env)

            release_json = json.dumps(
                {
                    "tag_name": "v1.0.3",
                    "draft": False,
                    "prerelease": False,
                    "assets": [
                        {
                            "name": "update-manifest.json",
                            "browser_download_url": "https://objects.githubusercontent.com/r/update-manifest.json",
                        },
                        {
                            "name": "update-manifest.json.sig",
                            "browser_download_url": "https://objects.githubusercontent.com/r/update-manifest.json.sig",
                        },
                        {
                            "name": port.name,
                            "browser_download_url": f"https://objects.githubusercontent.com/r/{port.name}",
                        },
                    ],
                }
            ).encode("utf-8")

            def _fetch(url: str) -> bytes:
                if url.endswith("/releases/latest"):
                    return release_json
                if url.endswith("update-manifest.json"):
                    return manifest_bytes
                if url.endswith("update-manifest.json.sig"):
                    return sig_bytes
                raise AssertionError(f"Unexpected metadata URL: {url}")

            snap = mgr.check_for_updates(force=True, fetch_bytes=_fetch)
            self.assertEqual(snap.state, UpdateState.AVAILABLE)
            self.assertEqual(snap.latest_version, "1.0.3")
            self.assertFalse(mgr.should_auto_check())

            class _Resp:
                def __init__(self, payload: bytes) -> None:
                    self._buf = io.BytesIO(payload)

                def read(self, n: int = -1) -> bytes:
                    return self._buf.read(n)

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

            port_bytes = port.read_bytes()
            staged_snap = mgr.download_and_stage(open_url=lambda req, timeout=30: _Resp(port_bytes))
            self.assertEqual(staged_snap.state, UpdateState.READY_TO_INSTALL)
            self.assertTrue((Path(staged_snap.staged_path) / "MCPApp.exe").is_file())
            self.assertEqual(
                hashlib.sha256((Path(staged_snap.staged_path) / "MCPApp.exe").read_bytes()).hexdigest(),
                hashlib.sha256(b"MZ-PORTABLE-1.0.3").hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
