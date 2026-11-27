"""TDD regression tests reproducing N02 independent review findings N02-01..N02-05."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import Settings
from app.updater.detector import InstallEnvironment, detect_install_environment
from app.updater.helper import (
    acquire_updater_lock,
    apply_installed_transaction,
    apply_portable_transaction,
    check_active_operations,
    has_active_tasks,
    recover_interrupted_update_on_boot,
    run_apply_update_cli,
)
from app.updater.manager import UpdateManager
from app.updater.models import (
    TrustRootKey,
    UpdateBlockReason,
    UpdateError,
    UpdaterPersistentState,
    UpdateState,
    UpdateTransaction,
)
from app.updater.staging import extract_verified_portable_zip, reverify_staged_bundle
from app.updater.trust import TrustPolicy, canonical_manifest_bytes, sign_manifest_bytes
from backend.automation.scheduler import _os_file_lock
from backend.tasks.models import TaskSpec
from backend.tasks.store import TaskStore


def _gen_keypair() -> tuple[bytes, str]:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, base64.b64encode(pub_raw).decode("ascii")


def _make_portable_zip(dest: Path, files: dict[str, bytes]) -> tuple[str, int]:
    with zipfile.ZipFile(dest, "w") as zf:
        for rel, content in files.items():
            zf.writestr(f"MCPApp/{rel}", content)
    raw = dest.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


class N02ReviewRegressionsTests(unittest.TestCase):
    def test_n02_01_production_cli_blocks_forged_unsigned_plan_and_no_parent_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            appdata = root / "appdata"
            data_dir = appdata / "MCPApp"
            updates = data_dir / "updates"
            helper_dir = updates / "helper_run" / "tx-forge"
            helper_dir.mkdir(parents=True)
            install_dir = root / "PortableApp"
            install_dir.mkdir()
            (install_dir / "MCPApp.exe").write_bytes(b"OLD_BIN")
            (install_dir / "_internal").mkdir()
            staged = updates / "staged" / "1.0.3"
            staged.mkdir(parents=True)
            (staged / "MCPApp.exe").write_bytes(b"EVIL_UNSIGNED")

            plan = {
                "tx_id": "tx-forge",
                "install_type": "portable",
                "install_dir": str(install_dir),
                "source_version": "1.0.2",
                "target_version": "1.0.3",
                "expected_hashes": {
                    "MCPApp.exe": hashlib.sha256(b"EVIL_UNSIGNED").hexdigest(),
                },
                "expected_token": "tok-123",
                "issued_at": time.time(),
                "parent_identity": None,
                "restart_gui": False,
            }
            plan_path = helper_dir / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            with (
                patch.dict(os.environ, {"APPDATA": str(appdata), "MCP_UPDATER_HANDOFF_TOKEN": "tok-123"}),
                patch("app.updater.helper.verify_updated_binary", return_value=True),
            ):
                rc = run_apply_update_cli(["--plan", str(plan_path)])
            self.assertNotEqual(rc, 0)
            self.assertEqual((install_dir / "MCPApp.exe").read_bytes(), b"OLD_BIN")

    def test_n02_02_staging_reverify_rejects_missing_empty_map_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zp = root / "bundle.zip"
            _make_portable_zip(zp, {"MCPApp.exe": b"EXE", "_internal/mod.txt": b"MOD"})
            stage_dir = root / "stage"
            hashes = extract_verified_portable_zip(zp, stage_dir)

            with self.assertRaises(UpdateError) as ctx_none:
                reverify_staged_bundle(stage_dir, None)
            self.assertEqual(ctx_none.exception.code, UpdateBlockReason.HASH_MISMATCH)

            with self.assertRaises(UpdateError) as ctx_empty:
                reverify_staged_bundle(stage_dir, {})
            self.assertEqual(ctx_empty.exception.code, UpdateBlockReason.HASH_MISMATCH)

            (stage_dir / "evil_extra.dll").write_bytes(b"EXTRA")
            with self.assertRaises(UpdateError) as ctx_extra:
                reverify_staged_bundle(stage_dir, hashes)
            self.assertEqual(ctx_extra.exception.code, UpdateBlockReason.HASH_MISMATCH)

    def test_n02_03_installed_rollback_requires_verified_bundle_and_post_rollback_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inst_dir = root / "InstalledApp"
            inst_dir.mkdir()
            (inst_dir / "MCPApp.exe").write_bytes(b"CUR")
            (inst_dir / "unins000.exe").write_bytes(b"UNINS")
            (inst_dir / "unins000.dat").write_bytes(b"DAT")

            rb_dir = root / "rollback"
            rb_dir.mkdir()
            # Bare unsigned Setup.exe without manifest/sig/Authenticode must NOT satisfy rollback contract
            rb_exe = rb_dir / "MCPApp-Setup-1.0.2.exe"
            rb_exe.write_bytes(b"UNVERIFIED-SETUP")
            _, pub = _gen_keypair()
            policy = TrustPolicy(trust_roots=(TrustRootKey("r1", pub),), allowed_thumbprints=("AA" * 20,))
            env = detect_install_environment(
                frozen=True,
                app_dir=inst_dir,
                current_version="1.0.2",
                rollback_cache_dir=rb_dir,
                policy=policy,
            )
            self.assertIn(UpdateBlockReason.NO_ROLLBACK_CONTRACT, env.block_reasons)

            # Even with mock installer returning exit 0, failed post-rollback verify must end FAILED
            new_exe = root / "MCPApp-Setup-1.0.3.exe"
            new_exe.write_bytes(b"NEW")
            tx = apply_installed_transaction(
                tx_id="tx-rb-verify",
                install_dir=inst_dir,
                installer_path=new_exe,
                rollback_installer_path=rb_exe,
                source_version="1.0.2",
                target_version="1.0.3",
                state_path=root / "state.json",
                expected_sha256=hashlib.sha256(b"NEW").hexdigest(),
                rollback_expected_sha256=hashlib.sha256(b"UNVERIFIED-SETUP").hexdigest(),
                require_authenticode=False,
                run_installer=lambda cmd, env_d: 0,
                verify_callback=lambda d, dd: False,
                rollback_verify_callback=lambda d, dd: False,
            )
            self.assertEqual(tx.state, UpdateState.FAILED)

    def test_n02_04_unified_tasks_path_fail_closed_corrupt_db_and_scheduler_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "MCPApp"
            tasks_db = data_dir / "tasks" / "tasks.sqlite3"
            store = TaskStore(tasks_db)
            store.create_task(
                owner_client_id="owner",
                profile="allowlist",
                title="Active job",
                spec=TaskSpec(kind="windows", command="echo hi"),
            )

            _, pub = _gen_keypair()
            port_dir = root / "Portable"
            port_dir.mkdir()
            (port_dir / "MCPApp.exe").write_bytes(b"OLD")
            (port_dir / "_internal").mkdir()
            env = InstallEnvironment(
                install_type="portable",
                install_dir=port_dir,
                exe_path=port_dir / "MCPApp.exe",
                uninstall_exe=None,
                writable=True,
                has_rollback_contract=True,
                rollback_installer=None,
            )
            mgr = UpdateManager(
                Settings(),
                data_dir,
                policy=TrustPolicy(trust_roots=(TrustRootKey("k1", pub),)),
                current_version="1.0.2",
                environment=env,
            )
            self.assertEqual(mgr.evaluate_block_reason(), UpdateBlockReason.ACTIVE_TASKS)

            # Corrupt DB must fail closed (True)
            corrupt_db = root / "corrupt.sqlite3"
            corrupt_db.write_bytes(b"not-a-sqlite-file")
            self.assertTrue(has_active_tasks(corrupt_db))

            # Clear task, hold scheduler lock -> must block
            store.recover_interrupted()
            lock_path = data_dir / "automation" / ".automation.lock"
            with _os_file_lock(lock_path):
                self.assertEqual(mgr.evaluate_block_reason(), UpdateBlockReason.SCHEDULER_ACTIVE)

    def test_n02_05_boot_recovery_respects_active_updater_lock_and_keeps_backup_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            updates = root / "updates"
            app_dir = root / "MCPApp"
            backup_dir = root / ".MCPApp-old-tx-live"
            app_dir.mkdir()
            backup_dir.mkdir()
            (app_dir / "MCPApp.exe").write_bytes(b"NEW")
            (backup_dir / "MCPApp.exe").write_bytes(b"OLD")
            state_path = updates / "state.json"
            tx = UpdateTransaction(
                tx_id="tx-live",
                state=UpdateState.VERIFYING_NEW,
                install_type="portable",
                source_version="1.0.2",
                target_version="1.0.3",
                install_dir=str(app_dir),
                backup_dir=str(backup_dir),
            )
            UpdaterPersistentState(active_transaction=tx).save(state_path)

            # While active helper holds .updater.lock, boot recovery must not clobber live install_dir
            with acquire_updater_lock(updates / ".updater.lock"):
                res = recover_interrupted_update_on_boot(state_path, updates, install_dir=app_dir)
                self.assertTrue(res is None or res.state == "ACTIVE_EXTERNAL")
                self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"NEW")

            # Backup must NOT be deleted before COMMITTED state write succeeds
            zp = root / "ok.zip"
            _make_portable_zip(zp, {"MCPApp.exe": b"NEW2"})
            staged = updates / "staged" / "1.0.3"
            hashes = extract_verified_portable_zip(zp, staged)
            with patch("app.updater.helper._finalize_tx", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    apply_portable_transaction(
                        tx_id="tx-commit-err",
                        install_dir=app_dir,
                        staged_dir=staged,
                        expected_hashes=hashes,
                        source_version="1.0.2",
                        target_version="1.0.3",
                        state_path=state_path,
                        verify_callback=lambda d, dd: True,
                    )
            expected_backup = root / ".MCPApp-old-tx-commit-err"
            self.assertTrue(expected_backup.is_dir(), "Backup directory deleted before state commit!")

    def test_n02_01_helper_cli_verifies_signed_manifest_blocks_tamper_replay_and_wrong_dir(self) -> None:
        priv, pub = _gen_keypair()
        policy = TrustPolicy(trust_roots=(TrustRootKey("rel-test", pub),), require_authenticode_for_installer=False)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "MCPAppData"
            updates = data_dir / "updates"
            install_dir = root / "PortableApp"
            install_dir.mkdir()
            (install_dir / "MCPApp.exe").write_bytes(b"OLD_BIN")
            (install_dir / "_internal").mkdir()

            zip_path = updates / "downloads" / "MCPApp-1.0.3-portable.zip"
            zip_path.parent.mkdir(parents=True)
            port_sha, port_size = _make_portable_zip(
                zip_path,
                {"MCPApp.exe": b"NEW_SIGNED_BIN", "_internal/lib.txt": b"LIB"},
            )
            extract_verified_portable_zip(zip_path, updates / "staged" / "1.0.3")

            manifest_bytes = canonical_manifest_bytes(
                {
                    "schema_version": 1,
                    "version": "1.0.3",
                    "channel": "stable",
                    "published_at": "2026-11-27T12:00:00Z",
                    "min_supported_version": "1.0.0",
                    "changelog": "Signed test",
                    "installer": {
                        "name": "MCPApp-Setup-1.0.3.exe",
                        "sha256": "a" * 64,
                        "size": 10,
                        "authenticode_required": False,
                    },
                    "portable": {
                        "name": zip_path.name,
                        "sha256": port_sha,
                        "size": port_size,
                        "authenticode_required": False,
                    },
                    "publisher_thumbprints": [],
                }
            )
            sig_b64 = sign_manifest_bytes(manifest_bytes, priv)
            m_dir = updates / "manifests" / "1.0.3"
            m_dir.mkdir(parents=True)
            (m_dir / "update-manifest.json").write_bytes(manifest_bytes)
            (m_dir / "update-manifest.json.sig").write_text(
                json.dumps({"key_id": "rel-test", "signature_b64": sig_b64}),
                encoding="utf-8",
            )

            h_dir = updates / "helper_run" / "tx-e2e"
            h_dir.mkdir(parents=True)
            plan_path = h_dir / "plan.json"
            plan_obj = {
                "tx_id": "tx-e2e",
                "install_type": "portable",
                "install_dir": str(install_dir),
                "target_version": "1.0.3",
                "expected_token": "tok-good",
                "issued_at": time.time(),
                "parent_identity": {
                    "pid": 99999999,
                    "create_time": 1000.0,
                    "executable": str(install_dir / "MCPApp.exe"),
                    "captured_at": 1000.0,
                },
                "restart_gui": False,
            }
            plan_path.write_text(json.dumps(plan_obj), encoding="utf-8")

            with (
                patch.dict(os.environ, {"MCP_UPDATER_HANDOFF_TOKEN": "tok-good"}),
                patch("app.updater.helper._query_binary_version", return_value="1.0.2"),
                patch("app.updater.helper.verify_updated_binary", return_value=True),
            ):
                rc = run_apply_update_cli(
                    ["--plan", str(plan_path)],
                    _policy_override=policy,
                    _data_dir_override=data_dir,
                )
                self.assertEqual(rc, 0)
                self.assertEqual((install_dir / "MCPApp.exe").read_bytes(), b"NEW_SIGNED_BIN")
                self.assertFalse(plan_path.exists())

                # Replaying exact same tx_id must fail even if attacker re-creates plan.json
                plan_path.write_text(json.dumps(plan_obj), encoding="utf-8")
                rc_replay = run_apply_update_cli(
                    ["--plan", str(plan_path)],
                    _policy_override=policy,
                    _data_dir_override=data_dir,
                )
                self.assertEqual(rc_replay, 3)

                # Non-MCPApp arbitrary target dir must be refused
                foreign_dir = root / "NotMCPApp"
                foreign_dir.mkdir()
                (foreign_dir / "random.txt").write_text("user", encoding="utf-8")
                p2 = h_dir / "plan2.json"
                p2.write_text(json.dumps({**plan_obj, "tx_id": "tx-e2e-2", "install_dir": str(foreign_dir)}), encoding="utf-8")
                rc_foreign = run_apply_update_cli(
                    ["--plan", str(p2)],
                    _policy_override=policy,
                    _data_dir_override=data_dir,
                )
                self.assertNotEqual(rc_foreign, 0)

                # Non-TEMP portable install dir matching parent_identity.executable succeeds; UNC/system target refused
                custom_port = root / "CustomPortable" / "MCPApp"
                custom_port.mkdir(parents=True)
                (custom_port / "MCPApp.exe").write_bytes(b"OLD_BIN")
                (custom_port / "_internal").mkdir()
                with patch("tempfile.gettempdir", return_value=str(root / "unrelated_tmp")):
                    p_custom = h_dir / "plan_custom.json"
                    p_custom.write_text(
                        json.dumps(
                            {
                                **plan_obj,
                                "tx_id": "tx-e2e-custom",
                                "install_dir": str(custom_port),
                                "parent_identity": {
                                    "pid": 99999999,
                                    "create_time": 1000.0,
                                    "executable": str(custom_port / "MCPApp.exe"),
                                    "captured_at": 1000.0,
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    rc_custom = run_apply_update_cli(
                        ["--plan", str(p_custom)],
                        _policy_override=policy,
                        _data_dir_override=data_dir,
                    )
                    self.assertEqual(rc_custom, 0)
                    self.assertEqual((custom_port / "MCPApp.exe").read_bytes(), b"NEW_SIGNED_BIN")

                p_unc = h_dir / "plan_unc.json"
                p_unc.write_text(
                    json.dumps(
                        {
                            **plan_obj,
                            "tx_id": "tx-e2e-unc",
                            "install_dir": r"\\server\share\MCPApp",
                            "parent_identity": {
                                "pid": 99999999,
                                "create_time": 1000.0,
                                "executable": r"\\server\share\MCPApp\MCPApp.exe",
                                "captured_at": 1000.0,
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(
                    run_apply_update_cli(
                        ["--plan", str(p_unc)],
                        _policy_override=policy,
                        _data_dir_override=data_dir,
                    ),
                    6,
                )

    def test_n02_06_handoff_plan_strips_trust_fields_and_corrupt_history_fails_closed(self) -> None:
        priv, pub = _gen_keypair()
        policy = TrustPolicy(trust_roots=(TrustRootKey("rel-test", pub),), require_authenticode_for_installer=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "MCPAppData"
            install_dir = root / "PortableApp"
            install_dir.mkdir()
            (install_dir / "MCPApp.exe").write_bytes(b"OLD")
            (install_dir / "_internal").mkdir()
            env = InstallEnvironment(
                install_type="portable",
                install_dir=install_dir,
                exe_path=install_dir / "MCPApp.exe",
                uninstall_exe=None,
                writable=True,
                has_rollback_contract=True,
                rollback_installer=None,
            )
            zp = root / "MCPApp-1.0.3-portable.zip"
            port_sha, port_size = _make_portable_zip(zp, {"MCPApp.exe": b"NEW"})
            manifest_bytes = canonical_manifest_bytes(
                {
                    "schema_version": 1,
                    "version": "1.0.3",
                    "channel": "stable",
                    "published_at": "2026-11-27T12:00:00Z",
                    "min_supported_version": "1.0.0",
                    "changelog": "Clean handoff",
                    "installer": {
                        "name": "MCPApp-Setup-1.0.3.exe",
                        "sha256": "a" * 64,
                        "size": 10,
                        "authenticode_required": False,
                    },
                    "portable": {
                        "name": zp.name,
                        "sha256": port_sha,
                        "size": port_size,
                        "authenticode_required": False,
                    },
                    "publisher_thumbprints": ["AB" * 20],
                }
            )
            sig_b64 = sign_manifest_bytes(manifest_bytes, priv)
            sig_bytes = json.dumps({"key_id": "rel-test", "signature_b64": sig_b64}).encode("utf-8")
            rel_json = json.dumps(
                {
                    "tag_name": "v1.0.3",
                    "prerelease": False,
                    "draft": False,
                    "assets": [
                        {"name": "update-manifest.json", "browser_download_url": "https://github.com/SolasFor/MCP-app/releases/download/v1.0.3/update-manifest.json"},
                        {"name": "update-manifest.json.sig", "browser_download_url": "https://github.com/SolasFor/MCP-app/releases/download/v1.0.3/update-manifest.json.sig"},
                        {"name": zp.name, "browser_download_url": f"https://github.com/SolasFor/MCP-app/releases/download/v1.0.3/{zp.name}"},
                    ],
                }
            ).encode("utf-8")

            def _fetch(url: str) -> bytes:
                if url.endswith("releases/latest"):
                    return rel_json
                if url.endswith(".sig"):
                    return sig_bytes
                return manifest_bytes

            class _Resp:
                def __init__(self, data: bytes) -> None:
                    self.headers = {"Content-Length": str(len(data))}
                    self._data = data
                    self._pos = 0

                def read(self, n: int = -1) -> bytes:
                    if n < 0:
                        chunk, self._pos = self._data[self._pos :], len(self._data)
                        return chunk
                    chunk = self._data[self._pos : self._pos + n]
                    self._pos += len(chunk)
                    return chunk

                def __enter__(self) -> "_Resp":
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            mgr = UpdateManager(Settings(), data_dir, policy=policy, current_version="1.0.2", environment=env)
            mgr.check_for_updates(force=True, fetch_bytes=_fetch)
            raw_zip = zp.read_bytes()
            mgr.download_and_stage(open_url=lambda _req, timeout=30: _Resp(raw_zip))
            with patch("subprocess.Popen") as popen_mock:
                ok = mgr.launch_staged_install_handoff(restart_gui=False)
            self.assertTrue(ok)
            self.assertEqual(popen_mock.call_count, 1)
            plan_files = list((data_dir / "updates" / "helper_run").glob("*/plan.json"))
            self.assertEqual(len(plan_files), 1)
            written_plan = json.loads(plan_files[0].read_text(encoding="utf-8"))
            for forbidden in ("expected_hashes", "require_authenticode", "allowed_thumbprints", "publisher_thumbprints"):
                self.assertNotIn(forbidden, written_plan)

            # Corrupt automation history.json must fail closed as SCHEDULER_ACTIVE
            auto_dir = data_dir / "automation"
            auto_dir.mkdir(parents=True, exist_ok=True)
            (auto_dir / "history.json").write_text("{corrupt", encoding="utf-8")
            self.assertEqual(
                check_active_operations(data_dir, install_dir, check_gui_mutex=False),
                UpdateBlockReason.SCHEDULER_ACTIVE,
            )
            # Clean real-schema history + mocked GUI mutex held must block installed mode
            (auto_dir / "history.json").write_text('{"version": 1, "runs": []}', encoding="utf-8")
            with patch("app.updater.helper._is_gui_mutex_held", return_value=True):
                self.assertEqual(
                    check_active_operations(data_dir, install_dir, check_gui_mutex=True),
                    UpdateBlockReason.ACTIVE_TASKS,
                )


if __name__ == "__main__":
    unittest.main()
