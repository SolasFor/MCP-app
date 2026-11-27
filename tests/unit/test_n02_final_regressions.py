"""TDD regression tests for N02-FINAL-01 (scheduler history & live runs) and N02-FINAL-02 (boot recovery)."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.updater.helper import check_active_operations, recover_interrupted_update_on_boot
from app.updater.models import (
    TrustRootKey,
    UpdateBlockReason,
    UpdaterPersistentState,
    UpdateState,
    UpdateTransaction,
)
from app.updater.trust import TrustPolicy, canonical_manifest_bytes, sign_manifest_bytes
from backend.automation.scheduler import AutomationScheduler, ScheduleSpec


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


def _write_signed_manifest(updates: Path, version: str, priv_raw: bytes, key_id: str = "rel-final") -> None:
    manifest_bytes = canonical_manifest_bytes(
        {
            "schema_version": 1,
            "version": version,
            "channel": "stable",
            "published_at": "2026-11-27T12:00:00Z",
            "min_supported_version": "1.0.0",
            "changelog": "Boot recovery manifest",
            "installer": {
                "name": f"MCPApp-Setup-{version}.exe",
                "sha256": "a" * 64,
                "size": 100,
                "authenticode_required": False,
            },
            "portable": {
                "name": f"MCPApp-{version}-portable.zip",
                "sha256": "b" * 64,
                "size": 100,
                "authenticode_required": False,
            },
            "publisher_thumbprints": [],
        }
    )
    sig_b64 = sign_manifest_bytes(manifest_bytes, priv_raw)
    m_dir = updates / "manifests" / version
    m_dir.mkdir(parents=True, exist_ok=True)
    (m_dir / "update-manifest.json").write_bytes(manifest_bytes)
    (m_dir / "update-manifest.json.sig").write_text(
        json.dumps({"key_id": key_id, "signature_b64": sig_b64}),
        encoding="utf-8",
    )


def _make_portable_dir(directory: Path, marker: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "MCPApp.exe").write_bytes(marker)
    (directory / "_internal").mkdir(exist_ok=True)


class N02FinalRegressionsTests(unittest.TestCase):
    def test_n02_final_01_scheduler_history_schema_and_live_inflight_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "MCPApp"
            auto_dir = data_dir / "automation"
            auto_dir.mkdir(parents=True)
            hist_path = auto_dir / "history.json"
            active_path = auto_dir / "active_runs.json"

            # 1. Real scheduler history schema with running status must block
            hist_path.write_text(
                json.dumps({"version": 1, "runs": [{"run_id": "r1", "status": "running"}]}),
                encoding="utf-8",
            )
            self.assertEqual(
                check_active_operations(data_dir, check_gui_mutex=False),
                UpdateBlockReason.SCHEDULER_ACTIVE,
            )

            # 2. Invalid or unknown schemas must fail closed as SCHEDULER_ACTIVE
            invalid_payloads: list[object] = [
                {},
                [],
                {"version": 2, "runs": []},
                {"version": True, "runs": []},
                {"version": 1, "runs": "bad"},
                {"version": 1, "runs": [{}]},
                {"version": 1, "extra": 1, "runs": []},
            ]
            for payload in invalid_payloads:
                hist_path.write_text(json.dumps(payload), encoding="utf-8")
                self.assertEqual(
                    check_active_operations(data_dir, check_gui_mutex=False),
                    UpdateBlockReason.SCHEDULER_ACTIVE,
                    f"Invalid history schema must block: {payload!r}",
                )

            # 3. Valid completed history schema unblocks
            hist_path.write_text(
                json.dumps({"version": 1, "runs": [{"run_id": "r1", "status": "succeeded"}]}),
                encoding="utf-8",
            )
            self.assertEqual(check_active_operations(data_dir, check_gui_mutex=False), UpdateBlockReason.OK)

            # 4. Corrupt active_runs.json fails closed; stale dead-PID entry does not hang forever
            active_path.write_text("{corrupt", encoding="utf-8")
            self.assertEqual(
                check_active_operations(data_dir, check_gui_mutex=False),
                UpdateBlockReason.SCHEDULER_ACTIVE,
            )
            active_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "active": {
                            "dead-1": {
                                "run_id": "dead-1",
                                "schedule_id": "s-dead",
                                "trigger": "manual",
                                "started_at": 1000.0,
                                "pid": 99999999,
                                "create_time": 1000.0,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(check_active_operations(data_dir, check_gui_mutex=False), UpdateBlockReason.OK)

            # 5. Live in-flight AutomationScheduler execution before history.json is appended
            async def _exercise_live_run() -> tuple[str, str]:
                entered = asyncio.Event()
                release = asyncio.Event()

                async def _exec(spec: ScheduleSpec, idem: str) -> dict[str, object]:
                    del spec, idem
                    entered.set()
                    await release.wait()
                    return {"ok": True}

                sched = AutomationScheduler(base_dir=auto_dir, async_executor=_exec)
                sched.upsert_schedule(
                    ScheduleSpec(
                        schedule_id="s-live",
                        name="Live job",
                        trigger_type="interval",
                        interval_seconds=60,
                        tool_name="echo",
                    )
                )
                task = asyncio.create_task(sched.trigger_now_async("s-live"))
                await asyncio.wait_for(entered.wait(), timeout=5.0)
                mid_status = check_active_operations(data_dir, check_gui_mutex=False)
                self.assertTrue(sched.has_active_runs())
                release.set()
                rec = await asyncio.wait_for(task, timeout=5.0)
                self.assertEqual(rec["status"], "succeeded")
                self.assertFalse(sched.has_active_runs())
                after_status = check_active_operations(data_dir, check_gui_mutex=False)
                return mid_status, after_status

            mid, after = asyncio.run(_exercise_live_run())
            self.assertEqual(mid, UpdateBlockReason.SCHEDULER_ACTIVE)
            self.assertEqual(after, UpdateBlockReason.OK)

    def test_n02_final_02_boot_recovery_blocks_empty_trust_roots_and_untrusted_tx(self) -> None:
        priv_raw, pub_b64 = _gen_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            updates = root / "updates"
            state_path = updates / "state.json"
            app_dir = root / "MCPApp"
            backup_dir = root / ".MCPApp-old-tx-evil"
            _make_portable_dir(app_dir, b"GOOD_BIN")
            _make_portable_dir(backup_dir, b"EVIL_BACKUP")

            tx = UpdateTransaction(
                tx_id="tx-evil",
                state=UpdateState.VERIFYING_NEW,
                install_type="portable",
                source_version="1.0.2",
                target_version="1.0.3",
                install_dir=str(app_dir),
                backup_dir=str(backup_dir),
            )
            UpdaterPersistentState(active_transaction=tx).save(state_path)

            # Empty production trust roots must refuse automatic boot recovery
            res_prod = recover_interrupted_update_on_boot(
                state_path,
                updates,
                install_dir=app_dir,
                verify_callback=lambda _d, _dd: True,
            )
            self.assertIsNotNone(res_prod)
            assert res_prod is not None
            self.assertEqual(res_prod.state, UpdateState.BLOCKED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"GOOD_BIN")

            # Trusted policy WITHOUT signed manifest must also remain BLOCKED without overwriting install_dir
            policy = TrustPolicy(
                trust_roots=(TrustRootKey("rel-final", pub_b64),),
                require_authenticode_for_installer=False,
            )
            UpdaterPersistentState(active_transaction=tx).save(state_path)
            res_nosig = recover_interrupted_update_on_boot(
                state_path,
                updates,
                install_dir=app_dir,
                policy=policy,
                verify_callback=lambda _d, _dd: True,
            )
            self.assertIsNotNone(res_nosig)
            assert res_nosig is not None
            self.assertEqual(res_nosig.state, UpdateState.BLOCKED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"GOOD_BIN")

            # Once signed manifest exists, verify unrelated scenario stays clean before next test
            _write_signed_manifest(updates, "1.0.3", priv_raw)
            self.assertTrue((updates / "manifests" / "1.0.3" / "update-manifest.json.sig").is_file())

    def test_n02_final_02_boot_recovery_enforces_bound_dir_exact_backup_no_reparse_and_corrupt_state(self) -> None:
        priv_raw, pub_b64 = _gen_keypair()
        policy = TrustPolicy(
            trust_roots=(TrustRootKey("rel-final", pub_b64),),
            require_authenticode_for_installer=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            updates = root / "updates"
            state_path = updates / "state.json"
            _write_signed_manifest(updates, "1.0.3", priv_raw)

            app_dir = root / "MCPApp"
            other_dir = root / "OtherApp"
            sibling_dir = root / "SiblingDir"
            wrong_backup = root / ".MCPApp-old-other"
            exact_backup = root / ".MCPApp-old-tx-valid"
            _make_portable_dir(app_dir, b"LIVE_GOOD")
            _make_portable_dir(other_dir, b"OTHER_GOOD")
            _make_portable_dir(sibling_dir, b"SIBLING_USER_DATA")
            _make_portable_dir(wrong_backup, b"WRONG_BACKUP")
            _make_portable_dir(exact_backup, b"EXACT_BACKUP")

            base_tx = UpdateTransaction(
                tx_id="tx-valid",
                state=UpdateState.VERIFYING_NEW,
                install_type="portable",
                source_version="1.0.2",
                target_version="1.0.3",
                install_dir=str(app_dir),
                backup_dir=str(exact_backup),
            )

            # 1. Unbound install_dir=None in non-frozen mode -> BLOCKED
            UpdaterPersistentState(active_transaction=base_tx).save(state_path)
            res_unbound = recover_interrupted_update_on_boot(
                state_path, updates, policy=policy, verify_callback=lambda _d, _dd: True
            )
            self.assertIsNotNone(res_unbound)
            assert res_unbound is not None
            self.assertEqual(res_unbound.state, UpdateState.BLOCKED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"LIVE_GOOD")

            # 2. tx.install_dir != bound install_dir -> BLOCKED
            tx_mismatch = UpdateTransaction(**{**base_tx.to_dict(), "install_dir": str(other_dir)})
            UpdaterPersistentState(active_transaction=tx_mismatch).save(state_path)
            res_mismatch = recover_interrupted_update_on_boot(
                state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
            )
            self.assertIsNotNone(res_mismatch)
            assert res_mismatch is not None
            self.assertEqual(res_mismatch.state, UpdateState.BLOCKED)
            self.assertEqual((other_dir / "MCPApp.exe").read_bytes(), b"OTHER_GOOD")

            # 3. Arbitrary sibling dir or wrong backup name -> BLOCKED without touching sibling
            for bad_backup in (sibling_dir, wrong_backup):
                tx_bad_bk = UpdateTransaction(**{**base_tx.to_dict(), "backup_dir": str(bad_backup)})
                UpdaterPersistentState(active_transaction=tx_bad_bk).save(state_path)
                res_bk = recover_interrupted_update_on_boot(
                    state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
                )
                self.assertIsNotNone(res_bk)
                assert res_bk is not None
                self.assertEqual(res_bk.state, UpdateState.BLOCKED)
                self.assertTrue((sibling_dir / "MCPApp.exe").is_file())
                self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"LIVE_GOOD")

            # 4. Invalid tx states -> BLOCKED
            for bad_state in ("unknown_state", UpdateState.INSTALLING):
                tx_bad_st = UpdateTransaction(**{**base_tx.to_dict(), "state": bad_state})
                UpdaterPersistentState(active_transaction=tx_bad_st).save(state_path)
                res_st = recover_interrupted_update_on_boot(
                    state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
                )
                self.assertIsNotNone(res_st)
                assert res_st is not None
                self.assertEqual(res_st.state, UpdateState.BLOCKED)

            # 5. Reparse/symlink detected inside backup_dir -> BLOCKED
            UpdaterPersistentState(active_transaction=base_tx).save(state_path)
            with patch(
                "app.updater.helper.is_reparse_or_symlink",
                side_effect=lambda p: os.path.normcase(str(p)) == os.path.normcase(str(exact_backup / "MCPApp.exe")),
            ):
                res_rep = recover_interrupted_update_on_boot(
                    state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
                )
            self.assertIsNotNone(res_rep)
            assert res_rep is not None
            self.assertEqual(res_rep.state, UpdateState.BLOCKED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"LIVE_GOOD")

            # 6. Corrupted state.json -> BLOCKED without destroying/overwriting corrupt evidence
            corrupt_raw = "{corrupt-json"
            state_path.write_text(corrupt_raw, encoding="utf-8")
            res_corrupt = recover_interrupted_update_on_boot(
                state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
            )
            self.assertIsNotNone(res_corrupt)
            assert res_corrupt is not None
            self.assertEqual(res_corrupt.state, UpdateState.BLOCKED)
            self.assertEqual(state_path.read_text(encoding="utf-8"), corrupt_raw)

            bad_schema_raw = json.dumps({"highest_seen_version": "1.0.2", "active_transaction": "not-a-dict"})
            state_path.write_text(bad_schema_raw, encoding="utf-8")
            res_bad_schema = recover_interrupted_update_on_boot(
                state_path, updates, install_dir=app_dir, policy=policy, verify_callback=lambda _d, _dd: True
            )
            self.assertIsNotNone(res_bad_schema)
            assert res_bad_schema is not None
            self.assertEqual(res_bad_schema.state, UpdateState.BLOCKED)
            self.assertEqual(state_path.read_text(encoding="utf-8"), bad_schema_raw)

    def test_n02_final_02_boot_recovery_verifies_restored_binary_and_preserves_good_copy(self) -> None:
        priv_raw, pub_b64 = _gen_keypair()
        policy = TrustPolicy(
            trust_roots=(TrustRootKey("rel-final", pub_b64),),
            require_authenticode_for_installer=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            updates = root / "updates"
            state_path = updates / "state.json"
            _write_signed_manifest(updates, "1.0.3", priv_raw)

            app_dir = root / "MCPApp"
            backup_dir = root / ".MCPApp-old-tx-verify"
            _make_portable_dir(app_dir, b"WORKING_COPY")
            _make_portable_dir(backup_dir, b"BACKUP_COPY")

            tx = UpdateTransaction(
                tx_id="tx-verify",
                state=UpdateState.VERIFYING_NEW,
                install_type="portable",
                source_version="1.0.2",
                target_version="1.0.3",
                install_dir=str(app_dir),
                backup_dir=str(backup_dir),
            )
            UpdaterPersistentState(active_transaction=tx).save(state_path)

            # Failed post-recovery verify -> BLOCKED, pre-existing working copy restored & backup kept
            res_fail = recover_interrupted_update_on_boot(
                state_path,
                updates,
                install_dir=app_dir,
                policy=policy,
                verify_callback=lambda _d, _dd: False,
            )
            self.assertIsNotNone(res_fail)
            assert res_fail is not None
            self.assertEqual(res_fail.state, UpdateState.BLOCKED)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"WORKING_COPY")
            self.assertEqual((backup_dir / "MCPApp.exe").read_bytes(), b"BACKUP_COPY")

            # Passing post-recovery verify -> ROLLED_BACK and displaced dir cleaned
            UpdaterPersistentState(active_transaction=tx).save(state_path)
            res_ok = recover_interrupted_update_on_boot(
                state_path,
                updates,
                install_dir=app_dir,
                policy=policy,
                verify_callback=lambda d, _dd: (d / "MCPApp.exe").read_bytes() == b"BACKUP_COPY",
            )
            self.assertIsNotNone(res_ok)
            assert res_ok is not None
            self.assertEqual(res_ok.state, UpdateState.ROLLED_BACK)
            self.assertEqual((app_dir / "MCPApp.exe").read_bytes(), b"BACKUP_COPY")
            self.assertFalse((root / ".MCPApp-displaced-tx-verify").exists())


if __name__ == "__main__":
    unittest.main()
