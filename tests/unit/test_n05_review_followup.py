"""Targeted RED/GREEN regression tests for ChatGPT N05 follow-up findings (N05-01, N05-02, N05-03)."""
from __future__ import annotations

import asyncio
import base64
import errno
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.shared.auth import OAuthClientInformationFull

from app.core.secret_store import SecretStore
from app.core.tunnels.base import _terminate_owned_cli_process, run_cli_capture_bounded
from backend.oauth_execution import PROFILE_ALLOWLIST, PROFILE_FULL
from backend.remote.discovery import SSHNetworkDiscoveryLimits, discover_tailscale_ssh_peers
from backend.remote.host_keys import probe_ssh_host_key, verify_independent_host_key
from backend.remote.models import DevicePermissions, DeviceProfile
from backend.remote.onboarding import (
    commit_device_wizard_plan,
    prepare_device_wizard_preview,
    resolve_effective_ssh_target,
)
from backend.remote.store import (
    MAX_KNOWN_HOSTS_FILE_BYTES,
    MAX_TX_JOURNAL_BYTES,
    TX_SCHEMA_VERSION,
    DeviceStore,
)
from tests.fixtures.local_ssh_server import LocalSSHServer


def _valid_tx_id() -> str:
    return "0123456789abcdef01234567"


def _minimal_devices_bytes(devices_payload: dict[str, dict] | None = None) -> bytes:
    return json.dumps({"version": 2, "devices": devices_payload or {}}).encode("utf-8")


def _build_tx_journal(
    store: DeviceStore,
    *,
    tx_id: str | None = None,
    op: str = "wizard_commit",
    device_id: str = "new_dev",
    files: list[dict] | None = None,
    created_secrets: list[list[str]] | None = None,
    schema_version: int = TX_SCHEMA_VERSION,
) -> dict:
    tid = tx_id or _valid_tx_id()
    default_files = [
        {"path": str(store.path), "existed": True, "content_b64": base64.b64encode(_minimal_devices_bytes()).decode("ascii")},
        {"path": str(store.managed_known_hosts_path), "existed": False, "content_b64": None},
        {"path": str(store._init_marker), "existed": True, "content_b64": base64.b64encode(b'{"schema_version": 2}').decode("ascii")},
    ]
    return {
        "schema_version": schema_version,
        "tx_id": tid,
        "op": op,
        "device_id": device_id,
        "files": default_files if files is None else files,
        "created_secrets": created_secrets if created_secrets is not None else [],
    }


class N0501WalSecretSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secrets = SecretStore(self.root / "secrets")
        self.store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.secrets)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_malformed_journal_with_empty_files_preserves_existing_secret_and_fails_closed(self) -> None:
        ref = self.store.set_secret("existing_dev", "password", "super-secret-existing")
        existing_prof = DeviceProfile(
            device_id="existing_dev",
            name="Existing",
            host="127.0.0.1",
            username="ops",
            auth_method="password_ref",
            password_ref=ref,
        )
        self.store.upsert(existing_prof)
        ns, key = self.secrets.parse_ref(ref)
        devices_before = self.store.path.read_bytes()

        malformed = {"schema_version": 1, "files": [], "created_secrets": [[ns, key]]}
        self.store.tx_journal_path.write_text(json.dumps(malformed), encoding="utf-8")

        with self.assertRaises(ValueError):
            self.store.load_all(strict=True)
        self.assertEqual(self.secrets.get_secret(ns, key), "super-secret-existing")
        self.assertEqual(self.store.path.read_bytes(), devices_before)
        self.assertTrue(self.store.tx_journal_path.exists())

    def test_rejects_malformed_incomplete_duplicate_extra_and_unbound_journals(self) -> None:
        ref = self.store.set_secret("keep_dev", "password", "keep-me")
        keep = DeviceProfile(
            device_id="keep_dev",
            name="Keep",
            host="127.0.0.1",
            username="ops",
            auth_method="password_ref",
            password_ref=ref,
        )
        self.store.upsert(keep)
        tid = _valid_tx_id()
        pre_devs = _minimal_devices_bytes({"keep_dev": keep.to_dict()})

        bad_journals: list[dict] = [
            # Wrong schema version
            _build_tx_journal(self.store, schema_version=1),
            # Bad tx_id
            _build_tx_journal(self.store, tx_id="deadbeef"),
            # Bad op
            _build_tx_journal(self.store, op="drop_all"),
            # Missing third required file entry
            _build_tx_journal(
                self.store,
                files=[
                    {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_devs).decode("ascii")},
                    {"path": str(self.store.managed_known_hosts_path), "existed": False, "content_b64": None},
                ],
            ),
            # Duplicate file entry instead of init marker
            _build_tx_journal(
                self.store,
                files=[
                    {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_devs).decode("ascii")},
                    {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_devs).decode("ascii")},
                    {"path": str(self.store.managed_known_hosts_path), "existed": False, "content_b64": None},
                ],
            ),
            # existed=False with non-None content_b64
            _build_tx_journal(
                self.store,
                files=[
                    {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_devs).decode("ascii")},
                    {"path": str(self.store.managed_known_hosts_path), "existed": False, "content_b64": "YWJj"},
                    {"path": str(self.store._init_marker), "existed": True, "content_b64": base64.b64encode(b'{"schema_version": 2}').decode("ascii")},
                ],
            ),
            # Wrong secret namespace
            _build_tx_journal(self.store, created_secrets=[["owner", f"new_dev__password__{tid}"]]),
            # Unbound secret key referencing a different device or tx_id
            _build_tx_journal(self.store, created_secrets=[["ssh", "keep_dev__password"]]),
            # host_key_rotate cannot declare created_secrets
            _build_tx_journal(self.store, op="host_key_rotate", device_id="keep_dev", created_secrets=[["ssh", f"keep_dev__password__{tid}"]]),
        ]

        for idx, journal in enumerate(bad_journals):
            with self.subTest(case=idx):
                self.store.tx_journal_path.write_text(json.dumps(journal), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.store.load_all(strict=True)
                self.assertEqual(self.secrets.get_secret("ssh", "keep_dev__password"), "keep-me")
        self.store.tx_journal_path.unlink(missing_ok=True)

        # Even if a secret was previously stored under a matching tx_id suffix and is referenced
        # by a profile in the preimage, recovery MUST refuse to delete it.
        colliding_ref = self.store.set_secret("keep_dev", "password", "preimage-protected", suffix=tid)
        keep_colliding = DeviceProfile(
            device_id="keep_dev",
            name="Keep2",
            host="127.0.0.1",
            username="ops",
            auth_method="password_ref",
            password_ref=colliding_ref,
        )
        self.store.upsert(keep_colliding)
        pre_colliding = _minimal_devices_bytes({"keep_dev": keep_colliding.to_dict()})
        self.store.tx_journal_path.write_text(
            json.dumps(
                _build_tx_journal(
                    self.store,
                    tx_id=tid,
                    device_id="keep_dev",
                    files=[
                        {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_colliding).decode("ascii")},
                        {"path": str(self.store.managed_known_hosts_path), "existed": False, "content_b64": None},
                        {"path": str(self.store._init_marker), "existed": True, "content_b64": base64.b64encode(b'{"schema_version": 2}').decode("ascii")},
                    ],
                    created_secrets=[["ssh", f"keep_dev__password__{tid}"]],
                )
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            self.store.load_all(strict=True)
        self.assertEqual(self.secrets.get_secret("ssh", f"keep_dev__password__{tid}"), "preimage-protected")

    def test_rejects_reparse_or_symlink_in_parent_directory(self) -> None:
        journal = _build_tx_journal(self.store)
        self.store.tx_journal_path.write_text(json.dumps(journal), encoding="utf-8")
        parent_norm = os.path.normcase(os.path.abspath(str(self.store.path.parent)))

        with patch(
            "backend.remote.store.is_reparse_or_symlink",
            side_effect=lambda p: os.path.normcase(os.path.abspath(os.fspath(p))) == parent_norm,
        ):
            with self.assertRaises(ValueError):
                self.store.load_all(strict=True)
        self.assertTrue(self.store.tx_journal_path.exists())

    def test_retains_journal_when_secret_delete_fails_and_recovers_idempotently(self) -> None:
        tid = _valid_tx_id()
        existing_ref = self.store.set_secret("existing_dev", "password", "preserve-existing")
        existing = DeviceProfile(
            device_id="existing_dev",
            name="Existing",
            host="127.0.0.1",
            username="ops",
            auth_method="password_ref",
            password_ref=existing_ref,
        )
        self.store.upsert(existing)
        pre_devs = self.store.path.read_bytes()
        pre_marker = self.store._init_marker.read_bytes()

        orphan_ref = self.store.set_secret("new_dev", "password", "orphan-val", suffix=tid)
        self.store.path.write_bytes(b"{INTERRUPTED_WRITE")
        self.store.managed_known_hosts_path.write_text("uncommitted-entry", encoding="utf-8")
        self.store.tx_journal_path.write_text(
            json.dumps(
                _build_tx_journal(
                    self.store,
                    tx_id=tid,
                    device_id="new_dev",
                    files=[
                        {"path": str(self.store.path), "existed": True, "content_b64": base64.b64encode(pre_devs).decode("ascii")},
                        {"path": str(self.store.managed_known_hosts_path), "existed": False, "content_b64": None},
                        {"path": str(self.store._init_marker), "existed": True, "content_b64": base64.b64encode(pre_marker).decode("ascii")},
                    ],
                    created_secrets=[["ssh", f"new_dev__password__{tid}"]],
                )
            ),
            encoding="utf-8",
        )

        # Fail secret deletion once -> journal MUST stay intact!
        with patch.object(self.secrets, "delete_secret", side_effect=PermissionError("vault locked")):
            with self.assertRaises(PermissionError):
                self.store.recover_pending_tx_unlocked()
        self.assertTrue(self.store.tx_journal_path.exists())
        self.assertEqual(self.secrets.resolve_ref(orphan_ref), "orphan-val")

        # Retry recovery succeeds, removes orphan & journal, preserves existing profile+secret, and repeats cleanly
        self.store.recover_pending_tx_unlocked()
        self.assertFalse(self.store.tx_journal_path.exists())
        self.assertIsNone(self.secrets.resolve_ref(orphan_ref))
        self.assertEqual(self.secrets.resolve_ref(existing_ref), "preserve-existing")
        self.assertEqual(list(self.store.load_all(strict=True).keys()), ["existing_dev"])
        self.store.recover_pending_tx_unlocked()

    def test_commit_failure_modes_preserve_existing_state_and_write_limits(self) -> None:
        srv = LocalSSHServer(self.root / "sftp", username="ops", password="pw").start()
        try:
            ext_ref = self.store.set_secret("existing_dev", "password", "stay-safe")
            self.store.upsert(
                DeviceProfile(
                    device_id="existing_dev",
                    name="Existing",
                    host="127.0.0.1",
                    port=srv.port + 1,
                    username="ops",
                    auth_method="password_ref",
                    password_ref=ext_ref,
                )
            )
            probe = probe_ssh_host_key(srv.host, srv.port, include_system_known_hosts=False)
            approved = verify_independent_host_key(
                probe, expected_fingerprint_input=probe.fingerprint_sha256, verified_independently=True
            )
            draft = DeviceProfile(
                device_id="commit_fail_dev",
                name="Fail Dev",
                host=srv.host,
                port=srv.port,
                username="ops",
                auth_method="password_ref",
            )
            preview = prepare_device_wizard_preview(self.store, draft, approved_host_key=approved, password="new-pw")

            # Fault during set_secret -> rolled back cleanly
            with patch.object(self.store, "set_secret", side_effect=PermissionError("DPAPI locked")):
                with self.assertRaises(PermissionError):
                    commit_device_wizard_plan(
                        self.store, draft, approved_host_key=approved, expected_snapshot=preview.snapshot, password="new-pw"
                    )
            self.assertFalse(self.store.tx_journal_path.exists())
            self.assertEqual(list(self.store.load_all(strict=True).keys()), ["existing_dev"])
            self.assertEqual(self.secrets.resolve_ref(ext_ref), "stay-safe")

            # Fault during save_all + rollback delete_secret failure -> journal retained, then recovered on next load
            real_delete = self.secrets.delete_secret

            def _fail_first_delete(ns: str, key: str) -> bool:
                if key.startswith("commit_fail_dev__"):
                    raise OSError(errno.ENOSPC, "Disk full")
                return real_delete(ns, key)

            with (
                patch.object(self.store, "save_all", side_effect=OSError(errno.ENOSPC, "Disk full")),
                patch.object(self.secrets, "delete_secret", side_effect=_fail_first_delete),
            ):
                with self.assertRaises(OSError):
                    commit_device_wizard_plan(
                        self.store, draft, approved_host_key=approved, expected_snapshot=preview.snapshot, password="new-pw"
                    )
            self.assertTrue(self.store.tx_journal_path.exists())
            recovered = self.store.load_all(strict=True)
            self.assertEqual(list(recovered.keys()), ["existing_dev"])
            self.assertEqual(self.secrets.resolve_ref(ext_ref), "stay-safe")
            self.assertEqual(self.secrets.list_keys("ssh"), [("ssh", "existing_dev__password")])

            # Oversized preimage (> MAX_KNOWN_HOSTS_FILE_BYTES) rejected before creating tx journal
            self.store.managed_known_hosts_path.write_bytes(b"k" * (MAX_KNOWN_HOSTS_FILE_BYTES + 1))
            oversized_preview = prepare_device_wizard_preview(
                self.store, draft, approved_host_key=approved, password="new-pw"
            )
            with self.assertRaises(ValueError):
                commit_device_wizard_plan(
                    self.store,
                    draft,
                    approved_host_key=approved,
                    expected_snapshot=oversized_preview.snapshot,
                    password="new-pw",
                )
            self.assertFalse(self.store.tx_journal_path.exists())
            self.assertGreater(MAX_TX_JOURNAL_BYTES, MAX_KNOWN_HOSTS_FILE_BYTES)
        finally:
            srv.stop()


class N0502EffectiveSSHEndpointAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        from backend import server as srv

        self.srv = srv
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ssh_dir = self.root / ".ssh"
        self.ssh_dir.mkdir()
        self.cfg_path = self.ssh_dir / "config"

        # Save globals cleanly to keep tests completely isolated
        self.orig_oauth = srv.oauth_provider
        self.orig_exec = srv.oauth_execution
        self.orig_remote_mgr = srv.REMOTE_MANAGER
        self.orig_allowed_hosts = srv.ALLOWED_HOSTS
        self.orig_exec_audit = srv.EXEC_AUDIT
        self.orig_task_mgr = srv.TASK_MANAGER
        self.orig_task_store = srv.TASK_STORE
        self.orig_runner = srv.PROCESS_RUNNER

        from backend.execution_audit import ExecutionAudit
        from backend.oauth_execution import ExecutionApprovals
        from backend.oauth_provider import LocalConsentOAuthProvider
        from backend.process_runner import ProcessRunner
        from backend.remote.manager import RemoteManager
        from backend.tasks import TaskManager, TaskStore

        self.sec_store = SecretStore(self.root / "secrets")
        self.dev_store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.sec_store)
        self.remote_mgr = RemoteManager(self.dev_store, redactor=srv.REDACTOR)
        self.runner = ProcessRunner(spool_dir=self.root / "spool", redactor=srv.REDACTOR)

        self.oauth_prov = LocalConsentOAuthProvider(
            "http://127.0.0.1:8765",
            "http://127.0.0.1:8765/mcp",
            "owner-tok",
            store_path=self.root / "oauth.sqlite3",
            default_profile=PROFILE_ALLOWLIST,
        )
        self.oauth_store = self.oauth_prov.store
        self.exec_approvals = ExecutionApprovals(self.oauth_store, default_profile=PROFILE_ALLOWLIST)
        self.exec_audit = ExecutionAudit(self.root / "audit.jsonl")
        self.task_store = TaskStore(self.root / "tasks.sqlite3")
        self.task_mgr = TaskManager(
            self.task_store,
            self.runner,
            artifacts_dir=self.root / "task_artifacts",
            redactor=srv.REDACTOR,
            auth_rechecker=srv._task_auth_rechecker,
            command_executor=srv._task_command_executor,
        )

        srv.oauth_provider = self.oauth_prov
        srv.oauth_execution = self.exec_approvals
        srv.REMOTE_MANAGER = self.remote_mgr
        srv.EXEC_AUDIT = self.exec_audit
        srv.TASK_STORE = self.task_store
        srv.TASK_MANAGER = self.task_mgr
        srv.PROCESS_RUNNER = self.runner

        for cid, prof in (("c-allow", PROFILE_ALLOWLIST), ("c-full", PROFILE_FULL)):
            self.oauth_store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=cid,
                    redirect_uris=["http://127.0.0.1/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            self.oauth_store.mark_approved(cid)
            self.exec_approvals.set_client_profile(cid, prof)

        self.connected_calls: list[dict] = []

    def tearDown(self) -> None:
        try:
            asyncio.run(self.task_mgr.close())
        except Exception:
            pass
        self.srv.oauth_provider = self.orig_oauth
        self.srv.oauth_execution = self.orig_exec
        self.srv.REMOTE_MANAGER = self.orig_remote_mgr
        self.srv.ALLOWED_HOSTS = self.orig_allowed_hosts
        self.srv.EXEC_AUDIT = self.orig_exec_audit
        self.srv.TASK_MANAGER = self.orig_task_mgr
        self.srv.TASK_STORE = self.orig_task_store
        self.srv.PROCESS_RUNNER = self.orig_runner
        self.runner.close()
        self.exec_audit.close()
        self.remote_mgr.close()
        self.tmp.cleanup()

    def _fake_ssh_cls(self):
        calls = self.connected_calls

        class _FakeChan:
            def recv_ready(self):
                return False

            def recv_stderr_ready(self):
                return False

            def exit_status_ready(self):
                return True

            def recv_exit_status(self):
                return 0

            def close(self):
                pass

        class _FakeSSH:
            def load_system_host_keys(self):
                pass

            def load_host_keys(self, _p):
                pass

            def set_missing_host_key_policy(self, policy):
                assert isinstance(policy, self_paramiko_reject)

            def connect(self, **kw):
                calls.append(dict(kw))

            def exec_command(self, _cmd, timeout=10):
                s = types.SimpleNamespace(channel=_FakeChan())
                return (None, s, s)

            def close(self):
                pass

        import paramiko as _p

        self_paramiko_reject = _p.RejectPolicy
        return _FakeSSH

    def _run_as_client(self, client_id: str, coro):
        from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
        from mcp.server.auth.provider import AccessToken
        from backend.oauth_provider import READ_SCOPE

        tok = auth_context_var.set(
            AuthenticatedUser(AccessToken(token="tok", client_id=client_id, scopes=[READ_SCOPE], resource="http://127.0.0.1:8765/mcp"))
        )
        try:
            return asyncio.run(coro)
        finally:
            auth_context_var.reset(tok)

    def test_alias_redirect_to_unauthorized_host_is_denied_and_authorized_alias_works(self) -> None:
        self.cfg_path.write_text(
            "Host lab-alias\n  HostName target.example.invalid\n  User svcops\n  Port 2299\n",
            encoding="utf-8",
        )
        self.exec_approvals.set_policy(windows="", hosts="lab-alias", ssh_commands="uname -a")
        with (
            patch.object(Path, "home", return_value=self.root),
            patch.object(self.srv.paramiko, "SSHClient", self._fake_ssh_cls()),
        ):
            res_denied = self._run_as_client("c-allow", self.srv.oauth_ssh_command("lab-alias", "uname -a"))
            self.assertIn("недоступны", res_denied)
            self.assertEqual(self.connected_calls, [])

            # Authorizing BOTH alias and resolved effective HostName keeps alias compatibility
            self.exec_approvals.set_policy(windows="", hosts="lab-alias\ntarget.example.invalid", ssh_commands="uname -a")
            res_ok = self._run_as_client("c-allow", self.srv.oauth_ssh_command("lab-alias", "uname -a"))
            self.assertIn("Exit code: 0", res_ok)
            self.assertEqual(len(self.connected_calls), 1)
            self.assertEqual(self.connected_calls[0]["hostname"], "target.example.invalid")
            self.assertEqual(self.connected_calls[0]["username"], "svcops")
            self.assertEqual(self.connected_calls[0]["port"], 2299)

    def test_detects_ssh_config_mutation_between_auth_and_execution_and_on_restart(self) -> None:
        self.cfg_path.write_text(
            "Host lab-alias\n  HostName target-a.example.invalid\n  User ops1\n  Port 2201\n",
            encoding="utf-8",
        )
        self.exec_approvals.set_policy(
            windows="",
            hosts="lab-alias\ntarget-a.example.invalid\ntarget-b.example.invalid",
            ssh_commands="uname -a",
        )

        # 1. Mutation between oauth_ssh_command authorization and spawn
        orig_run_ssh = self.srv.PROCESS_RUNNER.run_ssh

        async def _mutate_then_run(fn, *, client_id, pre_dispatch_check=None, run_id=None):
            self.cfg_path.write_text(
                "Host lab-alias\n  HostName target-b.example.invalid\n  User evil\n  Port 2299\n",
                encoding="utf-8",
            )
            return await orig_run_ssh(fn, client_id=client_id, pre_dispatch_check=pre_dispatch_check, run_id=run_id)

        with (
            patch.object(Path, "home", return_value=self.root),
            patch.object(self.srv.paramiko, "SSHClient", self._fake_ssh_cls()),
            patch.object(self.srv.PROCESS_RUNNER, "run_ssh", side_effect=_mutate_then_run),
        ):
            res_mut = self._run_as_client("c-allow", self.srv.oauth_ssh_command("lab-alias", "uname -a"))
            self.assertIn("недоступны", res_mut)
            self.assertEqual(self.connected_calls, [])

        # 2. task_start pins effective target; mutating ~/.ssh/config after enqueue or before task_restart fails closed
        self.cfg_path.write_text(
            "Host lab-alias\n  HostName target-a.example.invalid\n  User ops1\n  Port 2201\n",
            encoding="utf-8",
        )

        async def _task_flow():
            with (
                patch.object(Path, "home", return_value=self.root),
                patch.object(self.srv.paramiko, "SSHClient", self._fake_ssh_cls()),
            ):
                created = await self.srv.task_start(command="uname -a", kind="ssh", host="lab-alias")
                tid = created["task_id"]
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    st = await self.srv.task_status(tid)
                    if st["status"] in ("succeeded", "failed"):
                        break
                    await asyncio.sleep(0.02)
                self.assertEqual(st["status"], "succeeded")

                # Mutate SSH config before restart -> restart MUST fail closed!
                self.cfg_path.write_text(
                    "Host lab-alias\n  HostName target-b.example.invalid\n  User root\n  Port 2222\n",
                    encoding="utf-8",
                )
                restarted = await self.srv.task_restart(tid)
                self.assertTrue(getattr(restarted, "is_error", False))

                # Restore config and verify enqueue->dispatch mutation fails worker too
                self.cfg_path.write_text(
                    "Host lab-alias\n  HostName target-a.example.invalid\n  User ops1\n  Port 2201\n",
                    encoding="utf-8",
                )
                self.task_mgr._wake = lambda: None  # pause dispatch temporarily
                queued = await self.srv.task_start(command="uname -a", kind="ssh", host="lab-alias")
                qid = queued["task_id"]
                self.cfg_path.write_text(
                    "Host lab-alias\n  HostName target-a.example.invalid\n  User ops_hijacked\n  Port 2201\n",
                    encoding="utf-8",
                )
                spec = self.task_store.get_spec(qid)
                rec = self.task_store.get_task(qid)
                assert spec is not None and rec is not None
                with self.assertRaises(PermissionError):
                    self.srv._authorize_task_spec("c-allow", spec)

                # Revoke client also denies restart even with clean config
                self.cfg_path.write_text(
                    "Host lab-alias\n  HostName target-a.example.invalid\n  User ops1\n  Port 2201\n",
                    encoding="utf-8",
                )
                self.oauth_store.revoke_client("c-allow")
                restarted_revoked = await self.srv.task_restart(tid)
                self.assertTrue(getattr(restarted_revoked, "is_error", False))

        self._run_as_client("c-allow", _task_flow())

    def test_full_access_and_device_profile_interaction_and_legacy_run_ssh(self) -> None:
        # 1. Full Access still runs arbitrary unregistered hosts without prompts
        with (
            patch.object(Path, "home", return_value=self.root),
            patch.object(self.srv.paramiko, "SSHClient", self._fake_ssh_cls()),
        ):
            res_full = self._run_as_client("c-full", self.srv.oauth_ssh_command("any-host.example.invalid", "id && uname -a"))
            self.assertIn("Exit code: 0", res_full)

        # 2. Registered deny-by-default DeviceProfile blocks even Full Access on legacy oauth_ssh_command
        self.dev_store.upsert(
            DeviceProfile(
                device_id="guarded_box",
                name="Guarded",
                host="guarded.example.invalid",
                port=2222,
                username="ops",
                allow_oauth_clients=False,
                allowed_commands=("uname -s",),
                permissions=DevicePermissions(execute=True),
            )
        )
        with (
            patch.object(Path, "home", return_value=self.root),
            patch.object(self.srv.paramiko, "SSHClient", self._fake_ssh_cls()),
        ):
            res_deny_default = self._run_as_client(
                "c-full", self.srv.oauth_ssh_command("guarded.example.invalid", "whoami", user="ops", port=2222)
            )
            self.assertIn("недоступны", res_deny_default)

            # Enable OAuth clients, but mismatched username still denied; matching username passes in Full Access
            self.dev_store.upsert(
                DeviceProfile(
                    device_id="guarded_box",
                    name="Guarded",
                    host="guarded.example.invalid",
                    port=2222,
                    username="ops",
                    allow_oauth_clients=True,
                    allowed_commands=("uname -s",),
                    permissions=DevicePermissions(execute=True),
                )
            )
            res_wrong_user = self._run_as_client(
                "c-full", self.srv.oauth_ssh_command("guarded.example.invalid", "whoami", user="root", port=2222)
            )
            self.assertIn("недоступны", res_wrong_user)

            res_full_dev = self._run_as_client(
                "c-full", self.srv.oauth_ssh_command("guarded.example.invalid", "whoami", user="ops", port=2222)
            )
            self.assertIn("Exit code: 0", res_full_dev)

            # 3. Legacy run_ssh_command blocks alias pointing to unauthorized effective host
            self.cfg_path.write_text(
                "Host legacy-alias\n  HostName hidden.example.invalid\n  User ops\n  Port 22\n",
                encoding="utf-8",
            )
            self.srv.ALLOWED_HOSTS = frozenset({"legacy-alias"})
            legacy_denied = asyncio.run(self.srv.run_ssh_command("legacy-alias", "uname -a"))
            self.assertIn("Отказано", legacy_denied)

        # 4. Direct resolve_effective_ssh_target validates bad Port inside ~/.ssh/config fail-closed
        self.cfg_path.write_text("Host bad-port\n  HostName safe.example.invalid\n  Port notanumber\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            resolve_effective_ssh_target("bad-port", ssh_config_path=self.cfg_path)

        # 5. Scheduler checks deny allowlisted alias resolving to unauthorized effective host
        from backend.automation.scheduler import ScheduleSpec

        self.cfg_path.write_text("Host sched-alias\n  HostName unauth.example.invalid\n", encoding="utf-8")
        self.exec_approvals.set_policy(windows="", hosts="sched-alias", ssh_commands="uname -a")
        sched_ssh = ScheduleSpec(
            schedule_id="s-ssh",
            name="sched ssh",
            trigger_type="cron",
            client_id="c-allow",
            tool_name="oauth_ssh_command",
            cron_expr="*/5 * * * *",
            arguments={"host": "sched-alias", "command": "uname -a"},
        )
        sched_task = ScheduleSpec(
            schedule_id="s-task",
            name="sched task",
            trigger_type="cron",
            client_id="c-allow",
            tool_name="task_start",
            cron_expr="*/5 * * * *",
            arguments={"kind": "ssh", "host": "sched-alias", "command": "uname -a"},
        )
        with patch.object(Path, "home", return_value=self.root):
            self.assertIsNotNone(self.srv._scheduler_check_ssh_args(sched_ssh, PROFILE_ALLOWLIST, is_owner=False))
            self.assertIsNotNone(self.srv._scheduler_check_task_start_args(sched_task, PROFILE_ALLOWLIST, is_owner=False))


class N0503BoundedTailscaleDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_streaming_byte_limit_stops_reading_early_and_kills_owned_process(self) -> None:
        spam_script = self.root / "spam_stdout.py"
        spam_script.write_text(
            "import sys, time\n"
            "chunk = b'X' * 4096\n"
            "for _ in range(1024):\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "    sys.stdout.buffer.flush()\n"
            "    time.sleep(0.002)\n",
            encoding="utf-8",
        )
        res = run_cli_capture_bounded(
            [sys.executable, str(spam_script)],
            timeout=5.0,
            max_stdout_bytes=32 * 1024,
            max_stderr_bytes=8 * 1024,
            chunk_size=4096,
        )
        self.assertTrue(res.stdout_limit_exceeded)
        self.assertEqual(res.stdout, "")
        self.assertGreater(res.stdout_bytes_read, 32 * 1024)
        self.assertLessEqual(res.stdout_bytes_read, 32 * 1024 + 4096)

        real_popen = subprocess.Popen
        big_json_script = self.root / "tailscale.exe"
        big_json_script.write_text("", encoding="utf-8")
        with (
            patch("backend.remote.discovery._find_tailscale", return_value=str(big_json_script)),
            patch(
                "app.core.tunnels.base.subprocess.Popen",
                side_effect=lambda _cmd, **kw: real_popen(
                    [sys.executable, str(spam_script)],
                    stdin=kw.get("stdin"),
                    stdout=kw.get("stdout"),
                    stderr=kw.get("stderr"),
                    env=kw.get("env"),
                    creationflags=kw.get("creationflags", 0),
                ),
            ),
        ):
            disc = discover_tailscale_ssh_peers(
                owner_consent=True,
                configured_cli_path=str(big_json_script),
                limits=SSHNetworkDiscoveryLimits(max_tailscale_json_bytes=16 * 1024),
            )
        self.assertTrue(disc.available)
        self.assertEqual(disc.status, "error")
        self.assertIn("safety limit", disc.detail)

    def test_timeout_cancellation_secret_redaction_and_foreign_pid_guard(self) -> None:
        # 1. Total deadline kills sleeping child
        sleep_script = self.root / "sleep.py"
        sleep_script.write_text("import time; time.sleep(30)\n", encoding="utf-8")
        t0 = time.monotonic()
        res_to = run_cli_capture_bounded([sys.executable, str(sleep_script)], timeout=0.35)
        self.assertTrue(res_to.timed_out)
        self.assertLess(time.monotonic() - t0, 3.0)

        # 2. Cancellation event stops child early and Tailscale returns cancelled
        real_popen = subprocess.Popen
        ev = threading.Event()
        timer = threading.Timer(0.15, ev.set)
        timer.start()
        fake_exe = self.root / "tailscale.exe"
        fake_exe.write_text("", encoding="utf-8")
        try:
            with (
                patch("backend.remote.discovery._find_tailscale", return_value=str(fake_exe)),
                patch(
                    "app.core.tunnels.base.subprocess.Popen",
                    side_effect=lambda _cmd, **kw: real_popen(
                        [sys.executable, str(sleep_script)],
                        stdin=kw.get("stdin"),
                        stdout=kw.get("stdout"),
                        stderr=kw.get("stderr"),
                        env=kw.get("env"),
                        creationflags=kw.get("creationflags", 0),
                    ),
                ),
            ):
                disc_cancel = discover_tailscale_ssh_peers(owner_consent=True, cancel_event=ev)
        finally:
            timer.cancel()
        self.assertEqual(disc_cancel.status, "cancelled")

        # 3. Non-zero exit scrubs tailscale auth key from diagnostic message
        err_script = self.root / "err.py"
        err_script.write_text(
            "import sys; sys.stderr.write('failed with tskey-auth-secret12345678\\n'); sys.exit(1)\n",
            encoding="utf-8",
        )
        with (
            patch("backend.remote.discovery._find_tailscale", return_value=str(fake_exe)),
            patch(
                "app.core.tunnels.base.subprocess.Popen",
                side_effect=lambda _cmd, **kw: real_popen(
                    [sys.executable, str(err_script)],
                    stdin=kw.get("stdin"),
                    stdout=kw.get("stdout"),
                    stderr=kw.get("stderr"),
                    env=kw.get("env"),
                    creationflags=kw.get("creationflags", 0),
                ),
            ),
        ):
            disc_err = discover_tailscale_ssh_peers(owner_consent=True)
        self.assertEqual(disc_err.status, "not_running")
        self.assertNotIn("secret12345678", disc_err.detail)
        self.assertIn("tskey-[REDACTED]", disc_err.detail)

        # 4. Foreign PID guard: if verify_process_identity fails, never kill foreign PID
        fake_proc = types.SimpleNamespace(
            pid=999999,
            poll=lambda: None,
            kill=lambda: (_ for _ in ()).throw(AssertionError("Must not kill unverified PID")),
            wait=lambda timeout=2.0: 0,
        )
        fake_ident = types.SimpleNamespace(pid=999999, create_time=1.0)
        fake_platform = types.SimpleNamespace(
            verify_process_identity=lambda _i: False,
            terminate_process_tree=lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("Must not terminate foreign")),
        )
        with patch("app.core.tunnels.base.get_platform", return_value=fake_platform):
            _terminate_owned_cli_process(fake_proc, fake_ident)  # type: ignore[arg-type]


def _gen_ed25519_keypair():
    import io
    import paramiko
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem)), pem


class N05FinalUnifiedSSHTrustContractTests(unittest.TestCase):
    """RED/GREEN verification of unified SSH host-key trust across RemoteManager and legacy paths."""

    def setUp(self) -> None:
        from backend import server as srv
        from backend.execution_audit import ExecutionAudit
        from backend.oauth_execution import ExecutionApprovals
        from backend.oauth_provider import LocalConsentOAuthProvider
        from backend.process_runner import ProcessRunner
        from backend.remote.host_keys import compute_host_key_sha256
        from backend.remote.manager import RemoteManager
        from backend.remote.models import format_known_hosts_host
        from backend.tasks import TaskManager, TaskStore

        self.srv = srv
        self.compute_sha256 = compute_host_key_sha256
        self.format_kh_host = format_known_hosts_host
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home_dir = self.root / "home"
        self.ssh_dir = self.home_dir / ".ssh"
        self.ssh_dir.mkdir(parents=True)
        self.user_kh = self.ssh_dir / "known_hosts"

        self.orig_oauth = srv.oauth_provider
        self.orig_exec = srv.oauth_execution
        self.orig_remote_mgr = srv.REMOTE_MANAGER
        self.orig_allowed_hosts = srv.ALLOWED_HOSTS
        self.orig_exec_audit = srv.EXEC_AUDIT
        self.orig_task_mgr = srv.TASK_MANAGER
        self.orig_task_store = srv.TASK_STORE
        self.orig_runner = srv.PROCESS_RUNNER

        self.sec_store = SecretStore(self.root / "secrets")
        self.dev_store = DeviceStore(self.root / "remote" / "devices.json", secret_store=self.sec_store)
        self.remote_mgr = RemoteManager(self.dev_store, redactor=srv.REDACTOR)
        self.runner = ProcessRunner(spool_dir=self.root / "spool", redactor=srv.REDACTOR)

        self.oauth_prov = LocalConsentOAuthProvider(
            "http://127.0.0.1:8765",
            "http://127.0.0.1:8765/mcp",
            "owner-tok",
            store_path=self.root / "oauth.sqlite3",
            default_profile=PROFILE_ALLOWLIST,
        )
        self.oauth_store = self.oauth_prov.store
        self.exec_approvals = ExecutionApprovals(self.oauth_store, default_profile=PROFILE_ALLOWLIST)
        self.exec_audit = ExecutionAudit(self.root / "audit.jsonl")
        self.task_store = TaskStore(self.root / "tasks.sqlite3")
        self.task_mgr = TaskManager(
            self.task_store,
            self.runner,
            artifacts_dir=self.root / "task_artifacts",
            redactor=srv.REDACTOR,
            auth_rechecker=srv._task_auth_rechecker,
            command_executor=srv._task_command_executor,
        )

        srv.oauth_provider = self.oauth_prov
        srv.oauth_execution = self.exec_approvals
        srv.REMOTE_MANAGER = self.remote_mgr
        srv.ALLOWED_HOSTS = frozenset({"127.0.0.1"})
        srv.EXEC_AUDIT = self.exec_audit
        srv.TASK_STORE = self.task_store
        srv.TASK_MANAGER = self.task_mgr
        srv.PROCESS_RUNNER = self.runner

        for cid, prof in (("c-allow", PROFILE_ALLOWLIST), ("c-full", PROFILE_FULL)):
            self.oauth_store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=cid,
                    redirect_uris=["http://127.0.0.1/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            self.oauth_store.mark_approved(cid)
            self.exec_approvals.set_client_profile(cid, prof)

        self.key_a, _ = _gen_ed25519_keypair()
        self.key_b, _ = _gen_ed25519_keypair()
        self.client_key, client_pem = _gen_ed25519_keypair()
        self.client_key_path = self.ssh_dir / "id_ed25519"
        self.client_key_path.write_text(client_pem, encoding="utf-8")

        self.ssh_srv = LocalSSHServer(
            self.root / "sftp",
            username="ops",
            password="unused-password",
            authorized_pubkeys=(self.client_key,),
            host_key=self.key_b,
        )
        self.ssh_srv.start()
        self.cfg_path = self.ssh_dir / "config"
        self.cfg_path.write_text(
            f"Host 127.0.0.1\n  User ops\n  Port {self.ssh_srv.port}\n  IdentityFile {self.client_key_path}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.ssh_srv.stop()
        try:
            asyncio.run(self.task_mgr.close())
        except Exception:
            pass
        self.srv.oauth_provider = self.orig_oauth
        self.srv.oauth_execution = self.orig_exec
        self.srv.REMOTE_MANAGER = self.orig_remote_mgr
        self.srv.ALLOWED_HOSTS = self.orig_allowed_hosts
        self.srv.EXEC_AUDIT = self.orig_exec_audit
        self.srv.TASK_MANAGER = self.orig_task_mgr
        self.srv.TASK_STORE = self.orig_task_store
        self.srv.PROCESS_RUNNER = self.orig_runner
        self.runner.close()
        self.exec_audit.close()
        self.remote_mgr.close()
        self.tmp.cleanup()

    def _run_as_client(self, client_id: str, coro):
        from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
        from mcp.server.auth.provider import AccessToken
        from backend.oauth_provider import READ_SCOPE

        tok = auth_context_var.set(
            AuthenticatedUser(
                AccessToken(
                    token="tok",
                    client_id=client_id,
                    scopes=[READ_SCOPE],
                    resource="http://127.0.0.1:8765/mcp",
                )
            )
        )
        try:
            return asyncio.run(coro)
        finally:
            auth_context_var.reset(tok)

    def _write_known_hosts_line(self, path: Path, pkey) -> None:
        host_entry = self.format_kh_host("127.0.0.1", self.ssh_srv.port)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{host_entry} {pkey.get_name()} {pkey.get_base64()}\n", encoding="utf-8")

    def _make_pinned_device(self, device_id: str, pkey, *, kh_path: Path | None = None) -> DeviceProfile:
        kh = kh_path or self.dev_store.managed_known_hosts_path
        return DeviceProfile(
            device_id=device_id,
            name=f"Device {device_id}",
            host="127.0.0.1",
            port=self.ssh_srv.port,
            username="ops",
            auth_method="key",
            key_path=str(self.client_key_path),
            known_hosts_path=str(kh),
            pinned_host_key_algorithm=pkey.get_name(),
            pinned_host_key_sha256=self.compute_sha256(pkey),
            pinned_host_key_base64=pkey.get_base64(),
            enabled=True,
            allow_oauth_clients=True,
            min_profile="allowlist",
            permissions=DevicePermissions(execute=True),
            allowed_commands=("echo ok",),
        )

    async def _await_task_terminal(self, task_id: str) -> dict:
        deadline = time.monotonic() + 8.0
        st: dict = {}
        while time.monotonic() < deadline:
            st = await self.srv.task_status(task_id)
            if st.get("status") in ("succeeded", "failed", "cancelled", "interrupted"):
                return st
            await asyncio.sleep(0.02)
        return st

    def test_registered_pinned_device_rejects_mismatched_key_in_system_known_hosts_across_all_paths(self) -> None:
        from backend.automation.scheduler import ScheduleSpec

        managed_kh = self.dev_store.managed_known_hosts_path
        self._write_known_hosts_line(managed_kh, self.key_a)
        self._write_known_hosts_line(self.user_kh, self.key_b)
        self.dev_store.upsert(self._make_pinned_device("dev_pin_a", self.key_a, kh_path=managed_kh))
        self.exec_approvals.set_policy(windows="", hosts="127.0.0.1", ssh_commands="echo ok")

        sched_spec = ScheduleSpec(
            schedule_id="sched-ssh-pin",
            name="SSH Pin Check",
            tool_name="oauth_ssh_command",
            arguments={"host": "127.0.0.1", "user": "ops", "port": self.ssh_srv.port, "command": "echo ok"},
            trigger_type="interval",
            interval_seconds=60,
            client_id="c-allow",
        )

        async def _flow() -> None:
            # Server presents key_b (trusted in user known_hosts) while device is pinned to key_a:
            # EVERY path must reject key_b BEFORE sending auth packets.
            with self.assertRaises(PermissionError):
                self.remote_mgr.ssh_execute(
                    "dev_pin_a", "echo ok", client_id="c-allow", client_profile="allowlist", from_oauth=True
                )
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            res_oauth = await self.srv.oauth_ssh_command(
                "127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port
            )
            self.assertIn("❌", res_oauth)
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            res_legacy = await self.srv.run_ssh_command(
                "127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port
            )
            self.assertIn("❌", res_legacy)
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            started = await self.srv.task_start(
                command="echo ok", kind="ssh", host="127.0.0.1", user="ops", port=self.ssh_srv.port
            )
            st_failed = await self._await_task_terminal(started["task_id"])
            self.assertEqual(st_failed["status"], "failed")
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            with self.assertRaises(RuntimeError) as sched_ctx:
                await self.srv._execute_scheduled_tool_async(sched_spec, "idem-key-b")
            self.assertIn("❌", str(sched_ctx.exception))
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            # Rotate server to approved key_a (absent from user ~/.ssh/known_hosts!) -> all paths succeed
            self.ssh_srv.rotate_host_key(self.key_a)
            res_ok = await self.srv.oauth_ssh_command(
                "127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port
            )
            self.assertIn("Exit code: 0", res_ok)

            res_legacy_ok = await self.srv.run_ssh_command(
                "127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port
            )
            self.assertIn("Exit code: 0", res_legacy_ok)

            created_ok = await self.srv.task_start(
                command="echo ok", kind="ssh", host="127.0.0.1", user="ops", port=self.ssh_srv.port
            )
            tid_ok = created_ok["task_id"]
            st_ok = await self._await_task_terminal(tid_ok)
            self.assertEqual(st_ok["status"], "succeeded")

            sched_ok = await self.srv._execute_scheduled_tool_async(sched_spec, "idem-key-a")
            self.assertIn("Exit code: 0", sched_ok.get("text", ""))

            # Rotate server back to unpinned key_b -> task_restart worker rejects key_b pre-auth
            self.ssh_srv.rotate_host_key(self.key_b)
            attempts_before = len(self.ssh_srv.auth_attempts)
            restarted_info = await self.srv.task_restart(tid_ok)
            self.assertFalse(getattr(restarted_info, "is_error", False))
            st_restarted = await self._await_task_terminal(restarted_info["task_id"])
            self.assertEqual(st_restarted["status"], "failed")
            self.assertEqual(len(self.ssh_srv.auth_attempts), attempts_before)

            # Mutating device pin in DeviceStore fails closed immediately on task_restart
            self.dev_store.upsert(self._make_pinned_device("dev_pin_a", self.key_b, kh_path=managed_kh))
            restarted_pin_drift = await self.srv.task_restart(tid_ok)
            self.assertTrue(getattr(restarted_pin_drift, "is_error", False))
            await self.task_mgr.close()

        with patch.object(Path, "home", return_value=self.home_dir):
            self._run_as_client("c-allow", _flow())

    def test_conflicting_trust_sources_fail_closed_across_all_paths(self) -> None:
        from backend.automation.scheduler import ScheduleSpec

        managed_kh = self.dev_store.managed_known_hosts_path
        alt_kh = self.root / "remote" / "alt_known_hosts"
        self._write_known_hosts_line(managed_kh, self.key_a)
        self._write_known_hosts_line(alt_kh, self.key_b)
        self.exec_approvals.set_policy(windows="", hosts="127.0.0.1", ssh_commands="echo ok")

        sched_spec = ScheduleSpec(
            schedule_id="sched-ssh-conflict",
            name="SSH Conflict",
            tool_name="oauth_ssh_command",
            arguments={"host": "127.0.0.1", "user": "ops", "port": self.ssh_srv.port, "command": "echo ok"},
            trigger_type="interval",
            interval_seconds=60,
            client_id="c-allow",
        )

        # Case 1: Two registered DeviceProfiles disagree on pinned host key for same endpoint
        self.dev_store.upsert(self._make_pinned_device("dev_1", self.key_a, kh_path=managed_kh))
        self.dev_store.upsert(self._make_pinned_device("dev_2", self.key_b, kh_path=alt_kh))

        with patch.object(Path, "home", return_value=self.home_dir):
            with self.assertRaises(PermissionError):
                self.remote_mgr.authorize_legacy_ssh_endpoint(
                    effective_host="127.0.0.1",
                    effective_port=self.ssh_srv.port,
                    effective_user="ops",
                    command="echo ok",
                    client_id="c-allow",
                    client_profile="allowlist",
                    from_oauth=True,
                )
            res_oauth = self._run_as_client(
                "c-allow", self.srv.oauth_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("недоступны", res_oauth)
            res_legacy = asyncio.run(
                self.srv.run_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("Отказано", res_legacy)
            res_task = self._run_as_client(
                "c-allow",
                self.srv.task_start(command="echo ok", kind="ssh", host="127.0.0.1", user="ops", port=self.ssh_srv.port),
            )
            self.assertTrue(getattr(res_task, "is_error", False))
            ok_sched, _ = self.srv._scheduler_permission_check(sched_spec)
            self.assertFalse(ok_sched)
            self.assertEqual(self.ssh_srv.auth_attempts, [])

        # Case 2: Single registered DeviceProfile whose pin conflicts with its own known_hosts_path
        self.dev_store.remove("dev_2")
        self._write_known_hosts_line(managed_kh, self.key_b)
        with patch.object(Path, "home", return_value=self.home_dir):
            with self.assertRaises(PermissionError):
                self.remote_mgr.ssh_execute("dev_1", "echo ok", client_id="c-allow", client_profile="allowlist", from_oauth=True)
            res_oauth2 = self._run_as_client(
                "c-allow", self.srv.oauth_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("недоступны", res_oauth2)
            res_legacy2 = asyncio.run(
                self.srv.run_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("Отказано", res_legacy2)
            ok_sched2, _ = self.srv._scheduler_permission_check(sched_spec)
            self.assertFalse(ok_sched2)
            self.assertEqual(self.ssh_srv.auth_attempts, [])

        # Case 3: Reparse/symlink known_hosts_path fails closed
        self._write_known_hosts_line(managed_kh, self.key_a)
        with (
            patch.object(Path, "home", return_value=self.home_dir),
            patch("backend.remote.ssh_client.is_reparse_or_symlink", return_value=True),
        ):
            with self.assertRaises(PermissionError):
                self.remote_mgr.authorize_legacy_ssh_endpoint(
                    effective_host="127.0.0.1",
                    effective_port=self.ssh_srv.port,
                    effective_user="ops",
                    command="echo ok",
                    client_id="c-allow",
                    client_profile="allowlist",
                    from_oauth=True,
                )

    def test_unregistered_legacy_endpoint_preserves_strict_known_hosts_and_full_access(self) -> None:
        with patch.object(Path, "home", return_value=self.home_dir):
            # Unknown host key in user known_hosts -> rejected pre-auth even in Full Access
            res_unknown = self._run_as_client(
                "c-full", self.srv.oauth_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("❌", res_unknown)
            self.assertEqual(self.ssh_srv.auth_attempts, [])

            # Trusted in user known_hosts -> Full Access works without prompts
            self._write_known_hosts_line(self.user_kh, self.key_b)
            res_full = self._run_as_client(
                "c-full", self.srv.oauth_ssh_command("127.0.0.1", "echo ok", user="ops", port=self.ssh_srv.port)
            )
            self.assertIn("Exit code: 0", res_full)


if __name__ == "__main__":
    unittest.main()
