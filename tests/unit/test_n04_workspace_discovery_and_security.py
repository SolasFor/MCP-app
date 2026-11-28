"""TDD unit tests for Stage N04: bounded read-only workspace discovery, security guards, and atomic commit."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from app.core.secret_store import SecretStore
from app.updater.trust import PRODUCTION_PUBLISHER_THUMBPRINTS, PRODUCTION_TRUST_ROOTS
from backend.process_runner import ProcessRunner
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore
from backend.tasks.store import TaskStore
from backend.workspaces.compose_yaml import (
    ComposeYamlError,
    ComposeYamlSecurityError,
    parse_safe_compose_yaml,
)
from backend.workspaces.discovery import (
    DiscoveryCancelledError,
    DiscoveryLimits,
    ManifestDriftError,
    WizardConflictError,
    WizardStalePlanError,
    _trusted_system_which,
    analyze_workspace_directory,
    discover_projects_in_directory,
)
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.path_security import PathSecurityError
from backend.workspaces.server_links import WorkspaceServerCoordinator
from backend.workspaces.store import WorkspaceStore, detect_workspace_metadata


class N04DiscoveryAndSecurityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
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
        self.ws_manager = WorkspaceManager(
            self.ws_store,
            self.history,
            runner=self.runner,
            task_store=self.task_store,
            coordinator=self.coordinator,
        )

    def tearDown(self) -> None:
        self.ws_manager.close()
        self.runner.close()
        self.tmp.cleanup()

    def test_detects_python_venv_fastapi_with_zero_execution_or_network(self) -> None:
        proj = self.base / "py_api"
        (proj / "tests").mkdir(parents=True)
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "py-api"\ndependencies = ["fastapi>=0.110", "uvicorn"]\n'
            '[project.scripts]\nserve = "py_api.main:run"\n'
            '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
            encoding="utf-8",
        )
        (proj / "requirements.txt").write_text(
            "fastapi==0.115.0\nhttps://user:secretpass999@pypi.internal.local/simple/pkg.whl\n",
            encoding="utf-8",
        )
        (proj / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
        venv_bin = proj / ".venv" / ("Scripts" if os.name == "nt" else "bin")
        venv_bin.mkdir(parents=True)
        py_exe = venv_bin / ("python.exe" if os.name == "nt" else "python")
        py_exe.write_bytes(b"")
        (proj / ".git" / "refs").mkdir(parents=True)
        (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        # Canary files & rogue local executable inside project must never be read or executed
        (proj / ".env").write_text("API_KEY=CANARY_DOTENV_SECRET_441\n", encoding="utf-8")
        (proj / "node.exe").write_bytes(b"FAKE-ROGUE-EXE")
        (proj / "python.exe").write_bytes(b"FAKE-ROGUE-PY")

        def _forbid(*_a, **_kw):
            raise AssertionError("Discovery must not run subprocesses or network calls")

        with (
            patch.object(subprocess, "Popen", side_effect=_forbid),
            patch.object(subprocess, "run", side_effect=_forbid),
            patch.object(os, "system", side_effect=_forbid),
            patch.object(asyncio, "create_subprocess_exec", side_effect=_forbid),
            patch.object(socket, "create_connection", side_effect=_forbid),
            patch.object(urllib.request, "urlopen", side_effect=_forbid),
        ):
            res = analyze_workspace_directory(proj)
            compat = detect_workspace_metadata(proj)

        self.assertEqual(res.language, "python")
        self.assertIn("python", res.stacks)
        self.assertEqual(res.confidence, "high")
        self.assertTrue(res.git_verified)
        self.assertEqual(Path(res.git_root), proj.resolve())
        self.assertEqual(Path(res.python_venv), (proj / ".venv").resolve())
        cmd_names = {c.name for c in res.commands}
        self.assertIn("test", cmd_names)
        self.assertTrue(any(s.template == "python_fastapi" and not s.port_verified for s in res.server_proposals))
        self.assertTrue(all(not s.selected for s in res.server_proposals))
        self.assertIn("pyproject.toml", res.manifest_digests)
        self.assertEqual(compat["language"], "python")
        self.assertIn("test", compat["commands"])

        # Trusted PATH lookup ignores rogue executable inside project directory
        with patch.dict(os.environ, {"PATH": f"{proj}{os.pathsep}{os.environ.get('PATH', '')}"}):
            resolved_node = _trusted_system_which("node", project_root=proj)
            if resolved_node:
                self.assertFalse(Path(resolved_node).is_relative_to(proj.resolve()))

        # Secrets and URL credentials never appear in serialized result or diagnostics
        serialized = json.dumps(
            {
                "commands": [(c.name, c.command, c.warning) for c in res.commands],
                "diagnostics": [(d.code, d.message) for d in res.diagnostics],
                "sources": res.sources,
            }
        )
        self.assertNotIn("CANARY_DOTENV_SECRET_441", serialized)
        self.assertNotIn("secretpass999", serialized)

    def test_detects_nextjs_ts_node_scripts_and_hostile_secret_filtering(self) -> None:
        proj = self.base / "next_app"
        proj.mkdir()
        (proj / "tsconfig.json").write_text("{}", encoding="utf-8")
        (proj / "next.config.mjs").write_text("export default {}\n", encoding="utf-8")
        (proj / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        (proj / "package.json").write_text(
            json.dumps(
                {
                    "name": "@acme/web-app",
                    "packageManager": "pnpm@9.1.0",
                    "dependencies": {"next": "15.0.0", "react": "19.0.0"},
                    "scripts": {
                        "dev": "next dev -p 3100",
                        "build": "next build",
                        "prebuild": "echo pre-hook",
                        "leak": "curl -H 'Authorization: Bearer sk-supersecret1234567890' https://example.com",
                    },
                }
            ),
            encoding="utf-8",
        )

        res = analyze_workspace_directory(proj)
        self.assertEqual(res.language, "typescript")
        self.assertIn("nextjs", res.stacks)
        self.assertEqual(res.confidence, "high")
        cmd_map = {c.name: c for c in res.commands}
        self.assertIn("dev", cmd_map)
        self.assertIn("build", cmd_map)
        self.assertNotIn("test", cmd_map)  # never guessed when not in package.json scripts
        self.assertNotIn("leak", cmd_map)  # secret-bearing command rejected
        self.assertTrue(cmd_map["build"].has_lifecycle_hooks)
        self.assertTrue(any(d.code == "LIFECYCLE_HOOK_PRESENT" for d in res.diagnostics))
        self.assertTrue(any(d.code == "COMMAND_SECRET_FILTERED" for d in res.diagnostics))
        self.assertTrue(
            any(
                s.template == "vite_next" and s.port == 3100 and not s.port_verified
                for s in res.server_proposals
            )
        )
        dump = json.dumps([(d.code, d.message) for d in res.diagnostics])
        self.assertNotIn("sk-supersecret1234567890", dump)

    def test_docker_compose_safe_yaml_parser_rejects_unsafe_and_redacts_env(self) -> None:
        safe_yaml = (
            "services:\n"
            "  api:\n"
            "    image: python:3.12\n"
            "    ports:\n"
            "      - \"127.0.0.1:8085:8000\"\n"
            "    env_file:\n"
            "      - .env.prod\n"
            "    environment:\n"
            "      SECRET_KEY: super-secret-should-not-appear\n"
            "      PORT: ${APP_PORT:-8085}\n"
            "  worker:\n"
            "    build: .\n"
        )
        parsed = parse_safe_compose_yaml(safe_yaml)
        self.assertEqual([s.name for s in parsed.services], ["api", "worker"])
        self.assertEqual(parsed.services[0].ports, (8085,))
        self.assertTrue(parsed.services[0].has_env_file)
        self.assertTrue(parsed.services[0].has_environment)
        self.assertNotIn("super-secret-should-not-appear", repr(parsed))
        self.assertNotIn("APP_PORT", repr(parsed))

        # Unsafe YAML constructs must fail closed
        unsafe_cases = [
            "services:\n  a: !!python/object/apply:os.system ['calc']\n",
            "x-base: &anchor\n  image: alpine\nservices:\n  a:\n    <<: *anchor\n",
            "services:\n  api:\n    image: a\n  api:\n    image: b\n",
            "include:\n  - ../outside/compose.yaml\nservices:\n  api:\n    image: a\n",
            "services:\n  api:\n    extends:\n      file: /etc/passwd\n",
            "services:\n\tapi:\n\t\timage: a\n",
        ]
        for bad in unsafe_cases:
            with self.subTest(bad=bad[:40]):
                with self.assertRaises((ComposeYamlError, ComposeYamlSecurityError)):
                    parse_safe_compose_yaml(bad)

        # Oversized / deep YAML rejected
        huge_yaml = "services:\n" + "".join(f"  s{i}:\n    image: alpine\n" for i in range(600))
        with self.assertRaises(ComposeYamlError):
            parse_safe_compose_yaml(huge_yaml, max_nodes=200)

        # Compose workspace analysis integrates safely without expanding .env
        comp_dir = self.base / "compose_proj"
        comp_dir.mkdir()
        (comp_dir / "compose.yaml").write_text(safe_yaml, encoding="utf-8")
        (comp_dir / ".env.prod").write_text("SECRET_KEY=CANARY_ENV_PROD_777\n", encoding="utf-8")
        res = analyze_workspace_directory(comp_dir)
        self.assertIn("docker_compose", res.stacks)
        self.assertTrue(any(s.template == "docker_compose" and s.port == 8085 for s in res.server_proposals))
        self.assertNotIn("CANARY_ENV_PROD_777", repr(res))
        self.assertNotIn("super-secret-should-not-appear", repr(res))

    def test_monorepo_mixed_stack_and_unknown_project(self) -> None:
        mono = self.base / "mono"
        (mono / "apps" / "web").mkdir(parents=True)
        (mono / "services" / "api").mkdir(parents=True)
        (mono / "package.json").write_text(
            json.dumps({"name": "mono-root", "private": True, "workspaces": ["apps/*", "services/*"]}),
            encoding="utf-8",
        )
        (mono / "apps" / "web" / "package.json").write_text(
            json.dumps({"name": "web", "dependencies": {"next": "15.0.0"}, "scripts": {"dev": "next dev"}}),
            encoding="utf-8",
        )
        (mono / "services" / "api" / "pyproject.toml").write_text(
            '[project]\nname = "api"\ndependencies = ["fastapi"]\n',
            encoding="utf-8",
        )
        # Escape attempt in workspaces glob must be flagged and skipped
        (mono / "pnpm-workspace.yaml").write_text("packages:\n  - 'apps/*'\n  - '../outside/*'\n", encoding="utf-8")

        res = analyze_workspace_directory(mono)
        sub_paths = {s.relative_path for s in res.subprojects}
        self.assertIn("apps/web", sub_paths)
        self.assertIn("services/api", sub_paths)
        self.assertTrue(any(d.code == "WORKSPACE_GLOB_REJECTED" for d in res.diagnostics))

        empty_dir = self.base / "unknown_empty"
        empty_dir.mkdir()
        unk = analyze_workspace_directory(empty_dir)
        self.assertEqual(unk.language, "generic")
        self.assertEqual(unk.confidence, "unknown")
        self.assertEqual(unk.commands, ())
        self.assertEqual(unk.server_proposals, ())

    def test_malformed_oversized_duplicate_json_and_toml(self) -> None:
        bad_json = self.base / "bad_json"
        bad_json.mkdir()
        (bad_json / "package.json").write_text('{"name": "a", "name": "b"}', encoding="utf-8")
        res_dup = analyze_workspace_directory(bad_json)
        self.assertTrue(any(d.code == "MANIFEST_PARSE_ERROR" for d in res_dup.diagnostics))
        self.assertEqual(res_dup.commands, ())

        oversized = self.base / "oversized"
        oversized.mkdir()
        (oversized / "pyproject.toml").write_text("x = '" + ("a" * 200_000) + "'\n", encoding="utf-8")
        res_big = analyze_workspace_directory(
            oversized, limits=DiscoveryLimits(max_manifest_bytes=8192)
        )
        self.assertTrue(any(d.code == "MANIFEST_TOO_LARGE" for d in res_big.diagnostics))

    def test_rejects_symlinks_junctions_unc_ads_broad_roots_and_respects_cancel(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "package.json").write_text('{"name":"outside","scripts":{"dev":"echo pwn"}}', encoding="utf-8")

        proj = self.base / "symlink_test"
        proj.mkdir()
        link = proj / "package.json"
        try:
            os.symlink(outside / "package.json", link)
        except (OSError, NotImplementedError):
            if os.name == "nt":
                # Directory junction test fallback when symlink privilege is absent
                jdir = proj / "apps"
                subprocess.run(
                    ["cmd.exe", "/c", "mklink", "/J", str(jdir), str(outside)],
                    check=True,
                    capture_output=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
                )
        res = analyze_workspace_directory(proj)
        self.assertEqual(res.commands, ())
        self.assertNotIn("outside", {s.name for s in res.subprojects})

        # Unverified .git file (worktree/gitdir outside) must not set git_verified
        wt = self.base / "worktree_proj"
        wt.mkdir()
        (wt / ".git").write_text("gitdir: ../../outside/.git/worktrees/wt\n", encoding="utf-8")
        wt_res = analyze_workspace_directory(wt)
        self.assertFalse(wt_res.git_verified)
        self.assertEqual(wt_res.git_root, "")
        self.assertTrue(any(d.code == "GIT_WORKTREE_UNVERIFIED" for d in wt_res.diagnostics))

        # No climbing above boundary by default
        parent_git = self.base / "parent_repo"
        (parent_git / ".git" / "refs").mkdir(parents=True)
        (parent_git / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        child = parent_git / "sub"
        child.mkdir()
        self.assertEqual(analyze_workspace_directory(child).git_root, "")

        # UNC, ADS, and broad roots rejected
        for bad_root in ("\\\\server\\share\\proj", str(proj) + ":stream", str(Path.home())):
            with self.subTest(bad_root=bad_root):
                with self.assertRaises(PathSecurityError):
                    analyze_workspace_directory(bad_root)

        # Parent scan respects depth & cancellation
        scan_root = self.base / "parent_scan"
        (scan_root / "proj_a").mkdir(parents=True)
        (scan_root / "proj_a" / "pyproject.toml").write_text('[project]\nname="a"\n', encoding="utf-8")
        (scan_root / "node_modules" / "pkg").mkdir(parents=True)
        (scan_root / "node_modules" / "pkg" / "package.json").write_text('{"name":"ignored"}', encoding="utf-8")
        found = discover_projects_in_directory(scan_root, max_depth=2)
        self.assertEqual([c.name for c in found], ["proj_a"])

        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(DiscoveryCancelledError):
            analyze_workspace_directory(proj, cancel_event=cancel)

    def test_permissions_deny_by_default_and_backwards_compatibility(self) -> None:
        proj = self.base / "perm_proj"
        proj.mkdir()
        # Legacy dict without allow_oauth_clients keeps backwards-compatible True
        legacy = WorkspaceProfile.from_dict(
            "legacy_ws",
            {"name": "Legacy", "root_path": str(proj)},
        )
        self.assertTrue(legacy.allow_oauth_clients)

        # New wizard workspace is read-only and denies all OAuth clients by default
        new_ws = WorkspaceProfile(
            workspace_id="new_ws",
            name="New WS",
            root_path=str(proj),
            commands={"ping": f'"{sys.executable}" -c "print(\'OK\')"'},
            permissions=WorkspacePermissions(read=True),
            allow_oauth_clients=False,
        )
        self.ws_store.upsert_workspace(new_ws)

        with self.assertRaises(PermissionError):
            self.ws_manager.workspace_info("new_ws", client_id="approved-client", client_profile="full")
        self.assertEqual(
            self.ws_manager.list_workspaces(client_id="approved-client", client_profile="full"),
            [],
        )

        # Linked server also refuses OAuth access when workspace has allow_oauth_clients=False
        srv = ServerProfile(
            name="new_ws_api",
            argv=(sys.executable, "-c", "import time; time.sleep(1)"),
            cwd=str(proj),
            workspace_scoped=True,
            autostart=False,
            min_profile="allowlist",
        )
        self.srv_store.upsert_profile(srv)
        self.coordinator.link_server("new_ws", "new_ws_api")
        with self.assertRaises(PermissionError):
            self.coordinator.authorize_server_operation(
                "new_ws_api",
                client_id="approved-client",
                client_profile="full",
                mode="read",
                workspace_id="new_ws",
            )

    def test_atomic_commit_conflicts_stale_plan_rollback_and_manifest_drift(self) -> None:
        proj = self.base / "atomic_proj"
        proj.mkdir()
        pkg = proj / "package.json"
        pkg.write_text(json.dumps({"name": "atomic", "scripts": {"ping": "echo ok"}}), encoding="utf-8")
        res = analyze_workspace_directory(proj)

        # Pre-existing unrelated server must remain untouched
        untouched = ServerProfile(
            name="existing_srv",
            argv=(sys.executable, "-c", "print(1)"),
            cwd=str(proj),
            min_profile="allowlist",
            workspace_scoped=False,
            autostart=False,
        )
        self.srv_store.upsert_profile(untouched)

        ws = WorkspaceProfile(
            workspace_id="atomic_proj",
            name="Atomic Proj",
            root_path=str(proj),
            language="javascript",
            commands={"ping": f'"{sys.executable}" -c "print(\'SAFE\')"'},
            permissions=WorkspacePermissions(read=True, execute=True),
            allow_oauth_clients=False,
            manifest_digests=dict(res.manifest_digests),
        )
        new_srv = ServerProfile(
            name="atomic_srv",
            argv=(sys.executable, "-c", "import time; time.sleep(1)"),
            cwd=str(proj),
            autostart=False,
            workspace_scoped=True,
            template_params={"manifest_digests": dict(res.manifest_digests)},
        )

        preview = self.coordinator.prepare_addition_preview(
            ws,
            new_servers=(new_srv,),
            expected_manifest_digests=res.manifest_digests,
            expected_root_identity=res.root_identity,
        )
        self.assertEqual(preview.conflicts, ())

        # Simulated ENOSPC / PermissionError rollback leaves zero partial state
        with patch.object(self.ws_store, "save_workspaces", side_effect=OSError("No space left on device")):
            with self.assertRaises(OSError):
                self.coordinator.commit_workspace_addition(
                    ws,
                    new_servers=(new_srv,),
                    expected_state_fingerprint=preview.snapshot.state_fingerprint,
                    expected_root_identity=res.root_identity,
                    expected_manifest_digests=res.manifest_digests,
                )
        self.assertEqual(self.ws_store.load_workspaces(), {})
        self.assertEqual(list(self.srv_store.load_profiles()), ["existing_srv"])

        # Valid commit succeeds atomically
        commit_res = self.coordinator.commit_workspace_addition(
            ws,
            new_servers=(new_srv,),
            expected_state_fingerprint=preview.snapshot.state_fingerprint,
            expected_root_identity=res.root_identity,
            expected_manifest_digests=res.manifest_digests,
        )
        self.assertEqual(commit_res["workspace"].workspace_id, "atomic_proj")
        self.assertEqual(self.srv_store.get_profile("existing_srv"), untouched)
        self.assertTrue(self.srv_store.get_profile("atomic_srv").workspace_scoped)  # type: ignore[union-attr]
        self.assertFalse(self.srv_store.get_profile("atomic_srv").autostart)  # type: ignore[union-attr]

        # Stale plan & case-insensitive ID / canonical root duplicate rejected
        with self.assertRaises(WizardStalePlanError):
            self.coordinator.commit_workspace_addition(
                WorkspaceProfile(workspace_id="other_id", name="Other", root_path=str(proj)),
                expected_state_fingerprint=preview.snapshot.state_fingerprint,
            )

        dup_proj = WorkspaceProfile(
            workspace_id="ATOMIC_PROJ",
            name="Dup",
            root_path=str(proj),
            manifest_digests=dict(res.manifest_digests),
        )
        fresh_preview = self.coordinator.prepare_addition_preview(
            dup_proj,
            expected_manifest_digests=res.manifest_digests,
        )
        self.assertTrue(fresh_preview.conflicts)
        with self.assertRaises(WizardConflictError):
            self.coordinator.commit_workspace_addition(
                dup_proj,
                expected_state_fingerprint=fresh_preview.snapshot.state_fingerprint,
            )

        # Nested subproject requires explicit acknowledgement
        sub_dir = proj / "packages" / "sub"
        sub_dir.mkdir(parents=True)
        sub_ws = WorkspaceProfile(workspace_id="sub_pkg", name="Sub", root_path=str(sub_dir))
        sub_prev = self.coordinator.prepare_addition_preview(sub_ws)
        self.assertEqual(sub_prev.nested_workspaces, ("atomic_proj",))
        with self.assertRaises(WizardConflictError):
            self.coordinator.commit_workspace_addition(
                sub_ws,
                expected_state_fingerprint=sub_prev.snapshot.state_fingerprint,
                acknowledge_nested=False,
            )

        # Manifest drift on disk blocks execution fail-closed until re-approved
        pkg.write_text(json.dumps({"name": "atomic", "scripts": {"ping": "echo hijacked"}}), encoding="utf-8")
        with self.assertRaises(ManifestDriftError):
            asyncio.run(self.ws_manager.run_workspace_task("atomic_proj", "ping", client_id="owner"))

        # Re-approve digests restores execution
        refreshed = self.ws_store.refresh_manifest_digests("atomic_proj")
        self.assertEqual(
            refreshed.manifest_digests["package.json"],
            hashlib.sha256(pkg.read_bytes()).hexdigest(),
        )
        task_res = asyncio.run(self.ws_manager.run_workspace_task("atomic_proj", "ping", client_id="owner"))
        self.assertEqual(task_res["exit_code"], 0)

    def test_n02_production_trust_roots_remain_empty(self) -> None:
        self.assertEqual(PRODUCTION_TRUST_ROOTS, ())
        self.assertEqual(PRODUCTION_PUBLISHER_THUMBPRINTS, ())


if __name__ == "__main__":
    unittest.main()
