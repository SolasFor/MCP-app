"""Unit security tests for Stage 7 Workspaces: canonical paths, junctions, ADS, UNC, version conflicts, Git hooks."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.models import WorkspacePermissions, WorkspaceProfile
from backend.workspaces.path_security import (
    FileVersionConflictError,
    PathSecurityError,
    canonical_workspace_root,
    resolve_workspace_path,
)
from backend.workspaces.store import WorkspaceStore


class WorkspacesSecurityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.ws_root = self.base / "repo"
        self.ws_root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("TOP-SECRET-OUTSIDE", encoding="utf-8")
        (self.ws_root / "src").mkdir()
        (self.ws_root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        (self.ws_root / ".env").write_text("API_KEY=plain-env-secret\n", encoding="utf-8")
        (self.ws_root / ".gitignore").write_text("ignored_dir/\n*.log\n", encoding="utf-8")
        (self.ws_root / "ignored_dir").mkdir()
        (self.ws_root / "ignored_dir" / "temp.txt").write_text("ignore me", encoding="utf-8")
        (self.ws_root / "app.log").write_text("log line", encoding="utf-8")

        self.store = WorkspaceStore(
            self.base / "workspaces.json",
            secret_store=SecretStore(self.base / "secrets"),
        )
        self.history = WorkspaceHistory(self.base / "history")
        self.manager = WorkspaceManager(
            self.store, self.history, redactor=SecretRedactor(["plain-env-secret"])
        )
        self.profile = WorkspaceProfile(
            workspace_id="proj",
            name="Test Project",
            root_path=str(self.ws_root),
            exclude_patterns=("*.secret", "private/*"),
            permissions=WorkspacePermissions(read=True, write=True, delete=True, execute=True, git=True),
        )
        self.store.upsert_workspace(self.profile)

    def tearDown(self) -> None:
        self.manager.close()
        self.tmp.cleanup()

    def test_rejects_traversal_unc_ads_reserved_and_sensitive_paths(self) -> None:
        bad_paths = [
            "../outside/secret.txt",
            "..\\outside\\secret.txt",
            str(self.outside / "secret.txt"),
            "\\\\server\\share\\file.txt",
            "src/app.py:ads",
            "CON",
            "src/NUL.txt",
            ".env",
            ".env.local",
            ".git/config",
            "certs/server.pem",
            "private/keys.txt",
            "db.secret",
        ]
        for rel in bad_paths:
            with self.subTest(rel=rel):
                with self.assertRaises(PathSecurityError):
                    resolve_workspace_path(
                        self.ws_root,
                        rel,
                        allow_missing=True,
                        exclude_patterns=self.profile.exclude_patterns,
                    )

        with self.assertRaises(PathSecurityError):
            canonical_workspace_root("\\\\server\\share\\root")

    def test_rejects_junction_or_symlink_escape(self) -> None:
        link_path = self.ws_root / "escape_link"
        if os.name == "nt":
            subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link_path), str(self.outside)],
                check=True,
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
        else:
            os.symlink(self.outside, link_path)

        with self.assertRaises(PathSecurityError):
            resolve_workspace_path(self.ws_root, "escape_link/secret.txt")
        with self.assertRaises(PathSecurityError):
            self.manager.read_file("proj", "escape_link/secret.txt", client_id="owner")
        tree = self.manager.workspace_tree("proj", client_id="owner")
        self.assertFalse(any("escape_link" in e["path"] for e in tree["entries"]))

    def test_version_precondition_prevents_overwriting_user_edits_and_history_rolls_back(self) -> None:
        read1 = self.manager.read_file("proj", "src/app.py", client_id="owner")
        old_sha = read1["sha256"]

        # Simulate concurrent external user edit on disk
        (self.ws_root / "src" / "app.py").write_text("x = 999  # user edit\n", encoding="utf-8")

        with self.assertRaises(FileVersionConflictError):
            self.manager.write_file(
                "proj", "src/app.py", "x = 2\n", expected_sha256=old_sha, client_id="owner"
            )
        with self.assertRaises(FileVersionConflictError):
            self.manager.apply_patch(
                "proj",
                "src/app.py",
                expected_sha256=old_sha,
                edits=[{"old_text": "x = 1", "new_text": "x = 2"}],
                client_id="owner",
            )
        self.assertEqual((self.ws_root / "src" / "app.py").read_text(encoding="utf-8"), "x = 999  # user edit\n")

        # Update with matching SHA succeeds, records history, and rolls back cleanly
        read2 = self.manager.read_file("proj", "src/app.py", client_id="owner")
        patched = self.manager.apply_patch(
            "proj",
            "src/app.py",
            expected_sha256=read2["sha256"],
            edits=[{"old_text": "x = 999", "new_text": "x = 1000"}],
            client_id="owner",
        )
        self.assertIn("x = 1000", (self.ws_root / "src" / "app.py").read_text(encoding="utf-8"))

        hist = self.manager.workspace_history("proj", relative_path="src/app.py", client_id="owner")
        self.assertEqual(len(hist["snapshots"]), 1)
        rb = self.manager.workspace_history(
            "proj", rollback_snapshot_id=patched["snapshot_id"], client_id="owner"
        )
        self.assertTrue(rb["rolled_back"])
        self.assertIn("x = 999", (self.ws_root / "src" / "app.py").read_text(encoding="utf-8"))

    def test_gitignore_redacted_export_and_secret_store_refs(self) -> None:
        tree = self.manager.workspace_tree("proj", client_id="owner")
        paths = {e["path"] for e in tree["entries"]}
        self.assertIn("src/app.py", paths)
        self.assertNotIn("app.log", paths)
        self.assertNotIn("ignored_dir", paths)
        self.assertNotIn(".env", paths)

        ref = self.store.set_env_secret("proj", "DEPLOY_TOKEN", "ws-secret-value-555")
        prof = WorkspaceProfile(
            workspace_id="proj",
            name="Test Project",
            root_path=str(self.ws_root),
            env={"APP_ENV": "test"},
            env_secret_refs={"DEPLOY_TOKEN": ref},
            permissions=WorkspacePermissions(read=True),
        )
        self.store.upsert_workspace(prof)
        exported = self.store.export_redacted()
        raw = json.dumps(exported)
        self.assertNotIn("ws-secret-value-555", raw)
        self.assertIn("secret://workspaces/proj__DEPLOY_TOKEN", raw)

    def test_untrusted_git_hooks_never_execute(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is not installed")
        subprocess.run(["git", "init"], cwd=self.ws_root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=self.ws_root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=self.ws_root, check=True, capture_output=True)

        sentinel = self.base / "hook_ran.txt"
        hook_file = self.ws_root / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            # Git for Windows runs hook scripts via sh.exe
            hook_file.write_text(f"#!/bin/sh\necho pwn > '{sentinel.as_posix()}'\nexit 1\n", encoding="utf-8")
        else:
            hook_file.write_text(f"#!/bin/sh\necho pwn > '{sentinel.as_posix()}'\nexit 1\n", encoding="utf-8")
            os.chmod(hook_file, 0o755)

        prof = WorkspaceProfile(
            workspace_id="proj",
            name="Test Project",
            root_path=str(self.ws_root),
            git_root=str(self.ws_root),
            permissions=WorkspacePermissions(read=True, write=True, git=True),
            trust_git_hooks=False,
        )
        self.store.upsert_workspace(prof)

        res = self.manager.git_commit("proj", "safe commit", paths=["src/app.py"], client_id="owner")
        self.assertTrue(res["hooks_suppressed"])
        self.assertFalse(sentinel.exists(), "Untrusted Git pre-commit hook must NOT execute")


if __name__ == "__main__":
    unittest.main()
