"""Unit tests for ToolRegistry, per-client allowlists, temporary grants, and post-queue recheck."""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.process_runner import ProcessRunner
from backend.tool_registry import BASIC_TOOLS, EXEC_WINDOWS, FULL_TOOLS, OAUTH_TOOLS, ToolRegistry

BASE = "https://registry.example.com"
RESOURCE = BASE + "/mcp"


def _principal(client_id: str) -> AccessToken:
    return AccessToken(
        token="tok-" + client_id,
        client_id=client_id,
        scopes=["mcp:read"],
        resource=RESOURCE,
    )


class ToolRegistryAndGrantsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = OAuthStore(Path(self.tmp.name) / "oauth.sqlite3", BASE, RESOURCE)
        self.store.bind_owner("owner-secret")
        self.exec = ExecutionApprovals(self.store)
        for cid in ("alpha", "beta"):
            self.store.save_client(
                OAuthClientInformationFull(
                    client_id=cid,
                    client_name=cid,
                    redirect_uris=["http://127.0.0.1:4444/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            self.store.mark_approved(cid)
        self.registry = ToolRegistry()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_per_client_allowlist_and_revocation_cleanup(self) -> None:
        self.exec.set_client_profile("alpha", "allowlist")
        self.exec.set_client_profile("beta", "allowlist")
        self.exec.set_client_allowlist("alpha", windows="whoami", hosts="alpha.local", ssh_commands="uptime")
        self.assertTrue(self.exec.can_request("alpha", "windows", command="whoami"))
        self.assertFalse(self.exec.can_request("alpha", "windows", command="ipconfig"))
        self.assertTrue(self.exec.can_request("beta", "windows", command="ipconfig"))
        self.assertTrue(self.exec.can_request("alpha", "ssh", command="uptime", host="alpha.local"))
        self.assertFalse(self.exec.can_request("beta", "ssh", command="uptime", host="alpha.local"))

        self.store.revoke_client("alpha")
        self.assertIsNone(self.exec.client_allowlist("alpha"))
        self.assertFalse(self.exec.can_request("alpha", "windows", command="whoami"))

    def test_temporary_grants_authorize_expire_and_revoke(self) -> None:
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), BASIC_TOOLS)
        grant_id = self.exec.grant_temporary_access(
            "alpha",
            profile="allowlist",
            tool_names=(EXEC_WINDOWS,),
            windows_commands=("whoami",),
            ttl_seconds=60,
            reason="short check",
        )
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), OAUTH_TOOLS)
        self.assertTrue(self.exec.can_request("alpha", "windows", command="whoami"))
        self.assertTrue(self.exec.revoke_temporary_grant(grant_id))
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), BASIC_TOOLS)
        self.assertFalse(self.exec.can_request("alpha", "windows", command="whoami"))

        # Expired grant fails closed
        expired_id = self.exec.grant_temporary_access("alpha", profile="full", ttl_seconds=1)
        with self.store._db() as db:
            db.execute("UPDATE exec_temp_grants SET expires_at=1 WHERE grant_id=?", (expired_id,))
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), BASIC_TOOLS)

    def test_emergency_stop_blocks_discovery_and_dispatch(self) -> None:
        self.exec.set_client_profile("alpha", "full")
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), FULL_TOOLS)
        self.store.set_emergency_stop(True, "test")
        self.assertEqual(self.registry.allowed_tools(self.store, _principal("alpha"), self.exec), BASIC_TOOLS)
        with self.assertRaises(PermissionError):
            self.registry.authorize_call(EXEC_WINDOWS, self.store, _principal("alpha"), self.exec)

    def test_post_queue_permission_recheck_blocks_revoked_queued_command(self) -> None:
        self.exec.set_client_profile("alpha", "full")
        runner = ProcessRunner(spool_dir=Path(self.tmp.name) / "spool", max_concurrent_commands=1)
        spawned_second = False

        async def scenario():
            nonlocal spawned_second
            t1 = asyncio.create_task(
                runner.run_command(
                    [sys.executable, "-c", "import time; time.sleep(0.4)"],
                    cwd=self.tmp.name,
                    timeout=5,
                    client_id="alpha",
                )
            )
            await asyncio.sleep(0.05)

            def check_alpha():
                self.registry.authorize_call(EXEC_WINDOWS, self.store, _principal("alpha"), self.exec)
                nonlocal spawned_second
                spawned_second = True

            t2 = asyncio.create_task(
                runner.run_command(
                    [sys.executable, "-c", "print('should not run')"],
                    cwd=self.tmp.name,
                    timeout=5,
                    client_id="alpha",
                    pre_dispatch_check=check_alpha,
                )
            )
            await asyncio.sleep(0.05)
            # Revoke client while t2 is waiting for the concurrency slot
            self.store.revoke_client("alpha")
            res1 = await t1
            self.assertEqual(res1.exit_code, 0)
            with self.assertRaises(PermissionError):
                await t2

        try:
            with patch("backend.tool_registry.ToolRegistry.authorize_call", wraps=self.registry.authorize_call):
                asyncio.run(scenario())
            self.assertFalse(spawned_second)
        finally:
            runner.close()


if __name__ == "__main__":
    unittest.main()
