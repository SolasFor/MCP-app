"""Three execution scenarios, migrations, allowlist and OAuth isolation."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp.shared.auth import OAuthClientInformationFull

from backend.oauth_store import OAuthStore
from backend.oauth_execution import (
    ExecutionApprovals, DEFAULT_WINDOWS_ALLOWLIST, PROFILE_SAFE,
    PROFILE_ALLOWLIST, PROFILE_FULL, _parse_rules, windows_whitelisted,
)

BASE = "https://exec.example.com"
RESOURCE = BASE + "/mcp"


class OAuthExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth.db"
        self.store = OAuthStore(self.path, BASE, RESOURCE)
        self.store.bind_owner("test-owner-token")
        for cid in ("client-a", "client-b"):
            self.store.save_client(OAuthClientInformationFull(
                client_id=cid, client_name=cid,
                redirect_uris=["http://127.0.0.1:12345/callback"],
                token_endpoint_auth_method="none",
            ))
        self.store.mark_approved("client-a")
        self.policy = ExecutionApprovals(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_default_safe_and_allowlist_preset(self):
        self.assertEqual(self.policy.profile(), PROFILE_SAFE)
        self.assertEqual(self.policy.policy()["windows"], DEFAULT_WINDOWS_ALLOWLIST)
        self.assertFalse(self.policy.can_request("client-a", "windows", command="whoami"))
        self.assertFalse(self.policy.can_request("client-a", "ssh", command="uptime", host="machine.local"))

    def test_allowlist_executes_exact_rules_without_tickets(self):
        self.policy.set_profile(PROFILE_ALLOWLIST)
        self.assertTrue(self.policy.can_request("client-a", "windows", command="whoami"))
        self.assertTrue(self.policy.can_request("client-a", "windows", command="echo any literal text"))
        self.assertFalse(self.policy.can_request("client-a", "windows", command="python -c 'print(1)'"))
        self.assertFalse(self.policy.can_request("client-a", "windows", command="whoami && danger"))
        self.assertFalse(self.policy.can_request("client-a", "windows", command="whoami /priv"))
        self.assertFalse(self.policy.can_request("client-b", "windows", command="whoami"))
        self.policy.set_policy(
            windows="whoami\nhostname.exe",
            hosts="machine.local", ssh_commands="uptime",
        )
        self.assertTrue(self.policy.can_request("client-a", "ssh", command="uptime", host="machine.local"))
        self.assertFalse(self.policy.can_request("client-a", "ssh", command="uptime", host="other.local"))
        self.assertFalse(self.policy.can_request("client-a", "ssh", command="sudo reboot", host="machine.local"))
        self.assertFalse(self.policy.can_request("client-a", "windows", command="echo hello"))

    def test_full_executes_arbitrary_command_and_ssh_without_allowlist(self):
        self.policy.set_profile(PROFILE_FULL)
        self.assertTrue(self.policy.can_request("client-a", "windows", command="python -c 'print(123)'"))
        self.assertTrue(self.policy.can_request("client-a", "ssh", command="echo unrestricted", host="new.example"))
        self.assertFalse(self.policy.can_request("client-b", "ssh", command="echo unrestricted", host="new.example"))
        self.assertFalse(self.policy.can_request("mcp-app-user", "windows", command="whoami"))
        # Input bounds still apply to prevent resource abuse and host injection.
        self.assertFalse(self.policy.can_request("client-a", "ssh", command="uptime", host="bad/host"))
        self.assertFalse(self.policy.can_request("client-a", "windows", command="x" * 513))

    def test_switch_is_live_and_persistent_per_issuer(self):
        self.policy.set_profile(PROFILE_FULL)
        restarted = ExecutionApprovals(OAuthStore(self.path, BASE, RESOURCE))
        self.assertEqual(restarted.profile(), PROFILE_FULL)
        restarted.set_profile(PROFILE_ALLOWLIST)
        self.assertEqual(self.policy.profile(), PROFILE_ALLOWLIST)
        restarted.set_profile(PROFILE_SAFE)
        self.assertFalse(self.policy.can_request("client-a", "windows", command="whoami"))

    def test_old_exact_allowlist_without_profile_fails_closed(self):
        with self.store._db() as db:
            db.execute(
                "INSERT OR REPLACE INTO exec_policy VALUES (?,?)",
                (BASE, self.store._encrypt({
                    "windows": ["hostname.exe"], "hosts": ["prod.local"],
                    "ssh_commands": ["uptime"],
                })),
            )
        self.assertEqual(ExecutionApprovals(self.store).profile(), PROFILE_SAFE)
        self.assertFalse(self.policy.can_request("client-a", "windows", command="hostname.exe"))

    def test_old_approval_tickets_are_invalidated_and_no_ticket_api(self):
        with self.store._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS exec_requests(
                    digest TEXT PRIMARY KEY,issuer TEXT,client_id TEXT,
                    encrypted BLOB,created INTEGER,expires INTEGER,approved INTEGER
                )
            """)
            db.execute(
                "INSERT INTO exec_requests VALUES (?,?,?,?,?,?,?)",
                ("old", BASE, "client-a", b"data", 1, 99999999, 1),
            )
        upgraded = ExecutionApprovals(self.store)
        with self.store._db() as db:
            count = db.execute("SELECT count(*) FROM exec_requests WHERE issuer=?", (BASE,)).fetchone()[0]
        self.assertEqual(count, 0)
        self.assertFalse(hasattr(upgraded, "request"))
        self.assertFalse(hasattr(upgraded, "decision"))
        self.assertFalse(hasattr(upgraded, "consume"))

    def test_client_profiles_are_isolated_and_persist_without_restart(self):
        self.store.mark_approved("client-b")
        self.policy.set_profile(PROFILE_ALLOWLIST)
        self.assertEqual(self.policy.profile_for("client-a"), PROFILE_ALLOWLIST)
        self.assertEqual(self.policy.profile_for("client-b"), PROFILE_ALLOWLIST)
        self.policy.set_client_profile("client-a", PROFILE_FULL)
        self.policy.set_client_profile("client-b", PROFILE_SAFE)
        self.assertEqual(self.policy.profile_for("client-a"), PROFILE_FULL)
        self.assertEqual(self.policy.profile_for("client-b"), PROFILE_SAFE)
        self.assertTrue(self.policy.can_request(
            "client-a", "windows", command="not-on-any-allowlist"
        ))
        self.assertFalse(self.policy.can_request(
            "client-b", "windows", command="whoami"
        ))
        other = ExecutionApprovals(OAuthStore(self.path, BASE, RESOURCE))
        self.assertEqual(other.profile_for("client-a"), PROFILE_FULL)
        self.assertEqual(other.profile_for("client-b"), PROFILE_SAFE)
        # Global default changes do not override individual selections.
        self.policy.set_profile(PROFILE_SAFE)
        self.assertEqual(other.profile_for("client-a"), PROFILE_FULL)
        self.assertEqual(other.profile_for("client-b"), PROFILE_SAFE)
        # An absent override always inherits the global default.
        self.assertEqual(self.policy.profile(), PROFILE_SAFE)

    def test_revoke_and_owner_rotation_delete_client_profiles(self):
        self.store.mark_approved("client-b")
        self.policy.set_client_profile("client-a", PROFILE_FULL)
        self.policy.set_client_profile("client-b", PROFILE_ALLOWLIST)
        self.store.revoke_client("client-a")
        self.assertEqual(self.policy.profile_for("client-a"), PROFILE_SAFE)
        with self.store._db() as db:
            remaining = db.execute(
                "SELECT client_id FROM exec_client_profiles WHERE issuer=?",
                (BASE,),
            ).fetchall()
        self.assertEqual(remaining, [("client-b",)])
        self.store.bind_owner("new-token")
        with self.store._db() as db:
            remaining = db.execute(
                "SELECT COUNT(*) FROM exec_client_profiles WHERE issuer=?",
                (BASE,),
            ).fetchone()[0]
        self.assertEqual(remaining, 0)
        self.assertEqual(self.policy.profile_for("client-b"), PROFILE_SAFE)

    def test_unapproved_or_unknown_client_cannot_be_granted_access(self):
        with self.assertRaises(ValueError):
            self.policy.set_client_profile("client-b", PROFILE_FULL)
        with self.assertRaises(ValueError):
            self.policy.set_client_profile("unknown", PROFILE_FULL)
        with self.assertRaises(ValueError):
            self.policy.set_client_profile("mcp-app-user", PROFILE_FULL)
        with self.assertRaises(ValueError):
            self.policy.set_client_profile("client-a", "invalid")
        self.assertEqual(self.policy.profile_for("client-b"), PROFILE_SAFE)

    def test_invalid_profile_rejected(self):
        for value in ("dangerous", None, "FULL", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.policy.set_profile(value)

    def test_allowlist_rejects_wildcards_and_bad_hosts(self):
        for value in ("*.example.com", "whoami?", "x" * 513):
            with self.assertRaises(ValueError):
                _parse_rules(value)
        for value in ("user@host", "host:22", "host/path"):
            with self.assertRaises(ValueError):
                _parse_rules(value, host=True)
        self.assertTrue(windows_whitelisted("echo plain text", ("echo",)))
        self.assertFalse(windows_whitelisted("echo plain text", ("whoami",)))

    def test_revocation_does_not_recreate_client(self):
        self.policy.set_profile(PROFILE_FULL)
        self.store.revoke_client("client-a")
        self.assertFalse(self.policy.can_request("client-a", "windows", command="whoami"))
        self.store.bind_owner("changed-owner")
        self.assertFalse(self.policy.client_approved("client-b"))


if __name__ == "__main__":
    unittest.main()
