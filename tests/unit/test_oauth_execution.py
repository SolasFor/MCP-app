"""Fixed Windows/SSH capability with local one-time approvals."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.shared.auth import OAuthClientInformationFull

from backend.oauth_store import OAuthStore
from backend.oauth_execution import ExecutionApprovals, _parse_rules

BASE = "https://exec.example.com"
RESOURCE = BASE + "/mcp"


class OAuthExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth.db"
        self.store = OAuthStore(self.path, BASE, RESOURCE)
        self.store.bind_owner("owner-token-unique-for-test")
        for cid in ("client-a", "client-b"):
            self.store.save_client(OAuthClientInformationFull(
                client_id=cid, client_name=cid,
                redirect_uris=["http://127.0.0.1:12345/callback"],
                token_endpoint_auth_method="none",
            ))
        self.store.mark_approved("client-a")
        self.exec = ExecutionApprovals(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _configure(self):
        self.exec.set_policy(
            windows="hostname.exe\npython.exe -V",
            hosts="example.internal",
            ssh_commands="uptime\nhostname",
        )

    def test_access_is_immutable_and_policy_empty_by_default(self):
        self.assertTrue(self.exec.client_approved("client-a"))
        self.assertFalse(self.exec.client_approved("client-b"))
        self.assertFalse(self.exec.client_approved("mcp-app-user"))
        self.assertFalse(hasattr(self.exec, "set_grants"))
        self.assertFalse(hasattr(self.exec, "grants"))
        self.assertFalse(self.exec.can_request("client-a", "windows", command="hostname.exe"))
        self._configure()
        self.assertTrue(self.exec.can_request("client-a", "windows", command="hostname.exe"))
        self.assertTrue(self.exec.can_request("client-a", "ssh", command="uptime", host="example.internal"))
        self.assertFalse(self.exec.can_request("client-b", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.can_request("client-a", "windows", command="hostname.exe -V"))
        self.assertFalse(self.exec.can_request("client-a", "ssh", command="uptime", host="evil.internal"))
        self.assertFalse(self.exec.can_request("client-a", "ssh", command="rm -rf /", host="example.internal"))

    def test_policy_rejects_wildcards_and_invalid_host(self):
        for value in ("*.example.com", "abc?", "x" * 513):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                _parse_rules(value)
        for value in ("user@host", "host:22", "host/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _parse_rules(value, host=True)

    def test_upgrades_remove_legacy_editable_grants(self):
        with self.store._db() as db:
            db.execute("""
                CREATE TABLE exec_grants(
                    issuer TEXT NOT NULL, client_id TEXT NOT NULL,
                    can_windows INTEGER NOT NULL, can_ssh INTEGER NOT NULL,
                    PRIMARY KEY(issuer,client_id)
                )
            """)
            db.execute(
                "INSERT INTO exec_grants VALUES (?,?,?,?)",
                (BASE, "client-a", 0, 0),
            )
        restarted = ExecutionApprovals(OAuthStore(self.path, BASE, RESOURCE))
        self.assertTrue(restarted.client_approved("client-a"))
        with self.store._db() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='exec_grants'"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_ticket_requires_local_approval_exact_command_and_one_use(self):
        self._configure()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        pending = self.exec.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["command"], "hostname.exe")
        self.assertTrue(self.exec.decision(pending[0]["ticket_hash"], approve=True))
        self.assertFalse(self.exec.consume(ticket, "client-b", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="python.exe -V"))
        self.assertTrue(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_ssh_ticket_binds_host_user_port_and_command(self):
        self._configure()
        ticket = self.exec.request(
            "client-a", "ssh", command="uptime", host="example.internal",
            user="alice", port=2222,
        )
        self.assertTrue(self.exec.decision(self.exec.pending()[0]["ticket_hash"], approve=True))
        for params in (
            {"command": "uptime", "host": "example.internal", "user": "bob", "port": 2222},
            {"command": "uptime", "host": "example.internal", "user": "alice", "port": 22},
            {"command": "hostname", "host": "example.internal", "user": "alice", "port": 2222},
            {"command": "uptime", "host": "other.internal", "user": "alice", "port": 2222},
        ):
            self.assertFalse(self.exec.consume(ticket, "client-a", "ssh", **params))
        self.assertTrue(self.exec.consume(
            ticket, "client-a", "ssh", command="uptime",
            host="example.internal", user="alice", port=2222,
        ))

    def test_denial_and_policy_change_cancel_tickets(self):
        self._configure()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertTrue(self.exec.decision(self.exec.pending()[0]["ticket_hash"], approve=False))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertTrue(self.exec.decision(self.exec.pending()[0]["ticket_hash"], approve=True))
        self.exec.set_policy(windows="hostname.exe", hosts="", ssh_commands="")
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_expiration_is_fail_closed(self):
        self._configure()
        with patch("backend.oauth_execution.time.time", return_value=1000):
            ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        with patch("backend.oauth_execution.time.time", return_value=1200):
            self.assertEqual(self.exec.pending(), [])
            self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_client_revocation_and_owner_rotation_cancel_access(self):
        self._configure()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.store.revoke_client("client-a")
        self.assertFalse(self.exec.client_approved("client-a"))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        self.store.mark_approved("client-b")
        ticket = self.exec.request("client-b", "windows", command="hostname.exe")
        self.store.bind_owner("rotated-owner-token")
        self.assertFalse(self.exec.client_approved("client-b"))
        self.assertFalse(self.exec.consume(ticket, "client-b", "windows", command="hostname.exe"))

    def test_approval_data_is_encrypted_on_disk(self):
        self._configure()
        self.exec.request("client-a", "ssh", command="uptime", host="example.internal")
        db_data = self.path.read_bytes()
        for secret in (b"example.internal", b"hostname.exe", b"uptime"):
            self.assertNotIn(secret, db_data)

    def test_approval_across_independent_process_stores(self):
        self._configure()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        gui_store = OAuthStore(self.path, BASE, RESOURCE)
        owner_gui = ExecutionApprovals(gui_store)
        self.assertEqual(owner_gui.policy()["windows"], ("hostname.exe", "python.exe -V"))
        self.assertTrue(owner_gui.decision(owner_gui.pending()[0]["ticket_hash"], approve=True))
        self.assertTrue(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))


if __name__ == "__main__":
    unittest.main()
