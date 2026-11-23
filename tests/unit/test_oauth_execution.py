"""Per-client Windows/SSH approval-queue security regression tests."""
from __future__ import annotations

import tempfile
import time
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
        self.store.bind_owner("test-owner-token")
        for cid in ("client-a", "client-b"):
            self.store.save_client(OAuthClientInformationFull(
                client_id=cid, client_name=cid,
                redirect_uris=["http://127.0.0.1:12345/callback"],
                token_endpoint_auth_method="none",
            ))
            self.store.mark_approved(cid)
        self.exec = ExecutionApprovals(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _activate(self):
        self.exec.set_policy(
            windows="hostname.exe\npython.exe -V",
            hosts="example.internal",
            ssh_commands="uptime\nhostname",
        )
        self.exec.set_grants("client-a", windows=True, ssh=True)

    def test_default_deny_and_individual_client_grants(self):
        self.assertEqual(self.exec.grants("client-a"), (False, False))
        self.assertFalse(self.exec.can_request("client-a", "windows", command="hostname.exe"))
        self._activate()
        self.assertTrue(self.exec.can_request("client-a", "windows", command="hostname.exe"))
        self.assertTrue(self.exec.can_request("client-a", "ssh", command="uptime", host="example.internal"))
        self.assertFalse(self.exec.can_request("client-b", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.can_request("mcp-app-user", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.can_request("client-a", "windows", command="hostname.exe -V"))
        self.assertFalse(self.exec.can_request("client-a", "ssh", command="rm -rf /", host="example.internal"))
        self.assertFalse(self.exec.can_request("client-a", "ssh", command="uptime", host="evil.internal"))

    def test_grants_require_approved_clients(self):
        self.store.save_client(OAuthClientInformationFull(
            client_id="pending", redirect_uris=["http://127.0.0.1:12346/callback"],
            token_endpoint_auth_method="none",
        ))
        with self.assertRaises(ValueError):
            self.exec.set_grants("pending", windows=True, ssh=True)
        with self.assertRaises(ValueError):
            self.exec.set_grants("unknown", windows=True, ssh=True)
        with self.assertRaises(ValueError):
            self.exec.set_grants("client-a", windows=1, ssh=False)

    def test_policy_rejects_wildcards_and_invalid_host(self):
        for rules in ("*.example.com", "abc?", "x" * 513):
            with self.subTest(rules=rules[:20]), self.assertRaises(ValueError):
                _parse_rules(rules)
        for hosts in ("user@host", "host:22", "host/path"):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                _parse_rules(hosts, host=True)

    def test_ticket_requires_local_approval_exact_command_and_one_use(self):
        self._activate()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        queue = self.exec.pending()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["command"], "hostname.exe")
        self.assertFalse(queue[0]["approved"])
        self.assertTrue(self.exec.decision(queue[0]["ticket_hash"], approve=True))
        self.assertFalse(self.exec.consume(ticket, "client-b", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="python.exe -V"))
        self.assertTrue(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_ssh_approval_binds_host_user_port_and_command(self):
        self._activate()
        ticket = self.exec.request(
            "client-a", "ssh", command="uptime",
            host="example.internal", user="alice", port=2222,
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

    def test_denial_revocation_and_policy_change_cancel_tickets(self):
        self._activate()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertTrue(self.exec.decision(self.exec.pending()[0]["ticket_hash"], approve=False))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.assertTrue(self.exec.decision(self.exec.pending()[0]["ticket_hash"], approve=True))
        self.exec.set_grants("client-a", windows=False, ssh=True)
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        self.exec.set_grants("client-a", windows=True, ssh=True)
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.exec.set_policy(windows="hostname.exe", hosts="", ssh_commands="")
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_expiration_is_fail_closed(self):
        self._activate()
        with patch("backend.oauth_execution.time.time", return_value=1000):
            ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        with patch("backend.oauth_execution.time.time", return_value=1200):
            self.assertEqual(self.exec.pending(), [])
            self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))

    def test_client_and_owner_revocation_clear_grants(self):
        self._activate()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        self.store.revoke_client("client-a")
        self.assertEqual(self.exec.grants("client-a"), (False, False))
        self.assertFalse(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))
        self.exec.set_grants("client-b", windows=False, ssh=True)
        self.store.bind_owner("rotated-owner-token")
        self.assertEqual(self.exec.grants("client-b"), (False, False))

    def test_policy_and_requests_encrypted_on_disk(self):
        self._activate()
        self.exec.request("client-a", "ssh", command="uptime", host="example.internal")
        data = self.path.read_bytes()
        self.assertNotIn(b"example.internal", data)
        self.assertNotIn(b"hostname.exe", data)
        self.assertNotIn(b"uptime", data)

    def test_persistence_across_independent_store_instances(self):
        self._activate()
        ticket = self.exec.request("client-a", "windows", command="hostname.exe")
        other_store = OAuthStore(self.path, BASE, RESOURCE)
        owner_gui = ExecutionApprovals(other_store)
        self.assertEqual(owner_gui.grants("client-a"), (True, True))
        self.assertEqual(owner_gui.policy()["windows"], ("hostname.exe", "python.exe -V"))
        self.assertTrue(owner_gui.decision(owner_gui.pending()[0]["ticket_hash"], approve=True))
        self.assertTrue(self.exec.consume(ticket, "client-a", "windows", command="hostname.exe"))


if __name__ == "__main__":
    unittest.main()
