"""Persistent OAuth storage tests (SQLite + DPAPI or POSIX private key)."""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from backend.oauth_store import OAuthStore

URL = "https://stable.example.com"
RESOURCE = URL + "/mcp"
OWNER = "owner-token-unique-and-long"


def client(ident="client-1"):
    return OAuthClientInformationFull(
        client_id=ident,
        client_name="Client with a secret",
        client_secret="dcr-client-secret-never-plaintext",
        redirect_uris=["http://127.0.0.1:49152/callback"],
        token_endpoint_auth_method="client_secret_post",
        scope="mcp:read",
    )


class PersistentOAuthStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "oauth" / "state.sqlite3"
        self.store = OAuthStore(self.path, URL, RESOURCE)
        self.store.bind_owner(OWNER)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clients_survive_restart_and_client_secret_encrypted(self):
        self.store.save_client(client())
        self.store.mark_approved("client-1")
        another = OAuthStore(self.path, URL, RESOURCE)
        self.assertEqual(another.get_client("client-1").client_name, "Client with a secret")
        self.assertEqual(another.get_client("client-1").client_secret, "dcr-client-secret-never-plaintext")
        self.assertIsNotNone(another.list_clients()[0]["approved_at"])
        db_bytes = self.path.read_bytes()
        self.assertNotIn(b"dcr-client-secret-never-plaintext", db_bytes)
        self.assertNotIn(b"Client with a secret", db_bytes)
        key_bytes = self.path.with_suffix(".key").read_bytes()
        if sys.platform == "win32":
            self.assertTrue(key_bytes.startswith(b"DPAPI1:"))
            self.assertNotIn(b"dcr-client-secret-never-plaintext", key_bytes)
        else:
            self.assertTrue(key_bytes.startswith(b"POSIX1:"))
            self.assertEqual(self.path.with_suffix(".key").stat().st_mode & 0o077, 0)

    def _seed_tokens(self):
        self.store.save_client(client())
        expires = int(time.time()) + 3600
        access = AccessToken(
            token="opaque-access-token", client_id="client-1",
            scopes=["mcp:read"], expires_at=expires, resource=RESOURCE,
        )
        refresh = RefreshToken(
            token="opaque-refresh-token", client_id="client-1",
            scopes=["mcp:read"], expires_at=expires, resource=RESOURCE,
        )
        self.store.save_token(access, "access", "family-1")
        self.store.save_token(refresh, "refresh", "family-1")
        return access, refresh

    def test_tokens_survive_restart_without_plaintext(self):
        self._seed_tokens()
        restored = OAuthStore(self.path, URL, RESOURCE)
        self.assertEqual(restored.get_token("opaque-access-token", "access").client_id, "client-1")
        self.assertEqual(restored.get_token("opaque-refresh-token", "refresh").client_id, "client-1")
        raw_db = self.path.read_bytes()
        self.assertNotIn(b"opaque-access-token", raw_db)
        self.assertNotIn(b"opaque-refresh-token", raw_db)

    def test_gui_revocation_invalidates_tokens_without_backend_restart(self):
        self._seed_tokens()
        gui = OAuthStore(self.path, URL, RESOURCE)
        self.assertTrue(gui.revoke_client("client-1"))
        self.assertIsNone(self.store.get_client("client-1"))
        self.assertIsNone(self.store.get_token("opaque-access-token", "access"))
        self.assertIsNone(self.store.get_token("opaque-refresh-token", "refresh"))
        self.assertFalse(gui.revoke_client("client-1"))

    def test_revoke_family_removes_both_token_kinds(self):
        self._seed_tokens()
        self.store.revoke_family("family-1")
        self.assertIsNone(self.store.get_token("opaque-access-token", "access"))
        self.assertIsNone(self.store.get_token("opaque-refresh-token", "refresh"))

    def test_owner_change_invalidates_all_grants(self):
        self._seed_tokens()
        second = OAuthStore(self.path, URL, RESOURCE)
        second.bind_owner("different-owner-token")
        clients = second.list_clients()
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["client_id"], "client-1")
        self.assertIsNone(clients[0]["approved_at"])
        self.assertIsNone(second.get_token("opaque-access-token", "access"))
        self.assertIsNone(second.get_token("opaque-refresh-token", "refresh"))

    def test_resource_path_change_invalidates_grants(self):
        self._seed_tokens()
        changed = OAuthStore(self.path, URL, URL + "/different")
        changed.bind_owner(OWNER)
        self.assertEqual(changed.list_clients(), [])
        self.assertIsNone(changed.get_token("opaque-access-token", "access"))

    def test_quick_tunnel_rotation_discards_old_clients_and_tokens(self):
        first = OAuthStore(self.path, "https://old.trycloudflare.com", "https://old.trycloudflare.com/mcp")
        first.bind_owner(OWNER)
        first.save_client(client())
        next_store = OAuthStore(self.path, "https://new.trycloudflare.com", "https://new.trycloudflare.com/mcp")
        next_store.bind_owner(OWNER)
        next_store.remove_old_quick_tunnels()
        self.assertEqual(first.list_clients(), [])
        self.assertEqual(next_store.list_clients(), [])

    def test_issuer_isolation_for_named_domain(self):
        self.store.save_client(client())
        unrelated = OAuthStore(self.path, "https://other.example.com", "https://other.example.com/mcp")
        unrelated.bind_owner(OWNER)
        self.assertIsNone(unrelated.get_client("client-1"))
        self.assertEqual(self.store.count_clients(), 1)

    def test_expired_tokens_not_returned(self):
        self.store.save_client(client())
        expired = AccessToken(
            token="expired-token", client_id="client-1", scopes=["mcp:read"],
            expires_at=int(time.time()) - 30, resource=RESOURCE,
        )
        self.store.save_token(expired, "access", "expired-family")
        self.assertIsNone(self.store.get_token("expired-token", "access"))
        self.store.prune_expired()

    def test_existing_db_with_missing_key_fails_closed(self):
        self._seed_tokens()
        self.path.with_suffix(".key").unlink()
        with self.assertRaises(FileNotFoundError):
            OAuthStore(self.path, URL, RESOURCE)


if __name__ == "__main__":
    unittest.main()
