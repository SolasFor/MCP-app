"""Unit tests for SecretStore, legacy migrations, OAuthStore v1->v2 migration, and redaction."""
from __future__ import annotations

import json
import logging
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from app.core import domain_state, proxy, token_store
from app.core.redaction import RedactingLogFilter, SecretRedactor
from app.core.secret_store import SecretStore
from backend.oauth_store import OAuthStore


class SecretStoreTests(unittest.TestCase):
    def test_secret_store_roundtrip_encrypted_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SecretStore(Path(tmp) / "secrets")
            store.set_secret("api", "cloudflare", "cfut_super_secret_token_987654")
            store.set_secret("ssh", "key_pass", "ssh-passphrase-1234")
            self.assertEqual(
                store.get_secret("api", "cloudflare"), "cfut_super_secret_token_987654"
            )
            self.assertEqual(store.resolve_ref("secret://ssh/key_pass"), "ssh-passphrase-1234")
            vault_bytes = (Path(tmp) / "secrets" / "secrets.vault.enc").read_bytes()
            self.assertNotIn(b"cfut_super_secret_token_987654", vault_bytes)
            self.assertNotIn(b"ssh-passphrase-1234", vault_bytes)

            meta = store.export_metadata()
            self.assertEqual(meta["secret_count"], 2)
            self.assertNotIn("cfut_super_secret_token_987654", json.dumps(meta))
            self.assertTrue(store.delete_secret("api", "cloudflare"))
            self.assertIsNone(store.get_secret("api", "cloudflare"))

    @unittest.skipUnless(sys.platform == "win32", "Windows Credential Manager test")
    def test_windows_credman_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SecretStore(Path(tmp) / "secrets", use_credman=True)
            key = f"unit_test_{id(self)}"
            try:
                store.set_secret("api", key, "credman-secret-value")
                self.assertEqual(store.get_secret("api", key), "credman-secret-value")
            finally:
                store.delete_secret("api", key)
                self.assertIsNone(store.get_secret("api", key))

    def test_legacy_token_domain_and_proxy_migrations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            with (
                patch("app.core.token_store.user_data_dir", return_value=data_dir),
                patch("app.core.domain_state.user_data_dir", return_value=data_dir),
                patch("app.paths.user_data_dir", return_value=data_dir),
            ):
                # Legacy plaintext token.json
                (data_dir / "token.json").write_text(
                    json.dumps({"token": "legacy-owner-token-123456"}), encoding="utf-8"
                )
                loaded_token = token_store.load()
                self.assertEqual(loaded_token, "legacy-owner-token-123456")
                self.assertNotIn(
                    "legacy-owner-token-123456", (data_dir / "token.json").read_text(encoding="utf-8")
                )
                self.assertEqual(token_store.load(), "legacy-owner-token-123456")

                # Legacy plaintext domain.json
                (data_dir / "domain.json").write_text(
                    json.dumps({
                        "hostname": "mcp.example.com",
                        "tunnel_id": "tid-1",
                        "tunnel_token": "legacy-tunnel-secret-999",
                        "zone_name": "example.com",
                    }),
                    encoding="utf-8",
                )
                dom = domain_state.load()
                self.assertEqual(dom.tunnel_token, "legacy-tunnel-secret-999")
                self.assertNotIn(
                    "legacy-tunnel-secret-999", (data_dir / "domain.json").read_text(encoding="utf-8")
                )
                self.assertEqual(domain_state.load().tunnel_token, "legacy-tunnel-secret-999")

                # Legacy plaintext proxy.json with user:pass
                (data_dir / "proxy.json").write_text(
                    json.dumps({
                        "enabled": True,
                        "url": "socks5://alice:secretpass@127.0.0.1:1080",
                        "hosts": ["api.cloudflare.com:443"],
                    }),
                    encoding="utf-8",
                )
                px_loaded = proxy.load()
                self.assertEqual(px_loaded.url, "socks5://alice:secretpass@127.0.0.1:1080")
                self.assertNotIn("secretpass", (data_dir / "proxy.json").read_text(encoding="utf-8"))
                self.assertEqual(proxy.load().url, "socks5://alice:secretpass@127.0.0.1:1080")

    def test_oauth_store_v1_to_v2_migration_and_redacted_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "oauth" / "state.sqlite3"
            issuer = "https://stable.example.com"
            resource = issuer + "/mcp"
            store_v1 = OAuthStore(db_path, issuer, resource)
            store_v1.bind_owner("owner-secret-token-value")
            store_v1.save_client(
                OAuthClientInformationFull(
                    client_id="c1",
                    client_name="Client One",
                    client_secret="client-secret-never-backup",
                    redirect_uris=["http://127.0.0.1:1234/cb"],
                    token_endpoint_auth_method="client_secret_post",
                )
            )
            store_v1.mark_approved("c1")
            store_v1.save_token(
                AccessToken(
                    token="raw-access-token-value",
                    client_id="c1",
                    scopes=["mcp:read"],
                    expires_at=9999999999,
                    resource=resource,
                ),
                "access",
                "fam-1",
            )
            # Simulate a pre-migration v0.8.5 database without schema_migrations / v2 tables
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("DROP TABLE schema_migrations")
                conn.execute("DROP TABLE exec_client_allowlists")
                conn.execute("DROP TABLE exec_temp_grants")
                conn.execute("DROP TABLE runtime_control")
                conn.commit()
            finally:
                conn.close()

            migrated = OAuthStore(db_path, issuer, resource)
            self.assertEqual(migrated.schema_version(), 2)
            self.assertEqual(migrated.get_client("c1").client_name, "Client One")
            self.assertEqual(migrated.get_token("raw-access-token-value", "access").client_id, "c1")

            backup_path = Path(tmp) / "backup.json"
            migrated.export_redacted_backup(backup_path)
            raw_backup = backup_path.read_text(encoding="utf-8")
            self.assertIn("Client One", raw_backup)
            self.assertNotIn("raw-access-token-value", raw_backup)
            self.assertNotIn("client-secret-never-backup", raw_backup)
            self.assertNotIn("owner-secret-token-value", raw_backup)

    def test_redacting_log_filter_scrubs_secrets(self) -> None:
        redactor = SecretRedactor(["my-secret-token-1234"])
        flt = RedactingLogFilter(redactor)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Header Authorization: Bearer my-secret-token-1234 and ?token=abc123456789",
            args=(),
            exc_info=None,
        )
        self.assertTrue(flt.filter(record))
        self.assertNotIn("my-secret-token-1234", record.msg)
        self.assertNotIn("abc123456789", record.msg)


if __name__ == "__main__":
    unittest.main()
