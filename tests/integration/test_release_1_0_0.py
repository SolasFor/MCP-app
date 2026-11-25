"""Stage 12 (v1.0.0) E2E upgrade migration, resilience, security & secret-scan tests."""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from app import __version__
from app.config import PROVIDER_CF_QUICK, Settings
from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from backend.automation import AutomationScheduler, BackupManager, ScheduleSpec
from backend.gateway.store import GatewayConfigStore
from backend.oauth_execution import ExecutionApprovals
from backend.oauth_store import OAuthStore
from backend.process_runner import ProcessRunner
from backend.remote.store import DeviceStore
from backend.servers.store import ServerConfigStore
from backend.tool_registry import DEFAULT_REGISTRY, EXEC_WINDOWS, SERVER_LIST


class Release100E2ETests(unittest.TestCase):
    def test_v085_to_v1_upgrade_migrations_and_client_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. Legacy v0.8.5 settings.json with allow_query_token=True -> forced False, quick provider mapped
            s_path = root / "settings.json"
            s_path.write_text(
                json.dumps(
                    {
                        "allow_query_token": True,
                        "tunnel_mode": "quick",
                        "public_url": "https://legacy-temp.trycloudflare.com/mcp",
                        "unknown_legacy_key": "ignored",
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(Settings, "path", return_value=s_path):
                loaded = Settings.load()
            self.assertFalse(loaded.allow_query_token)
            self.assertEqual(loaded.active_provider, PROVIDER_CF_QUICK)
            self.assertEqual(loaded.public_url, "")

            # 2. Legacy v1 managed_servers.json -> v2 lossless migration + backup
            srv_path = root / "servers" / "managed_servers.json"
            srv_path.parent.mkdir(parents=True)
            srv_path.write_text(
                json.dumps(
                    {
                        "legacy_srv": {
                            "argv": [sys.executable, "-V"],
                            "cwd": tmp,
                            "lifecycle": "controlled",
                        }
                    }
                ),
                encoding="utf-8",
            )
            srv_store = ServerConfigStore(srv_path, secret_store=SecretStore(root / "secrets"))
            self.assertEqual(srv_store.detect_schema_version(), 1)
            mig = srv_store.migrate_legacy_file(create_backup=True)
            self.assertEqual(mig["imported"], ["legacy_srv"])
            self.assertTrue(Path(mig["backup_path"]).is_file())
            self.assertEqual(srv_store.detect_schema_version(), 2)

            # 3. OAuth client preserved across reload and schema v2 checks
            oauth_db = root / "oauth" / "connections.sqlite3"
            issuer = "https://upgrade.example.com"
            res_url = f"{issuer}/mcp"
            store1 = OAuthStore(oauth_db, issuer, res_url)
            store1.save_client(
                OAuthClientInformationFull(
                    client_id="v085-client",
                    client_name="Upgraded Client",
                    redirect_uris=["http://127.0.0.1:19990/cb"],
                    token_endpoint_auth_method="none",
                )
            )
            store1.mark_approved("v085-client")

            store2 = OAuthStore(oauth_db, issuer, res_url)
            self.assertEqual(store2.schema_version(), 3)
            self.assertEqual([c["client_id"] for c in store2.list_clients()], ["v085-client"])

    def test_broken_config_fail_closed_and_backup_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_file = root / "settings.json"
            cfg_file.write_text("{corrupt-json", encoding="utf-8")
            with patch.object(Settings, "path", return_value=cfg_file):
                s = Settings.load()
            self.assertFalse(s.allow_query_token)
            self.assertFalse(s.enable_advanced_tools)

            (root / "gateway").mkdir()
            (root / "gateway" / "servers.json").write_text("{broken", encoding="utf-8")
            gw = GatewayConfigStore(root / "gateway" / "servers.json")
            self.assertEqual(gw.list_profiles(), [])

            (root / "remote").mkdir()
            (root / "remote" / "devices.json").write_text("not-json", encoding="utf-8")
            dev = DeviceStore(root / "remote" / "devices.json", secret_store=SecretStore(root / "secrets"))
            self.assertEqual(dev.load_all(), {})

            auto_dir = root / "automation"
            auto_dir.mkdir()
            (auto_dir / "schedules.json").write_text("{bad", encoding="utf-8")
            sched = AutomationScheduler(auto_dir)
            self.assertEqual(sched.list_schedules(), [])

            # Restore clean config roundtrip
            cfg_file.write_text('{"theme_mode": "light", "language": "en"}', encoding="utf-8")
            zpath = root / "release-backup.zip"
            BackupManager.create_backup(root, zpath)
            cfg_file.write_text('{"theme_mode": "dark"}', encoding="utf-8")
            BackupManager.restore_backup(zpath, root)
            self.assertIn("light", cfg_file.read_text(encoding="utf-8"))

    def test_concurrent_clients_midflight_revoke_and_schedule_pause(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            issuer = "https://conc.example.com"
            res_url = f"{issuer}/mcp"
            store = OAuthStore(root / "oauth" / "c.sqlite3", issuer, res_url)
            exec_app = ExecutionApprovals(store)

            for cid, prof in (("c-safe", "safe"), ("c-allow", "allowlist")):
                store.save_client(
                    OAuthClientInformationFull(
                        client_id=cid,
                        client_name=cid,
                        redirect_uris=["http://127.0.0.1:19991/cb"],
                        token_endpoint_auth_method="none",
                    )
                )
                store.mark_approved(cid)
                exec_app.set_client_profile(cid, prof)

            tok_safe = AccessToken(token="ts", client_id="c-safe", scopes=["mcp:read"], resource=res_url)
            tok_allow = AccessToken(token="ta", client_id="c-allow", scopes=["mcp:read"], resource=res_url)

            self.assertEqual(DEFAULT_REGISTRY.allowed_tools(store, tok_safe, exec_app), frozenset({"server_info"}))
            self.assertIn(EXEC_WINDOWS, DEFAULT_REGISTRY.allowed_tools(store, tok_allow, exec_app))
            self.assertIn(SERVER_LIST, DEFAULT_REGISTRY.allowed_tools(store, tok_allow, exec_app))

            sched = AutomationScheduler(
                root / "automation",
                permission_checker=lambda sp: (
                    exec_app.client_approved(sp.client_id),
                    "" if exec_app.client_approved(sp.client_id) else "Revoked",
                ),
            )
            sched.upsert_schedule(
                ScheduleSpec(
                    schedule_id="client-job",
                    name="Client Job",
                    trigger_type="interval",
                    tool_name="server_info",
                    client_id="c-allow",
                )
            )
            self.assertEqual(sched.trigger_now("client-job")["status"], "succeeded")

            # Mid-flight revoke -> denies client calls & auto-pauses schedule
            store.revoke_client("c-allow")
            with self.assertRaises(PermissionError):
                DEFAULT_REGISTRY.authorize_call(EXEC_WINDOWS, store, tok_allow, exec_app)
            self.assertEqual(sched.trigger_now("client-job")["status"], "paused_revoked")
            self.assertFalse(sched.list_schedules()[0]["enabled"])

    def test_output_flood_truncation_and_redaction(self) -> None:
        secret = "release-top-secret-flood-999111"
        redactor = SecretRedactor([secret])
        with tempfile.TemporaryDirectory() as tmp:
            runner = ProcessRunner(spool_dir=Path(tmp) / "spool", redactor=redactor)
            try:
                code = (
                    "import sys; "
                    f"line = 'payload-{secret}-' + ('X' * 120) + '\\n'; "
                    "sys.stdout.write(line * 400); sys.stdout.flush()"
                )
                res = asyncio.run(
                    runner.run_command([sys.executable, "-c", code], cwd=tmp, timeout=10.0)
                )
                self.assertEqual(res.exit_code, 0)
                self.assertGreater(res.stdout_bytes, 40000)
                self.assertLess(len(res.stdout), 16000)
                self.assertNotIn(secret, res.stdout)
                self.assertNotIn(secret, res.stderr)
            finally:
                runner.close()

    def test_version_consistency_and_tracked_secret_scan(self) -> None:
        self.assertEqual(__version__, "1.0.0")
        repo_root = Path(__file__).resolve().parents[2]
        pyproj = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(pyproj, r'version\s*=\s*"1\.0\.0"')

        # Tracked files must never contain real leaked API keys or private key headers
        ls = subprocess.run(
            ["git", "ls-files"], cwd=repo_root, capture_output=True, text=True, check=True
        )
        secret_patterns = (
            re.compile(r"ghp_[A-Za-z0-9]{20,}"),
            re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
            re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
            re.compile(r"xoxb-[0-9]{8,}-[A-Za-z0-9]{10,}"),
            re.compile(r"AIza[0-9A-Za-z_-]{35}"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        )
        for rel in ls.stdout.splitlines():
            p = repo_root / rel
            if not p.is_file() or p.suffix.lower() in (".png", ".ico", ".zip", ".exe"):
                continue
            if rel.startswith("tests/fixtures/"):
                continue
            content = p.read_text(encoding="utf-8", errors="ignore")
            for pat in secret_patterns:
                self.assertIsNone(pat.search(content), f"Potential secret pattern {pat.pattern} found in {rel}")


if __name__ == "__main__":
    unittest.main()
