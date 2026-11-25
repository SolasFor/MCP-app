"""Unit & security tests for Stage 11 Automation, Monitoring, Admin API, Backup & Updater."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import stat
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from app.core.redaction import SecretRedactor
from backend.automation import (
    AutomationScheduler,
    BackupManager,
    MetricsRegistry,
    ScheduleSpec,
    StagedUpdater,
    UpdateCandidate,
    build_admin_app,
    export_redacted_diagnostics,
    filter_audit_entries,
    next_cron_timestamp,
    parse_cron_expr,
    prune_audit_file,
    resolve_timezone,
)


class _DeterministicSpringDST(tzinfo):
    """Deterministic tzinfo jumping 01:59 EST (-5) -> 03:00 EDT (-4) at 07:00 UTC."""

    _SWITCH_LOCAL = datetime(2026, 3, 8, 2, 0)
    _SWITCH_UTC_NAIVE = datetime(2026, 3, 8, 7, 0)

    def utcoffset(self, dt: datetime | None) -> timedelta:
        if dt is None:
            return timedelta(hours=-5)
        return timedelta(hours=-4) if dt.replace(tzinfo=None) >= self._SWITCH_LOCAL else timedelta(hours=-5)

    def fromutc(self, dt: datetime) -> datetime:
        naive_utc = dt.replace(tzinfo=None)
        offset = timedelta(hours=-4) if naive_utc >= self._SWITCH_UTC_NAIVE else timedelta(hours=-5)
        return (naive_utc + offset).replace(tzinfo=self)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=1) if self.utcoffset(dt) == timedelta(hours=-4) else timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        return "EDT" if self.dst(dt) else "EST"


class SchedulerSecurityTests(unittest.TestCase):
    def test_cron_validation_and_dst_transition(self) -> None:
        mins, hrs, dom, months, dow = parse_cron_expr("15 3 */2 1-6 0,7")
        self.assertEqual(mins, frozenset({15}))
        self.assertEqual(hrs, frozenset({3}))
        self.assertIn(1, dom)
        self.assertIn(6, months)
        self.assertEqual(dow, frozenset({0}))

        with self.assertRaises(ValueError):
            parse_cron_expr("*/5 * *")
        with self.assertRaises(ValueError):
            parse_cron_expr("99 * * * *")

        # Unknown IANA zone falls back cleanly to UTC without crashing minimal Windows envs
        self.assertEqual(resolve_timezone("Mars/Olympus_Mons"), timezone.utc)

        # Deterministic DST transition: at 01:30 EST (06:30 UTC), 02:30 does not exist; 03:00 EDT is 07:00 UTC
        from unittest.mock import patch

        dst_tz = _DeterministicSpringDST()
        before_jump = datetime(2026, 3, 8, 6, 30, tzinfo=timezone.utc).timestamp()
        with patch("backend.automation.scheduler.resolve_timezone", return_value=dst_tz):
            nxt = next_cron_timestamp("30 3 * * *", before_jump, tz_name="America/New_York")
        local_hit = datetime.fromtimestamp(nxt, tz=timezone.utc).astimezone(dst_tz)
        self.assertEqual((local_hit.hour, local_hit.minute), (3, 30))

    def test_safe_only_retry_and_mutation_guards(self) -> None:
        with self.assertRaises(ValueError):
            ScheduleSpec(
                schedule_id="unsafe-retry",
                name="Unsafe",
                trigger_type="interval",
                tool_name="oauth_windows_command",
                safe_retry=False,
                max_retries=2,
            )

        with tempfile.TemporaryDirectory() as tmp:
            sched = AutomationScheduler(Path(tmp))
            spec = ScheduleSpec(
                schedule_id="health-check",
                name="Health Check",
                trigger_type="interval",
                tool_name="server_info",
                safe_retry=True,
                max_retries=2,
            )
            with self.assertRaises(PermissionError):
                sched.upsert_schedule(spec, actor_id="client-1", actor_profile="allowlist")
            with self.assertRaises(PermissionError):
                sched.upsert_schedule(spec, actor_id="client-1", actor_profile="safe")

            saved = sched.upsert_schedule(spec, actor_id="owner", actor_profile="safe")
            self.assertEqual(saved["schedule_id"], "health-check")
            with self.assertRaises(PermissionError):
                sched.remove_schedule("health-check", actor_id="client-1", actor_profile="allowlist")

    def test_misfire_concurrency_idempotency_retry_and_revoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            calls = 0
            perm_ok = True

            def _exec(_spec: ScheduleSpec, _idem: str) -> dict:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("transient glitch")
                return {"ok": True, "calls": calls}

            sched = AutomationScheduler(
                Path(tmp),
                executor=_exec,
                permission_checker=lambda _s: (perm_ok, "" if perm_ok else "OAuth revoked"),
            )
            spec = ScheduleSpec(
                schedule_id="s1",
                name="S1",
                trigger_type="cron",
                cron_expr="* * * * *",
                tool_name="server_info",
                misfire_policy="skip",
                concurrency_policy="forbid",
                safe_retry=True,
                max_retries=1,
                idempotency_key="slot",
                next_run_at=1000.0,
            )
            sched.upsert_schedule(spec, now=1000.0)

            # Overdue by 500s -> skipped_misfire
            out = sched.tick(now=1500.0)
            self.assertEqual(out, [])
            self.assertEqual(sched.list_history()[-1]["status"], "skipped_misfire")

            # Normal run with safe retry: attempt 1 fails, attempt 2 succeeds
            sched.upsert_schedule(
                ScheduleSpec(
                    schedule_id="s1",
                    name="S1",
                    trigger_type="cron",
                    cron_expr="* * * * *",
                    tool_name="server_info",
                    misfire_policy="coalesce",
                    safe_retry=True,
                    max_retries=1,
                    idempotency_key="slot",
                    next_run_at=1560.0,
                ),
                now=1500.0,
            )
            ran = sched.tick(now=1565.0)
            self.assertEqual(len(ran), 1)
            self.assertEqual(ran[0]["status"], "succeeded")
            self.assertEqual(ran[0]["attempts"], 2)

            # Duplicate idempotency suffix must skip
            dup = sched.trigger_now("s1", trigger="manual", idem_suffix="1560", now=1570.0)
            self.assertEqual(dup["status"], "skipped_idempotent")

            # Concurrency forbid skips when already marked active
            sched._active_ids.add("s1")
            try:
                conc = sched.trigger_now("s1", trigger="manual", idem_suffix="fresh", now=1571.0)
                self.assertEqual(conc["status"], "skipped_concurrency")
            finally:
                sched._active_ids.discard("s1")

            # Permission revoke auto-pauses schedule & logs paused_revoked
            perm_ok = False
            revoked = sched.trigger_now("s1", trigger="manual", idem_suffix="rev", now=1575.0)
            self.assertEqual(revoked["status"], "paused_revoked")
            stored = sched.list_schedules()[0]
            self.assertFalse(stored["enabled"])
            self.assertEqual(stored["paused_reason"], "OAuth revoked")


class AdminApiAndMonitoringTests(unittest.TestCase):
    def test_admin_api_negative_auth_loopback_and_tunnel_headers(self) -> None:
        metrics = MetricsRegistry()
        metrics.record_call("server_info", 12.5, error=False)
        app = build_admin_app(
            admin_tokens={
                "rw-secret-token": frozenset({"admin:read", "admin:write"}),
                "ro-secret-token": frozenset({"admin:read"}),
            },
            snapshot_provider=lambda: {"metrics": metrics.snapshot()},
            scheduler_list_provider=lambda: [{"schedule_id": "job1"}],
            scheduler_trigger_fn=lambda sid: {"triggered": sid},
            diagnostics_export_fn=lambda: json.dumps({"ok": True}),
        )

        client = TestClient(app, base_url="http://127.0.0.1:8001", client=("127.0.0.1", 51000))
        self.assertEqual(client.get("/api/v1/monitoring").status_code, 401)
        self.assertEqual(
            client.get("/api/v1/monitoring", headers={"Authorization": "Bearer wrong"}).status_code,
            401,
        )
        # Read-only token cannot trigger schedule
        self.assertEqual(
            client.post(
                "/api/v1/schedules/job1/run",
                headers={"Authorization": "Bearer ro-secret-token"},
            ).status_code,
            403,
        )
        # Foreign Host & tunnel forwarding headers rejected
        self.assertEqual(
            client.get(
                "/api/v1/monitoring",
                headers={"Authorization": "Bearer rw-secret-token", "Host": "evil.example.com"},
            ).status_code,
            403,
        )
        for hdr in ("Cf-Ray", "X-Forwarded-For", "X-Forwarded-Host", "Ngrok-Trace-Id", "Tailscale-User-Login"):
            self.assertEqual(
                client.get(
                    "/api/v1/monitoring",
                    headers={"Authorization": "Bearer rw-secret-token", hdr: "1"},
                ).status_code,
                403,
            )

        # Non-loopback client address rejected
        remote_client = TestClient(app, base_url="http://127.0.0.1:8001", client=("203.0.113.10", 51000))
        self.assertEqual(
            remote_client.get(
                "/api/v1/monitoring",
                headers={"Authorization": "Bearer rw-secret-token"},
            ).status_code,
            403,
        )

        # Valid loopback scoped access succeeds
        ok_mon = client.get("/api/v1/monitoring", headers={"Authorization": "Bearer ro-secret-token"})
        self.assertEqual(ok_mon.status_code, 200)
        self.assertEqual(ok_mon.json()["metrics"]["total_requests"], 1)

        ok_run = client.post(
            "/api/v1/schedules/job1/run",
            headers={"X-MCP-Admin-Token": "rw-secret-token"},
        )
        self.assertEqual(ok_run.status_code, 200)
        self.assertEqual(ok_run.json()["triggered"], "job1")

    def test_redacted_diagnostics_audit_filter_and_prune(self) -> None:
        red = SecretRedactor(["super-secret-value-123"])
        reg = MetricsRegistry()
        reg.record_call("server_info", 10.0)
        reg.record_call("server_info", 30.0, error=True)
        bundle = export_redacted_diagnostics(
            {"metrics": reg.snapshot(), "token": "super-secret-value-123"},
            audit_lines=["[INFO] started", "[ERROR] leak super-secret-value-123"],
            redactor=red,
        )
        self.assertNotIn("super-secret-value-123", bundle)
        filtered = filter_audit_entries(
            ["[INFO] ok", "[ERROR] disk warn", "[ERROR] auth fail"],
            query="auth",
            level="ERROR",
        )
        self.assertEqual(filtered, ["[ERROR] auth fail"])

        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "audit.log"
            log_file.write_text("\n".join(f"line {i}" for i in range(15)) + "\n", encoding="utf-8")
            removed = prune_audit_file(log_file, max_lines=5)
            self.assertEqual(removed, 10)
            self.assertEqual(len(log_file.read_text(encoding="utf-8").splitlines()), 5)


class BackupAndUpdaterSecurityTests(unittest.TestCase):
    def test_backup_excludes_secrets_and_rejects_traversal_symlink_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cfg"
            root.mkdir()
            (root / "settings.json").write_text('{"theme":"dark"}', encoding="utf-8")
            (root / "token.json").write_text('{"token":"DO-NOT-BACKUP"}', encoding="utf-8")
            (root / "oauth").mkdir()
            (root / "oauth" / "connections.sqlite3").write_bytes(b"secret-db")
            (root / "secrets").mkdir()
            (root / "secrets" / "secrets.vault.enc").write_bytes(b"vault")

            zpath = Path(tmp) / "backup.zip"
            meta = BackupManager.create_backup(root, zpath)
            self.assertEqual(meta["file_count"], 1)
            with zipfile.ZipFile(zpath, "r") as zf:
                names = zf.namelist()
                self.assertIn("config/settings.json", names)
                self.assertFalse(any("token.json" in n or "oauth" in n or "secrets" in n for n in names))

            # Zip-slip traversal
            evil_zip = Path(tmp) / "evil_slip.zip"
            with zipfile.ZipFile(evil_zip, "w") as zf:
                zf.writestr("../escape.txt", "boom")
            with self.assertRaises(ValueError):
                BackupManager.restore_backup(evil_zip, root)

            # Symlink rejection
            sym_zip = Path(tmp) / "sym.zip"
            with zipfile.ZipFile(sym_zip, "w") as zf:
                zi = zipfile.ZipInfo("config/settings.json")
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, "/etc/passwd")
            with self.assertRaises(ValueError):
                BackupManager.restore_backup(sym_zip, root)

            # Tampered checksum rejected
            tamper_zip = Path(tmp) / "tamper.zip"
            buf = io.BytesIO()
            with zipfile.ZipFile(zpath, "r") as src, zipfile.ZipFile(buf, "w") as dst:
                for item in src.infolist():
                    data = src.read(item.filename)
                    if item.filename == "config/settings.json":
                        data = b'{"theme":"hacked"}'
                    dst.writestr(item, data)
            tamper_zip.write_bytes(buf.getvalue())
            with self.assertRaises(PermissionError):
                BackupManager.restore_backup(tamper_zip, root)

    def test_updater_rejects_unsigned_corrupt_and_keeps_auto_install_disabled(self) -> None:
        priv = Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pub_b64 = base64.b64encode(pub_raw).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            updater = StagedUpdater(Path(tmp) / "updates", trusted_pubkeys={"k1": pub_b64})
            self.assertFalse(updater.auto_install_enabled)

            payload_buf = io.BytesIO()
            with zipfile.ZipFile(payload_buf, "w") as zf:
                zf.writestr("version.txt", "1.0.0")
            payload = payload_buf.getvalue()
            sha = hashlib.sha256(payload).hexdigest()

            # Unsigned rejected
            with self.assertRaises(PermissionError):
                updater.stage_bytes(
                    UpdateCandidate("1.0.0", "notes", "https://example/upd.zip", sha),
                    payload,
                )

            # Bad signature rejected
            with self.assertRaises(PermissionError):
                updater.stage_bytes(
                    UpdateCandidate("1.0.0", "notes", "https://example/upd.zip", sha, sig_b64=base64.b64encode(b"0" * 64).decode(), key_id="k1"),
                    payload,
                )

            # SHA mismatch rejected
            sig_b64 = base64.b64encode(priv.sign(sha.encode("ascii"))).decode("ascii")
            with self.assertRaises(PermissionError):
                updater.stage_bytes(
                    UpdateCandidate("1.0.0", "notes", "https://example/upd.zip", sha, sig_b64=sig_b64, key_id="k1"),
                    payload + b"corrupt",
                )

            # Valid sign stages, but auto_install stays refused without owner_explicit_install=True
            staged = updater.stage_bytes(
                UpdateCandidate("1.0.0", "notes", "https://example/upd.zip", sha, sig_b64=sig_b64, key_id="k1"),
                payload,
            )
            install_dir = Path(tmp) / "install"
            install_dir.mkdir()
            with self.assertRaises(PermissionError):
                updater.apply_staged(
                    UpdateCandidate("1.0.0", "notes", "https://example/upd.zip", sha, sig_b64=sig_b64, key_id="k1"),
                    staged,
                    install_dir=install_dir,
                )

            cand = StagedUpdater.parse_github_release(
                {
                    "tag_name": "v0.9.9",
                    "body": f"Changelog\nSHA256: {sha}",
                    "assets": [{"name": "MCPApp-0.9.9-portable.zip", "browser_download_url": "https://example/p.zip"}],
                }
            )
            self.assertEqual(cand.version, "0.9.9")
            self.assertEqual(cand.sha256, sha)
            self.assertFalse(cand.authenticode_signed)


if __name__ == "__main__":
    unittest.main()
