"""Unit tests for the centralized persistent LoggingManager and redacted diagnostics ZIP export."""
from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from app.core.diagnostics_bundle import export_diagnostics_zip
from app.core.logging_manager import (
    DEFAULT_LEVEL,
    DEFAULT_MAX_FILE_MB,
    DEFAULT_MAX_TOTAL_MB,
    DEFAULT_RETENTION_DAYS,
    LOG_COMPONENTS,
    LogConfig,
    LoggingManager,
)
from app.core.redaction import SecretRedactor

ROOT = Path(__file__).resolve().parents[2]


class LoggingManagerTests(unittest.TestCase):
    def test_creates_all_15_logs_and_archive_with_expected_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logs_dir = Path(tmp) / "logs"
            lm = LoggingManager(base_dir=logs_dir, auto_start=False)
            lm.initialize(data_root=Path(tmp))
            try:
                self.assertEqual(len(LOG_COMPONENTS), 15)
                self.assertEqual(lm.config.level, DEFAULT_LEVEL)
                self.assertEqual(lm.config.max_file_mb, DEFAULT_MAX_FILE_MB)
                self.assertEqual(lm.config.retention_days, DEFAULT_RETENTION_DAYS)
                self.assertEqual(lm.config.max_total_mb, DEFAULT_MAX_TOTAL_MB)
                self.assertTrue(lm.config.enabled)
                self.assertTrue(lm.config.auto_rotate)
                self.assertTrue(lm.config.archive_enabled)
                self.assertTrue((logs_dir / "archive").is_dir())
                for comp in LOG_COMPONENTS:
                    self.assertTrue((logs_dir / f"{comp}.log").is_file(), f"Missing {comp}.log")
            finally:
                lm.shutdown()

    def test_redacts_secrets_even_in_debug_and_mirrors_errors_without_loops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logs_dir = Path(tmp) / "logs"
            red = SecretRedactor(["owner-tok-secret-123456"])
            lm = LoggingManager(
                base_dir=logs_dir,
                config=LogConfig(enabled=True, level="DEBUG"),
                redactor=red,
                auto_start=False,
            )
            lm.initialize(data_root=Path(tmp))
            try:
                lm.debug(
                    "oauth",
                    "Authorization: Bearer owner-tok-secret-123456 code=authcode999 "
                    "code_verifier=pkceverifier123 cookie=mcp_oauth_csrf=secretcookie "
                    "Proxy-Authorization: Basic dXNlcjpwYXNz",
                    event_code="oauth_debug",
                )
                lm.debug(
                    "computer_use",
                    "screenshot data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC==",
                    event_code="screenshot",
                )
                lm.error("tunnel", "Tunnel failed cfut_topsecret_token_999", event_code="tunnel_err")
                lm.error("errors", "Direct error entry should not duplicate infinitely", event_code="direct_err")
                lm.flush(timeout=3.0)

                oauth_txt = (logs_dir / "oauth.log").read_text(encoding="utf-8")
                self.assertNotIn("owner-tok-secret-123456", oauth_txt)
                self.assertNotIn("authcode999", oauth_txt)
                self.assertNotIn("pkceverifier123", oauth_txt)
                self.assertNotIn("secretcookie", oauth_txt)
                self.assertNotIn("dXNlcjpwYXNz", oauth_txt)

                cu_txt = (logs_dir / "computer_use.log").read_text(encoding="utf-8")
                self.assertNotIn("iVBORw0KGgo", cu_txt)

                err_txt = (logs_dir / "errors.log").read_text(encoding="utf-8")
                self.assertIn("event=tunnel_err", err_txt)
                self.assertNotIn("cfut_topsecret_token_999", err_txt)
                self.assertEqual(err_txt.count("Direct error entry should not duplicate infinitely"), 1)
            finally:
                lm.shutdown()

    def test_rotation_archiving_retention_and_protected_audit_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs_dir = root / "logs"
            # Seed legacy logs outside logs/
            (root / "crash.log").write_text("legacy Bearer super-secret-crash", encoding="utf-8")
            (root / "server").mkdir()
            (root / "server" / "mcp_audit.log").write_text("legacy audit line 1\n", encoding="utf-8")

            # Seed protected security audit files that must NEVER be deleted
            audit_exec = logs_dir / "mcp_execution_audit.jsonl"
            audit_dt = logs_dir / "desktop_policy_audit.jsonl"
            logs_dir.mkdir(parents=True)
            audit_exec.write_text('{"event":"protected_exec"}\n', encoding="utf-8")
            audit_dt.write_text('{"event":"protected_desktop"}\n', encoding="utf-8")

            # Seed stale archive > 30 days old
            arch = logs_dir / "archive"
            arch.mkdir(exist_ok=True)
            stale = arch / "app_20200101_000000_0.log.gz"
            with gzip.open(stale, "wt", encoding="utf-8") as gz:
                gz.write("old line\n")
            old_ts = 1577836800.0
            os.utime(stale, (old_ts, old_ts))

            lm = LoggingManager(
                base_dir=logs_dir,
                config=LogConfig(
                    enabled=True,
                    level="INFO",
                    max_file_mb=1,
                    retention_days=30,
                    max_total_mb=2,
                    auto_rotate=True,
                    archive_enabled=True,
                ),
                auto_start=False,
            )
            lm.initialize(data_root=root)
            try:
                # Legacy files copied cleanly without destroying originals
                self.assertTrue((root / "crash.log").is_file())
                self.assertTrue((root / "server" / "mcp_audit.log").is_file())
                legacy_archives = list(arch.glob("legacy_crash_*.log.gz"))
                self.assertEqual(len(legacy_archives), 1)
                with gzip.open(legacy_archives[0], "rt", encoding="utf-8") as gz:
                    legacy_txt = gz.read()
                self.assertNotIn("super-secret-crash", legacy_txt)

                # Trigger > 1 MB rotation quickly via realistic lines
                payload = "x" * 16000
                for idx in range(75):
                    lm.info("backend", f"log line {idx:03d} {payload}", event_code="rot", sync=True)

                rotated = list(arch.glob("backend_*.log.gz"))
                self.assertTrue(rotated, "Expected rotated gzip archives")
                self.assertFalse(stale.exists(), "Stale >30d archive should have been pruned")

                # Clear normal logs -> protected security audit files MUST stay intact
                lm.clear_normal_logs("all")
                self.assertEqual(audit_exec.read_text(encoding="utf-8"), '{"event":"protected_exec"}\n')
                self.assertEqual(audit_dt.read_text(encoding="utf-8"), '{"event":"protected_desktop"}\n')
            finally:
                lm.shutdown()

    def test_crash_logging_and_redacted_diagnostics_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs_dir = root / "logs"
            red = SecretRedactor(["zip-owner-secret-abcdef"])
            lm = LoggingManager(base_dir=logs_dir, redactor=red, auto_start=False)
            lm.initialize(data_root=root)
            try:
                try:
                    raise RuntimeError("Boom with secret zip-owner-secret-abcdef")
                except RuntimeError as exc:
                    lm.log_crash(type(exc), exc, exc.__traceback__, context="unit_test")
                lm.info("proxy", "Checking proxy", event_code="proxy_check", sync=True)
                lm.flush(timeout=2.0)

                crash_txt = (logs_dir / "crash.log").read_text(encoding="utf-8")
                self.assertIn("RuntimeError", crash_txt)
                self.assertNotIn("zip-owner-secret-abcdef", crash_txt)

                zip_path = root / "diag.zip"
                export_diagnostics_zip(
                    zip_path,
                    logging_manager=lm,
                    redactor=red,
                    network_report={"token": "zip-owner-secret-abcdef", "summary": "ok"},
                )
                with zipfile.ZipFile(zip_path, "r") as zf:
                    names = set(zf.namelist())
                    self.assertIn("manifest.json", names)
                    self.assertIn("settings_redacted.json", names)
                    self.assertIn("logs/crash.log", names)
                    self.assertFalse(any(n.endswith(".sqlite3") or n.endswith(".png") for n in names))
                    manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                    self.assertFalse(manifest["secrets_included"])
                    self.assertFalse(manifest["oauth_db_included"])
                    for n in names:
                        raw = zf.read(n).decode("utf-8", errors="replace")
                        self.assertNotIn("zip-owner-secret-abcdef", raw)
            finally:
                lm.shutdown()

    def test_multiprocess_concurrent_writes_and_tail_paging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logs_dir = Path(tmp) / "logs"
            lm = LoggingManager(
                base_dir=logs_dir,
                config=LogConfig(max_file_mb=1, auto_rotate=True, archive_enabled=True),
                auto_start=False,
            )
            lm.initialize(data_root=Path(tmp))
            lm.shutdown()

            script = (
                "import sys; from pathlib import Path; "
                "from app.core.logging_manager import LoggingManager, LogConfig; "
                "lm = LoggingManager(base_dir=Path(sys.argv[1]), "
                "config=LogConfig(max_file_mb=1, auto_rotate=True, archive_enabled=True), auto_start=False); "
                "lm.initialize(touch_files=False); "
                "[lm.info('tasks', f'worker={sys.argv[2]} seq={i}', sync=True) for i in range(40)]; "
                "lm.shutdown()"
            )
            procs = [
                subprocess.Popen([sys.executable, "-c", script, str(logs_dir), f"p{n}"], cwd=ROOT)
                for n in range(3)
            ]
            for p in procs:
                self.assertEqual(p.wait(timeout=20), 0)

            lm2 = LoggingManager(base_dir=logs_dir, auto_start=False)
            recs, offset, has_more = lm2.read_tail_page("tasks", offset_from_end=0, max_lines=10)
            self.assertGreater(len(recs), 0)
            self.assertTrue(isinstance(offset, int) and isinstance(has_more, bool))


if __name__ == "__main__":
    unittest.main()
