"""Managed development server lifecycle tests using benign child processes."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

from backend.managed_servers import ManagedServers


class ManagedServerTests(unittest.TestCase):
    def test_local_config_lifecycle_and_client_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "managed_servers.json"
            path.write_text(json.dumps({
                "dev": {"argv": [sys.executable, "-c", "import time; time.sleep(30)"], "cwd": tmp}
            }), encoding="utf-8")
            jobs = ManagedServers(path)
            try:
                self.assertFalse(jobs.list("a")[0]["running"])
                self.assertTrue(jobs.start("a", "dev")["running"])
                self.assertTrue(jobs.start("a", "dev")["running"])
                self.assertTrue(jobs.list("a")[0]["running"])
                with self.assertRaises(ValueError):
                    jobs.stop("b", "dev")
                with self.assertRaises(ValueError):
                    jobs.start("b", "dev")
                self.assertFalse(jobs.stop("a", "dev")["running"])
                with self.assertRaises(ValueError):
                    jobs.start("a", "unconfigured")
            finally:
                jobs.close()

    def test_no_config_no_remote_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs = ManagedServers(Path(tmp) / "missing.json")
            self.assertEqual(jobs.list("a"), [])
            with self.assertRaises(ValueError):
                jobs.start("a", "dev")


if __name__ == "__main__":
    unittest.main()
