"""Integration tests for Stage 9 Extensions: out-of-process IPC, update/rollback, crash recovery, official catalog & GUI."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from app.ui import theme
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from app.ui.pages.extensions_page import ExtensionsPage
from backend.extensions.manager import ExtensionManager
from backend.extensions.packaging import create_extension_zip, generate_signing_keypair
from backend.extensions.store import ExtensionStore


def _make_signed_ext(
    root: Path,
    *,
    version: str,
    priv_b64: str,
    key_id: str,
    zip_path: Path,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "id": "note_counter",
        "name": "Note Counter",
        "version": version,
        "api_version": "1.0",
        "entrypoint": "main.py",
        "description": "Test stateful extension",
        "permissions": ["read_metrics"],
        "secret_keys": ["EXT_TOKEN"],
        "tools": [
            {"name": "write_and_read", "description": "Persist note and read version", "permission": "read_metrics", "read_only": True},
            {"name": "crash_worker", "description": "Simulate worker crash", "permission": "read_metrics", "read_only": True},
        ],
        "ui_components": [
            {"id": "c1", "type": "status_card", "title": "Note Counter"},
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "main.py").write_text(
        f"""
import os
from pathlib import Path
from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("note_counter", "{version}")

@app.tool("write_and_read")
def write_and_read(append_line: str = "") -> dict:
    note_file = app.data_dir / "state.txt"
    if append_line:
        prev = note_file.read_text(encoding="utf-8") if note_file.is_file() else ""
        note_file.write_text(prev + append_line + "\\n", encoding="utf-8")
    content = note_file.read_text(encoding="utf-8") if note_file.is_file() else ""
    return {{
        "version": "{version}",
        "pid": os.getpid(),
        "has_core_token": "MCP_SECRET_TOKEN" in os.environ,
        "ext_secret_present": bool(app.secret("EXT_TOKEN")),
        "ext_secret_echo": app.secret("EXT_TOKEN"),
        "content": content,
    }}

@app.tool("crash_worker")
def crash_worker() -> dict:
    os._exit(1)

@app.ui_provider()
def ui() -> dict:
    return {{"version": "{version}"}}

if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
""",
        encoding="utf-8",
    )
    create_extension_zip(root, zip_path, private_key_b64=priv_b64, key_id=key_id)


class ExtensionsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.redactor = SecretRedactor(["CORE_SUPER_SECRET_TOKEN"])
        self.store = ExtensionStore(
            self.root / "extensions",
            secret_store=SecretStore(self.root / "secrets"),
        )
        self.mgr = ExtensionManager(self.store, redactor=self.redactor)

    def tearDown(self) -> None:
        self.mgr.shutdown_all()
        i18n.set_language(LANG_RU)
        theme.apply(self.app, theme.THEME_DARK)
        self.tmp.cleanup()

    def test_install_ipc_secret_update_rollback_and_crash_recovery(self) -> None:
        priv, pub = generate_signing_keypair()
        self.store.add_trusted_key("ci-sign", pub)
        zip_v1 = self.root / "ext-1.0.0.zip"
        zip_v2 = self.root / "ext-1.1.0.zip"
        _make_signed_ext(self.root / "src1", version="1.0.0", priv_b64=priv, key_id="ci-sign", zip_path=zip_v1)
        _make_signed_ext(self.root / "src2", version="1.1.0", priv_b64=priv, key_id="ci-sign", zip_path=zip_v2)

        os.environ["MCP_SECRET_TOKEN"] = "CORE_SUPER_SECRET_TOKEN"
        try:
            self.mgr.install_zip(zip_v1, grant_permissions=("read_metrics",), enable_after_install=True)
            self.mgr.set_secret("note_counter", "EXT_TOKEN", "ext-secret-value-999")
            r1 = self.mgr.call_tool("note_counter", "write_and_read", {"append_line": "first"})["result"]
            self.assertEqual(r1["version"], "1.0.0")
            self.assertNotEqual(r1["pid"], os.getpid())
            self.assertFalse(r1["has_core_token"])
            self.assertTrue(r1["ext_secret_present"])
            # Output secret must be redacted before reaching caller/logs
            self.assertNotIn("ext-secret-value-999", r1["ext_secret_echo"])
            self.assertIn("first", r1["content"])

            # Disable -> blocks tool calls
            self.mgr.disable("note_counter")
            with self.assertRaises(PermissionError):
                self.mgr.call_tool("note_counter", "write_and_read", {})

            # Update v1.1.0 -> preserves data & settings
            self.mgr.enable("note_counter")
            self.mgr.update_zip("note_counter", zip_v2)
            r2 = self.mgr.call_tool("note_counter", "write_and_read", {"append_line": "second"})["result"]
            self.assertEqual(r2["version"], "1.1.0")
            self.assertIn("first", r2["content"])
            self.assertIn("second", r2["content"])

            # Simulate worker crash -> core survives and next call restarts cleanly
            with self.assertRaises(RuntimeError):
                self.mgr.call_tool("note_counter", "crash_worker", {})
            self.assertEqual(self.mgr.status("note_counter").state, "crashed")
            r_after = self.mgr.call_tool("note_counter", "write_and_read", {})["result"]
            self.assertEqual(r_after["version"], "1.1.0")
            self.assertNotEqual(r_after["pid"], r2["pid"])

            # Rollback to v1.0.0 -> restores v1.0.0 while preserving data dir
            self.mgr.rollback("note_counter")
            r_rb = self.mgr.call_tool("note_counter", "write_and_read", {})["result"]
            self.assertEqual(r_rb["version"], "1.0.0")
            self.assertIn("second", r_rb["content"])
        finally:
            os.environ.pop("MCP_SECRET_TOKEN", None)

    def test_official_extensions_and_oauth_tools_roundtrip(self) -> None:
        cat = {c["id"] for c in self.mgr.list_catalog()}
        self.assertTrue({"system_monitor", "git_manager", "docker_manager", "browser_automation"} <= cat)

        self.mgr.install_official("system_monitor", enable_after_install=True)
        metrics = self.mgr.call_tool("system_monitor", "system_metrics")["result"]
        self.assertGreater(metrics["ram_total_mb"], 0)

        # Git manager on a fresh temporary git repository
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "CI"], cwd=repo, check=True)
        (repo / "README.txt").write_text("hi\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
        self.mgr.install_official("git_manager", enable_after_install=True)
        gst = self.mgr.call_tool("git_manager", "git_repo_status", {"repo_path": str(repo)})["result"]
        self.assertEqual(gst["changed_count"], 0)

        # Verify backend.server extension_* OAuth tools enforce profiles & return live extension output
        from backend import server

        server.EXTENSION_STORE = self.store
        server.EXTENSION_MANAGER = self.mgr
        assert server.oauth_provider is not None and server.oauth_execution is not None
        server.oauth_provider.store.save_client(
            OAuthClientInformationFull(
                client_id="ext-client",
                client_name="Ext Client",
                redirect_uris=["http://127.0.0.1:19995/cb"],
                token_endpoint_auth_method="none",
            )
        )
        server.oauth_provider.store.mark_approved("ext-client")
        server.oauth_execution.set_client_profile("ext-client", "allowlist")
        tok = AccessToken(token="t", client_id="ext-client", scopes=["mcp:read"], resource=server.RESOURCE_URL)
        with patch("backend.tool_permissions.get_access_token", return_value=tok):
            listed = asyncio.run(server.extension_list())
            self.assertTrue(any(x["id"] == "system_monitor" for x in listed["installed"]))
            called = asyncio.run(server.extension_call_tool("system_monitor", "system_metrics", {}))
            self.assertGreater(called["result"]["cpu_count"], 0)
            # extension_enable requires full profile
            with self.assertRaises(PermissionError):
                asyncio.run(server.extension_enable("system_monitor"))

    def test_headless_extensions_gui_catalog_toggle_and_i18n(self) -> None:
        page = ExtensionsPage(
            extensions_dir=self.root / "gui_ext",
            secret_store=SecretStore(self.root / "gui_secrets"),
            redactor=self.redactor,
        )
        try:
            self.assertGreaterEqual(page.catalog_table.rowCount(), 4)
            page.catalog_table.selectRow(0)
            page.install_selected_catalog()
            self.assertEqual(page.installed_table.rowCount(), 1)
            page.installed_table.selectRow(0)
            page.toggle_selected()
            self.assertIn("Работает", page.installed_table.item(0, 3).text())

            i18n.set_language(LANG_EN)
            page.retranslate()
            self.assertEqual(page.install_zip_btn.text(), "Install ZIP…")
            self.assertIn("Running", page.installed_table.item(0, 3).text())
        finally:
            page.shutdown()


if __name__ == "__main__":
    unittest.main()
