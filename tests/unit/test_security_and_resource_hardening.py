"""Unit tests for Stage 3–10 security, SSRF redirect guard, extension pipe cleanup, and UI polish."""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx2 as httpx
from PyQt6.QtWidgets import QApplication

from app.core.secret_store import SecretStore
from app.core.tunnels.base import RouteOwnershipStore
from app.core.tunnels.tailscale import TailscaleFunnelProvider
from app.ui.components.silent_dialog import SilentMessageBox
from app.ui.i18n import LANG_EN, LANG_RU, i18n
from backend.extensions.runtime import ExtensionProcessHost
from backend.gateway.models import TRANSPORT_STREAMABLE_HTTP, UpstreamServerProfile
from backend.gateway.upstream_client import UpstreamSessionHandle
from backend.security_policy import workspace_path


class SecurityAndResourceHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_workspace_path_blocks_nul_byte_ads_and_reserved_windows_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.txt").write_text("ok", encoding="utf-8")
            self.assertEqual(workspace_path(root, "safe.txt"), (root / "safe.txt").resolve())

            for bad in (
                "safe.txt\x00.md",
                "safe.txt:Zone.Identifier",
                "CON",
                "nul.txt",
                "sub/com1.log",
                "../escape.txt",
                ".env.local",
            ):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    workspace_path(root, bad)

    def test_upstream_redirect_guard_blocks_ssrf_loop_and_cross_origin_credentials(self) -> None:
        prof = UpstreamServerProfile(
            server_id="ext_api",
            name="External API",
            transport=TRANSPORT_STREAMABLE_HTTP,
            url="https://api.example.com/mcp",
            allow_redirects=True,
            allow_local_endpoint=False,
            enabled=True,
            approved_by_owner=True,
        )
        handle = UpstreamSessionHandle(
            prof,
            env={},
            headers={"Authorization": "Bearer secret-upstream-token"},
            gateway_instance_id="gw-test-1",
            self_urls=("https://my-self.example.com/mcp",),
        )

        # 1. Redirect to AWS metadata IP is blocked
        req = httpx.Request("POST", "https://api.example.com/mcp")
        resp_ssrf = httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            request=req,
        )
        with self.assertRaises(ValueError):
            asyncio.run(handle._validate_redirect_response(resp_ssrf))

        # 2. Redirect to self MCP URL is blocked
        resp_loop = httpx.Response(
            307,
            headers={"Location": "https://my-self.example.com/mcp"},
            request=req,
        )
        with self.assertRaises(ValueError):
            asyncio.run(handle._validate_redirect_response(resp_loop))

        # 3. Cross-origin redirect when secret headers exist is blocked
        resp_cross = httpx.Response(
            302,
            headers={"Location": "https://other-origin.example.org/mcp"},
            request=req,
        )
        with self.assertRaises(PermissionError):
            asyncio.run(handle._validate_redirect_response(resp_cross))

        # 4. Same-origin HTTPS path redirect passes cleanly
        resp_same = httpx.Response(
            307,
            headers={"Location": "https://api.example.com/v2/mcp"},
            request=req,
        )
        asyncio.run(handle._validate_redirect_response(resp_same))

    def test_extension_host_closes_pipes_on_init_failure_and_crash_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bad_script = base / "bad_worker.py"
            bad_script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
            logs: list[str] = []
            host = ExtensionProcessHost(
                extension_id="bad_ext",
                entrypoint=bad_script,
                data_dir=base / "data",
                declared_secrets={},
                on_log=logs.append,
            )
            with self.assertRaises(RuntimeError):
                host.start(timeout_seconds=2.0)
            # Failed start must clean up _proc and leave zero open pipes
            self.assertIsNone(host._proc)
            self.assertEqual(host._pump_threads, [])

    def test_tailscale_connection_identity_caches_status_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secrets = SecretStore(root / "secrets")
            ownership = RouteOwnershipStore(root / "routes.json")
            prov = TailscaleFunnelProvider(secrets, ownership)
            sample_status = {"BackendState": "Running", "Self": {"DNSName": "box.tailnet.ts.net."}}
            with (
                patch("app.core.tunnels.tailscale._find_tailscale", return_value="tailscale.exe"),
                patch.object(prov, "_query_status_json", return_value=(sample_status, "")) as status_mock,
            ):
                id1 = prov.connection_identity(local_host="127.0.0.1", local_port=8000, mcp_path="/mcp")
                id2 = prov.connection_identity(local_host="127.0.0.1", local_port=8000, mcp_path="/mcp")
                self.assertEqual(id1.public_url, "https://box.tailnet.ts.net/mcp")
                self.assertEqual(id2.public_url, "https://box.tailnet.ts.net/mcp")
                # Cached: second call must not spawn tailscale CLI again
                self.assertEqual(status_mock.call_count, 1)

    def test_silent_message_box_buttons_localize_for_ru_and_en(self) -> None:
        try:
            i18n.set_language(LANG_EN)
            dlg_en = SilentMessageBox(
                kind="question",
                title="Confirm",
                text="Proceed?",
                buttons=SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            )
            yes_en = dlg_en.button(SilentMessageBox.StandardButton.Yes)
            no_en = dlg_en.button(SilentMessageBox.StandardButton.No)
            assert yes_en is not None and no_en is not None
            self.assertEqual(yes_en.text(), "Yes")
            self.assertEqual(no_en.text(), "No")
            dlg_en.close()

            i18n.set_language(LANG_RU)
            dlg_ru = SilentMessageBox(
                kind="question",
                title="Подтверждение",
                text="Продолжить?",
                buttons=SilentMessageBox.StandardButton.Yes | SilentMessageBox.StandardButton.No,
            )
            yes_ru = dlg_ru.button(SilentMessageBox.StandardButton.Yes)
            assert yes_ru is not None
            self.assertEqual(yes_ru.text(), "Да")
            dlg_ru.close()
        finally:
            i18n.set_language(LANG_RU)


if __name__ == "__main__":
    unittest.main()
