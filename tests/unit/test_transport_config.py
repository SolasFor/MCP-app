"""stdlib-only regression tests for Quick Tunnel Host/Origin policy."""
from __future__ import annotations

import unittest

from backend.transport_config import transport_allowlists, validate_mcp_path, validate_public_url


class TransportConfigTests(unittest.TestCase):
    def test_quick_tunnel_host_allowlist(self) -> None:
        hosts, origins = transport_allowlists("https://one-two.trycloudflare.com/mcp", 8000)
        self.assertIn("one-two.trycloudflare.com", hosts)
        self.assertIn("one-two.trycloudflare.com:443", hosts)
        self.assertIn("127.0.0.1:8000", hosts)
        self.assertNotIn("*.trycloudflare.com", hosts)
        self.assertNotIn("evil.example.com", hosts)
        self.assertIn("https://one-two.trycloudflare.com", origins)
        self.assertNotIn("https://evil.example.com", origins)

    def test_rotation_does_not_keep_old_host(self) -> None:
        hosts, _ = transport_allowlists("https://new.trycloudflare.com/mcp", 8000)
        self.assertIn("new.trycloudflare.com", hosts)
        self.assertNotIn("old.trycloudflare.com", hosts)

    def test_custom_port_and_local_checks(self) -> None:
        hosts, origins = transport_allowlists("https://mcp.example.com:8443/mcp", 9000)
        self.assertIn("mcp.example.com:8443", hosts)
        self.assertNotIn("mcp.example.com:443", hosts)
        self.assertIn("localhost:9000", hosts)
        self.assertIn("http://localhost:9000", origins)

    def test_validate_path(self) -> None:
        self.assertEqual(validate_mcp_path("/api/mcp"), "/api/mcp")
        for invalid in ("/", "/mcp/", "mcp", "//mcp", "/mcp?token=x", "/health", "/ready"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_mcp_path(invalid)

    def test_public_url_valid(self) -> None:
        self.assertEqual(
            validate_public_url(" https://abc.trycloudflare.com/mcp/ ", "/mcp"),
            "https://abc.trycloudflare.com/mcp",
        )
        self.assertEqual(validate_public_url("http://127.0.0.1:8000/mcp", "/mcp"), "http://127.0.0.1:8000/mcp")

    def test_reject_bad_public_urls(self) -> None:
        bad = (
            "http://cloud.example.com/mcp",
            "https://abc.trycloudflare.com/other",
            "https://abc.trycloudflare.com/mcp?token=secret",
            "https://abc.trycloudflare.com/mcp#fragment",
            "https://user:password@abc.trycloudflare.com/mcp",
            "https://abc.trycloudflare.com:bogus/mcp",
            "https://abc.trycloudflare.com:99999/mcp",
        )
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_public_url(url, "/mcp")

    def test_extra_origins_opt_in(self) -> None:
        _, origins = transport_allowlists(
            "https://abc.trycloudflare.com/mcp", 8000,
            "https://gemini.google.com, https://gemini.google.com,https://chatgpt.com",
        )
        self.assertIn("https://gemini.google.com", origins)
        self.assertIn("https://chatgpt.com", origins)
        self.assertEqual(origins.count("https://gemini.google.com"), 1)

    def test_extra_origins_reject_wildcards_and_http_remote(self) -> None:
        for origin in ("*", "https://*.example.com", "http://evil.example.com", "https://evil.example.com/path", "https://user@evil.example.com"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                transport_allowlists("https://abc.trycloudflare.com/mcp", 8000, origin)

    def test_local_port_invalid(self) -> None:
        with self.assertRaises(ValueError):
            transport_allowlists("https://abc.trycloudflare.com/mcp", 0)


if __name__ == "__main__":
    unittest.main()
