"""Connection diagnostics tests with all network calls stubbed.

Guarantees that an owner Bearer credential is never transmitted to the public
Cloudflare endpoint, and that error paths do not reveal credentials.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app.core import diagnostics as d

PUBLIC = "https://test.trycloudflare.com"
RESOURCE = PUBLIC + "/mcp"
SECRET = "never-print-owner-token"


class DiagnosticTests(unittest.TestCase):
    def test_url_restrictions(self):
        for bad in (
            "http://test.trycloudflare.com/mcp",
            "https://user:password@test.trycloudflare.com/mcp",
            "https://test.trycloudflare.com/mcp?token=leaked",
            "https://test.trycloudflare.com/mcp#fragment",
            "not-a-url",
        ):
            results = d.probe_connection(bad, 8000, "/health", SECRET)
            self.assertEqual(len(results), 1)
            self.assertFalse(results[0].passed)
            self.assertNotIn(SECRET, results[0].message)

    def test_token_must_never_be_sent_publicly(self):
        with self.assertRaises(ValueError):
            d._request(PUBLIC + "/health", public=True, token=SECRET)

    def test_healthy_services_and_local_mcp_initialize(self):
        requests = []
        def fake_request(url, *, public, method="GET", token="", payload=None):
            requests.append((url, public, method, token, payload))
            if url.endswith("/health"):
                return 200, "application/json", b'{"status":"ok"}'
            if url.endswith("/.well-known/oauth-authorization-server"):
                metadata = {
                    "issuer": PUBLIC,
                    "authorization_endpoint": PUBLIC + "/authorize",
                    "token_endpoint": PUBLIC + "/token",
                    "registration_endpoint": PUBLIC + "/register",
                }
                return 200, "application/json", json.dumps(metadata).encode()
            if method == "POST":
                return 200, "application/json", b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'
            raise AssertionError(url)

        with patch("app.core.diagnostics._request", side_effect=fake_request):
            results = d.probe_connection(RESOURCE, 8000, "/health", SECRET)
        self.assertEqual(len(results), 4)
        self.assertTrue(all(x.passed for x in results), results)
        self.assertEqual([x.label for x in results], [
            "Локальный сервер", "Публичный HTTPS",
            "OAuth discovery", "MCP initialize (локально)",
        ])
        public = [row for row in requests if row[1]]
        self.assertTrue(public)
        self.assertTrue(all(row[3] == "" for row in public))
        authenticated = [row for row in requests if row[3]]
        self.assertEqual(len(authenticated), 1)
        self.assertEqual(authenticated[0][0], "http://127.0.0.1:8000/mcp")
        self.assertEqual(authenticated[0][3], SECRET)
        self.assertTrue(all(SECRET not in r.message for r in results))

    def test_rejects_bad_oauth_issuer_even_when_health_passes(self):
        def fake_request(url, *, public, method="GET", token="", payload=None):
            if url.endswith("/health"):
                return 200, "application/json", b'{"status":"ok"}'
            if url.endswith("oauth-authorization-server"):
                return 200, "application/json", json.dumps({
                    "issuer": "https://evil.example",
                    "authorization_endpoint": PUBLIC + "/authorize",
                    "registration_endpoint": PUBLIC + "/register",
                    "token_endpoint": PUBLIC + "/token",
                }).encode()
            return 200, "application/json", b'{"result":{}}'

        with patch("app.core.diagnostics._request", side_effect=fake_request):
            results = d.probe_connection(RESOURCE, 8000, "/health", SECRET)
        self.assertTrue(results[0].passed)
        self.assertTrue(results[1].passed)
        self.assertFalse(results[2].passed)
        self.assertTrue(results[3].passed)

    def test_rejects_missing_local_token(self):
        with patch("app.core.diagnostics._request", return_value=(
            200, "application/json", b'{"status":"ok"}'
        )):
            result = d.probe_connection(RESOURCE, 8000, "/health", "")
        self.assertFalse(result[-1].passed)
        self.assertIn("Токен", result[-1].message)

    def test_http_error_does_not_include_token(self):
        error = d.HTTPError(
            "http://127.0.0.1:8000/mcp?token=" + SECRET,
            401, "Authentication failed " + SECRET, {}, None,
        )
        self.assertEqual(d._short_error(error), "HTTP 401")

    def test_health_200_without_ok_is_error(self):
        with patch("app.core.diagnostics._request", return_value=(
            200, "application/json", b'{"status":"error"}'
        )):
            with self.assertRaises(ValueError):
                d._health(PUBLIC + "/health", public=True)


if __name__ == "__main__":
    unittest.main()
