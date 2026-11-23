"""Distinguish routine Cloudflare request cancellation from origin outages."""
from __future__ import annotations

import unittest

from app.core.tunnel_log import classify_tunnel_error


class TunnelLogTests(unittest.TestCase):
    def test_individual_cancellation_is_not_classified_as_outage(self):
        examples = [
            '2026-11-23Z ERR error="context canceled" connIndex=1 event=1 '
            'ingressRule=0 originService=http://127.0.0.1:8000',
            '2026-11-23Z ERR failed to serve incoming request '
            'error="failed to proxy HTTP: context canceled"',
        ]
        for line in examples:
            with self.subTest(line=line):
                self.assertEqual(classify_tunnel_error(line), "request_canceled")

    def test_actual_origin_failure_is_a_distinct_error(self):
        examples = [
            'ERR Unable to reach the origin service: dial tcp 127.0.0.1:8000: connect: connection refused',
            'ERR failed to proxy HTTP: dial tcp 127.0.0.1:8000: connect: connection refused',
            'ERR originService=http://127.0.0.1:8000 no route to host',
        ]
        for line in examples:
            with self.subTest(line=line):
                self.assertEqual(classify_tunnel_error(line), "origin_unreachable")

    def test_registered_tunnels_and_quic_checks_are_not_outages(self):
        for line in (
            "INF Registered tunnel connection connIndex=0 protocol=http2",
            "INF UDP Connectivity FAIL QUIC connection failed",
            "INF TCP Connectivity PASS HTTP/2 connection successful",
            "ERR Failed to initialize DNS local resolver error=i/o timeout",
            "INFO context canceled by a test caller",  # not a proxy failure
        ):
            with self.subTest(line=line):
                self.assertIsNone(classify_tunnel_error(line))


if __name__ == "__main__":
    unittest.main()
