"""Unit tests for BackoffPolicy, sleep/network resilience, SSE classification, and report redaction."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.core.diagnostics import ProbeResult, build_diagnostic_report, export_diagnostic_report
from app.core.network_watch import detect_sleep_gap, network_interface_fingerprint
from app.core.reconnect import BackoffPolicy
from app.core.tunnel_log import classify_tunnel_event


class ReconnectAndResilienceTests(unittest.TestCase):
    def test_backoff_exponential_jitter_and_reset(self) -> None:
        policy = BackoffPolicy(
            base_seconds=2.0, max_seconds=30.0, jitter_ratio=0.25, max_attempts=5, stable_uptime_seconds=60.0
        )
        # rng=0.0 -> -25%, rng=1.0 -> +25%, rng=0.5 -> exact
        self.assertAlmostEqual(policy.next_delay(1, rng=lambda: 0.5), 2.0)
        self.assertAlmostEqual(policy.next_delay(2, rng=lambda: 0.0), 3.0)
        self.assertAlmostEqual(policy.next_delay(2, rng=lambda: 1.0), 5.0)
        self.assertLessEqual(policy.next_delay(10, rng=lambda: 1.0), 30.0)
        self.assertTrue(policy.exhausted(6))
        self.assertFalse(policy.exhausted(5))
        self.assertTrue(policy.should_reset_attempts(10.0, now=75.0))
        self.assertFalse(policy.should_reset_attempts(10.0, now=30.0))

    def test_sleep_gap_and_network_fingerprint(self) -> None:
        # 120s wall clock jump vs 2s monotonic jump => ~118s sleep gap
        gap = detect_sleep_gap(10.0, 1000.0, 12.0, 1120.0, threshold_s=20.0)
        self.assertIsNotNone(gap)
        self.assertGreater(gap, 100.0)
        self.assertIsNone(detect_sleep_gap(10.0, 1000.0, 15.0, 1005.0, threshold_s=20.0))
        fp = network_interface_fingerprint()
        self.assertIsInstance(fp, tuple)

    def test_tunnel_event_distinguishes_sse_cancel_from_network_error(self) -> None:
        sse = classify_tunnel_event('ERR failed to serve incoming request error="failed to proxy HTTP: context canceled"')
        self.assertIsNotNone(sse)
        self.assertEqual(sse.category, "sse_canceled")
        self.assertTrue(sse.is_transient)

        net = classify_tunnel_event("ERR Failed to dial to edge error=tls handshake timeout")
        self.assertIsNotNone(net)
        self.assertEqual(net.category, "network_error")

        rate = classify_tunnel_event("ERR HTTP 429 too many requests")
        self.assertIsNotNone(rate)
        self.assertEqual(rate.category, "rate_limited")

    def test_diagnostic_report_export_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = build_diagnostic_report(
                app_version="0.8.6",
                public_url="https://demo.example.com/mcp",
                local_port=8000,
                health_path="/health",
                tunnel_mode="named",
                tunnel_protocol="http2",
                probe_results=[ProbeResult("Local", True, "OK Bearer top-secret-bearer-token")],
                recent_logs=[
                    "Authorization: Bearer owner-secret-99999",
                    "socks5://user:proxy-pass-888@127.0.0.1:1080",
                ],
                secrets_to_redact=["owner-secret-99999"],
            )
            out = Path(tmp) / "report.json"
            export_diagnostic_report(out, report)
            raw = out.read_text(encoding="utf-8")
            self.assertNotIn("owner-secret-99999", raw)
            self.assertNotIn("top-secret-bearer-token", raw)
            self.assertNotIn("proxy-pass-888", raw)
            parsed = json.loads(raw)
            self.assertEqual(parsed["app_version"], "0.8.6")


if __name__ == "__main__":
    unittest.main()
