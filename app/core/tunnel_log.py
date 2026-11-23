"""Interpret cloudflared log lines without confusing canceled requests with outages.

The original cloudflared ERROR lines are always retained. These categories
only drive one-time contextual hints in the Windows interface.
"""
from __future__ import annotations


def classify_tunnel_error(line: str) -> str | None:
    text = line.lower()
    if "context canceled" in text and ("error=" in text or "failed to serve incoming request" in text):
        return "request_canceled"
    if any(fragment in text for fragment in (
        "unable to reach the origin service",
        "failed to connect to origin",
        "connection refused",
        "no route to host",
    )) and any(origin in text for origin in (
        "originservice=", "127.0.0.1", "localhost", "origin service", "failed to proxy",
    )):
        return "origin_unreachable"
    return None
