"""Interpret tunnel log lines, distinguishing canceled SSE/HTTP requests from outages.

The original cloudflared ERROR lines are always retained. `classify_tunnel_error`
is preserved for existing callers; `classify_tunnel_event` provides richer
classification (SSE cancel, origin unreachable, network error, rate limit).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TunnelLogEvent:
    """Structured classification of a tunnel log line."""

    category: str  # sse_canceled | origin_unreachable | network_error | rate_limited | provision_failed
    severity: str  # info | warning | error
    is_transient: bool
    detail: str


def classify_tunnel_error(line: str) -> str | None:
    text = line.lower()
    if "context canceled" in text and ("error=" in text or "failed to serve incoming request" in text):
        return "request_canceled"
    if any(
        fragment in text
        for fragment in (
            "unable to reach the origin service",
            "failed to connect to origin",
            "connection refused",
            "no route to host",
        )
    ) and any(
        origin in text
        for origin in (
            "originservice=",
            "127.0.0.1",
            "localhost",
            "origin service",
            "failed to proxy",
        )
    ):
        return "origin_unreachable"
    return None


def classify_tunnel_event(line: str) -> TunnelLogEvent | None:
    legacy = classify_tunnel_error(line)
    if legacy == "request_canceled":
        return TunnelLogEvent(
            category="sse_canceled",
            severity="info",
            is_transient=True,
            detail="Отменён отдельный HTTP/SSE-запрос клиента",
        )
    if legacy == "origin_unreachable":
        return TunnelLogEvent(
            category="origin_unreachable",
            severity="error",
            is_transient=False,
            detail="Локальный MCP-сервер недоступен для туннеля",
        )

    text = line.lower()
    if "429" in text and ("too many requests" in text or "rate limit" in text):
        return TunnelLogEvent(
            category="rate_limited",
            severity="warning",
            is_transient=True,
            detail="Ограничение частоты запросов провайдера туннеля",
        )
    if any(
        marker in text
        for marker in (
            "failed to request quick tunnel",
            "quick tunnel provisioning failed",
            "failed to unmarshal quick tunnel",
            "failed to read quick-tunnel response",
        )
    ):
        return TunnelLogEvent(
            category="provision_failed",
            severity="error",
            is_transient=False,
            detail="Не удалось получить временный адрес туннеля",
        )
    if any(
        marker in text
        for marker in (
            "failed to dial to edge",
            "connection with edge closed",
            "unregistering tunnel",
            "tls handshake timeout",
            "no such host",
            "network is unreachable",
            "connection reset by peer",
            "served tunnel error",
        )
    ):
        return TunnelLogEvent(
            category="network_error",
            severity="error",
            is_transient=True,
            detail="Сетевая ошибка связи туннеля с внешним edge",
        )
    return None
