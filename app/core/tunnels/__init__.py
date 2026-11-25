"""Unified TunnelProvider registry and all 6 supported connection transports."""
from __future__ import annotations

__all__ = [
    "ALL_PROVIDERS",
    "CloudflareNamedProvider",
    "CloudflareQuickProvider",
    "ConnectionIdentity",
    "ConnectionManager",
    "DiagnosticCheck",
    "EXTERNAL_PROVIDERS",
    "IssuerTransitionWarning",
    "LaunchSpec",
    "LocalOnlyProvider",
    "NgrokProvider",
    "OpenAISecureTunnelProvider",
    "PROVIDER_CF_LOCAL",
    "PROVIDER_CF_NAMED",
    "PROVIDER_CF_QUICK",
    "PROVIDER_LOCAL",
    "PROVIDER_NGROK",
    "PROVIDER_OPENAI",
    "PROVIDER_TAILSCALE",
    "ProviderDetection",
    "ProviderState",
    "ProviderStatus",
    "RouteOwnershipStore",
    "TailscaleFunnelProvider",
    "TunnelProvider",
]

from app.core.tunnels.base import (
    ALL_PROVIDERS,
    EXTERNAL_PROVIDERS,
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_OPENAI,
    PROVIDER_TAILSCALE,
    ConnectionIdentity,
    DiagnosticCheck,
    IssuerTransitionWarning,
    LaunchSpec,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    RouteOwnershipStore,
    TunnelProvider,
)
from app.core.tunnels.cloudflare import CloudflareNamedProvider, CloudflareQuickProvider
from app.core.tunnels.local_only import LocalOnlyProvider
from app.core.tunnels.manager import ConnectionManager
from app.core.tunnels.ngrok import NgrokProvider
from app.core.tunnels.openai_tunnel import OpenAISecureTunnelProvider
from app.core.tunnels.tailscale import TailscaleFunnelProvider

PROVIDER_CF_LOCAL = PROVIDER_LOCAL
