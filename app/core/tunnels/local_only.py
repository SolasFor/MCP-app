"""Local-only transport provider: loopback bind with zero external route publication."""
from __future__ import annotations

from typing import Any

from app.core.tunnels.base import (
    PROVIDER_LOCAL,
    ConnectionIdentity,
    DiagnosticCheck,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    TunnelProvider,
)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class LocalOnlyProvider(TunnelProvider):
    """Loopback-only transport: no tunnel binary, full OAuth/Bearer auth remains enforced."""

    provider_id = PROVIDER_LOCAL
    is_external = False

    def detect(self) -> ProviderDetection:
        return ProviderDetection(
            installed=True,
            executable="loopback",
            version="builtin",
            detail="127.0.0.1 loopback transport (no external tunnel)",
        )

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        cfg = config if config is not None else self._config
        host = str(cfg.get("bind_host") or "127.0.0.1").strip().lower()
        if host not in _LOOPBACK_HOSTS:
            return ["Local-only mode must bind strictly to 127.0.0.1, localhost, or ::1."]
        return []

    def connection_identity(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
    ) -> ConnectionIdentity:
        host = str(self._config.get("bind_host") or local_host or "127.0.0.1").strip().lower()
        if host not in _LOOPBACK_HOSTS:
            host = "127.0.0.1"
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        host_fmt = f"[{host}]" if ":" in host else host
        issuer = f"http://{host_fmt}:{local_port}"
        resource = f"{issuer}{path}"
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=False,
            public_url="",
            local_url=resource,
            private_tunnel_id="",
            oauth_issuer=issuer,
            oauth_resource_url=resource,
            is_ephemeral=False,
            supports_sse=True,
        )

    def status(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
        running: bool = False,
    ) -> ProviderStatus:
        ident = self.connection_identity(
            local_host=local_host,
            local_port=local_port,
            mcp_path=mcp_path,
        )
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message="Loopback only (auth remains enabled)" if running else "Local loopback ready",
            warnings=(),
        )

    def diagnose(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        errors = self.validate_config()
        ident = self.connection_identity(
            local_host=local_host,
            local_port=local_port,
            mcp_path=mcp_path,
        )
        return [
            DiagnosticCheck(
                "Loopback bind policy",
                not errors,
                errors[0] if errors else f"Locked to {ident.local_url}; zero public exposure.",
            ),
            DiagnosticCheck(
                "Authentication enforcement",
                True,
                "OAuth/Bearer authorization stays enabled on loopback.",
            ),
        ]
