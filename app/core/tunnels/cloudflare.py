"""Cloudflare Quick & Named Tunnel provider adapters preserving legacy workflows."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core import domain_state
from app.core.tunnels.base import (
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    ConnectionIdentity,
    DiagnosticCheck,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    TunnelProvider,
    run_cli_capture,
)
from app.paths import resolve_cloudflared


def _detect_cloudflared() -> ProviderDetection:
    exe = resolve_cloudflared()
    if not exe:
        return ProviderDetection(installed=False, detail="cloudflared.exe not found")
    version = ""
    try:
        rc, out, err = run_cli_capture([exe, "--version"], timeout=4.0)
        if rc == 0:
            version = (out or err).strip().splitlines()[0]
    except OSError:
        version = ""
    return ProviderDetection(installed=True, executable=exe, version=version)


class CloudflareQuickProvider(TunnelProvider):
    provider_id = PROVIDER_CF_QUICK
    is_external = True

    def detect(self) -> ProviderDetection:
        return _detect_cloudflared()

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        det = self.detect()
        if not det.installed:
            return ["cloudflared binary not found"]
        return []

    def connection_identity(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
    ) -> ConnectionIdentity:
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        local_url = f"http://{local_host}:{local_port}{path}"
        clean = runtime_url.strip().rstrip("/")
        issuer = ""
        if clean:
            parts = urlsplit(clean)
            if parts.scheme and parts.netloc:
                issuer = f"{parts.scheme}://{parts.netloc}"
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=bool(clean),
            public_url=clean,
            local_url=local_url,
            private_tunnel_id="",
            oauth_issuer=issuer,
            oauth_resource_url=clean,
            is_ephemeral=True,
            supports_sse=False,
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
            runtime_url=runtime_url,
        )
        warnings = (
            "Quick Tunnel URL (*.trycloudflare.com) rotates on restart; SSE is not guaranteed.",
        )
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message=ident.public_url or "Temporary *.trycloudflare.com mode",
            warnings=warnings,
        )

    def diagnose(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        det = self.detect()
        return [
            DiagnosticCheck(
                "cloudflared binary",
                det.installed,
                det.version or det.executable or det.detail,
            ),
            DiagnosticCheck(
                "Transport caveats",
                True,
                "Ephemeral URL changes per start; clients must re-authorize on new URL.",
            ),
        ]


class CloudflareNamedProvider(TunnelProvider):
    provider_id = PROVIDER_CF_NAMED
    is_external = True

    def detect(self) -> ProviderDetection:
        return _detect_cloudflared()

    def _effective_config_file(self, config: dict[str, Any] | None = None) -> Path:
        cfg = config if config is not None else self._config
        raw = str(cfg.get("cloudflared_config") or "~/.cloudflared/config.yml")
        return Path(raw).expanduser()

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        det = self.detect()
        if not det.installed:
            return ["cloudflared binary not found"]
        cfg = config if config is not None else self._config
        wizard = domain_state.load()
        configured_url = str(cfg.get("public_url") or "").strip()
        if wizard.is_configured:
            return []
        if self._effective_config_file(cfg).is_file() and configured_url:
            return []
        return ["Configure custom domain via Domain Wizard or ~/.cloudflared/config.yml"]

    def connection_identity(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
    ) -> ConnectionIdentity:
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        local_url = f"http://{local_host}:{local_port}{path}"
        wizard = domain_state.load()
        configured_url = runtime_url.strip() or str(self._config.get("public_url") or "").strip()
        if not configured_url and wizard.is_configured:
            configured_url = f"https://{wizard.hostname}{path}"
        issuer = ""
        if configured_url:
            parts = urlsplit(configured_url)
            if parts.scheme and parts.netloc:
                issuer = f"{parts.scheme}://{parts.netloc}"
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=bool(configured_url),
            public_url=configured_url,
            local_url=local_url,
            private_tunnel_id=wizard.tunnel_id,
            oauth_issuer=issuer,
            oauth_resource_url=configured_url,
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
            runtime_url=runtime_url,
        )
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message=ident.public_url or "Named Cloudflare Tunnel not configured yet",
        )

    def diagnose(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        det = self.detect()
        wizard = domain_state.load()
        cfg_file = self._effective_config_file()
        return [
            DiagnosticCheck(
                "cloudflared binary",
                det.installed,
                det.version or det.executable or det.detail,
            ),
            DiagnosticCheck(
                "Named tunnel reuse",
                wizard.is_configured or cfg_file.is_file(),
                f"Reusing wizard domain {wizard.hostname}"
                if wizard.is_configured
                else (f"Using config {cfg_file}" if cfg_file.is_file() else "No domain.json or config.yml configured"),
            ),
        ]
