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
        return ProviderDetection(
            installed=False,
            detail="cloudflared.exe не найден. Установите: winget install --id Cloudflare.cloudflared (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).",
        )
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

    def secret_refs(self) -> list[str]:
        ref = str(self._config.get("tunnel_token_ref") or "").strip()
        if ref:
            return [ref]
        return [self._secrets.secret_ref("tunnel", "cloudflare_named_token")]

    def resolve_effective_state(
        self,
        mcp_path: str = "/mcp",
        config: dict[str, Any] | None = None,
    ) -> domain_state.DomainState:
        """Merge persisted domain.json, connections.json provider config, and SecretStore without clearing data."""
        cfg = config if config is not None else self._config
        wizard = domain_state.load()

        hostname = wizard.hostname.strip().lower()
        cfg_url = str(cfg.get("public_url") or wizard.public_url or "").strip()
        if not hostname:
            cfg_host = str(cfg.get("hostname") or "").strip().lower()
            if cfg_host:
                hostname = cfg_host
            elif cfg_url:
                hostname = (urlsplit(cfg_url).hostname or "").strip().lower()
        if hostname.endswith(".trycloudflare.com"):
            hostname = ""

        token = wizard.tunnel_token
        decrypt_error = wizard.decrypt_error
        ref = str(cfg.get("tunnel_token_ref") or "").strip()
        if not token and not decrypt_error and ref:
            try:
                token = self._secrets.resolve_ref(ref) or ""
            except (OSError, ValueError, RuntimeError) as exc:
                decrypt_error = f"{type(exc).__name__}: {exc}"
        if not token and not decrypt_error:
            try:
                token = self._secrets.get_secret("tunnel", "cloudflare_named_token") or ""
            except (OSError, ValueError, RuntimeError) as exc:
                decrypt_error = f"{type(exc).__name__}: {exc}"

        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        resolved_url = cfg_url
        if not resolved_url and hostname:
            resolved_url = f"https://{hostname}{path}"

        return domain_state.DomainState(
            hostname=hostname,
            tunnel_id=wizard.tunnel_id or str(cfg.get("tunnel_id") or "").strip(),
            tunnel_token=token,
            zone_name=wizard.zone_name or str(cfg.get("zone_name") or "").strip(),
            setup_mode=wizard.setup_mode or str(cfg.get("setup_mode") or "").strip(),
            public_url=resolved_url,
            decrypt_error=decrypt_error,
        )

    def diagnose_issue(
        self,
        *,
        mcp_path: str = "/mcp",
        config: dict[str, Any] | None = None,
        check_binary: bool = True,
    ) -> tuple[str, str]:
        """Classify Cloudflare Named Tunnel readiness into an explicit diagnostic code + message."""
        cfg = config if config is not None else self._config
        if check_binary:
            det = self.detect()
            if not det.installed:
                return (
                    "agent_missing",
                    "cloudflared.exe не найден. Установите: winget install --id Cloudflare.cloudflared "
                    "(https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).",
                )
        state = self.resolve_effective_state(mcp_path=mcp_path, config=cfg)
        if state.decrypt_error:
            return (
                "secret_decrypt_failed",
                f"Не удалось расшифровать сохранённый Cloudflare Tunnel Token в SecretStore ({state.decrypt_error}). "
                "Перейдите в «Настроить…» и введите токен туннеля заново.",
            )
        if state.hostname:
            if "." not in state.hostname or state.hostname.endswith(".trycloudflare.com"):
                return (
                    "domain_invalid",
                    f"Домен «{state.hostname}» указан неверно. Укажите постоянный домен вида mcp.example.com.",
                )
        cfg_file = self._effective_config_file(cfg)
        if state.is_configured:
            if any(ch.isspace() for ch in state.tunnel_token) or len(state.tunnel_token.strip()) < 16:
                return (
                    "token_invalid",
                    "Сохранённый Cloudflare Tunnel Token имеет некорректный формат.",
                )
            return ("", "")
        if state.hostname and not state.tunnel_token:
            if cfg_file.is_file() and state.public_url:
                return ("", "")
            return (
                "token_missing",
                f"Для домена {state.hostname} отсутствует Cloudflare Tunnel Token. "
                "Откройте «Настроить…» и укажите токен существующего туннеля или настройте через Cloudflare API.",
            )
        if cfg_file.is_file():
            if not state.public_url:
                return (
                    "domain_not_configured",
                    "Найден config.yml, но не указан публичный адрес своего домена.",
                )
            return ("", "")
        return (
            "domain_not_configured",
            "Свой домен ещё не настроен. Откройте «Подключения» → «Настроить…» для Cloudflare Named Tunnel.",
        )

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        code, msg = self.diagnose_issue(config=config, check_binary=True)
        return [msg] if code else []

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
        state = self.resolve_effective_state(mcp_path=path)
        configured_url = runtime_url.strip() or state.public_url or str(self._config.get("public_url") or "").strip()
        if not configured_url and state.hostname:
            configured_url = f"https://{state.hostname}{path}"
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
            private_tunnel_id=state.tunnel_id,
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
        state = self.resolve_effective_state(mcp_path=mcp_path)
        cfg_file = self._effective_config_file()
        code, msg = self.diagnose_issue(mcp_path=mcp_path, check_binary=False)
        return [
            DiagnosticCheck(
                "cloudflared binary",
                det.installed,
                det.version or det.executable or (
                    "cloudflared.exe не найден. Установите: winget install --id Cloudflare.cloudflared"
                ),
            ),
            DiagnosticCheck(
                "Named tunnel config & token",
                not code,
                f"Reusing saved domain {state.hostname} (mode={state.setup_mode or 'saved'})"
                if not code and state.is_configured
                else (f"Using config {cfg_file}" if not code and cfg_file.is_file() else msg),
            ),
        ]
