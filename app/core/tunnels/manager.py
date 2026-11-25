"""ConnectionManager: unified provider registry, config store, single-active policy, issuer checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.secret_store import SecretStore
from app.core.tunnels.base import (
    ALL_PROVIDERS,
    PROVIDER_CF_NAMED,
    PROVIDER_CF_QUICK,
    PROVIDER_LOCAL,
    PROVIDER_NGROK,
    PROVIDER_OPENAI,
    PROVIDER_TAILSCALE,
    ConnectionIdentity,
    DiagnosticCheck,
    IssuerTransitionWarning,
    RouteOwnershipStore,
    TunnelProvider,
)
from app.core.tunnels.cloudflare import CloudflareNamedProvider, CloudflareQuickProvider
from app.core.tunnels.local_only import LocalOnlyProvider
from app.core.tunnels.ngrok import NgrokProvider
from app.core.tunnels.openai_tunnel import OpenAISecureTunnelProvider
from app.core.tunnels.tailscale import TailscaleFunnelProvider
from app.platform import get_platform

CONNECTIONS_FILE = "connections.json"
ROUTES_FILE = "routes.json"


class ConnectionManager:
    """Manages all 6 MCP-app transport providers and non-secret connection persistence."""

    def __init__(self, data_dir: Path, secret_store: SecretStore | None = None) -> None:
        self._data_dir = Path(data_dir)
        self._tunnels_dir = self._data_dir / "tunnels"
        self._tunnels_dir.mkdir(parents=True, exist_ok=True)
        self._platform = get_platform()
        self._platform.restrict_path_acl(self._tunnels_dir, is_dir=True)

        self._config_path = self._tunnels_dir / CONNECTIONS_FILE
        self.secrets = secret_store or SecretStore(self._data_dir / "secrets")
        self.ownership = RouteOwnershipStore(self._tunnels_dir / ROUTES_FILE)

        self.providers: dict[str, TunnelProvider] = {
            PROVIDER_CF_QUICK: CloudflareQuickProvider(self.secrets, self.ownership),
            PROVIDER_CF_NAMED: CloudflareNamedProvider(self.secrets, self.ownership),
            PROVIDER_NGROK: NgrokProvider(self.secrets, self.ownership),
            PROVIDER_TAILSCALE: TailscaleFunnelProvider(self.secrets, self.ownership),
            PROVIDER_OPENAI: OpenAISecureTunnelProvider(self.secrets, self.ownership),
            PROVIDER_LOCAL: LocalOnlyProvider(self.secrets, self.ownership),
        }
        self._active_provider_id = PROVIDER_CF_QUICK
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        active = str(raw.get("active_provider") or PROVIDER_CF_QUICK)
        if active in ALL_PROVIDERS:
            self._active_provider_id = active
        configs = raw.get("providers")
        if isinstance(configs, dict):
            for pid, cfg in configs.items():
                if pid in self.providers and isinstance(cfg, dict):
                    # Strip any accidentally injected raw secret fields from JSON on disk.
                    clean_cfg = {
                        k: v
                        for k, v in cfg.items()
                        if k not in ("authtoken", "api_key", "tunnel_token", "token")
                    }
                    self.providers[pid].load_config(clean_cfg)

    def save(self) -> None:
        payload = {
            "active_provider": self._active_provider_id,
            "providers": {
                pid: {
                    k: v
                    for k, v in prov.export_config().items()
                    if k not in ("authtoken", "api_key", "tunnel_token", "token")
                }
                for pid, prov in self.providers.items()
            },
        }
        tmp = self._config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._config_path)
        self._platform.restrict_path_acl(self._config_path, is_dir=False)

    @property
    def active_provider_id(self) -> str:
        return self._active_provider_id

    def get(self, provider_id: str) -> TunnelProvider:
        if provider_id not in self.providers:
            raise KeyError(f"Unknown transport provider: {provider_id!r}")
        return self.providers[provider_id]

    @property
    def active_provider(self) -> TunnelProvider:
        return self.providers[self._active_provider_id]

    def set_active_provider(self, provider_id: str) -> str:
        if provider_id not in self.providers:
            raise ValueError(f"Unsupported provider: {provider_id!r}")
        # Single external provider policy: selecting one replaces previous active provider.
        self._active_provider_id = provider_id
        self.save()
        return provider_id

    def configure_provider(
        self,
        provider_id: str,
        config: dict[str, Any],
        *,
        secrets: dict[str, str] | None = None,
    ) -> list[str]:
        provider = self.get(provider_id)
        errors = provider.configure(config, secrets=secrets)
        if not errors:
            self.save()
        return errors

    def check_issuer_transition(
        self,
        *,
        previous_identity: ConnectionIdentity | None,
        next_provider_id: str,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> IssuerTransitionWarning:
        next_ident = self.get(next_provider_id).connection_identity(
            local_host=local_host,
            local_port=local_port,
            mcp_path=mcp_path,
        )
        prev_issuer = previous_identity.oauth_issuer if previous_identity else ""
        next_issuer = next_ident.oauth_issuer
        changed = bool(prev_issuer and next_issuer and prev_issuer != next_issuer) or (
            previous_identity is not None and previous_identity.provider_id != next_provider_id
        )
        if changed:
            msg = (
                "Changing transport provider or OAuth issuer keeps tokens strictly scoped to their original issuer. "
                "Clients must re-authorize when connecting through a new address or provider."
            )
        else:
            msg = ""
        return IssuerTransitionWarning(
            issuer_changed=changed,
            previous_issuer=prev_issuer,
            next_issuer=next_issuer,
            message=msg,
        )

    def diagnose_provider(
        self,
        provider_id: str,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        return self.get(provider_id).diagnose(
            local_host=local_host,
            local_port=local_port,
            mcp_path=mcp_path,
        )

    def list_statuses(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
        running: bool = False,
    ) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for pid, provider in self.providers.items():
            is_this_active = pid == self._active_provider_id
            result[pid] = provider.summary_dict(
                local_host=local_host,
                local_port=local_port,
                mcp_path=mcp_path,
                runtime_url=runtime_url if is_this_active else "",
                running=running and is_this_active,
            )
        return result

    def collect_secret_values(self) -> list[str]:
        """Collect stored tunnel secrets for SecretRedactor without exposing them externally."""
        values: list[str] = []
        for ref in (
            ref
            for provider in self.providers.values()
            for ref in provider.secret_refs()
        ):
            try:
                val = self.secrets.resolve_ref(ref)
            except (OSError, ValueError, RuntimeError):
                val = None
            if val:
                values.append(val)
        return values
