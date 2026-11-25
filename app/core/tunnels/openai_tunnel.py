"""OpenAI Secure MCP Tunnel provider (`openai/tunnel-client`), private outbound tunnel."""
from __future__ import annotations

import os
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core.tunnels.base import (
    PROVIDER_OPENAI,
    ConnectionIdentity,
    DiagnosticCheck,
    LaunchSpec,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    TunnelProvider,
    run_cli_capture,
)

OPENAI_SECRET_NS = "tunnel"
OPENAI_SECRET_KEY = "openai_tunnel_api_key"
DEFAULT_PROFILE_NAME = "mcp-app"
DEFAULT_OBSERVABILITY_URL = "http://127.0.0.1:8080"
_TUNNEL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _find_tunnel_client(configured: str = "") -> str:
    if configured and Path(configured).is_file():
        return configured
    for exe_name in ("tunnel-client", "tunnel-client.exe"):
        found = shutil.which(exe_name)
        if found:
            return found
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidate = Path(local_app) / "openai" / "tunnel-client.exe"
        if candidate.is_file():
            return str(candidate)
    return ""


class OpenAISecureTunnelProvider(TunnelProvider):
    """Outbound-only OpenAI Secure MCP Tunnel: NEVER exposes a public URL and enforces local auth."""

    provider_id = PROVIDER_OPENAI
    is_external = True

    def detect(self) -> ProviderDetection:
        exe = _find_tunnel_client(str(self._config.get("binary_path") or "").strip())
        if not exe:
            return ProviderDetection(
                installed=False,
                detail="Official openai/tunnel-client binary not found in PATH or configured binary_path",
            )
        version = ""
        for flag in ("version", "--version"):
            try:
                rc, out, err = run_cli_capture([exe, flag], timeout=4.0)
                if rc == 0 and (out or err).strip():
                    version = (out or err).strip().splitlines()[0]
                    break
            except OSError:
                break
        return ProviderDetection(installed=True, executable=exe, version=version)

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        cfg = config if config is not None else self._config
        errors: list[str] = []
        tunnel_id = str(cfg.get("tunnel_id") or "").strip()
        if tunnel_id and not _TUNNEL_ID_RE.fullmatch(tunnel_id):
            errors.append("OpenAI Tunnel ID must contain 8–128 alphanumeric, '_' or '-' characters.")
        profile = str(cfg.get("profile_name") or DEFAULT_PROFILE_NAME).strip()
        if not _PROFILE_RE.fullmatch(profile):
            errors.append("OpenAI tunnel-client profile name must match [A-Za-z0-9_.-]{1,64}.")
        obs_url = str(cfg.get("observability_url") or DEFAULT_OBSERVABILITY_URL).strip()
        parts = urlsplit(obs_url)
        if parts.scheme != "http" or (parts.hostname or "") not in ("127.0.0.1", "localhost"):
            errors.append("Observability URL (/readyz) must point to loopback 127.0.0.1 or localhost.")
        return errors

    def configure(self, config: dict[str, Any], *, secrets: dict[str, str] | None = None) -> list[str]:
        errors = super().configure(config, secrets=secrets)
        if errors:
            return errors
        if secrets is not None and "api_key" in secrets:
            key = secrets["api_key"].strip()
            if key:
                self._secrets.set_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY, key)
            else:
                self._secrets.delete_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY)
        return []

    def has_api_key(self) -> bool:
        try:
            return bool(self._secrets.get_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY))
        except (OSError, ValueError, RuntimeError):
            return False

    def secret_refs(self) -> list[str]:
        return [self._secrets.secret_ref(OPENAI_SECRET_NS, OPENAI_SECRET_KEY)]

    def connection_identity(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
        runtime_url: str = "",
    ) -> ConnectionIdentity:
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        local_target = f"http://{local_host}:{local_port}{path}"
        tunnel_id = str(self._config.get("tunnel_id") or "").strip()
        # CRITICAL: OpenAI Secure MCP Tunnel has NO public HTTPS URL.
        # Keep public_url empty (`is_public_url=False`) and expose private_tunnel_id separately.
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=False,
            public_url="",
            local_url=local_target,
            private_tunnel_id=tunnel_id,
            oauth_issuer=f"http://{local_host}:{local_port}",
            oauth_resource_url=local_target,
            is_ephemeral=False,
            supports_sse=True,
        )

    def build_launch_spec(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> LaunchSpec | None:
        det = self.detect()
        if not det.installed:
            return None
        tunnel_id = str(self._config.get("tunnel_id") or "").strip()
        if not tunnel_id:
            return None
        profile = str(self._config.get("profile_name") or DEFAULT_PROFILE_NAME).strip() or DEFAULT_PROFILE_NAME
        env: dict[str, str] = {}
        api_key = self._secrets.get_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY)
        if api_key:
            env["CONTROL_PLANE_API_KEY"] = api_key
        return LaunchSpec(
            program=det.executable,
            args=("run", "--profile", profile),
            env=env,
            uses_managed_process=True,
            ready_hint=str(self._config.get("observability_url") or DEFAULT_OBSERVABILITY_URL),
        )

    def initialize_profile(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> tuple[bool, str]:
        """Run `tunnel-client init` for an existing local HTTP MCP server target."""
        det = self.detect()
        if not det.installed:
            return False, det.detail
        tunnel_id = str(self._config.get("tunnel_id") or "").strip()
        if not tunnel_id:
            return False, "Tunnel ID is required."
        profile = str(self._config.get("profile_name") or DEFAULT_PROFILE_NAME).strip() or DEFAULT_PROFILE_NAME
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        target = f"http://{local_host}:{local_port}{path}"
        cmd = [
            det.executable,
            "init",
            "--sample",
            "sample_mcp_remote_no_auth",
            "--profile",
            profile,
            "--tunnel-id",
            tunnel_id,
            "--mcp-server-url",
            target,
        ]
        env: dict[str, str] = {}
        api_key = self._secrets.get_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY)
        if api_key:
            env["CONTROL_PLANE_API_KEY"] = api_key
        rc, out, err = run_cli_capture(cmd, env=env, timeout=10.0)
        if rc == 0:
            return True, (out or f"Profile {profile} initialized for {target}").strip()
        return False, (err or out or "tunnel-client init failed").strip()

    def run_doctor(self) -> DiagnosticCheck:
        det = self.detect()
        if not det.installed:
            return DiagnosticCheck("tunnel-client doctor", False, det.detail)
        profile = str(self._config.get("profile_name") or DEFAULT_PROFILE_NAME).strip() or DEFAULT_PROFILE_NAME
        env: dict[str, str] = {}
        api_key = self._secrets.get_secret(OPENAI_SECRET_NS, OPENAI_SECRET_KEY)
        if api_key:
            env["CONTROL_PLANE_API_KEY"] = api_key
        rc, out, err = run_cli_capture([det.executable, "doctor", "--profile", profile, "--explain"], env=env, timeout=10.0)
        summary = (out or err or "").strip()[:320]
        return DiagnosticCheck("tunnel-client doctor", rc == 0, summary or ("OK" if rc == 0 else f"exit={rc}"))

    def check_observability_ready(self, timeout: float = 1.5) -> bool:
        obs_url = str(self._config.get("observability_url") or DEFAULT_OBSERVABILITY_URL).strip().rstrip("/")
        try:
            with urllib.request.urlopen(f"{obs_url}/readyz", timeout=timeout) as resp:  # noqa: S310
                return 200 <= int(resp.status) < 300
        except (OSError, ValueError):
            return False

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
        warnings = [
            "OpenAI Secure MCP Tunnel does not expose a public URL; only private Tunnel ID is used by entitled OpenAI workspaces.",
            "Do not assume every ChatGPT plan supports Secure MCP Tunnels; keep MCP authentication enforced even over the tunnel.",
        ]
        if not self.has_api_key():
            warnings.append("Runtime API key (CONTROL_PLANE_API_KEY) is not saved in SecretStore.")
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message=f"Tunnel ID: {ident.private_tunnel_id}" if ident.private_tunnel_id else "Tunnel ID not configured",
            warnings=tuple(warnings),
        )

    def diagnose(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> list[DiagnosticCheck]:
        det = self.detect()
        tunnel_id = str(self._config.get("tunnel_id") or "").strip()
        checks = [
            DiagnosticCheck("openai/tunnel-client CLI", det.installed, det.version or det.executable or det.detail),
            DiagnosticCheck(
                "Runtime API key (SecretStore)",
                self.has_api_key(),
                "CONTROL_PLANE_API_KEY stored encrypted" if self.has_api_key() else "Missing runtime API key (Tunnels Read+Use)",
            ),
            DiagnosticCheck(
                "Private Tunnel ID",
                bool(tunnel_id),
                tunnel_id or "Set tunnel_id from platform.openai.com",
            ),
            DiagnosticCheck(
                "Auth & entitlement guarantee",
                True,
                "Tunnel transport does not replace client identity/OAuth verification; fails closed on unverified auth.",
            ),
        ]
        if det.installed and tunnel_id:
            checks.append(self.run_doctor())
        return checks
