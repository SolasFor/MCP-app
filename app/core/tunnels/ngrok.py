"""ngrok Agent v3 TunnelProvider: SecretStore authtoken, --url reuse, local 4040 JSON API."""
from __future__ import annotations

import json
import os
import shutil
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core.tunnels.base import (
    PROVIDER_NGROK,
    ConnectionIdentity,
    DiagnosticCheck,
    LaunchSpec,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    TunnelProvider,
    run_cli_capture,
)

NGROK_SECRET_NS = "tunnel"
NGROK_SECRET_KEY = "ngrok_authtoken"
DEFAULT_NGROK_API_URL = "http://127.0.0.1:4040"


def _candidate_ngrok_paths(configured: str = "") -> list[Path]:
    out: list[Path] = []
    if configured:
        out.append(Path(configured))
    found = shutil.which("ngrok")
    if found:
        out.append(Path(found))
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        out.append(Path(local_app) / "ngrok" / "ngrok.exe")
        out.append(Path(local_app) / "Microsoft" / "WindowsApps" / "ngrok.exe")
    return out


def fetch_ngrok_public_url(api_base: str = DEFAULT_NGROK_API_URL, timeout: float = 2.0) -> tuple[str, list[str]]:
    """Query ngrok local JSON API (`/api/endpoints` v3, fallback `/api/tunnels`)."""
    base = api_base.rstrip("/")
    warnings: list[str] = []
    for path, key in (("/api/endpoints", "endpoints"), ("/api/tunnels", "tunnels")):
        req = urllib.request.Request(f"{base}{path}", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        entries = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            continue
        https_url = ""
        for item in entries:
            if not isinstance(item, dict):
                continue
            url = str(item.get("public_url") or item.get("url") or "").strip()
            if url.startswith("https://"):
                https_url = url.rstrip("/")
                break
        if https_url:
            if ".ngrok-free." in https_url:
                warnings.append(
                    "ngrok free domains may return an HTTP browser warning interstitial on first request unless bypassed or using a paid/reserved domain."
                )
            return https_url, warnings
    return "", warnings


def parse_ngrok_log_line(line: str) -> str | None:
    """Extract ERR_NGROK_* diagnostics or quota/auth messages without exposing secrets."""
    raw = line.strip()
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if isinstance(data, dict):
            err = str(data.get("err") or data.get("msg") or "")
            if "ERR_NGROK" in err or data.get("lvl") == "eror":
                return err[:240]
    if "ERR_NGROK_" in raw:
        return raw[:240]
    return None


class NgrokProvider(TunnelProvider):
    provider_id = PROVIDER_NGROK
    is_external = True

    def detect(self) -> ProviderDetection:
        configured = str(self._config.get("binary_path") or "").strip()
        for candidate in _candidate_ngrok_paths(configured):
            if candidate.is_file():
                exe = str(candidate)
                version = ""
                try:
                    rc, out, err = run_cli_capture([exe, "--version"], timeout=4.0)
                    if rc == 0:
                        version = (out or err).strip().splitlines()[0]
                except OSError:
                    version = ""
                return ProviderDetection(installed=True, executable=exe, version=version)
        return ProviderDetection(installed=False, detail="ngrok CLI not found in PATH or LOCALAPPDATA")

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        cfg = config if config is not None else self._config
        errors: list[str] = []
        reserved = str(cfg.get("reserved_domain") or "").strip()
        if reserved:
            cleaned = reserved if "://" in reserved else f"https://{reserved}"
            parts = urlsplit(cleaned)
            if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
                errors.append("ngrok reserved domain must be a valid HTTPS hostname (e.g. mcp.ngrok.app).")
        api_url = str(cfg.get("local_api_url") or DEFAULT_NGROK_API_URL).strip()
        api_parts = urlsplit(api_url)
        if api_parts.scheme != "http" or (api_parts.hostname or "") not in ("127.0.0.1", "localhost"):
            errors.append("ngrok local API URL must point to loopback 127.0.0.1 or localhost.")
        return errors

    def configure(self, config: dict[str, Any], *, secrets: dict[str, str] | None = None) -> list[str]:
        errors = super().configure(config, secrets=secrets)
        if errors:
            return errors
        if secrets is not None and "authtoken" in secrets:
            token = secrets["authtoken"].strip()
            if token:
                self._secrets.set_secret(NGROK_SECRET_NS, NGROK_SECRET_KEY, token)
            else:
                self._secrets.delete_secret(NGROK_SECRET_NS, NGROK_SECRET_KEY)
        return []

    def has_authtoken(self) -> bool:
        try:
            return bool(self._secrets.get_secret(NGROK_SECRET_NS, NGROK_SECRET_KEY))
        except (OSError, ValueError, RuntimeError):
            return False

    def secret_refs(self) -> list[str]:
        return [self._secrets.secret_ref(NGROK_SECRET_NS, NGROK_SECRET_KEY)]

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
        reserved = str(self._config.get("reserved_domain") or "").strip()
        base = runtime_url.strip().rstrip("/")
        if not base and reserved:
            host_url = reserved if "://" in reserved else f"https://{reserved}"
            parts = urlsplit(host_url)
            base = f"https://{parts.netloc}" if parts.netloc else ""
        full_url = ""
        issuer = ""
        if base:
            parts = urlsplit(base)
            issuer = f"{parts.scheme}://{parts.netloc}"
            full_url = f"{issuer}{path}"
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=bool(full_url),
            public_url=full_url,
            local_url=local_url,
            private_tunnel_id="",
            oauth_issuer=issuer,
            oauth_resource_url=full_url,
            is_ephemeral=not bool(reserved),
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
        args: list[str] = ["http"]
        reserved = str(self._config.get("reserved_domain") or "").strip()
        if reserved:
            host_url = reserved if "://" in reserved else f"https://{reserved}"
            parts = urlsplit(host_url)
            args.append(f"--url=https://{parts.netloc}")
        args.extend(["--log=stdout", "--log-format=json", f"http://{local_host}:{local_port}"])

        env: dict[str, str] = {}
        token = self._secrets.get_secret(NGROK_SECRET_NS, NGROK_SECRET_KEY)
        if token:
            # Passed strictly via process environment so authtoken never leaks in CLI/Task Manager/logs.
            env["NGROK_AUTHTOKEN"] = token
        return LaunchSpec(
            program=det.executable,
            args=tuple(args),
            env=env,
            uses_managed_process=True,
            ready_hint=str(self._config.get("local_api_url") or DEFAULT_NGROK_API_URL),
        )

    def poll_active_endpoint(self) -> tuple[str, list[str]]:
        api_url = str(self._config.get("local_api_url") or DEFAULT_NGROK_API_URL).strip()
        return fetch_ngrok_public_url(api_url)

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
        warnings: list[str] = []
        if not self.has_authtoken():
            warnings.append("ngrok authtoken is not stored in SecretStore yet.")
        if ident.public_url and ".ngrok-free." in ident.public_url:
            warnings.append(
                "Free-tier ngrok domains may show a browser warning interstitial; OAuth works best with a reserved domain."
            )
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message=ident.public_url or "Ready to launch ngrok agent v3",
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
        checks = [
            DiagnosticCheck(
                "ngrok CLI",
                det.installed,
                det.version or det.executable or det.detail,
            ),
            DiagnosticCheck(
                "Authtoken in SecretStore",
                self.has_authtoken(),
                "Stored encrypted (DPAPI/SecretStore)" if self.has_authtoken() else "Authtoken missing",
            ),
        ]
        reserved = str(self._config.get("reserved_domain") or "").strip()
        checks.append(
            DiagnosticCheck(
                "Domain mode",
                True,
                f"Reserved domain configured: {reserved}"
                if reserved
                else "Ephemeral URL mode (changes per session; reserved domain recommended for persistent OAuth)",
            )
        )
        return checks
