"""Tailscale Funnel TunnelProvider: tailnet status, Funnel grants, route ownership, non-destructive stop."""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from app.core.tunnels.base import (
    PROVIDER_TAILSCALE,
    ConnectionIdentity,
    DiagnosticCheck,
    ProviderDetection,
    ProviderState,
    ProviderStatus,
    TunnelProvider,
    run_cli_capture,
)

ALLOWED_FUNNEL_PORTS = (443, 8443, 10000)
_IDENTITY_DNS_CACHE_TTL_S = 30.0


def _find_tailscale(configured: str = "") -> str:
    if configured and Path(configured).is_file():
        return configured
    found = shutil.which("tailscale")
    if found:
        return found
    for prefix in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")):
        if prefix:
            candidate = Path(prefix) / "Tailscale" / "tailscale.exe"
            if candidate.is_file():
                return str(candidate)
    return ""


class TailscaleFunnelProvider(TunnelProvider):
    provider_id = PROVIDER_TAILSCALE
    is_external = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._dns_cache: tuple[float, str] | None = None

    def detect(self) -> ProviderDetection:
        exe = _find_tailscale(str(self._config.get("binary_path") or "").strip())
        if not exe:
            return ProviderDetection(
                installed=False,
                detail="tailscale CLI не найден. Установите: winget install --id Tailscale.Tailscale (https://tailscale.com/download).",
            )
        version = ""
        try:
            rc, out, err = run_cli_capture([exe, "version"], timeout=4.0)
            if rc == 0:
                version = (out or err).strip().splitlines()[0]
        except OSError:
            version = ""
        return ProviderDetection(installed=True, executable=exe, version=version)

    def _query_status_json(self, exe: str) -> tuple[dict[str, Any], str]:
        try:
            rc, out, err = run_cli_capture([exe, "status", "--json"], timeout=6.0)
        except (OSError, Exception) as exc:
            return {}, str(exc)
        if rc != 0:
            return {}, (err or out or "tailscale status failed").strip()
        try:
            data = json.loads(out)
        except ValueError:
            return {}, "Invalid JSON from tailscale status --json"
        return (data if isinstance(data, dict) else {}), ""

    def _query_funnel_json(self, exe: str) -> tuple[dict[str, Any], str]:
        try:
            rc, out, err = run_cli_capture([exe, "funnel", "status", "--json"], timeout=6.0)
        except (OSError, Exception) as exc:
            return {}, str(exc)
        if rc != 0:
            return {}, (err or out or "tailscale funnel status failed").strip()
        if not out.strip():
            return {}, ""
        try:
            data = json.loads(out)
        except ValueError:
            return {}, "Invalid JSON from tailscale funnel status --json"
        return (data if isinstance(data, dict) else {}), ""

    def validate_config(self, config: dict[str, Any] | None = None) -> list[str]:
        cfg = config if config is not None else self._config
        errors: list[str] = []
        raw_port = cfg.get("https_port", 443)
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return ["Tailscale Funnel HTTPS port must be an integer (443, 8443, or 10000)."]
        if port not in ALLOWED_FUNNEL_PORTS:
            errors.append(
                f"Tailscale Funnel only allows HTTPS ports {', '.join(map(str, ALLOWED_FUNNEL_PORTS))} (got {port})."
            )
        return errors

    def _selected_https_port(self) -> int:
        raw = self._config.get("https_port", 443)
        try:
            port = int(raw)
        except (TypeError, ValueError):
            return 443
        return port if port in ALLOWED_FUNNEL_PORTS else 443

    def _resolve_dns_name(self, status_data: dict[str, Any]) -> str:
        override = str(self._config.get("hostname_override") or "").strip().rstrip(".")
        if override:
            return override
        self_node = status_data.get("Self")
        if isinstance(self_node, dict):
            dns = str(self_node.get("DNSName") or "").strip().rstrip(".")
            if dns:
                return dns
        certs = status_data.get("CertDomains")
        if isinstance(certs, list) and certs:
            return str(certs[0]).strip().rstrip(".")
        return ""

    @staticmethod
    def _has_funnel_capability(status_data: dict[str, Any]) -> bool:
        self_node = status_data.get("Self")
        if not isinstance(self_node, dict):
            return False
        caps = self_node.get("Capabilities")
        if isinstance(caps, list):
            for cap in caps:
                if "funnel" in str(cap).lower():
                    return True
        cap_map = self_node.get("CapMap")
        if isinstance(cap_map, dict):
            for key in cap_map:
                if "funnel" in str(key).lower():
                    return True
        return False

    def _foreign_conflict(
        self,
        funnel_cfg: dict[str, Any],
        *,
        dns_name: str,
        https_port: int,
        mcp_path: str,
        local_port: int,
    ) -> str | None:
        web = funnel_cfg.get("Web")
        if not isinstance(web, dict) or not dns_name:
            return None
        host_key = f"{dns_name}:{https_port}"
        entry = web.get(host_key)
        if not isinstance(entry, dict):
            return None
        handlers = entry.get("Handlers")
        if not isinstance(handlers, dict):
            return None
        existing = handlers.get(mcp_path)
        if not isinstance(existing, dict):
            return None
        owned = self._ownership.get_route(self.provider_id)
        if owned and owned.get("host_key") == host_key and owned.get("mcp_path") == mcp_path:
            return None
        proxy_target = str(existing.get("Proxy") or "")
        if f":{local_port}" in proxy_target:
            return None
        return f"Foreign Tailscale Funnel route already registered at {host_key}{mcp_path} -> {proxy_target}."

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
        clean_runtime = runtime_url.strip().rstrip("/")
        if clean_runtime:
            host_base = f"{urlsplit_scheme_netloc(clean_runtime)}"
            full = clean_runtime
        else:
            dns = str(self._config.get("hostname_override") or "").strip().rstrip(".")
            if not dns:
                owned_route = self._ownership.get_route(self.provider_id)
                if owned_route and owned_route.get("host_key"):
                    dns = str(owned_route["host_key"]).split(":", 1)[0].strip().rstrip(".")
            if not dns:
                now = time.monotonic()
                if self._dns_cache is not None and (now - self._dns_cache[0]) < _IDENTITY_DNS_CACHE_TTL_S:
                    dns = self._dns_cache[1]
                else:
                    exe = _find_tailscale(str(self._config.get("binary_path") or "").strip())
                    if exe:
                        st_json, _ = self._query_status_json(exe)
                        dns = self._resolve_dns_name(st_json)
                    self._dns_cache = (now, dns)
            port = self._selected_https_port()
            if dns:
                netloc = dns if port == 443 else f"{dns}:{port}"
                host_base = f"https://{netloc}"
                full = f"{host_base}{path}"
            else:
                host_base = ""
                full = ""
        return ConnectionIdentity(
            provider_id=self.provider_id,
            is_public_url=bool(full),
            public_url=full,
            local_url=local_url,
            private_tunnel_id="",
            oauth_issuer=host_base,
            oauth_resource_url=full,
            is_ephemeral=False,
            supports_sse=True,
        )

    def start(
        self,
        *,
        local_host: str,
        local_port: int,
        mcp_path: str,
    ) -> tuple[bool, str]:
        det = self.detect()
        if not det.installed:
            return False, det.detail
        errors = self.validate_config()
        if errors:
            return False, errors[0]

        st_json, st_err = self._query_status_json(det.executable)
        if st_err:
            return False, st_err
        if str(st_json.get("BackendState") or "") != "Running":
            return False, f"Tailscale client state is {st_json.get('BackendState') or 'Stopped'} (sign in via Tailscale app)."
        dns = self._resolve_dns_name(st_json)
        if not dns:
            return False, "Tailscale MagicDNS / HTTPS hostname not available."

        https_port = self._selected_https_port()
        path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        funnel_json, _ = self._query_funnel_json(det.executable)
        conflict = self._foreign_conflict(
            funnel_json,
            dns_name=dns,
            https_port=https_port,
            mcp_path=path,
            local_port=local_port,
        )
        if conflict:
            return False, conflict

        cmd = [
            det.executable,
            "funnel",
            "--bg",
            f"--https={https_port}",
            f"--set-path={path}",
            f"http://{local_host}:{local_port}{path}",
        ]
        rc, out, err = run_cli_capture(cmd, timeout=10.0)
        if rc != 0:
            return False, (err or out or "tailscale funnel activation failed").strip()

        netloc = dns if https_port == 443 else f"{dns}:{https_port}"
        public_url = f"https://{netloc}{path}"
        self._ownership.record_route(
            self.provider_id,
            {
                "https_port": https_port,
                "mcp_path": path,
                "host_key": f"{dns}:{https_port}",
                "public_url": public_url,
            },
        )
        return True, public_url

    def stop(self) -> tuple[bool, str]:
        route = self._ownership.get_route(self.provider_id)
        if route is None:
            return True, "No MCP-app-owned Tailscale Funnel route recorded."
        det = self.detect()
        if not det.installed:
            return False, "tailscale CLI missing while cleaning up owned route."
        port = int(route.get("https_port") or 443)
        path = str(route.get("mcp_path") or "/mcp")
        # Tear down ONLY the route registered by MCP-app; never call `tailscale funnel reset`.
        cmd = [det.executable, "funnel", f"--https={port}", f"--set-path={path}", "off"]
        rc, out, err = run_cli_capture(cmd, timeout=8.0)
        if rc == 0:
            self._ownership.clear_route(self.provider_id)
            return True, ""
        return False, (err or out or "Failed to stop owned Tailscale Funnel route").strip()

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
            "Funnel exposes the endpoint publicly on HTTPS (unlike Serve which stays tailnet-private). URL follows device MagicDNS hostname.",
        )
        return ProviderStatus(
            provider_id=self.provider_id,
            state=ProviderState.RUNNING if running else ProviderState.STOPPED,
            identity=ident,
            message=ident.public_url or "Tailscale Funnel ready",
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
        if not det.installed:
            return [DiagnosticCheck("tailscale CLI", False, det.detail)]
        checks: list[DiagnosticCheck] = [
            DiagnosticCheck("tailscale CLI", True, det.version or det.executable)
        ]
        st_json, st_err = self._query_status_json(det.executable)
        if st_err:
            checks.append(DiagnosticCheck("Tailscale client state", False, st_err))
            return checks
        state = str(st_json.get("BackendState") or "Unknown")
        checks.append(DiagnosticCheck("Tailscale BackendState", state == "Running", state))
        dns = self._resolve_dns_name(st_json)
        checks.append(
            DiagnosticCheck("MagicDNS HTTPS hostname", bool(dns), dns or "Enable MagicDNS and HTTPS certificates in tailnet")
        )
        funnel_cap = self._has_funnel_capability(st_json)
        checks.append(
            DiagnosticCheck(
                "Funnel ACL grant vs private Serve",
                funnel_cap,
                "Public Funnel capability present on node"
                if funnel_cap
                else "Funnel nodeAttr/grant not detected (only private Serve may work until Funnel is enabled in tailnet ACL).",
            )
        )
        port = self._selected_https_port()
        checks.append(
            DiagnosticCheck("Configured HTTPS port", port in ALLOWED_FUNNEL_PORTS, f"Port {port} (allowed: 443, 8443, 10000)")
        )
        return checks


def urlsplit_scheme_netloc(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""
