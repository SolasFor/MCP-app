"""Security guards for MCP Gateway: namespaces, SSRF, loop prevention, header isolation."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Iterable, Mapping
from urllib.parse import urlsplit

GATEWAY_HOP_HEADER = "X-MCP-Gateway-Hop"
GATEWAY_ID_HEADER = "X-MCP-Gateway-Id"
MAX_GATEWAY_HOPS = 2

_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
})
_UNTRUSTED_LAUNCHERS = frozenset({"npx", "npx.cmd", "uvx", "pipx", "dlx", "pnpx", "bunx"})
_SECRET_NAME_HINTS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH", "CREDENTIAL", "COOKIE")


def make_namespaced_tool(server_id: str, raw_name: str, taken: set[str] | Iterable[str] = ()) -> str:
    """Create a deterministic, <=64-char collision-free `<server_id>__<slug>` tool name."""
    sid = re.sub(r"[^a-z0-9_-]+", "_", (server_id or "srv").lower()).strip("_-") or "srv"
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", (raw_name or "tool").strip()).strip("_.") or "tool"
    candidate = f"{sid}__{slug}"
    used = set(taken)
    if len(candidate) <= 64 and candidate not in used:
        return candidate
    digest = hashlib.sha256(f"{server_id}:{raw_name}".encode("utf-8")).hexdigest()[:6]
    max_slug = max(4, 64 - len(sid) - 2 - 7)
    trimmed = f"{sid}__{slug[:max_slug]}_{digest}"
    if trimmed not in used:
        return trimmed
    for idx in range(2, 100):
        suffix = f"_{digest}{idx}"
        alt = f"{sid}__{slug[: max(4, 64 - len(sid) - 2 - len(suffix))]}{suffix}"
        if alt not in used:
            return alt
    raise ValueError("Unable to allocate unique namespaced tool name")


def validate_upstream_url(
    raw_url: str,
    *,
    allow_local_endpoint: bool = False,
    self_urls: Iterable[str] = (),
) -> str:
    """Validate an upstream HTTP/SSE endpoint against SSRF, cloud metadata, and self-loop URLs."""
    url = (raw_url or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Upstream URL must use http:// or https:// with a valid hostname.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials must not be embedded inside upstream URLs.")
    host = parts.hostname.lower().strip("[]")
    if host in _METADATA_HOSTS:
        raise ValueError(f"Blocked cloud metadata host in upstream URL: {host}")

    # Check IP literals against link-local/metadata and optional local loopback/private policy.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"Blocked unsafe IP address range: {host}")
        if (ip.is_loopback or ip.is_private) and not allow_local_endpoint:
            raise ValueError(
                f"Private/loopback upstream IP {host} requires explicit allow_local_endpoint=True."
            )
    elif host in ("localhost", "host.docker.internal") and not allow_local_endpoint:
        raise ValueError(
            f"Local upstream host {host} requires explicit allow_local_endpoint=True."
        )

    if parts.scheme == "http" and not _is_loopback_host(host, ip):
        raise ValueError("Remote non-loopback upstream MCP servers must use HTTPS.")

    norm_self = {u.strip().rstrip("/").lower() for u in self_urls if u}
    if url.rstrip("/").lower() in norm_self:
        raise ValueError("Gateway self-recursion blocked: upstream URL points to this MCP-app server.")
    return url


def _is_loopback_host(host: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    return ip is not None and ip.is_loopback


def check_loop_headers(headers: Mapping[str, str], instance_id: str) -> str | None:
    """Inspect inbound HTTP headers for gateway loop ID or excessive hops. Returns error reason or None."""
    lower = {k.lower(): v for k, v in headers.items()}
    seen_ids = [item.strip() for item in lower.get(GATEWAY_ID_HEADER.lower(), "").split(",") if item.strip()]
    if instance_id and instance_id in seen_ids:
        return "Gateway routing loop detected (instance ID already in chain)."
    raw_hop = lower.get(GATEWAY_HOP_HEADER.lower(), "0").strip()
    try:
        hops = int(raw_hop)
    except ValueError:
        return "Invalid X-MCP-Gateway-Hop header."
    if hops >= MAX_GATEWAY_HOPS:
        return f"Gateway hop limit exceeded ({hops} >= {MAX_GATEWAY_HOPS})."
    return None


def strip_downstream_auth_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Never forward downstream client Authorization or cookies upstream."""
    blocked = {"authorization", "cookie", "x-api-key", "proxy-authorization"}
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


def sanitize_tool_description(text: str | None, max_len: int = 1024) -> str:
    """Strip control characters and bound untrusted upstream tool descriptions."""
    raw = (text or "").replace("\r", " ").replace("\n", " ")
    cleaned = "".join(ch for ch in raw if ch >= " ")
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        return cleaned[: max_len - 1] + "…"
    return cleaned


def detect_untrusted_launcher(command: str, args: Iterable[str]) -> bool:
    """Detect package-runner or remote-fetch launchers so imports require explicit owner confirmation."""
    exe = Path((command or "").strip()).name.lower()
    if exe in _UNTRUSTED_LAUNCHERS:
        return True
    arg_list = [str(a).lower() for a in args]
    if exe in ("powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe", "bash", "sh"):
        joined = " ".join(arg_list)
        if any(marker in joined for marker in ("iex", "invoke-webrequest", "curl ", "wget ", "-enc", "npx ")):
            return True
    return False


def looks_like_secret_env_name(name: str) -> bool:
    upper = (name or "").upper()
    return any(hint in upper for hint in _SECRET_NAME_HINTS)
