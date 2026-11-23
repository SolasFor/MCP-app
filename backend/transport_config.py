"""Validated network policy for the Streamable HTTP endpoint.

Cloudflare Quick Tunnel's hostname changes after restarts. The MCP SDK must
allow the active hostname, not all *.trycloudflare.com hostnames, while keeping
DNS rebinding checks enabled.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_PATH_RE = re.compile(r"/(?:[A-Za-z0-9._~-]+)(?:/[A-Za-z0-9._~-]+)*\Z")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_mcp_path(value: str) -> str:
    """Return an unambiguous endpoint path."""
    path = value.strip()
    if not _PATH_RE.fullmatch(path) or path in ("/health", "/ready"):
        raise ValueError(f"Invalid MCP_PATH: {value!r}; expected /mcp or /name/segment")
    return path


def validate_public_url(value: str, mcp_path: str) -> str:
    """Validate canonical public resource URL used for auth and Host checks."""
    url = value.strip().rstrip("/")
    parts = urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or "*" in parts.netloc
        or parts.query
        or parts.fragment
        or parts.path != mcp_path
    ):
        raise ValueError("MCP_PUBLIC_URL must be an absolute URL ending in MCP_PATH, without credentials/query/fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid port in MCP_PUBLIC_URL") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Invalid port in MCP_PUBLIC_URL")
    if parts.scheme != "https" and parts.hostname.lower() not in _LOOPBACK:
        raise ValueError("Remote MCP_PUBLIC_URL must use HTTPS")
    return url


def _valid_extra_origin(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid port in MCP_ALLOWED_ORIGINS") from exc
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or "*" in parts.netloc
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or (port is not None and not (1 <= port <= 65535))
        or (parts.scheme == "http" and parts.hostname.lower() not in _LOOPBACK)
    ):
        raise ValueError(f"Invalid MCP_ALLOWED_ORIGINS origin: {value!r}")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def transport_allowlists(public_url: str, local_port: int, extra_origins: str = "") -> tuple[list[str], list[str]]:
    """Return exact Host/Origin allowlists; never grant wildcard cloudflared hosts."""
    if not 1 <= local_port <= 65535:
        raise ValueError("Invalid MCP_PORT")
    parts = urlsplit(public_url)
    if not parts.hostname or not parts.scheme:
        raise ValueError("Invalid public URL")
    public_host = parts.hostname.lower()
    host_literal = f"[{public_host}]" if ":" in public_host else public_host
    hosts = [f"127.0.0.1:{local_port}", f"localhost:{local_port}", f"[::1]:{local_port}"]
    hosts.append(parts.netloc.lower())
    if parts.port is None:
        hosts.append(f"{host_literal}:{443 if parts.scheme == 'https' else 80}")
    origins = [
        f"http://127.0.0.1:{local_port}",
        f"http://localhost:{local_port}",
        f"http://[::1]:{local_port}",
        f"{parts.scheme}://{parts.netloc.lower()}",
    ]
    for candidate in extra_origins.split(","):
        if candidate.strip():
            origins.append(_valid_extra_origin(candidate))
    return list(dict.fromkeys(hosts)), list(dict.fromkeys(origins))
