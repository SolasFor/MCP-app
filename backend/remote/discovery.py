"""Opt-in bounded SSH endpoint discovery (explicit local CIDR/IPs & read-only Tailscale peers)."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from app.core.redaction import SecretRedactor
from app.core.tunnels.base import run_cli_capture_bounded
from app.core.tunnels.tailscale import _find_tailscale

_TS_KEY_RE = re.compile(r"tskey-[A-Za-z0-9_-]{8,}", re.IGNORECASE)

_CGNAT_NET = ipaddress.IPv4Network((0x64400000, 10))  # RFC 6598 100.64.0.0/10 CGNAT


@dataclass(frozen=True)
class SSHNetworkDiscoveryLimits:
    max_hosts: int = 256
    max_ports: int = 5
    connect_timeout_s: float = 0.5
    total_deadline_s: float = 12.0
    max_concurrency: int = 16
    max_tailscale_json_bytes: int = 1024 * 1024


@dataclass(frozen=True)
class DiscoveredSSHEndpoint:
    host: str
    port: int
    banner: str = ""
    source: str = "cidr_probe"
    trusted: bool = False
    authenticated: bool = False


@dataclass(frozen=True)
class TailscalePeerCandidate:
    node_id: str
    hostname: str
    dns_name: str
    ip: str
    all_ips: tuple[str, ...]
    os_name: str
    online: bool
    ssh_host_keys: tuple[str, ...] = ()
    trusted: bool = False
    authenticated: bool = False


@dataclass(frozen=True)
class TailscaleDiscoveryResult:
    available: bool
    status: str
    detail: str
    backend_state: str = ""
    peers: tuple[TailscalePeerCandidate, ...] = ()


def _is_permitted_discovery_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address) and int(ip_obj) == 0xFFFFFFFF:
        return False
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_private:
        return True
    return isinstance(ip_obj, ipaddress.IPv4Address) and (ip_obj in _CGNAT_NET)


def _expand_network_hosts(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    max_hosts: int,
) -> list[str]:
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 24:
        raise ValueError("IPv4 CIDR discovery scope is bounded to /24 or smaller (<= 256 hosts)")
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < 120:
        raise ValueError("IPv6 CIDR discovery scope is bounded to /120 or smaller (<= 256 hosts)")
    if not _is_permitted_discovery_ip(net.network_address):
        raise ValueError(f"Public or non-local CIDR {net} is forbidden for SSH discovery")
    if net.num_addresses > max_hosts:
        raise ValueError(f"Scope exceeds max {max_hosts} hosts")
    if net.num_addresses == 1:
        if not _is_permitted_discovery_ip(net.network_address):
            raise ValueError(f"Prohibited target IP: {net.network_address}")
        return [str(net.network_address)]
    hosts = [str(ip) for ip in net.hosts() if _is_permitted_discovery_ip(ip)]
    if not hosts:
        raise ValueError(f"No routable local host addresses in {net}")
    return hosts


def _expand_scope_token(token: str, *, max_hosts: int) -> list[str]:
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR scope {token!r}") from exc
        return _expand_network_hosts(net, max_hosts=max_hosts)
    clean_tok = token[1:-1] if token.startswith("[") and token.endswith("]") else token
    try:
        ip_obj = ipaddress.ip_address(clean_tok)
    except ValueError as exc:
        raise ValueError(f"Discovery accepts IP/CIDR only (not DNS {token!r})") from exc
    if not _is_permitted_discovery_ip(ip_obj):
        raise ValueError(f"Public or prohibited IP {clean_tok!r} cannot be scanned")
    return [str(ip_obj)]


def _validate_discovery_ports(ports: tuple[int, ...] | list[int], max_ports: int) -> tuple[int, ...]:
    clean_ports: list[int] = []
    for p in ports:
        if type(p) is not int or not (1 <= p <= 65535):
            raise ValueError(f"Invalid SSH discovery port: {p!r}")
        if p not in clean_ports:
            clean_ports.append(p)
    if not clean_ports or len(clean_ports) > max_ports:
        raise ValueError(f"Select between 1 and {max_ports} ports for SSH discovery")
    return tuple(clean_ports)


def _collect_scope_hosts(tokens: list[str], max_hosts: int) -> tuple[str, ...]:
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for token in tokens:
        for h in _expand_scope_token(token, max_hosts=max_hosts):
            if h not in seen_hosts:
                seen_hosts.add(h)
                hosts.append(h)
            if len(hosts) > max_hosts:
                raise ValueError(f"Discovery scope exceeds maximum {max_hosts} hosts")
    return tuple(hosts)


def validate_discovery_scope(
    scope_text: str,
    ports: tuple[int, ...] | list[int] = (22,),
    *,
    limits: SSHNetworkDiscoveryLimits | None = None,
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    """Validate explicit local CIDR/IP targets and SSH ports (never scans public internet)."""
    cfg = limits or SSHNetworkDiscoveryLimits()
    raw_scope = (scope_text or "").strip()
    if not raw_scope or any(ch in raw_scope for ch in ("\x00", "\r")):
        raise ValueError("Provide a local CIDR (e.g. 192.168.1.0/24) or explicit private IP list")
    tokens = [t.strip() for t in raw_scope.replace("\n", ",").split(",") if t.strip()]
    if not tokens:
        raise ValueError("Discovery target list is empty")
    return _collect_scope_hosts(tokens, cfg.max_hosts), _validate_discovery_ports(ports, cfg.max_ports)


def _sanitize_ssh_banner(raw: bytes) -> str:
    text = raw.decode("ascii", errors="ignore").splitlines()[0].strip() if raw else ""
    if not text.startswith("SSH-"):
        return ""
    safe = "".join(ch for ch in text if 32 <= ord(ch) <= 126)
    return safe[:80]


def _probe_single_endpoint(
    host: str,
    port: int,
    *,
    timeout_s: float,
    deadline: float,
    cancel_event: threading.Event | None,
) -> DiscoveredSSHEndpoint | None:
    if (cancel_event is not None and cancel_event.is_set()) or time.monotonic() >= deadline:
        return None
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(min(timeout_s, max(0.05, deadline - time.monotonic())))
    try:
        sock.connect((host, port))
        banner = ""
        try:
            sock.settimeout(min(0.25, timeout_s))
            banner = _sanitize_ssh_banner(sock.recv(128))
        except OSError:
            banner = ""
        return DiscoveredSSHEndpoint(
            host=host,
            port=port,
            banner=banner,
            source="cidr_probe",
            trusted=False,
            authenticated=False,
        )
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def discover_ssh_endpoints_in_cidr(
    scope_text: str,
    *,
    ports: tuple[int, ...] | list[int] = (22,),
    owner_consent: bool,
    limits: SSHNetworkDiscoveryLimits | None = None,
    cancel_event: threading.Event | None = None,
) -> list[DiscoveredSSHEndpoint]:
    """Bounded opt-in TCP SSH probe strictly within an explicitly consented local CIDR/IP scope."""
    if not owner_consent:
        raise PermissionError("Explicit owner consent is required before scanning a network range")
    cfg = limits or SSHNetworkDiscoveryLimits()
    hosts, clean_ports = validate_discovery_scope(scope_text, ports, limits=cfg)
    targets = [(h, p) for h in hosts for p in clean_ports]
    deadline = time.monotonic() + cfg.total_deadline_s

    found: list[DiscoveredSSHEndpoint] = []
    workers = max(1, min(cfg.max_concurrency, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                _probe_single_endpoint,
                h,
                p,
                timeout_s=cfg.connect_timeout_s,
                deadline=deadline,
                cancel_event=cancel_event,
            )
            for h, p in targets
        ]
        for fut in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                break
            res = fut.result()
            if res is not None:
                found.append(res)
    found.sort(key=lambda item: (item.host, item.port))
    return found


def _parse_tailscale_peer(node_id: str, raw: dict) -> TailscalePeerCandidate | None:
    ips = tuple(
        str(ip).strip()
        for ip in (raw.get("TailscaleIPs") or ())
        if isinstance(ip, str) and ip.strip()
    )
    if not ips:
        return None
    ipv4 = next((ip for ip in ips if ":" not in ip), ips[0])
    host_keys = tuple(
        str(k).strip()
        for k in (raw.get("sshHostKeys") or ())
        if isinstance(k, str) and k.strip()
    )
    return TailscalePeerCandidate(
        node_id=str(node_id),
        hostname=str(raw.get("HostName") or "").strip(),
        dns_name=str(raw.get("DNSName") or "").strip().rstrip("."),
        ip=ipv4,
        all_ips=ips,
        os_name=str(raw.get("OS") or "").strip(),
        online=bool(raw.get("Online", False)),
        ssh_host_keys=host_keys,
        trusted=False,
        authenticated=False,
    )


def _parse_tailscale_status_json(raw_text: str, max_bytes: int) -> tuple[dict | None, str]:
    if len(raw_text.encode("utf-8", errors="replace")) > max_bytes:
        return None, "Tailscale status output exceeded 1 MiB safety limit"
    try:
        data = json.loads(raw_text)
    except ValueError:
        return None, "Invalid JSON from tailscale status --json"
    if not isinstance(data, dict):
        return None, "Unexpected Tailscale JSON shape"
    return data, ""


def _collect_tailscale_peers(peer_map: object) -> tuple[TailscalePeerCandidate, ...]:
    if not isinstance(peer_map, dict):
        return ()
    peers = [
        cand
        for nid, prec in peer_map.items()
        if isinstance(prec, dict)
        for cand in [_parse_tailscale_peer(str(nid), prec)]
        if cand is not None
    ]
    peers.sort(key=lambda p: (not p.online, p.hostname.casefold(), p.ip))
    return tuple(peers)


def _sanitize_cli_error(stderr: str, stdout: str) -> str:
    raw = (stderr or stdout or "").strip()
    if not raw:
        return "tailscale status failed"
    first_line = raw.splitlines()[0].strip()
    scrubbed = _TS_KEY_RE.sub("tskey-[REDACTED]", first_line)
    clean = SecretRedactor().redact_text(scrubbed)
    return (clean or "tailscale status failed")[:200]


def discover_tailscale_ssh_peers(
    *,
    owner_consent: bool,
    configured_cli_path: str = "",
    limits: SSHNetworkDiscoveryLimits | None = None,
    cancel_event: threading.Event | None = None,
) -> TailscaleDiscoveryResult:
    """Read local `tailscale status --json` (never runs `up`/`login` or mutates ACLs/routes)."""
    if not owner_consent:
        raise PermissionError("Explicit owner consent is required before reading Tailscale peer status")
    cfg = limits or SSHNetworkDiscoveryLimits()
    exe = _find_tailscale(configured_cli_path.strip())
    if not exe:
        return TailscaleDiscoveryResult(
            available=False,
            status="not_available",
            detail="Tailscale CLI was not found on this machine. Use manual SSH host entry.",
        )
    try:
        res = run_cli_capture_bounded(
            [exe, "status", "--json"],
            timeout=min(6.0, float(cfg.total_deadline_s)),
            max_stdout_bytes=cfg.max_tailscale_json_bytes,
            max_stderr_bytes=64 * 1024,
            cancel_event=cancel_event,
        )
    except OSError as exc:
        return TailscaleDiscoveryResult(
            available=False,
            status="error",
            detail=f"Unable to run tailscale CLI: {type(exc).__name__}",
        )
    if res.cancelled:
        return TailscaleDiscoveryResult(available=True, status="cancelled", detail="Tailscale discovery cancelled")
    if res.timed_out:
        return TailscaleDiscoveryResult(available=True, status="error", detail="Tailscale status command timed out")
    if res.stdout_limit_exceeded or res.stderr_limit_exceeded:
        return TailscaleDiscoveryResult(
            available=True,
            status="error",
            detail="Tailscale status output exceeded 1 MiB safety limit",
        )
    if res.returncode != 0:
        return TailscaleDiscoveryResult(
            available=True,
            status="not_running",
            detail=_sanitize_cli_error(res.stderr, res.stdout),
        )
    data, parse_err = _parse_tailscale_status_json(res.stdout, cfg.max_tailscale_json_bytes)
    if parse_err or data is None:
        return TailscaleDiscoveryResult(available=True, status="error", detail=parse_err)
    peers = _collect_tailscale_peers(data.get("Peer"))
    return TailscaleDiscoveryResult(
        available=True,
        status="ok",
        detail=f"Found {len(peers)} Tailscale peer(s)",
        backend_state=str(data.get("BackendState") or ""),
        peers=peers,
    )
