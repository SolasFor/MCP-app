"""Independent SSH host-key pre-auth probing, SHA-256 verification, and managed known_hosts."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import paramiko

from app.core.atomic_io import atomic_write_text, is_reparse_or_symlink
from backend.remote.models import format_known_hosts_host, validate_host

SUPPORTED_HOST_KEY_ALGORITHMS: tuple[str, ...] = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)

KEX_KEY_TYPES_BY_PUBLIC_ALG: dict[str, tuple[str, ...]] = {
    "ssh-ed25519": ("ssh-ed25519",),
    "ecdsa-sha2-nistp256": ("ecdsa-sha2-nistp256",),
    "ecdsa-sha2-nistp384": ("ecdsa-sha2-nistp384",),
    "ecdsa-sha2-nistp521": ("ecdsa-sha2-nistp521",),
    "ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
}

_SHA256_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


class HostKeyVerificationError(PermissionError):
    """Raised when SSH host-key verification fails or lacks independent confirmation."""


class HostKeyChangedError(HostKeyVerificationError):
    """Raised when a remote endpoint presents a different host key than trusted/pinned."""


@dataclass(frozen=True)
class ParsedExpectedHostKey:
    kind: Literal["sha256", "pubkey"]
    sha256: str
    algorithm: str = ""
    base64: str = ""


@dataclass(frozen=True)
class KnownHostsCheck:
    status: Literal["trusted", "unknown_host", "host_key_changed"]
    source_path: str
    existing_algorithms: tuple[str, ...]
    existing_sha256s: tuple[str, ...]


@dataclass(frozen=True)
class HostKeyProbeResult:
    host: str
    port: int
    status: Literal["trusted", "unknown_host", "host_key_changed"]
    key_algorithm: str
    fingerprint_sha256: str
    public_key_base64: str
    known_hosts_source: str
    existing_algorithms: tuple[str, ...]
    existing_sha256s: tuple[str, ...]
    endpoint_ip: str = ""


@dataclass(frozen=True)
class ApprovedHostKey:
    host: str
    port: int
    key_algorithm: str
    fingerprint_sha256: str
    public_key_base64: str
    verified_at: float


def compute_host_key_sha256(key: paramiko.PKey) -> str:
    """Return canonical OpenSSH SHA256:<base64_no_pad> fingerprint of a Paramiko PKey."""
    digest = hashlib.sha256(key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def load_public_host_key(algorithm: str, key_base64: str) -> paramiko.PKey:
    """Strictly decode a base64 OpenSSH public host key and verify its algorithm matches."""
    alg = (algorithm or "").strip()
    b64 = (key_base64 or "").strip()
    if alg not in SUPPORTED_HOST_KEY_ALGORITHMS:
        raise ValueError(f"Unsupported SSH host key algorithm: {alg!r}")
    if not b64:
        raise ValueError("Host key base64 payload is required")
    try:
        raw = base64.b64decode(b64.encode("ascii"), validate=True)
        pkey = paramiko.PKey.from_type_string(alg, raw)
    except (ValueError, binascii.Error, paramiko.SSHException) as exc:
        raise ValueError(f"Invalid SSH public host key payload: {type(exc).__name__}") from exc
    if pkey.get_name() != alg:
        raise ValueError("Host key algorithm mismatch")
    return pkey


def _parse_sha256_fingerprint(text: str) -> ParsedExpectedHostKey:
    b64 = text[len("SHA256:") :].rstrip("=")
    if len(b64) != 43 or any(ch not in _SHA256_B64_CHARS for ch in b64):
        raise HostKeyVerificationError("Invalid SHA256 host key fingerprint format")
    try:
        decoded = base64.b64decode((b64 + "=").encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HostKeyVerificationError("Invalid SHA256 host key fingerprint encoding") from exc
    if len(decoded) != 32:
        raise HostKeyVerificationError("Invalid SHA256 digest length")
    return ParsedExpectedHostKey(kind="sha256", sha256=f"SHA256:{b64}")


def parse_expected_fingerprint_input(raw: str) -> ParsedExpectedHostKey:
    """Parse expected SHA256:... fingerprint or OpenSSH public key line for independent verification."""
    text = (raw or "").strip()
    if not text or any(ch in text for ch in ("\x00", "\r", "\n")):
        raise HostKeyVerificationError("Expected SSH host key fingerprint is required")
    if text.startswith("SHA256:"):
        return _parse_sha256_fingerprint(text)

    parts = text.split()
    if len(parts) >= 2 and parts[0] in SUPPORTED_HOST_KEY_ALGORITHMS:
        try:
            pkey = load_public_host_key(parts[0], parts[1])
        except ValueError as exc:
            raise HostKeyVerificationError(str(exc)) from exc
        return ParsedExpectedHostKey(
            kind="pubkey",
            sha256=compute_host_key_sha256(pkey),
            algorithm=pkey.get_name(),
            base64=pkey.get_base64(),
        )
    raise HostKeyVerificationError(
        "Enter an OpenSSH SHA256:... fingerprint or '<algorithm> <base64>' public key"
    )


def _lookup_names(clean_host: str, port: int) -> tuple[str, ...]:
    primary = format_known_hosts_host(clean_host, port)
    names = [primary]
    if port == 22:
        bracketed = f"[{clean_host}]:22"
        if bracketed not in names:
            names.append(bracketed)
        if clean_host not in names:
            names.append(clean_host)
    return tuple(names)


def _load_host_keys_safe(path: Path) -> paramiko.HostKeys:
    if is_reparse_or_symlink(path) or not path.is_file():
        return paramiko.HostKeys()
    try:
        return paramiko.HostKeys(str(path))
    except (OSError, paramiko.SSHException) as exc:
        raise HostKeyVerificationError(f"Unreadable known_hosts file {path}: {type(exc).__name__}") from exc


def _system_known_hosts_candidates() -> list[Path]:
    candidates = [
        Path("/etc/ssh/ssh_known_hosts"),
        Path("/etc/ssh/ssh_known_hosts2"),
    ]
    if sys.platform == "win32":
        prog_data = os.environ.get("ProgramData", "").strip()
        if prog_data:
            candidates.append(Path(prog_data) / "ssh" / "ssh_known_hosts")
    candidates.append(Path.home() / ".ssh" / "known_hosts")
    return candidates


def _collect_known_hosts_sources(
    known_hosts_path: str | Path | None,
    include_system_known_hosts: bool,
) -> list[tuple[str, paramiko.HostKeys]]:
    sources: list[tuple[str, paramiko.HostKeys]] = []
    seen_paths: set[str] = set()

    def _add_path(p: Path, *, require_exists: bool) -> None:
        key = os.path.normcase(os.path.abspath(os.fspath(p)))
        if key in seen_paths or (require_exists and not p.is_file()):
            return
        seen_paths.add(key)
        sources.append((str(p), _load_host_keys_safe(p)))

    explicit = str(known_hosts_path).strip() if known_hosts_path else ""
    if explicit:
        _add_path(Path(explicit).expanduser(), require_exists=False)
    if include_system_known_hosts:
        for sys_path in _system_known_hosts_candidates():
            _add_path(sys_path, require_exists=True)
    return sources


def _scan_subdict_for_key(
    subdict: Any,
    remote_alg: str,
    remote_bytes: bytes,
    existing_algs: list[str],
    existing_fps: list[str],
) -> tuple[str, str] | None:
    for alg, known_key in subdict.items():
        if known_key is None:
            continue
        if alg == remote_alg and known_key.asbytes() == remote_bytes:
            return alg, compute_host_key_sha256(known_key)
        if alg not in existing_algs:
            existing_algs.append(alg)
        fp = compute_host_key_sha256(known_key)
        if fp not in existing_fps:
            existing_fps.append(fp)
    return None


def inspect_known_hosts(
    host: str,
    port: int,
    remote_key: paramiko.PKey,
    *,
    known_hosts_path: str | Path | None = None,
    include_system_known_hosts: bool = True,
) -> KnownHostsCheck:
    """Check whether `remote_key` is trusted, unknown, or changed for exact `(host, port)`."""
    clean_host = validate_host(host)
    if not (1 <= int(port) <= 65535):
        raise ValueError(f"Invalid SSH port: {port}")
    lookup_names = _lookup_names(clean_host, int(port))
    sources = _collect_known_hosts_sources(known_hosts_path, include_system_known_hosts)

    existing_algs: list[str] = []
    existing_fps: list[str] = []
    matched_source = ""
    remote_alg = remote_key.get_name()
    remote_bytes = remote_key.asbytes()

    for src_name, host_keys in sources:
        for lname in lookup_names:
            subdict = host_keys.lookup(lname)
            if not subdict:
                continue
            matched_source = matched_source or src_name
            hit = _scan_subdict_for_key(subdict, remote_alg, remote_bytes, existing_algs, existing_fps)
            if hit is not None:
                return KnownHostsCheck(
                    status="trusted",
                    source_path=src_name,
                    existing_algorithms=(hit[0],),
                    existing_sha256s=(hit[1],),
                )

    if existing_fps:
        return KnownHostsCheck(
            status="host_key_changed",
            source_path=matched_source,
            existing_algorithms=tuple(existing_algs),
            existing_sha256s=tuple(existing_fps),
        )
    return KnownHostsCheck(
        status="unknown_host",
        source_path=str(known_hosts_path or ""),
        existing_algorithms=(),
        existing_sha256s=(),
    )


def _connect_tcp_endpoint(
    clean_host: str,
    port: int,
    *,
    timeout: float,
    cancel_event: threading.Event | None,
) -> tuple[socket.socket, str]:
    infos = socket.getaddrinfo(clean_host, port, type=socket.SOCK_STREAM)
    last_err: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in infos:
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("SSH host-key probe cancelled")
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock, str(sockaddr[0])
        except OSError as exc:
            last_err = exc
            sock.close()
    if last_err is not None:
        raise last_err
    raise OSError(f"Could not resolve SSH endpoint {clean_host}:{port}")


def _configure_transport_key_preference(
    transport: paramiko.Transport,
    expected_pin: tuple[str, str, str] | None,
) -> None:
    if not (expected_pin and expected_pin[0] in KEX_KEY_TYPES_BY_PUBLIC_ALG):
        return
    sec_opts = transport.get_security_options()
    preferred = [k for k in KEX_KEY_TYPES_BY_PUBLIC_ALG[expected_pin[0]] if k in sec_opts.key_types]
    if preferred:
        other = [k for k in sec_opts.key_types if k not in preferred]
        sec_opts.key_types = [*preferred, *other]


def _wait_for_client_handshake(
    transport: paramiko.Transport,
    *,
    timeout: float,
    cancel_event: threading.Event | None,
) -> paramiko.PKey:
    ev = threading.Event()
    transport.start_client(event=ev)
    deadline = time.monotonic() + timeout
    while not ev.wait(0.05):
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("SSH host-key probe cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("Timed out during SSH host-key handshake")
    if not transport.is_active():
        exc = transport.get_exception()
        if exc is not None:
            raise exc
        raise HostKeyVerificationError("SSH host-key handshake failed before completion")
    remote_key = transport.get_remote_server_key()
    if remote_key is None:
        raise HostKeyVerificationError("Remote SSH endpoint presented no host key")
    return remote_key


def _perform_preauth_handshake(
    clean_host: str,
    port_num: int,
    *,
    expected_pin: tuple[str, str, str] | None,
    timeout: float,
    cancel_event: threading.Event | None,
) -> tuple[paramiko.PKey, str]:
    sock, endpoint_ip = _connect_tcp_endpoint(
        clean_host, port_num, timeout=timeout, cancel_event=cancel_event
    )
    transport: paramiko.Transport | None = None
    try:
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        _configure_transport_key_preference(transport, expected_pin)
        remote_key = _wait_for_client_handshake(
            transport, timeout=timeout, cancel_event=cancel_event
        )
        return remote_key, endpoint_ip
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            sock.close()
        except OSError:
            pass


def probe_ssh_host_key(
    host: str,
    port: int = 22,
    *,
    known_hosts_path: str | Path | None = None,
    include_system_known_hosts: bool = True,
    expected_pin: tuple[str, str, str] | None = None,
    timeout: float = 8.0,
    cancel_event: threading.Event | None = None,
) -> HostKeyProbeResult:
    """Perform a pre-auth SSH handshake ONLY (zero auth packets) to inspect the host key."""
    clean_host = validate_host(host)
    port_num = int(port)
    if not (1 <= port_num <= 65535):
        raise ValueError(f"Invalid SSH port: {port}")
    if cancel_event is not None and cancel_event.is_set():
        raise TimeoutError("SSH host-key probe cancelled")
    bounded_timeout = max(1.0, min(float(timeout), 30.0))

    remote_key, endpoint_ip = _perform_preauth_handshake(
        clean_host,
        port_num,
        expected_pin=expected_pin,
        timeout=bounded_timeout,
        cancel_event=cancel_event,
    )
    alg = remote_key.get_name()
    b64 = remote_key.get_base64()
    sha256 = compute_host_key_sha256(remote_key)

    if expected_pin and any(expected_pin) and (alg, sha256, b64) != expected_pin:
        exp_alg, exp_sha, _exp_b64 = expected_pin
        return HostKeyProbeResult(
            host=clean_host,
            port=port_num,
            status="host_key_changed",
            key_algorithm=alg,
            fingerprint_sha256=sha256,
            public_key_base64=b64,
            known_hosts_source="profile_pin",
            existing_algorithms=(exp_alg,) if exp_alg else (),
            existing_sha256s=(exp_sha,) if exp_sha else (),
            endpoint_ip=endpoint_ip,
        )

    kh_check = inspect_known_hosts(
        clean_host,
        port_num,
        remote_key,
        known_hosts_path=known_hosts_path,
        include_system_known_hosts=include_system_known_hosts,
    )
    return HostKeyProbeResult(
        host=clean_host,
        port=port_num,
        status=kh_check.status,
        key_algorithm=alg,
        fingerprint_sha256=sha256,
        public_key_base64=b64,
        known_hosts_source=kh_check.source_path,
        existing_algorithms=kh_check.existing_algorithms,
        existing_sha256s=kh_check.existing_sha256s,
        endpoint_ip=endpoint_ip,
    )


def verify_independent_host_key(
    probe: HostKeyProbeResult,
    *,
    expected_fingerprint_input: str,
    verified_independently: bool,
    allow_rotation: bool = False,
) -> ApprovedHostKey:
    """Bind host-key approval strictly to independent out-of-band fingerprint matching."""
    if not verified_independently:
        raise HostKeyVerificationError(
            "Confirm independent verification of the host key fingerprint before continuing"
        )
    if probe.status == "host_key_changed" and not allow_rotation:
        raise HostKeyChangedError(
            f"SSH host key CHANGED for {probe.host}:{probe.port}; use explicit key rotation"
        )
    parsed = parse_expected_fingerprint_input(expected_fingerprint_input)
    if not hmac.compare_digest(parsed.sha256, probe.fingerprint_sha256):
        raise HostKeyVerificationError(
            "Presented host key SHA-256 fingerprint does not match the expected fingerprint"
        )
    if parsed.kind == "pubkey":
        if not hmac.compare_digest(parsed.algorithm, probe.key_algorithm) or not hmac.compare_digest(
            parsed.base64, probe.public_key_base64
        ):
            raise HostKeyVerificationError("Presented host public key does not match expected key")
    load_public_host_key(probe.key_algorithm, probe.public_key_base64)
    return ApprovedHostKey(
        host=probe.host,
        port=probe.port,
        key_algorithm=probe.key_algorithm,
        fingerprint_sha256=probe.fingerprint_sha256,
        public_key_base64=probe.public_key_base64,
        verified_at=time.time(),
    )


def _line_matches_endpoint_key(
    line: str,
    lookup_names: tuple[str, ...],
) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    try:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(stripped)
    except Exception:  # noqa: BLE001
        return False
    if entry is None:
        return False
    hk = paramiko.HostKeys()
    for name in entry.hostnames:
        hk.add(name, entry.key.get_name(), entry.key)
    return any(bool(hk.lookup(lname)) for lname in lookup_names)


def _rebuild_known_host_lines(
    existing_lines: list[str],
    approved: ApprovedHostKey,
    *,
    is_already_trusted: bool,
    replace_existing: bool,
) -> list[str]:
    lookup_names = _lookup_names(approved.host, approved.port)
    kept_lines: list[str] = []
    for line in existing_lines:
        if not _line_matches_endpoint_key(line, lookup_names):
            kept_lines.append(line)
        elif is_already_trusted and not replace_existing:
            kept_lines.append(line)
    if not is_already_trusted or replace_existing:
        host_entry = format_known_hosts_host(approved.host, approved.port)
        kept_lines.append(f"{host_entry} {approved.key_algorithm} {approved.public_key_base64}")
    return kept_lines


def upsert_managed_known_host_entry(
    known_hosts_path: Path,
    approved: ApprovedHostKey,
    *,
    replace_existing: bool = False,
) -> None:
    """Atomically write or rotate an entry in the app-managed known_hosts file."""
    target = Path(known_hosts_path)
    if is_reparse_or_symlink(target.parent) or is_reparse_or_symlink(target):
        raise HostKeyVerificationError("Refusing symlink/reparse point for known_hosts")

    pkey = load_public_host_key(approved.key_algorithm, approved.public_key_base64)
    check = inspect_known_hosts(
        approved.host,
        approved.port,
        pkey,
        known_hosts_path=target,
        include_system_known_hosts=False,
    )
    if check.status == "host_key_changed" and not replace_existing:
        raise HostKeyChangedError(
            f"Conflicting key already exists in managed known_hosts for {approved.host}:{approved.port}"
        )

    existing_lines = target.read_text(encoding="utf-8").splitlines() if target.is_file() else []
    kept_lines = _rebuild_known_host_lines(
        existing_lines,
        approved,
        is_already_trusted=(check.status == "trusted"),
        replace_existing=replace_existing,
    )
    content = ("\n".join(kept_lines) + "\n") if kept_lines else ""
    atomic_write_text(target, content, encoding="utf-8", restrict_acl=True)


def remove_managed_known_host_entry(known_hosts_path: Path, host: str, port: int) -> bool:
    """Remove matching host/port lines from the app-managed known_hosts file."""
    target = Path(known_hosts_path)
    if not target.is_file() or is_reparse_or_symlink(target):
        return False
    clean_host = validate_host(host)
    lookup_names = _lookup_names(clean_host, int(port))
    lines = target.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if not _line_matches_endpoint_key(ln, lookup_names)]
    if len(kept) == len(lines):
        return False
    content = ("\n".join(kept) + "\n") if kept else ""
    atomic_write_text(target, content, encoding="utf-8", restrict_acl=True)
    return True
