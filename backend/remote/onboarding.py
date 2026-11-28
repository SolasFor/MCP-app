"""Stage N05 SSH device onboarding: safe OpenSSH import, auth/OS probes, keygen & WAL commit."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.atomic_io import atomic_write_json, is_reparse_or_symlink, try_init_private_dir
from app.platform import get_platform
from backend.remote.host_keys import (
    ApprovedHostKey,
    compute_host_key_sha256,
    load_public_host_key,
    upsert_managed_known_host_entry,
)
from backend.remote.models import (
    DevicePermissions,
    DeviceProfile,
    canonical_endpoint_key,
    validate_device_id,
    validate_host,
    validate_ssh_username,
)

if TYPE_CHECKING:
    from backend.remote.ssh_client import SSHConnectionManager
    from backend.remote.store import DeviceStore

_MAX_SSH_CONFIG_BYTES = 256 * 1024
_MAX_SSH_CONFIG_LINES = 4096
_SUPPORTED_CONFIG_KEYS = frozenset({"host", "hostname", "user", "port", "identityfile", "identitiesonly"})
_UNSAFE_OR_UNSUPPORTED_KEYS = frozenset({
    "match",
    "proxycommand",
    "proxyjump",
    "localcommand",
    "remotecommand",
    "include",
    "certificatefile",
    "pkcs11provider",
    "securitykeyprovider",
    "dynamicforward",
    "localforward",
    "remoteforward",
})


class WizardDeviceConflictError(ValueError):
    """Raised when a device ID or endpoint conflicts with an existing DeviceStore profile."""


class WizardStalePlanError(RuntimeError):
    """Raised when the draft, approved host key, credentials, or store changed after preview."""


@dataclass(frozen=True)
class SSHConfigHostCandidate:
    profile: DeviceProfile
    source_alias: str
    is_duplicate: bool
    duplicate_reason: str = ""
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class SSHConfigImportReport:
    path: str
    candidates: tuple[SSHConfigHostCandidate, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class SSHKeyPairResult:
    private_key_path: str
    public_key_path: str
    public_key_line: str
    fingerprint_sha256: str
    algorithm: str = "ssh-ed25519"


@dataclass(frozen=True)
class RemoteCapabilityProbeResult:
    detected_os: str
    os_detail: str
    capabilities: tuple[str, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class SSHDevicePlanSnapshot:
    plan_fingerprint: str
    registry_fingerprint: str
    known_hosts_digest: str
    endpoint_key: tuple[str, int, str]
    approved_host_key_sha256: str
    secret_digest: str


@dataclass(frozen=True)
class SSHDevicePreview:
    draft: DeviceProfile
    approved_host_key: ApprovedHostKey
    effective_permissions_lines: tuple[str, ...]
    warnings: tuple[str, ...]
    summary_text: str
    snapshot: SSHDevicePlanSnapshot


def _resolve_identity_path(raw_ident: str) -> str:
    clean = (raw_ident or "").strip().strip('"').strip("'")
    if not clean or any(ch in clean for ch in ("\x00", "\r", "\n", "%")):
        return ""
    p = Path(clean).expanduser()
    if is_reparse_or_symlink(p):
        return ""
    return str(p)


def _strip_ssh_config_comment(line: str) -> str:
    in_quote = False
    for idx, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif ch == "#" and not in_quote:
            return line[:idx].strip()
    return line.strip()


def _parse_host_directive_tokens(
    lineno: int,
    raw_targets: str,
    warnings: list[str],
) -> tuple[list[str], list[str], bool]:
    tokens = raw_targets.split()
    literal = [t for t in tokens if not any(ch in t for ch in ("*", "?", "!", "%"))]
    ignored = [t for t in tokens if t not in literal]
    diags: list[str] = []
    if ignored:
        msg = f"Line {lineno}: skipped wildcard/negated Host token(s): {', '.join(ignored)}"
        warnings.append(msg)
        if literal:
            diags.append(msg)
    return literal, diags, (not literal)


def _apply_config_option_line(
    lineno: int,
    raw_key: str,
    val: str,
    cur_aliases: list[str],
    cur_opts: dict[str, str],
    cur_diags: list[str],
    warnings: list[str],
) -> None:
    key = raw_key.lower()
    if key in _UNSAFE_OR_UNSUPPORTED_KEYS:
        cur_diags.append(f"Ignored unsupported directive '{raw_key}' (configure manually if required)")
        warnings.append(f"Line {lineno}: ignored '{raw_key}' for host(s) {', '.join(cur_aliases)}")
        return
    if key not in _SUPPORTED_CONFIG_KEYS:
        cur_diags.append(f"Ignored directive '{raw_key}'")
        return
    if key == "identityfile" and "identityfile" in cur_opts:
        return
    cur_opts[key] = val.strip('"').strip("'")


def _parse_ssh_config_blocks(raw_text: str) -> tuple[list[tuple[str, dict[str, str], list[str]]], list[str]]:
    blocks: list[tuple[str, dict[str, str], list[str]]] = []
    warnings: list[str] = []
    cur_aliases: list[str] = []
    cur_opts: dict[str, str] = {}
    cur_diags: list[str] = []
    skip_block = False

    def _flush() -> None:
        if cur_aliases and not skip_block:
            for alias in cur_aliases:
                blocks.append((alias, dict(cur_opts), list(cur_diags)))

    for lineno, raw_line in enumerate(raw_text.splitlines(), 1):
        if lineno > _MAX_SSH_CONFIG_LINES:
            warnings.append(f"OpenSSH config truncated at {_MAX_SSH_CONFIG_LINES} lines")
            break
        stripped = _strip_ssh_config_comment(raw_line)
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            _flush()
            cur_aliases, cur_opts, cur_diags, skip_block = [], {}, [], True
            warnings.append(f"Line {lineno}: skipped 'Match' block (not evaluated automatically)")
            continue
        if key == "host":
            _flush()
            cur_aliases, cur_diags, skip_block = _parse_host_directive_tokens(lineno, val, warnings)
            cur_opts = {}
            continue
        if not skip_block:
            _apply_config_option_line(lineno, parts[0], val, cur_aliases, cur_opts, cur_diags, warnings)

    _flush()
    return blocks, warnings


def _build_import_candidate(
    alias: str,
    opts: dict[str, str],
    diags: list[str],
    existing_ids: dict[str, DeviceProfile],
    existing_endpoints: dict[tuple[str, int, str], str],
    seen_ids: set[str],
) -> SSHConfigHostCandidate | None:
    hostname_raw = opts.get("hostname") or alias
    try:
        host = validate_host(hostname_raw)
        user = validate_ssh_username(opts.get("user") or "", required=False)
        port_raw = opts.get("port") or "22"
        if not port_raw.isdigit():
            raise ValueError("Non-numeric Port")
        port = int(port_raw)
        safe_id = re.sub(r"[^a-zA-Z0-9_.-]+", "_", alias).strip("._-") or "device"
        dev_id = validate_device_id(safe_id[:64])
        key_path = _resolve_identity_path(opts.get("identityfile") or "")
        prof = DeviceProfile(
            device_id=dev_id,
            name=alias,
            host=host,
            port=port,
            username=user,
            group="imported",
            auth_method="key" if key_path else "agent",
            key_path=key_path,
            permissions=DevicePermissions(),
            allow_oauth_clients=False,
            enabled=True,
        )
    except ValueError as exc:
        diags.append(f"Skipped invalid entry '{alias}': {exc}")
        return None

    if dev_id in seen_ids:
        return None
    seen_ids.add(dev_id)

    dup_reason = ""
    if dev_id.casefold() in {k.casefold() for k in existing_ids}:
        dup_reason = f"Device ID '{dev_id}' already exists"
    else:
        ep = canonical_endpoint_key(prof.host, prof.port, prof.username)
        if ep in existing_endpoints:
            dup_reason = f"Endpoint already registered as '{existing_endpoints[ep]}'"

    return SSHConfigHostCandidate(
        profile=prof,
        source_alias=alias,
        is_duplicate=bool(dup_reason),
        duplicate_reason=dup_reason,
        diagnostics=tuple(diags),
    )


def inspect_ssh_config(
    path: Path | None = None,
    *,
    existing_store: DeviceStore | None = None,
) -> SSHConfigImportReport:
    """Safely inspect explicit Host blocks from OpenSSH config without executing directives or reading keys."""
    cfg_path = Path(path).expanduser() if path is not None else (Path.home() / ".ssh" / "config")
    if is_reparse_or_symlink(cfg_path) or not cfg_path.is_file():
        return SSHConfigImportReport(path=str(cfg_path), candidates=(), warnings=())
    if cfg_path.stat().st_size > _MAX_SSH_CONFIG_BYTES:
        return SSHConfigImportReport(
            path=str(cfg_path),
            candidates=(),
            warnings=(f"OpenSSH config exceeds {_MAX_SSH_CONFIG_BYTES} bytes safety limit",),
        )
    raw_text = cfg_path.read_text(encoding="utf-8", errors="replace")
    blocks, warnings = _parse_ssh_config_blocks(raw_text)

    existing_ids = existing_store.load_all() if existing_store is not None else {}
    existing_endpoints = {
        canonical_endpoint_key(d.host, d.port, d.username): d.device_id
        for d in existing_ids.values()
    }

    candidates: list[SSHConfigHostCandidate] = []
    seen_ids: set[str] = set()
    for alias, opts, diags in blocks:
        cand = _build_import_candidate(alias, opts, diags, existing_ids, existing_endpoints, seen_ids)
        if cand is not None:
            candidates.append(cand)
    return SSHConfigImportReport(
        path=str(cfg_path),
        candidates=tuple(candidates),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def test_ssh_authentication(
    host: str,
    port: int,
    username: str,
    *,
    auth_method: str,
    approved_host_key: ApprovedHostKey,
    key_path: str = "",
    password: str | None = None,
    passphrase: str | None = None,
    known_hosts_path: str = "",
    ssh_client: SSHConnectionManager | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Authenticate strictly with the chosen method against an already-verified host key."""
    clean_host = validate_host(host)
    clean_user = validate_ssh_username(username, required=True)
    if ssh_client is None:
        from backend.remote.ssh_client import SSHConnectionManager
        from backend.remote.store import DeviceStore

        mgr = SSHConnectionManager(DeviceStore(Path(known_hosts_path or ".").parent / "devices.json"))
    else:
        mgr = ssh_client
    with mgr.open_verified_session(
        host=clean_host,
        port=int(port),
        username=clean_user,
        auth_method=auth_method,
        approved_host_key=approved_host_key,
        key_path=key_path,
        password=password,
        passphrase=passphrase,
        known_hosts_path=known_hosts_path,
        timeout=timeout,
    ):
        return {"ok": True, "host": clean_host, "port": int(port), "auth_method": auth_method}


def _exec_bounded_probe_cmd(client: paramiko.SSHClient, cmd: str, *, timeout: float = 5.0) -> tuple[int, str]:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    chan = stdout.channel
    out_buf = bytearray()
    err_buf = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if chan.recv_ready():
            out_buf.extend(chan.recv(4096)[: max(0, 4096 - len(out_buf))])
        if chan.recv_stderr_ready():
            err_buf.extend(chan.recv_stderr(4096)[: max(0, 4096 - len(err_buf))])
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        time.sleep(0.03)
    code = chan.recv_exit_status() if chan.exit_status_ready() else -1
    chan.close()
    text = out_buf.decode("utf-8", errors="replace").strip() or err_buf.decode("utf-8", errors="replace").strip()
    return int(code), text


def _detect_os_from_session(client: paramiko.SSHClient) -> tuple[str, str]:
    code, uname_out = _exec_bounded_probe_cmd(client, "uname -s -m", timeout=4.0)
    if code == 0 and uname_out:
        low = uname_out.lower()
        if low.startswith("linux"):
            return "linux", uname_out
        if "msys" in low or "mingw" in low or "cygwin" in low:
            return "windows", uname_out
        return "unknown", uname_out

    ver_code, ver_out = _exec_bounded_probe_cmd(client, "cmd.exe /d /c ver", timeout=4.0)
    if ver_code == 0 and "windows" in ver_out.lower():
        return "windows", ver_out
    return "unknown", (uname_out or ver_out or "Unidentified SSH platform")[:200]


def probe_remote_os_and_capabilities(
    ssh_client: SSHConnectionManager,
    host: str,
    port: int,
    username: str,
    *,
    auth_method: str,
    approved_host_key: ApprovedHostKey,
    key_path: str = "",
    password: str | None = None,
    passphrase: str | None = None,
    known_hosts_path: str = "",
    cancel_event: threading.Event | None = None,
    emergency_stop_checker: Callable[[], bool] | None = None,
) -> RemoteCapabilityProbeResult:
    """Run fixed read-only OS & SFTP capability checks (no remote writes, no sudo/UAC)."""
    if emergency_stop_checker is not None and emergency_stop_checker():
        raise PermissionError("Emergency stop is active; remote probing is blocked")
    if cancel_event is not None and cancel_event.is_set():
        raise TimeoutError("Remote probe cancelled")

    clean_host = validate_host(host)
    clean_user = validate_ssh_username(username, required=True)
    caps: list[str] = ["ssh_exec"]
    warnings: list[str] = []

    with ssh_client.open_verified_session(
        host=clean_host,
        port=int(port),
        username=clean_user,
        auth_method=auth_method,
        approved_host_key=approved_host_key,
        key_path=key_path,
        password=password,
        passphrase=passphrase,
        known_hosts_path=known_hosts_path,
        timeout=8.0,
    ) as client:
        if cancel_event is not None and cancel_event.is_set():
            raise TimeoutError("Remote probe cancelled")
        detected_os, os_detail = _detect_os_from_session(client)
        if detected_os == "unknown":
            warnings.append("OS was not recognized as Linux or Windows; device-specific N10 tools may be unavailable.")

        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            sftp.normalize(".")
            caps.append("sftp")
        except (OSError, paramiko.SSHException):
            warnings.append("SFTP subsystem is unavailable or disabled on this SSH account.")
        finally:
            if sftp is not None:
                try:
                    sftp.close()
                except Exception:  # noqa: BLE001
                    pass

    return RemoteCapabilityProbeResult(
        detected_os=detected_os,
        os_detail=os_detail,
        capabilities=tuple(caps),
        warnings=tuple(warnings),
    )


def _write_exclusive_key_files(
    priv_path: Path,
    pub_path: Path,
    priv_bytes: bytes,
    pub_line: str,
) -> None:
    priv_created = False
    try:
        fd = os.open(os.fspath(priv_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        priv_created = True
        with os.fdopen(fd, "wb") as fh:
            fh.write(priv_bytes)
            fh.flush()
        get_platform().restrict_path_acl(priv_path, is_dir=False)

        pub_fd = os.open(os.fspath(pub_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(pub_fd, "wb") as fh:
            fh.write((pub_line + "\n").encode("utf-8"))
            fh.flush()
    except BaseException:
        if priv_created:
            try:
                priv_path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            pub_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def generate_ssh_ed25519_keypair(
    private_key_path: Path,
    *,
    passphrase: str = "",
    comment: str = "mcp-app",
) -> SSHKeyPairResult:
    """Generate a new Ed25519 OpenSSH keypair exclusively (never overwrites existing files)."""
    priv_path = Path(private_key_path).expanduser()
    pub_path = priv_path.with_name(priv_path.name + ".pub")
    if is_reparse_or_symlink(priv_path) or is_reparse_or_symlink(pub_path) or is_reparse_or_symlink(priv_path.parent):
        raise PermissionError("Refusing symlink or reparse point for SSH key generation")
    if priv_path.exists() or pub_path.exists():
        raise FileExistsError(f"SSH key file already exists: {priv_path}")
    try_init_private_dir(priv_path.parent)

    key = ed25519.Ed25519PrivateKey.generate()
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=enc,
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    clean_comment = re.sub(r"[\r\n\x00]+", "", (comment or "mcp-app").strip())[:64]
    pub_line = pub_bytes.decode("ascii") + (f" {clean_comment}" if clean_comment else "")

    _write_exclusive_key_files(priv_path, pub_path, priv_bytes, pub_line)
    pkey = load_public_host_key("ssh-ed25519", pub_line.split()[1])
    return SSHKeyPairResult(
        private_key_path=str(priv_path),
        public_key_path=str(pub_path),
        public_key_line=pub_line,
        fingerprint_sha256=compute_host_key_sha256(pkey),
    )


def _digest_json(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _known_hosts_digest(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _secret_input_digest(password: str, passphrase: str) -> str:
    payload = f"{len(password)}:{hashlib.sha256(password.encode('utf-8')).hexdigest()}|{len(passphrase)}:{hashlib.sha256(passphrase.encode('utf-8')).hexdigest()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _plan_snapshot_for_draft(
    store: DeviceStore,
    draft: DeviceProfile,
    approved_host_key: ApprovedHostKey,
    *,
    password: str = "",
    passphrase: str = "",
) -> SSHDevicePlanSnapshot:
    existing = store.load_all(strict=True)
    reg_fp = _digest_json({k: v.to_dict() for k, v in sorted(existing.items())})
    kh_digest = _known_hosts_digest(store.managed_known_hosts_path)
    sec_digest = _secret_input_digest(password, passphrase)
    plan_payload = {
        "draft": draft.to_dict(),
        "approved": {
            "host": approved_host_key.host,
            "port": approved_host_key.port,
            "alg": approved_host_key.key_algorithm,
            "sha256": approved_host_key.fingerprint_sha256,
            "b64": approved_host_key.public_key_base64,
        },
        "reg_fp": reg_fp,
        "kh_digest": kh_digest,
        "sec_digest": sec_digest,
    }
    return SSHDevicePlanSnapshot(
        plan_fingerprint=_digest_json(plan_payload),
        registry_fingerprint=reg_fp,
        known_hosts_digest=kh_digest,
        endpoint_key=canonical_endpoint_key(draft.host, draft.port, draft.username),
        approved_host_key_sha256=approved_host_key.fingerprint_sha256,
        secret_digest=sec_digest,
    )


def _check_conflicts(existing: dict[str, DeviceProfile], draft: DeviceProfile) -> None:
    if draft.device_id.casefold() in {k.casefold() for k in existing}:
        raise WizardDeviceConflictError(f"Device ID '{draft.device_id}' already exists")
    new_ep = canonical_endpoint_key(draft.host, draft.port, draft.username)
    for dev in existing.values():
        if canonical_endpoint_key(dev.host, dev.port, dev.username) == new_ep:
            raise WizardDeviceConflictError(
                f"SSH endpoint {draft.host}:{draft.port} ({draft.username or 'default'}) already exists as '{dev.device_id}'"
            )


def _validate_preview_inputs(
    draft: DeviceProfile,
    approved_host_key: ApprovedHostKey,
    password: str,
) -> None:
    load_public_host_key(approved_host_key.key_algorithm, approved_host_key.public_key_base64)
    if (draft.host, draft.port) != (approved_host_key.host, approved_host_key.port):
        raise ValueError("Approved host key endpoint does not match device host and port")
    if draft.auth_method == "password_ref" and not password and not draft.password_ref:
        raise ValueError("Password is required for password_ref authentication")
    if draft.auth_method == "key" and not draft.key_path:
        raise ValueError("Private key path is required for key authentication")


def _format_preview_summary(
    normalized: DeviceProfile,
    approved_host_key: ApprovedHostKey,
    snap: SSHDevicePlanSnapshot,
    *,
    password: str,
    passphrase: str,
) -> tuple[list[str], list[str], str]:
    clients_desc = (
        ", ".join(normalized.allowed_clients)
        if normalized.allowed_clients
        else ("all approved" if normalized.allow_oauth_clients else "none")
    )
    eff_lines = [
        "Global OAuth Safe: BLOCKED (safe profile cannot access remote devices)",
        f"OAuth clients enabled on device: {'YES' if normalized.allow_oauth_clients else 'NO (deny-by-default)'}",
        f"Required client profile: {normalized.min_profile}",
        f"Allowed OAuth client IDs: {clients_desc}",
        (
            f"Capabilities: execute={normalized.permissions.execute}, sftp_read={normalized.permissions.sftp_read}, "
            f"sftp_write={normalized.permissions.sftp_write}, service_control={normalized.permissions.service_control}, "
            f"metrics={normalized.permissions.metrics}, docker_read={normalized.permissions.docker_read}"
        ),
    ]
    warnings: list[str] = []
    if normalized.detected_os == "unknown":
        warnings.append("Remote OS is 'unknown'; platform-specific metrics/services (N10) will remain restricted.")
    if normalized.min_profile == "full" and normalized.allow_oauth_clients:
        warnings.append("Full Access OAuth clients can run arbitrary commands on this device without per-call prompts.")
    endpoint_label = f"{normalized.username}@{normalized.host}:{normalized.port}" if normalized.username else f"{normalized.host}:{normalized.port}"
    auth_flags = (" [SecretStore password set]" if password else "") + (" [key passphrase set]" if passphrase else "")
    summary = "\n".join([
        f"Device ID: {normalized.device_id} ({normalized.name})",
        f"Endpoint: {endpoint_label}",
        f"Host Key (RejectPolicy pinned): {approved_host_key.key_algorithm} {approved_host_key.fingerprint_sha256}",
        f"Auth: {normalized.auth_method}{auth_flags}",
        f"Detected OS: {normalized.detected_os or 'not probed'} | Capabilities: {', '.join(normalized.detected_capabilities) or 'none'}",
        *eff_lines,
        f"Plan Fingerprint: {snap.plan_fingerprint[:16]}",
    ])
    return eff_lines, warnings, summary


def prepare_device_wizard_preview(
    store: DeviceStore,
    draft: DeviceProfile,
    *,
    approved_host_key: ApprovedHostKey,
    password: str = "",
    passphrase: str = "",
) -> SSHDevicePreview:
    """Validate draft against store, compute effective permissions & exact preview snapshot (zero writes)."""
    _validate_preview_inputs(draft, approved_host_key, password)
    with store.lock():
        existing = store.load_all(strict=True)
        _check_conflicts(existing, draft)
        normalized = replace(
            draft,
            strict_host_key=True,
            known_hosts_path=str(store.managed_known_hosts_path),
            pinned_host_key_algorithm=approved_host_key.key_algorithm,
            pinned_host_key_sha256=approved_host_key.fingerprint_sha256,
            pinned_host_key_base64=approved_host_key.public_key_base64,
        )
        snap = _plan_snapshot_for_draft(
            store,
            normalized,
            approved_host_key,
            password=password,
            passphrase=passphrase,
        )
    eff_lines, warnings, summary = _format_preview_summary(
        normalized, approved_host_key, snap, password=password, passphrase=passphrase
    )
    return SSHDevicePreview(
        draft=normalized,
        approved_host_key=approved_host_key,
        effective_permissions_lines=tuple(eff_lines),
        warnings=tuple(warnings),
        summary_text=summary,
        snapshot=snap,
    )


def _capture_preimage(path: Path) -> dict[str, Any]:
    if is_reparse_or_symlink(path):
        raise PermissionError(f"Refusing symlink/reparse target: {path}")
    if path.exists():
        raw = path.read_bytes()
        return {"path": str(path), "existed": True, "content_b64": base64.b64encode(raw).decode("ascii")}
    return {"path": str(path), "existed": False, "content_b64": None}


def _restore_preimages_and_secrets(
    store: DeviceStore,
    preimages: list[dict[str, Any]],
    created_secrets: list[tuple[str, str]],
) -> None:
    from app.core.atomic_io import atomic_write_bytes

    for item in preimages:
        target = Path(item["path"])
        if item["existed"]:
            raw = base64.b64decode(item["content_b64"].encode("ascii"))
            atomic_write_bytes(target, raw, restrict_acl=True)
        else:
            target.unlink(missing_ok=True)
    sec_store = store._secret_store()
    for ns, key in created_secrets:
        try:
            sec_store.delete_secret(ns, key)
        except Exception:  # noqa: BLE001
            pass


def _secret_key_from_ref(store: DeviceStore, ref: str) -> tuple[str, str] | None:
    if not ref:
        return None
    try:
        return store._secret_store().parse_ref(ref)
    except ValueError:
        return None


def _prepare_planned_secrets(
    device_id: str,
    auth_method: str,
    password: str,
    passphrase: str,
) -> tuple[str, str, list[tuple[str, str]]]:
    pwd_suffix = secrets.token_hex(4) if (auth_method == "password_ref" and password) else ""
    pass_suffix = secrets.token_hex(4) if (auth_method == "key" and passphrase) else ""
    created: list[tuple[str, str]] = []
    if pwd_suffix:
        created.append(("ssh", f"{device_id}__password__{pwd_suffix}"))
    if pass_suffix:
        created.append(("ssh", f"{device_id}__passphrase__{pass_suffix}"))
    return pwd_suffix, pass_suffix, created


def commit_device_wizard_plan(
    store: DeviceStore,
    draft: DeviceProfile,
    *,
    approved_host_key: ApprovedHostKey,
    expected_snapshot: SSHDevicePlanSnapshot,
    password: str = "",
    passphrase: str = "",
) -> DeviceProfile:
    """Atomically commit DeviceProfile, app-managed known_hosts entry, and SecretStore refs."""
    load_public_host_key(approved_host_key.key_algorithm, approved_host_key.public_key_base64)
    normalized = replace(
        draft,
        strict_host_key=True,
        known_hosts_path=str(store.managed_known_hosts_path),
        pinned_host_key_algorithm=approved_host_key.key_algorithm,
        pinned_host_key_sha256=approved_host_key.fingerprint_sha256,
        pinned_host_key_base64=approved_host_key.public_key_base64,
    )
    with store.lock():
        existing = store.load_all(strict=True)
        _check_conflicts(existing, normalized)
        cur_snap = _plan_snapshot_for_draft(
            store, normalized, approved_host_key, password=password, passphrase=passphrase
        )
        if cur_snap.plan_fingerprint != expected_snapshot.plan_fingerprint:
            raise WizardStalePlanError(
                "Wizard draft, host key, credentials, or device registry changed after preview; refresh preview first."
            )

        preimages = [
            _capture_preimage(p)
            for p in (store.path, store.managed_known_hosts_path, store._init_marker)
        ]
        pwd_suffix, pass_suffix, created_secrets = _prepare_planned_secrets(
            normalized.device_id, normalized.auth_method, password, passphrase
        )
        atomic_write_json(
            store.tx_journal_path,
            {
                "schema_version": 1,
                "files": preimages,
                "created_secrets": [[ns, k] for ns, k in created_secrets],
            },
            indent=2,
            restrict_acl=True,
        )
        try:
            pwd_ref = (
                store.set_secret(normalized.device_id, "password", password, suffix=pwd_suffix)
                if pwd_suffix
                else normalized.password_ref
            )
            pass_ref = (
                store.set_secret(normalized.device_id, "passphrase", passphrase, suffix=pass_suffix)
                if pass_suffix
                else normalized.passphrase_ref
            )
            final_profile = replace(normalized, password_ref=pwd_ref, passphrase_ref=pass_ref)
            upsert_managed_known_host_entry(store.managed_known_hosts_path, approved_host_key)
            existing[final_profile.device_id] = final_profile
            store.save_all(existing)
        except BaseException:
            _restore_preimages_and_secrets(store, preimages, created_secrets)
            store.tx_journal_path.unlink(missing_ok=True)
            raise
        store.tx_journal_path.unlink(missing_ok=True)
        return final_profile


def rotate_device_host_key(
    store: DeviceStore,
    device_id: str,
    approved_host_key: ApprovedHostKey,
) -> DeviceProfile:
    """Atomically rotate the pinned SSH host key into app-managed known_hosts for an existing device."""
    clean_id = validate_device_id(device_id)
    load_public_host_key(approved_host_key.key_algorithm, approved_host_key.public_key_base64)
    with store.lock():
        existing = store.load_all(strict=True)
        dev = existing.get(clean_id)
        if dev is None:
            raise KeyError(f"Unknown device: {clean_id}")
        if (dev.host, dev.port) != (approved_host_key.host, approved_host_key.port):
            raise ValueError("Rotated host key endpoint does not match device profile")

        watch = [store.path, store._init_marker, store.managed_known_hosts_path]
        preimages = [_capture_preimage(p) for p in watch]
        atomic_write_json(
            store.tx_journal_path,
            {"schema_version": 1, "files": preimages, "created_secrets": []},
            indent=2,
            restrict_acl=True,
        )
        try:
            upsert_managed_known_host_entry(
                store.managed_known_hosts_path,
                approved_host_key,
                replace_existing=True,
            )
            updated = replace(
                dev,
                known_hosts_path=str(store.managed_known_hosts_path),
                pinned_host_key_algorithm=approved_host_key.key_algorithm,
                pinned_host_key_sha256=approved_host_key.fingerprint_sha256,
                pinned_host_key_base64=approved_host_key.public_key_base64,
            )
            existing[clean_id] = updated
            store.save_all(existing)
        except BaseException:
            _restore_preimages_and_secrets(store, preimages, [])
            store.tx_journal_path.unlink(missing_ok=True)
            raise
        store.tx_journal_path.unlink(missing_ok=True)
        return updated


def compute_preview_secret_cleanup(store: DeviceStore, old_refs: tuple[str, ...]) -> None:
    """Best-effort cleanup helper for retired secret refs after profile update."""
    sec_store = store._secret_store()
    for ref in old_refs:
        pair = _secret_key_from_ref(store, ref)
        if pair:
            try:
                sec_store.delete_secret(pair[0], pair[1])
            except Exception:  # noqa: BLE001
                pass
