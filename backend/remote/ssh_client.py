"""Strict Paramiko SSH & SFTP transport client (RejectPolicy always, path & quota guards)."""
from __future__ import annotations

import base64
import errno
import hmac
import io
import posixpath
import secrets
import socket
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app.core.atomic_io import is_reparse_or_symlink
from app.core.reconnect import BackoffPolicy
from backend.remote.host_keys import (
    ApprovedHostKey,
    KEX_KEY_TYPES_BY_PUBLIC_ALG,
    compute_host_key_sha256,
    inspect_known_hosts,
    load_public_host_key,
)
from backend.remote.models import (
    DeviceProfile,
    format_known_hosts_host,
    normalize_posix_path,
    validate_remote_posix_path,
)
from backend.remote.store import DeviceStore

MAX_CMD_OUTPUT_BYTES = 32 * 1024


class SSHAuthDiagnosticError(PermissionError):
    """Auth failure carrying a machine-readable diagnostic phase/code without leaking secrets."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SSHTrustPolicy:
    """Resolved host-key trust policy for an SSH endpoint."""

    registered: bool = False
    known_hosts_path: str = ""
    pinned: tuple[str, str, str] | None = None
    device_ids: tuple[str, ...] = ()


def _assert_safe_known_hosts_path(path: Path) -> None:
    if is_reparse_or_symlink(path) or is_reparse_or_symlink(path.parent):
        raise PermissionError("Refusing symlink or reparse point known_hosts path")


_PARAMIKO_KEY_CLASSES: tuple[tuple[type[Any], type[paramiko.PKey]], ...] = (
    (rsa.RSAPrivateKey, paramiko.RSAKey),
    (ed25519.Ed25519PrivateKey, paramiko.Ed25519Key),
    (ec.EllipticCurvePrivateKey, paramiko.ECDSAKey),
)


def _validate_private_key_file(key_path: str) -> tuple[Path, bytes]:
    clean = (key_path or "").strip()
    if not clean or "\x00" in clean:
        raise SSHAuthDiagnosticError("key_path_missing", "Select a private key file")
    path = Path(clean).expanduser()
    if is_reparse_or_symlink(path) or is_reparse_or_symlink(path.parent):
        raise SSHAuthDiagnosticError("key_path_symlink", "Refusing symlink or reparse point key path")
    if not path.is_file():
        raise SSHAuthDiagnosticError("key_file_missing", "Private key file was not found")
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > 256 * 1024:
            raise SSHAuthDiagnosticError("key_invalid_file", "Private key file is not a bounded regular file")
        return path, path.read_bytes()
    except OSError as exc:
        raise SSHAuthDiagnosticError("key_unreadable", f"Cannot access private key: {type(exc).__name__}") from exc


def _decode_cryptography_private_key(raw_bytes: bytes, pwd_bytes: bytes | None) -> Any:
    is_openssh = b"BEGIN OPENSSH PRIVATE KEY" in raw_bytes
    loader = serialization.load_ssh_private_key if is_openssh else serialization.load_pem_private_key
    try:
        return loader(data=raw_bytes, password=pwd_bytes)
    except ValueError as val_exc:
        if pwd_bytes is not None:
            try:
                loader(data=raw_bytes, password=None)
            except TypeError:
                raise SSHAuthDiagnosticError(
                    "key_passphrase_invalid", "Encrypted private key passphrase was rejected"
                ) from val_exc
            except ValueError:
                pass
        raise


def _map_key_parse_exception(exc: BaseException, pwd: str | None) -> SSHAuthDiagnosticError:
    if isinstance(exc, paramiko.PasswordRequiredException):
        return SSHAuthDiagnosticError("key_passphrase_required", "Private key is encrypted and requires a passphrase")
    msg = str(exc).lower()
    passphrase_markers = ("password", "passphrase", "encrypted", "decrypt", "incorrect", "bad decrypt")
    if any(tok in msg for tok in passphrase_markers):
        code = "key_passphrase_required" if not pwd else "key_passphrase_invalid"
        label = (
            "Private key is encrypted and requires a passphrase"
            if code == "key_passphrase_required"
            else "Encrypted private key passphrase was rejected"
        )
        return SSHAuthDiagnosticError(code, label)
    return SSHAuthDiagnosticError("key_parse_failed", f"Cannot parse private key ({type(exc).__name__})")


def load_private_key_strict(key_path: str, passphrase: str | None = None) -> paramiko.PKey:
    """Safely load a user-selected regular non-symlink SSH private key without agent/auto fallback."""
    path, raw_bytes = _validate_private_key_file(key_path)
    pwd = passphrase or None
    pwd_bytes = pwd.encode("utf-8") if pwd is not None else None
    try:
        loaded = _decode_cryptography_private_key(raw_bytes, pwd_bytes)
        key_cls = next((cls for crypto_t, cls in _PARAMIKO_KEY_CLASSES if isinstance(loaded, crypto_t)), None)
        if key_cls is None:
            raise SSHAuthDiagnosticError("key_parse_failed", f"Unsupported SSH key type: {type(loaded).__name__}")
        pkey = key_cls.from_private_key(io.StringIO(raw_bytes.decode("utf-8")), password=pwd)
        cert_path = Path(f"{path}-cert.pub")
        if cert_path.is_file() and not is_reparse_or_symlink(cert_path):
            pkey.load_certificate(str(cert_path))
        return pkey
    except SSHAuthDiagnosticError:
        raise
    except (TypeError, paramiko.SSHException, ValueError, OSError) as exc:
        raise _map_key_parse_exception(exc, pwd) from exc


def check_ssh_agent_keys() -> int:
    """Return number of identities exposed by the local SSH agent, or fail closed if unavailable."""
    agent = paramiko.Agent()
    try:
        keys = agent.get_keys()
        count = len(keys)
    except Exception as exc:  # noqa: BLE001
        raise SSHAuthDiagnosticError("agent_unavailable", f"SSH agent is unavailable: {type(exc).__name__}") from exc
    finally:
        try:
            agent.close()
        except Exception:  # noqa: BLE001
            pass
    if count <= 0:
        raise SSHAuthDiagnosticError("agent_unavailable", "SSH agent has no loaded identities")
    return count


def _is_sftp_enoent(exc: BaseException) -> bool:
    """Return True only when an SFTP exception explicitly indicates ENOENT."""
    if isinstance(exc, PermissionError):
        return False
    if isinstance(exc, FileNotFoundError) or getattr(exc, "errno", None) == errno.ENOENT:
        return True
    return getattr(exc, "errno", None) is None and "no such file" in str(exc).lower()


def _is_sftp_unsupported(exc: BaseException) -> bool:
    """Return True when an SFTP server reports an optional operation is unsupported."""
    err_no = getattr(exc, "errno", None)
    if err_no in {getattr(errno, "EOPNOTSUPP", -1), getattr(errno, "ENOSYS", -1)}:
        return True
    msg = str(exc).lower()
    return "unsupported" in msg or "not supported" in msg or "op_unsupported" in msg


def _same_inode_when_reported(expected_lstat: Any, f_info: Any) -> bool:
    """Compare nonzero (st_dev, st_ino) pairs reported by remote SFTP servers."""
    exp_ino = getattr(expected_lstat, "st_ino", None)
    cur_ino = getattr(f_info, "st_ino", None)
    if isinstance(exp_ino, int) and isinstance(cur_ino, int) and exp_ino > 0 and cur_ino > 0:
        if exp_ino != cur_ino:
            return False
        exp_dev = getattr(expected_lstat, "st_dev", None)
        cur_dev = getattr(f_info, "st_dev", None)
        if isinstance(exp_dev, int) and isinstance(cur_dev, int) and exp_dev > 0 and cur_dev > 0:
            return exp_dev == cur_dev
    return True


def _verify_open_reg_handle(
    fh: Any,
    clean_path: str,
    *,
    expected_lstat: Any | None = None,
    max_bytes: int | None = None,
) -> Any:
    """Verify an already-open SFTP file handle refers to a regular file matching expected lstat."""
    try:
        f_info = fh.stat()
    except (OSError, paramiko.SSHException) as exc:
        raise PermissionError(f"Cannot fstat opened SFTP target {clean_path!r}: {type(exc).__name__}") from exc
    mode = getattr(f_info, "st_mode", None)
    if mode is None or stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise PermissionError(f"Opened SFTP handle for {clean_path!r} is not a regular file")
    if expected_lstat is not None and not _same_inode_when_reported(expected_lstat, f_info):
        raise PermissionError(f"SFTP target {clean_path!r} changed inode between lstat and open")
    if max_bytes is not None and int(getattr(f_info, "st_size", 0) or 0) > max_bytes:
        raise PermissionError("Remote file exceeded configured SFTP quota")
    return f_info


def _path_within_roots(candidate: str, allowed_norm: list[str]) -> bool:
    return any(
        root == "/" or candidate == root or candidate.startswith(root.rstrip("/") + "/")
        for root in allowed_norm
    )


def _probe_missing_sftp_ancestor(sftp: paramiko.SFTPClient, cur: str, exc: BaseException) -> None:
    """Distinguish a genuine missing SFTP path from a permission/IO error or dangling symlink."""
    if not _is_sftp_enoent(exc):
        raise PermissionError(
            f"Cannot resolve canonical SFTP ancestor {cur!r}: {type(exc).__name__}"
        ) from exc
    try:
        anc_lst = sftp.lstat(cur)
    except (OSError, paramiko.SSHException) as lstat_exc:
        if not _is_sftp_enoent(lstat_exc):
            raise PermissionError(
                f"Cannot inspect SFTP ancestor {cur!r}: {type(lstat_exc).__name__}"
            ) from lstat_exc
        return
    anc_mode = getattr(anc_lst, "st_mode", None)
    if isinstance(anc_mode, int) and (stat.S_ISLNK(anc_mode) or not stat.S_ISDIR(anc_mode)):
        raise PermissionError(f"Refusing dangling or unresolvable SFTP component {cur!r}") from exc


def _resolve_sftp_write_parent(sftp: paramiko.SFTPClient, clean_path: str) -> str:
    """Resolve the deepest existing canonical ancestor of `dirname(clean_path)` and rejoin tail parts."""
    cur = posixpath.dirname(clean_path) or "/"
    tail_parts: list[str] = []
    while True:
        try:
            real_anc = normalize_posix_path(sftp.normalize(cur))
            break
        except (OSError, paramiko.SSHException) as exc:
            _probe_missing_sftp_ancestor(sftp, cur, exc)
            if cur == "/":
                raise PermissionError(
                    f"Unable to canonicalize remote SFTP path ancestor for {clean_path!r}"
                ) from exc
            leaf = posixpath.basename(cur)
            if leaf:
                tail_parts.append(leaf)
            cur = posixpath.dirname(cur) or "/"
    if not tail_parts:
        return real_anc
    return normalize_posix_path(posixpath.join(real_anc, *reversed(tail_parts)))


def _verify_existing_sftp_write_target(
    sftp: paramiko.SFTPClient,
    clean_path: str,
    allowed_norm: list[str],
) -> None:
    """Reject existing symlinks/special files at `clean_path` and verify canonical root membership."""
    try:
        target_lst = sftp.lstat(clean_path)
    except (OSError, paramiko.SSHException) as exc:
        if not _is_sftp_enoent(exc):
            raise PermissionError(
                f"Cannot inspect remote SFTP target {clean_path!r}: {type(exc).__name__}"
            ) from exc
        return
    mode = getattr(target_lst, "st_mode", None)
    if mode is not None and not isinstance(mode, int):
        return
    if mode is None or stat.S_ISLNK(mode):
        raise PermissionError(f"Refusing SFTP write through symlink: {clean_path!r}")
    if not stat.S_ISREG(mode):
        raise PermissionError(f"Refusing SFTP write to non-regular target: {clean_path!r}")
    try:
        resolved_existing = normalize_posix_path(sftp.normalize(clean_path))
    except (OSError, paramiko.SSHException) as exc:
        raise PermissionError(
            f"Cannot canonicalize existing SFTP target {clean_path!r}: {type(exc).__name__}"
        ) from exc
    if not _path_within_roots(resolved_existing, allowed_norm):
        raise PermissionError(
            f"Resolved existing SFTP target {resolved_existing!r} escapes allowed SFTP roots"
        )


class SSHConnectionError(RuntimeError):
    """Raised when an SSH connection drops, times out, or fails transport I/O."""


class SSHConnectionManager:
    """Stateless-per-call strict SSH/SFTP wrapper enforcing known_hosts RejectPolicy.

    Note on SFTP v3 TOCTOU boundaries: standard SFTP v3 (`SSH_FXP_OPEN`) has no
    `O_NOFOLLOW` or directory-fd `openat2(RESOLVE_NO_SYMLINKS)` primitive. This
    client minimizes windows via ancestor `normalize` + `lstat` checks, `"xb"`
    exclusive creation for new files, sibling `"xb"` staging + `posix_rename` for
    overwrites when supported, and `fh.stat()` regular-file + inode verification.
    """

    def __init__(self, store: DeviceStore) -> None:
        self._store = store
        self._health_backoff = BackoffPolicy(base_seconds=0.25, max_seconds=1.5, max_attempts=2)

    @staticmethod
    def _build_pinned_transport_factory(expected_alg: str):
        preferred = KEX_KEY_TYPES_BY_PUBLIC_ALG.get(expected_alg, (expected_alg,))

        def _factory(sock: socket.socket, disabled_algorithms: dict[str, Any] | None = None) -> paramiko.Transport:
            transport = paramiko.Transport(sock, disabled_algorithms=disabled_algorithms)
            sec_opts = transport.get_security_options()
            allowed = [k for k in preferred if k in sec_opts.key_types]
            if allowed:
                sec_opts.key_types = allowed
            return transport

        return _factory

    @staticmethod
    def _verify_connected_pin(client: paramiko.SSHClient, expected_key: paramiko.PKey, host: str, port: int) -> None:
        transport = client.get_transport() if hasattr(client, "get_transport") else None
        if transport is None:
            return
        remote_key = transport.get_remote_server_key()
        if remote_key is None:
            raise PermissionError(f"SSH server {host}:{port} provided no host key")
        if remote_key.get_name() != expected_key.get_name() or not hmac.compare_digest(
            remote_key.asbytes(), expected_key.asbytes()
        ):
            raise PermissionError(f"SSH host key CHANGED/MISMATCHED for {host}:{port}")

    @staticmethod
    def _validate_pinned_policy(host: str, port: int, policy: SSHTrustPolicy) -> paramiko.PKey:
        assert policy.pinned is not None
        expected_alg, expected_sha, expected_b64 = policy.pinned
        try:
            expected_pkey = load_public_host_key(expected_alg, expected_b64)
        except ValueError as exc:
            raise PermissionError(str(exc)) from exc
        if compute_host_key_sha256(expected_pkey) != expected_sha:
            raise PermissionError("Pinned SSH host key SHA-256 mismatch")
        if policy.known_hosts_path:
            kh_check = inspect_known_hosts(
                host,
                port,
                expected_pkey,
                known_hosts_path=policy.known_hosts_path,
                include_system_known_hosts=False,
            )
            if kh_check.status == "host_key_changed":
                raise PermissionError(
                    f"SSH host key CHANGED in known_hosts for {host}:{port} (refusing connection)"
                )
        return expected_pkey

    @staticmethod
    def validate_host_key_trust_policy(*, host: str, port: int, policy: SSHTrustPolicy) -> paramiko.PKey | None:
        """Validate a resolved SSH host-key trust policy fail-closed before connecting."""
        if policy.known_hosts_path:
            _assert_safe_known_hosts_path(Path(policy.known_hosts_path).expanduser())
        if policy.pinned and any(policy.pinned):
            return SSHConnectionManager._validate_pinned_policy(host, port, policy)
        if not policy.known_hosts_path:
            return None
        kh_path = Path(policy.known_hosts_path).expanduser()
        if not kh_path.is_file():
            return None
        try:
            paramiko.HostKeys(str(kh_path))
        except (OSError, paramiko.SSHException) as exc:
            raise PermissionError(f"Unreadable known_hosts file: {type(exc).__name__}") from exc
        return None

    @staticmethod
    def _configure_pinned_trust(
        client: paramiko.SSHClient,
        *,
        host: str,
        port: int,
        known_hosts_path: str,
        pinned: tuple[str, str, str],
    ) -> tuple[paramiko.PKey, Any]:
        expected_alg = pinned[0]
        expected_pkey = SSHConnectionManager.validate_host_key_trust_policy(
            host=host,
            port=port,
            policy=SSHTrustPolicy(registered=True, known_hosts_path=known_hosts_path, pinned=pinned),
        )
        assert expected_pkey is not None
        host_keys = client.get_host_keys()
        host_keys.clear()
        host_keys.add(format_known_hosts_host(host, port), expected_alg, expected_pkey)
        if port == 22 and ":" not in host:
            host_keys.add(f"[{host}]:22", expected_alg, expected_pkey)
        return expected_pkey, SSHConnectionManager._build_pinned_transport_factory(expected_alg)

    @staticmethod
    def _prepare_host_key_trust(
        client: paramiko.SSHClient,
        *,
        host: str,
        port: int,
        known_hosts_path: str,
        pinned: tuple[str, str, str] | None,
    ) -> tuple[paramiko.PKey | None, Any | None]:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        if pinned and any(pinned):
            return SSHConnectionManager._configure_pinned_trust(
                client, host=host, port=port, known_hosts_path=known_hosts_path, pinned=pinned
            )
        if known_hosts_path:
            kh_path = Path(known_hosts_path).expanduser()
            _assert_safe_known_hosts_path(kh_path)
            if kh_path.is_file():
                client.load_host_keys(str(kh_path))
            return None, None
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        known_hosts = Path.home() / ".ssh" / "known_hosts"
        if not is_reparse_or_symlink(known_hosts) and not is_reparse_or_symlink(known_hosts.parent) and known_hosts.is_file():
            client.load_host_keys(str(known_hosts))
        return None, None

    def _build_auth_kwargs(
        self,
        *,
        auth_method: str,
        key_path: str,
        password: str | None,
        passphrase: str | None,
        strict_key_load: bool,
    ) -> dict[str, Any]:
        if auth_method == "password_ref":
            if not password:
                raise SSHAuthDiagnosticError("password_missing", "SSH password is not configured")
            return {
                "password": password,
                "pkey": None,
                "key_filename": None,
                "passphrase": None,
                "allow_agent": False,
                "look_for_keys": False,
            }
        if auth_method == "key":
            pkey = load_private_key_strict(key_path, passphrase) if strict_key_load else None
            return {
                "password": None,
                "pkey": pkey,
                "key_filename": None if pkey is not None else (str(Path(key_path).expanduser()) if key_path else None),
                "passphrase": None if pkey is not None else passphrase,
                "allow_agent": False,
                "look_for_keys": False,
            }
        return {
            "password": None,
            "pkey": None,
            "key_filename": None,
            "passphrase": None,
            "allow_agent": True,
            "look_for_keys": False,
        }

    @staticmethod
    def _translate_ssh_exception(exc: paramiko.SSHException, host: str, port: int) -> Exception:
        msg = str(exc)
        low = msg.lower()
        if "no acceptable host key" in low:
            return PermissionError(
                f"SSH host key algorithm changed or mismatched for {host}:{port} (refusing connection)"
            )
        if "not found in known_hosts" in low or "reject" in low or "unknown" in low:
            return PermissionError(f"SSH host key not trusted in known_hosts for {host}:{port}")
        return SSHConnectionError(f"SSH protocol error: {exc}")

    def _connect_with_params(
        self,
        *,
        host: str,
        port: int,
        username: str,
        auth_method: str,
        key_path: str,
        password: str | None,
        passphrase: str | None,
        known_hosts_path: str,
        pinned: tuple[str, str, str] | None,
        timeout: float,
        strict_key_load: bool,
    ) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        try:
            expected_pkey, transport_factory = self._prepare_host_key_trust(
                client, host=host, port=port, known_hosts_path=known_hosts_path, pinned=pinned
            )
            auth_kwargs = self._build_auth_kwargs(
                auth_method=auth_method,
                key_path=key_path,
                password=password,
                passphrase=passphrase,
                strict_key_load=strict_key_load,
            )
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": username or None,
                "timeout": timeout,
                "banner_timeout": timeout,
                "auth_timeout": timeout,
                **auth_kwargs,
            }
            if transport_factory is not None:
                connect_kwargs["transport_factory"] = transport_factory
            client.connect(**connect_kwargs)
            if expected_pkey is not None:
                self._verify_connected_pin(client, expected_pkey, host, port)
            return client
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise PermissionError(f"SSH host key CHANGED for {host}:{port} (refusing connection)") from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise SSHAuthDiagnosticError("auth_failed", f"SSH authentication failed for {host}:{port}") from exc
        except paramiko.SSHException as exc:
            client.close()
            raise self._translate_ssh_exception(exc, host, port) from exc
        except (SSHAuthDiagnosticError, PermissionError):
            client.close()
            raise
        except (OSError, socket.error) as exc:
            client.close()
            raise SSHConnectionError(f"SSH network error connecting to {host}:{port}: {exc}") from exc

    @contextmanager
    def open_verified_session(
        self,
        *,
        host: str,
        port: int,
        username: str,
        auth_method: str,
        approved_host_key: ApprovedHostKey,
        key_path: str = "",
        password: str | None = None,
        passphrase: str | None = None,
        known_hosts_path: str = "",
        timeout: float = 8.0,
    ) -> Iterator[paramiko.SSHClient]:
        """Open a single verified SSH session bound to an approved pre-auth host key pin."""
        if approved_host_key.host != host or approved_host_key.port != int(port):
            raise PermissionError("Approved host key does not match target endpoint")
        if auth_method == "agent":
            check_ssh_agent_keys()
        client = self._connect_with_params(
            host=host,
            port=int(port),
            username=username,
            auth_method=auth_method,
            key_path=key_path,
            password=password,
            passphrase=passphrase,
            known_hosts_path=known_hosts_path,
            pinned=(
                approved_host_key.key_algorithm,
                approved_host_key.fingerprint_sha256,
                approved_host_key.public_key_base64,
            ),
            timeout=timeout,
            strict_key_load=True,
        )
        try:
            yield client
        finally:
            client.close()

    def _open_client(self, device: DeviceProfile, *, timeout: float = 10.0) -> paramiko.SSHClient:
        password = self._store.resolve_secret_ref(device.password_ref) if device.password_ref else None
        passphrase = self._store.resolve_secret_ref(device.passphrase_ref) if device.passphrase_ref else None
        pinned = (
            (
                device.pinned_host_key_algorithm,
                device.pinned_host_key_sha256,
                device.pinned_host_key_base64,
            )
            if device.has_pinned_host_key()
            else None
        )
        strict_key_load = bool(device.auth_method == "key" and device.key_path and Path(device.key_path).expanduser().exists())
        effective_kh = device.known_hosts_path
        if not effective_kh and pinned is not None and self._store.managed_known_hosts_path.exists():
            effective_kh = str(self._store.managed_known_hosts_path)
        return self._connect_with_params(
            host=device.host,
            port=device.port,
            username=device.username,
            auth_method=device.auth_method,
            key_path=device.key_path,
            password=password,
            passphrase=passphrase,
            known_hosts_path=effective_kh,
            pinned=pinned,
            timeout=timeout,
            strict_key_load=strict_key_load,
        )

    def run_command(
        self,
        device: DeviceProfile,
        command: str,
        *,
        timeout: int = 12,
    ) -> dict[str, Any]:
        bounded_timeout = max(1, min(int(timeout), 600))
        client = self._open_client(device, timeout=min(10.0, float(bounded_timeout)))
        try:
            _, stdout, _stderr = client.exec_command(command, timeout=bounded_timeout)
            chan = stdout.channel
            out_buf = bytearray()
            err_buf = bytearray()
            deadline = time.monotonic() + bounded_timeout
            while True:
                if time.monotonic() >= deadline:
                    chan.close()
                    raise TimeoutError(f"SSH command timed out after {bounded_timeout}s")
                progressed = False
                if chan.recv_ready():
                    chunk = chan.recv(16384)
                    out_buf.extend(chunk[: max(0, MAX_CMD_OUTPUT_BYTES - len(out_buf))])
                    progressed = True
                if chan.recv_stderr_ready():
                    chunk = chan.recv_stderr(16384)
                    err_buf.extend(chunk[: max(0, MAX_CMD_OUTPUT_BYTES - len(err_buf))])
                    progressed = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if chan.closed and not chan.recv_ready() and not chan.recv_stderr_ready():
                    raise SSHConnectionError(
                        "SSH channel closed unexpectedly; remote process completion could not be confirmed"
                    )
                if not progressed:
                    time.sleep(0.05)
            code = chan.recv_exit_status()
            if code < 0:
                raise SSHConnectionError(
                    "SSH connection lost before remote exit status arrived"
                )
            return {
                "exit_code": int(code),
                "stdout": out_buf.decode("utf-8", errors="replace"),
                "stderr": err_buf.decode("utf-8", errors="replace"),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError, EOFError) as exc:
            raise SSHConnectionError(
                f"SSH transport interrupted ({type(exc).__name__}); remote process state is unconfirmed"
            ) from exc
        finally:
            client.close()

    def probe_health(self, device: DeviceProfile) -> dict[str, Any]:
        """Run bounded read-only health check with small backoff on transient socket failures."""
        t0 = time.monotonic()
        last_err: Exception | None = None
        for attempt in range(self._health_backoff.max_attempts):
            try:
                res = self.run_command(device, "uname -s -m", timeout=5)
                latency_ms = int((time.monotonic() - t0) * 1000)
                return {
                    "device_id": device.device_id,
                    "reachable": res["exit_code"] == 0,
                    "latency_ms": latency_ms,
                    "system": res["stdout"].strip(),
                    "stderr": res["stderr"].strip(),
                }
            except PermissionError:
                raise
            except (SSHConnectionError, TimeoutError) as exc:
                last_err = exc
                if attempt + 1 < self._health_backoff.max_attempts:
                    time.sleep(min(0.4, self._health_backoff.next_delay(attempt + 1)))
        assert last_err is not None
        raise last_err

    def _verify_sftp_canonical(
        self,
        sftp: paramiko.SFTPClient,
        clean_path: str,
        allowed_roots: tuple[str, ...],
        *,
        for_write: bool = False,
    ) -> str:
        allowed_norm = [normalize_posix_path(r) for r in allowed_roots]
        if not for_write:
            try:
                resolved = normalize_posix_path(sftp.normalize(clean_path))
            except (OSError, paramiko.SSHException) as exc:
                raise PermissionError(
                    f"Unable to canonicalize remote SFTP path {clean_path!r}: {type(exc).__name__}"
                ) from exc
            if not _path_within_roots(resolved, allowed_norm):
                raise PermissionError(f"Resolved remote symlink/path {resolved!r} escapes allowed SFTP roots")
            return clean_path

        real_parent = _resolve_sftp_write_parent(sftp, clean_path)
        real_target = normalize_posix_path(posixpath.join(real_parent, posixpath.basename(clean_path)))
        if not (_path_within_roots(real_parent, allowed_norm) and _path_within_roots(real_target, allowed_norm)):
            raise PermissionError(f"Resolved remote symlink/path {real_target!r} escapes allowed SFTP roots")
        _verify_existing_sftp_write_target(sftp, clean_path, allowed_norm)
        return clean_path

    def _inspect_regular_target(
        self,
        sftp: paramiko.SFTPClient,
        clean_path: str,
        *,
        allow_absent: bool,
    ) -> Any | None:
        """Inspect remote target via lstat and fail closed on symlinks, special files, or non-ENOENT errors."""
        try:
            lst = sftp.lstat(clean_path)
        except (OSError, paramiko.SSHException) as exc:
            if allow_absent and _is_sftp_enoent(exc):
                return None
            if _is_sftp_enoent(exc):
                raise SSHConnectionError(f"Remote SFTP file not found: {clean_path!r}") from exc
            raise PermissionError(f"Cannot lstat remote SFTP target {clean_path!r}: {type(exc).__name__}") from exc
        mode = getattr(lst, "st_mode", None)
        if mode is None or stat.S_ISLNK(mode):
            raise PermissionError(f"Refusing SFTP symlink target: {clean_path!r}")
        if not stat.S_ISREG(mode):
            raise PermissionError(f"Refusing SFTP non-regular target: {clean_path!r}")
        return lst

    def sftp_list(self, device: DeviceProfile, remote_path: str) -> dict[str, Any]:
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots)
            dir_lst = sftp.lstat(clean)
            if dir_lst.st_mode is None or stat.S_ISLNK(dir_lst.st_mode) or not stat.S_ISDIR(dir_lst.st_mode):
                raise PermissionError(f"Refusing SFTP list of non-directory or symlink path: {clean!r}")
            entries = []
            for attr in sftp.listdir_attr(clean)[:250]:
                mode = attr.st_mode or 0
                kind = "symlink" if stat.S_ISLNK(mode) else ("dir" if stat.S_ISDIR(mode) else "file")
                entries.append({
                    "name": attr.filename,
                    "type": kind,
                    "size": int(attr.st_size or 0),
                    "mtime": int(attr.st_mtime or 0),
                })
            return {"device_id": device.device_id, "path": clean, "entries": entries}
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP list failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def sftp_download(
        self,
        device: DeviceProfile,
        remote_path: str,
        *,
        as_base64: bool = False,
    ) -> dict[str, Any]:
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots)
            lstat_info = self._inspect_regular_target(sftp, clean, allow_absent=False)
            assert lstat_info is not None
            declared_size = int(lstat_info.st_size or 0)
            if declared_size > device.sftp_max_bytes:
                raise PermissionError(
                    f"Remote file ({declared_size} bytes) exceeds SFTP quota ({device.sftp_max_bytes} bytes)"
                )
            with sftp.open(clean, "rb") as fh:
                _verify_open_reg_handle(
                    fh,
                    clean,
                    expected_lstat=lstat_info,
                    max_bytes=device.sftp_max_bytes,
                )
                raw = fh.read(device.sftp_max_bytes + 1)
            if len(raw) > device.sftp_max_bytes:
                raise PermissionError("Remote file stream exceeded configured SFTP quota")
            return {
                "device_id": device.device_id,
                "path": clean,
                "size_bytes": len(raw),
                "encoding": "base64" if as_base64 else "utf-8",
                "content": base64.b64encode(raw).decode("ascii") if as_base64 else raw.decode("utf-8", errors="replace"),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP download failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def sftp_upload(
        self,
        device: DeviceProfile,
        remote_path: str,
        data: bytes,
    ) -> dict[str, Any]:
        if len(data) > device.sftp_max_bytes:
            raise PermissionError(
                f"Upload payload ({len(data)} bytes) exceeds SFTP quota ({device.sftp_max_bytes} bytes)"
            )
        clean = validate_remote_posix_path(remote_path, device.allowed_sftp_roots)
        client = self._open_client(device, timeout=10.0)
        sftp: paramiko.SFTPClient | None = None
        try:
            sftp = client.open_sftp()
            self._verify_sftp_canonical(sftp, clean, device.allowed_sftp_roots, for_write=True)
            target_lstat = self._inspect_regular_target(sftp, clean, allow_absent=True)
            if target_lstat is None:
                # Exclusive creation prevents following a symlink raced into place after lstat.
                try:
                    with sftp.open(clean, "wxb") as fh:
                        _verify_open_reg_handle(fh, clean)
                        fh.write(data)
                except (OSError, paramiko.SSHException) as exc:
                    if self._target_exists_on_open_race(sftp, clean, exc):
                        raise PermissionError(
                            f"Refusing SFTP upload after concurrent target appearance at {clean!r}"
                        ) from exc
                    raise
            else:
                self._upload_overwrite_staged(sftp, clean, data, target_lstat)
            return {
                "device_id": device.device_id,
                "path": clean,
                "bytes_written": len(data),
            }
        except PermissionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(f"SFTP upload failed: {exc}") from exc
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    @staticmethod
    def _target_exists_on_open_race(sftp: paramiko.SFTPClient, clean: str, exc: BaseException) -> bool:
        if isinstance(exc, FileExistsError) or getattr(exc, "errno", None) == errno.EEXIST:
            return True
        if "failure" not in str(exc).lower():
            return False
        try:
            sftp.lstat(clean)
            return True
        except (OSError, paramiko.SSHException):
            return False

    def _upload_overwrite_staged(
        self,
        sftp: paramiko.SFTPClient,
        clean: str,
        data: bytes,
        initial_lstat: Any,
    ) -> None:
        """Overwrite an existing regular SFTP file via sibling exclusive staging + posix_rename."""
        tmp_clean = posixpath.join(
            posixpath.dirname(clean) or "/",
            f".{posixpath.basename(clean)}.mcp-{secrets.token_hex(6)}.tmp",
        )
        staged = False
        try:
            with sftp.open(tmp_clean, "wxb") as fh:
                staged = True
                _verify_open_reg_handle(fh, tmp_clean)
                fh.write(data)
            cur_lstat = self._inspect_regular_target(sftp, clean, allow_absent=False)
            if cur_lstat is not None and not _same_inode_when_reported(initial_lstat, cur_lstat):
                raise PermissionError(f"SFTP target {clean!r} changed inode before atomic rename")
            sftp.posix_rename(tmp_clean, clean)
            staged = False
        except (OSError, paramiko.SSHException) as exc:
            if staged:
                try:
                    sftp.remove(tmp_clean)
                except (OSError, paramiko.SSHException):
                    pass
                staged = False
            if not _is_sftp_unsupported(exc):
                raise
            # Minimal/legacy SFTP servers without posix-rename fall back to verified in-place write.
            cur_lstat = self._inspect_regular_target(sftp, clean, allow_absent=False)
            assert cur_lstat is not None
            if not _same_inode_when_reported(initial_lstat, cur_lstat):
                raise PermissionError(f"SFTP target {clean!r} changed inode before overwrite") from exc
            with sftp.open(clean, "wb") as fh:
                _verify_open_reg_handle(fh, clean, expected_lstat=cur_lstat)
                fh.write(data)
        except BaseException:
            if staged:
                try:
                    sftp.remove(tmp_clean)
                except (OSError, paramiko.SSHException):
                    pass
            raise
