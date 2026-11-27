"""Strict Paramiko SSH & SFTP transport client (RejectPolicy always, path & quota guards)."""
from __future__ import annotations

import base64
import errno
import posixpath
import secrets
import socket
import stat
import time
from pathlib import Path
from typing import Any

import paramiko

from app.core.reconnect import BackoffPolicy
from backend.remote.models import (
    DeviceProfile,
    normalize_posix_path,
    validate_remote_posix_path,
)
from backend.remote.store import DeviceStore

MAX_CMD_OUTPUT_BYTES = 32 * 1024


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

    def _open_client(self, device: DeviceProfile, *, timeout: float = 10.0) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        if not device.known_hosts_path:
            try:
                client.load_system_host_keys()
            except OSError:
                pass
        known_hosts = (
            Path(device.known_hosts_path).expanduser()
            if device.known_hosts_path
            else (Path.home() / ".ssh" / "known_hosts")
        )
        if known_hosts.is_file():
            client.load_host_keys(str(known_hosts))
        # Fail closed: never trust an unverified host when known_hosts is absent or unmatched.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        password = self._store.resolve_secret_ref(device.password_ref) if device.password_ref else None
        passphrase = self._store.resolve_secret_ref(device.passphrase_ref) if device.passphrase_ref else None
        key_filename = str(Path(device.key_path).expanduser()) if (device.auth_method == "key" and device.key_path) else None
        allow_agent = device.auth_method != "password_ref"
        look_for_keys = device.auth_method == "agent"

        try:
            client.connect(
                hostname=device.host,
                port=device.port,
                username=device.username or None,
                password=password if device.auth_method == "password_ref" else None,
                key_filename=key_filename,
                passphrase=passphrase,
                allow_agent=allow_agent,
                look_for_keys=look_for_keys,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
            return client
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise PermissionError(
                f"SSH host key CHANGED for {device.host}:{device.port} (refusing connection)"
            ) from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise PermissionError(f"SSH authentication failed for {device.host}:{device.port}") from exc
        except paramiko.SSHException as exc:
            client.close()
            msg = str(exc)
            if "not found in known_hosts" in msg.lower() or "reject" in msg.lower() or "unknown" in msg.lower():
                raise PermissionError(
                    f"SSH host key not trusted in known_hosts for {device.host}:{device.port}"
                ) from exc
            raise SSHConnectionError(f"SSH protocol error: {exc}") from exc
        except (OSError, socket.error) as exc:
            client.close()
            raise SSHConnectionError(f"SSH network error connecting to {device.host}:{device.port}: {exc}") from exc

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
