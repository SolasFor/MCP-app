"""Out-of-tree transactional helper, mutex/handoff guards, verification, and crash rollback."""
from __future__ import annotations

import hmac
import http.client
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import psutil

from app.paths import APP_ID, automation_dir_path, tasks_db_path, user_data_dir
from app.platform import get_platform
from app.platform.base import ProcessIdentity
from app.updater.detector import detect_install_environment, verify_cached_rollback_bundle
from app.updater.models import (
    UpdateBlockReason,
    UpdateError,
    UpdateManifest,
    UpdaterPersistentState,
    UpdateState,
    UpdateTransaction,
    parse_semver,
)
from app.updater.staging import (
    ensure_disk_headroom,
    is_reparse_or_symlink,
    reverify_staged_bundle,
    verify_portable_zip_and_compute_map,
)
from app.updater.trust import TrustPolicy, verify_manifest_and_signature, verify_windows_authenticode

UPDATER_MUTEX_NAME = "Local\\MCPApp-Updater"
_GUI_MUTEX_NAME = "MCPApp-Running"
_VERSION_RE = re.compile(r"\b(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\b")
_TX_ID_RE = re.compile(r"[A-Za-z0-9_-]{3,48}")
_TERMINAL_SCHEDULE_STATUSES = frozenset(
    {
        "succeeded",
        "failed",
        "cancelled",
        "paused_revoked",
        "skipped_idempotent",
        "skipped_concurrency",
        "skipped_misfire",
    }
)


def _sanitize_confined_path(raw: str, allowed_roots: tuple[Path, ...]) -> Path:
    text = str(raw or "").strip()
    if not text or "\x00" in text:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Invalid path value")
    resolved = os.path.realpath(os.path.abspath(text))
    for root in allowed_roots:
        base = os.path.realpath(os.path.abspath(str(root)))
        if resolved == base or resolved.startswith(base + os.sep):
            return Path(resolved)
    raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Path escaped allowed boundary: {resolved}")


def _allowed_install_roots(parent_id: ProcessIdentity | None = None) -> tuple[Path, ...]:
    roots: list[Path] = [Path(tempfile.gettempdir())]
    local_app = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app:
        roots.append(Path(local_app) / "Programs")
    roots.append(user_data_dir())
    if parent_id is not None and "\x00" not in parent_id.executable and not parent_id.executable.startswith("\\\\"):
        exe_path = Path(os.path.realpath(os.path.abspath(parent_id.executable)))
        if exe_path.name.lower() == f"{APP_ID.lower()}.exe":
            roots.append(exe_path.parent)
    return tuple(roots)


def _validate_install_target(install_dir: Path) -> None:
    if str(install_dir).startswith("\\\\"):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Refusing UNC install directory target")
    resolved = install_dir.resolve()
    forbidden = {resolved.parent, Path.home().resolve(), user_data_dir().resolve(), Path(tempfile.gettempdir()).resolve()}
    for env_name in ("SystemRoot", "WINDIR", "ProgramData"):
        val = os.environ.get(env_name, "").strip()
        if val:
            forbidden.add(Path(val).resolve())
    if resolved in forbidden:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Refusing unsafe install directory target: {resolved}")
    if is_reparse_or_symlink(install_dir):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Refusing symlink/reparse install dir: {install_dir}")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def verify_handoff_token(
    expected: str,
    provided: str,
    *,
    issued_at: float,
    now: float | None = None,
    ttl_seconds: float = 120.0,
) -> bool:
    """Validate single-use handoff secret in constant time with strict expiration."""
    if not expected or not provided:
        return False
    cur = time.time() if now is None else now
    if cur < issued_at - 5.0 or (cur - issued_at) > ttl_seconds:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


def has_active_tasks(task_db_path: Path) -> bool:
    """Return True (fail-closed) if SQLite TaskStore has non-terminal tasks or is unreadable/corrupt."""
    if not task_db_path.exists():
        wal_or_key = (
            task_db_path.with_name(f"{task_db_path.name}-wal").exists()
            or task_db_path.with_name(f"{task_db_path.name}-shm").exists()
            or task_db_path.with_suffix(".key").exists()
        )
        return wal_or_key
    if is_reparse_or_symlink(task_db_path) or not task_db_path.is_file():
        return True
    try:
        if task_db_path.stat().st_size == 0:
            return True
        conn = sqlite3.connect(f"file:{task_db_path}?mode=ro", uri=True, timeout=2.0)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')"
            ).fetchone()
            return bool(row and int(row[0]) > 0)
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError):
        return True


def _is_lock_contended(lock_path: Path) -> bool:
    if not lock_path.exists():
        return False
    try:
        fh = lock_path.open("a+b")
    except OSError:
        return True
    try:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            if lock_path.stat().st_size == 0:
                return False
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        fh.close()


def _is_gui_mutex_held() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    k32 = getattr(getattr(ctypes, "windll", None), "kernel32", None)
    if k32 is None:
        return False
    h = k32.OpenMutexW(0x00100000, False, _GUI_MUTEX_NAME)
    if h:
        k32.CloseHandle(h)
        return True
    return False


def _has_processes_inside_dir(install_dir: Path) -> bool:
    prefix = os.path.normcase(os.path.realpath(str(install_dir))) + os.sep
    my_pid = os.getpid()
    for proc in psutil.process_iter(["pid", "exe"]):
        try:
            if proc.info.get("pid") == my_pid:
                continue
            exe = proc.info.get("exe") or ""
            if exe and os.path.normcase(os.path.realpath(exe)).startswith(prefix):
                return True
        except (psutil.Error, OSError):
            continue
    return False


def _is_terminal_history_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    status = entry.get("status")
    return isinstance(status, str) and status.strip() in _TERMINAL_SCHEDULE_STATUSES


def _has_unsafe_or_running_history(hist_path: Path) -> bool:
    if is_reparse_or_symlink(hist_path):
        return True
    if not hist_path.exists():
        return False
    if not hist_path.is_file():
        return True
    try:
        raw = json.loads(hist_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(raw, dict) or set(raw.keys()) != {"version", "runs"}:
        return True
    if type(raw.get("version")) is not int or raw.get("version") != 1:
        return True
    runs = raw.get("runs")
    return not isinstance(runs, list) or any(not _is_terminal_history_entry(entry) for entry in runs)


def _is_active_run_process_alive(item: object) -> bool:
    if not isinstance(item, dict):
        return True
    pid = item.get("pid")
    ctime = item.get("create_time")
    sched_id = item.get("schedule_id")
    if (
        type(pid) is not int
        or pid <= 0
        or not isinstance(ctime, (int, float))
        or isinstance(ctime, bool)
        or ctime <= 0
        or not isinstance(sched_id, str)
        or not sched_id.strip()
    ):
        return True
    try:
        proc = psutil.Process(pid)
        return proc.is_running() and abs(float(proc.create_time()) - float(ctime)) <= 2.0
    except psutil.NoSuchProcess:
        return False
    except (psutil.Error, OSError):
        return True


def _has_active_scheduler_runs(active_path: Path) -> bool:
    if is_reparse_or_symlink(active_path):
        return True
    if not active_path.exists():
        return False
    if not active_path.is_file():
        return True
    try:
        raw = json.loads(active_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(raw, dict) or set(raw.keys()) != {"version", "active"}:
        return True
    if type(raw.get("version")) is not int or raw.get("version") != 1:
        return True
    active = raw.get("active")
    if not isinstance(active, dict):
        return True
    return any(not isinstance(k, str) or not k or _is_active_run_process_alive(v) for k, v in active.items())


def check_active_operations(
    data_dir: Path,
    install_dir: Path | None = None,
    *,
    check_gui_mutex: bool = False,
) -> str:
    """Fail-closed check across TaskStore, scheduler locks/active runs/history, GUI mutex, and install-dir processes."""
    if has_active_tasks(tasks_db_path(data_dir)):
        return UpdateBlockReason.ACTIVE_TASKS
    auto_dir = automation_dir_path(data_dir)
    if (auto_dir.exists() and is_reparse_or_symlink(auto_dir)) or is_reparse_or_symlink(auto_dir / ".automation.lock"):
        return UpdateBlockReason.SCHEDULER_ACTIVE
    if _is_lock_contended(auto_dir / ".automation.lock"):
        return UpdateBlockReason.SCHEDULER_ACTIVE
    if _has_active_scheduler_runs(auto_dir / "active_runs.json"):
        return UpdateBlockReason.SCHEDULER_ACTIVE
    if _has_unsafe_or_running_history(auto_dir / "history.json"):
        return UpdateBlockReason.SCHEDULER_ACTIVE
    if check_gui_mutex and _is_gui_mutex_held():
        return UpdateBlockReason.ACTIVE_TASKS
    if install_dir is not None and install_dir.exists() and _has_processes_inside_dir(install_dir):
        return UpdateBlockReason.ACTIVE_TASKS
    return UpdateBlockReason.OK


def wait_for_parent_exit(parent_identity: ProcessIdentity | None, timeout_s: float = 15.0) -> bool:
    """Wait until captured parent process exits cleanly (strictly requiring valid ProcessIdentity)."""
    if parent_identity is None or parent_identity.pid <= 0 or parent_identity.create_time <= 0:
        return False
    if not parent_identity.executable.strip():
        return False
    adapter = get_platform()
    deadline = time.monotonic() + max(0.5, timeout_s)
    while time.monotonic() < deadline:
        if not adapter.verify_process_identity(parent_identity):
            return True
        time.sleep(0.2)
    return not adapter.verify_process_identity(parent_identity)


def _acquire_os_lock(fh: Any, lock_path: Path) -> None:
    if sys.platform == "win32":
        import msvcrt

        fh.seek(0)
        if lock_path.stat().st_size == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_os_lock(fh: Any) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def acquire_updater_lock(lock_path: Path) -> Iterator[None]:
    """Acquire non-blocking single-instance advisory lock without swallowing body OSErrors."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+b")
    try:
        _acquire_os_lock(fh, lock_path)
    except OSError as exc:
        fh.close()
        raise UpdateError(UpdateBlockReason.ACTIVE_TASKS, f"Another updater transaction is already active: {exc}") from exc
    try:
        yield
    finally:
        _release_os_lock(fh)
        fh.close()


def _persist_tx(state_path: Path, tx: UpdateTransaction) -> None:
    tx.updated_at = _utc_now_iso()
    st = UpdaterPersistentState.load(state_path)
    st.active_transaction = tx
    st.save(state_path)


def _finalize_tx(state_path: Path, tx: UpdateTransaction, *, highest_seen: str | None = None) -> None:
    tx.updated_at = _utc_now_iso()
    st = UpdaterPersistentState.load(state_path)
    st.active_transaction = None
    st.last_completed_tx = tx.to_dict()
    if highest_seen and tx.state == UpdateState.COMMITTED:
        st.highest_seen_version = highest_seen
    st.save(state_path)


def _find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _probe_headless_health(
    exe: Path,
    port: int,
    headless_env: dict[str, str],
    flags: int,
    timeout_s: float,
) -> bool:
    adapter = get_platform()
    proc = subprocess.Popen(
        [str(exe), "--headless"],
        env=headless_env,
        creationflags=flags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    identity = adapter.capture_process_identity(proc.pid)
    try:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
                try:
                    conn.request("GET", "/health")
                    if conn.getresponse().status == 200:
                        return True
                finally:
                    conn.close()
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        return False
    finally:
        if identity is not None:
            adapter.terminate_process_tree(identity, grace_seconds=2.0)
        else:
            proc.terminate()


def _query_binary_version(exe: Path, env: dict[str, str], flags: int) -> str:
    ver_proc = subprocess.run(
        [str(exe), "--version"],
        env=env,
        creationflags=flags,
        timeout=10.0,
        capture_output=True,
        text=True,
        check=False,
    )
    if ver_proc.returncode != 0:
        return ""
    m = _VERSION_RE.search(ver_proc.stdout or "")
    return m.group(0) if m else ""


def verify_updated_binary(
    target_dir: Path,
    target_version: str,
    data_dir: Path | None = None,
    *,
    timeout_s: float = 20.0,
) -> bool:
    """Verify `--version`, `--selftest`, and loopback `--headless /health == 200` on updated binary."""
    exe = target_dir / f"{APP_ID}.exe"
    if not exe.is_file():
        return False
    flags = get_platform().subprocess_creation_flags(detached=False, hide_console=True)
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    if data_dir is not None and data_dir.name == APP_ID:
        env["APPDATA"] = str(data_dir.parent)

    try:
        if _query_binary_version(exe, env, flags) != target_version:
            return False

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "selftest.txt"
            selftest_res = subprocess.run(
                [str(exe), "--selftest", str(report)],
                env=env,
                creationflags=flags,
                timeout=max(10.0, timeout_s),
                check=False,
            )
            if selftest_res.returncode != 0 or not report.is_file():
                return False
            if "RESULT OK" not in report.read_text(encoding="utf-8"):
                return False

        port = _find_free_loopback_port()
        headless_env = dict(env)
        headless_env["MCP_PORT"] = str(port)
        headless_env["MCP_HOST"] = "127.0.0.1"
        return _probe_headless_health(exe, port, headless_env, flags, timeout_s)
    except Exception:  # noqa: BLE001
        return False


def _has_any_reparse_inside(root_dir: Path) -> bool:
    if is_reparse_or_symlink(root_dir):
        return True
    for base, dirs, files in os.walk(root_dir, followlinks=False):
        base_path = Path(base)
        if any(is_reparse_or_symlink(base_path / name) for name in (*dirs, *files)):
            return True
    return False


def _validate_backup_dir_for_restore(install_dir: Path, backup_dir: Path, tx_id: str) -> Path:
    if not _TX_ID_RE.fullmatch(tx_id):
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Invalid transaction id for portable restore")
    _validate_install_target(install_dir)
    if is_reparse_or_symlink(install_dir) or is_reparse_or_symlink(install_dir.parent):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Refusing portable restore across symlink/reparse path")
    expected = install_dir.parent / f".{install_dir.name}-old-{tx_id}"
    if Path(backup_dir).name != expected.name or is_reparse_or_symlink(backup_dir):
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Portable backup path does not match transaction")
    if os.path.normcase(os.path.realpath(str(backup_dir))) != os.path.normcase(os.path.realpath(str(expected))):
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Portable backup canonical path mismatch")
    if not expected.is_dir() or _has_any_reparse_inside(expected):
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Portable backup missing or unsafe")
    env_bk = detect_install_environment(frozen=True, app_dir=expected)
    if env_bk.install_type != "portable" or env_bk.block_reasons:
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Portable backup failed layout integrity check")
    return expected


def _safe_verify_call(verify_fn: Callable[[Path], bool], target_dir: Path) -> bool:
    try:
        return bool(verify_fn(target_dir))
    except Exception:  # noqa: BLE001
        return False


def _restore_portable_backup(
    install_dir: Path,
    backup_dir: Path,
    *,
    tx_id: str,
    verify_fn: Callable[[Path], bool],
) -> Path | None:
    expected = _validate_backup_dir_for_restore(install_dir, backup_dir, tx_id)
    displaced = install_dir.parent / f".{install_dir.name}-displaced-{tx_id}"
    if displaced.exists() or is_reparse_or_symlink(displaced):
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Stale displaced directory prevents safe restore")
    if install_dir.exists():
        install_dir.replace(displaced)
    expected.replace(install_dir)
    if _safe_verify_call(verify_fn, install_dir):
        return displaced if displaced.exists() else None
    install_dir.replace(expected)
    if displaced.exists():
        displaced.replace(install_dir)
    raise UpdateError(
        UpdateBlockReason.NO_ROLLBACK_CONTRACT,
        "Post-recovery verification failed; existing copy and backup preserved",
    )


def _rollback_portable_tx(
    tx: UpdateTransaction,
    install_dir: Path,
    backup_dir: Path,
    state_path: Path,
    *,
    verify_fn: Callable[[Path], bool],
) -> UpdateTransaction:
    tx.state = UpdateState.ROLLING_BACK
    _persist_tx(state_path, tx)
    displaced: Path | None = None
    try:
        displaced = _restore_portable_backup(install_dir, backup_dir, tx_id=tx.tx_id, verify_fn=verify_fn)
        tx.state = UpdateState.ROLLED_BACK
    except Exception as exc:  # noqa: BLE001
        tx.error = f"{tx.error}; rollback failed: {exc}" if tx.error else str(exc)
        tx.state = UpdateState.FAILED
    _finalize_tx(state_path, tx)
    if displaced is not None and displaced.exists():
        shutil.rmtree(displaced, ignore_errors=True)
    return tx


def _prepare_portable_candidate(
    staged_dir: Path,
    candidate_dir: Path,
    install_dir: Path,
    expected_hashes: dict[str, str] | None,
) -> None:
    reverify_staged_bundle(staged_dir, expected_hashes)
    total_bytes = sum(p.stat().st_size for p in staged_dir.rglob("*") if p.is_file())
    ensure_disk_headroom(install_dir.parent, total_bytes)
    if candidate_dir.exists():
        shutil.rmtree(candidate_dir, ignore_errors=True)
    shutil.copytree(staged_dir, candidate_dir, symlinks=False)
    get_platform().restrict_path_acl(candidate_dir, is_dir=True)
    reverify_staged_bundle(candidate_dir, expected_hashes)


def _verify_or_rollback_portable(
    tx: UpdateTransaction,
    install_dir: Path,
    backup_dir: Path,
    state_path: Path,
    target_version: str,
    data_dir: Path | None,
    verify_callback: Callable[[Path, Path | None], bool] | None,
    rollback_verify_callback: Callable[[Path, Path | None], bool] | None,
) -> UpdateTransaction:
    verifier = verify_callback or (lambda tgt, dd: verify_updated_binary(tgt, target_version, dd))
    rb_verifier = rollback_verify_callback or (
        (lambda tgt, dd: verify_updated_binary(tgt, tx.source_version, dd))
        if verify_callback is None
        else (lambda _tgt, _dd: True)
    )
    ok = False
    try:
        ok = bool(verifier(install_dir, data_dir))
    except Exception as exc:  # noqa: BLE001
        tx.error = str(exc)
    if not ok:
        tx.error = tx.error or "Post-upgrade verification failed"
        return _rollback_portable_tx(
            tx,
            install_dir,
            backup_dir,
            state_path,
            verify_fn=lambda d: bool(rb_verifier(d, data_dir)),
        )
    tx.state = UpdateState.COMMITTED
    _finalize_tx(state_path, tx, highest_seen=target_version)
    if backup_dir.exists():
        shutil.rmtree(backup_dir, ignore_errors=True)
    return tx


def apply_portable_transaction(
    *,
    tx_id: str,
    install_dir: Path,
    staged_dir: Path,
    expected_hashes: dict[str, str] | None,
    source_version: str,
    target_version: str,
    state_path: Path,
    data_dir: Path | None = None,
    verify_callback: Callable[[Path, Path | None], bool] | None = None,
    rollback_verify_callback: Callable[[Path, Path | None], bool] | None = None,
    _lock_already_held: bool = False,
) -> UpdateTransaction:
    """Execute atomic portable swap retaining `.MCPApp-old-<tx_id>` until COMMITTED state is persisted."""
    _validate_install_target(install_dir)
    backup_dir = install_dir.parent / f".{install_dir.name}-old-{tx_id}"
    candidate_dir = install_dir.parent / f".{install_dir.name}-new-{tx_id}"
    tx = UpdateTransaction(
        tx_id=tx_id,
        state=UpdateState.PREPARED,
        install_type="portable",
        source_version=source_version,
        target_version=target_version,
        install_dir=str(install_dir),
        backup_dir=str(backup_dir),
        staged_dir=str(staged_dir),
        data_dir=str(data_dir) if data_dir else "",
        created_at=_utc_now_iso(),
    )

    lock_cm = nullcontext() if _lock_already_held else acquire_updater_lock(state_path.parent / ".updater.lock")
    with lock_cm:
        _persist_tx(state_path, tx)
        _prepare_portable_candidate(staged_dir, candidate_dir, install_dir, expected_hashes)

        tx.state = UpdateState.BACKING_UP
        _persist_tx(state_path, tx)
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        if install_dir.exists():
            install_dir.replace(backup_dir)

        tx.state = UpdateState.SWAPPING
        _persist_tx(state_path, tx)
        try:
            candidate_dir.replace(install_dir)
        except Exception as exc:  # noqa: BLE001
            tx.error = str(exc)
            rb_verifier = rollback_verify_callback or (
                (lambda tgt, dd: verify_updated_binary(tgt, source_version, dd))
                if verify_callback is None
                else (lambda _tgt, _dd: True)
            )
            return _rollback_portable_tx(
                tx,
                install_dir,
                backup_dir,
                state_path,
                verify_fn=lambda d: bool(rb_verifier(d, data_dir)),
            )

        tx.state = UpdateState.VERIFYING_NEW
        _persist_tx(state_path, tx)
        return _verify_or_rollback_portable(
            tx,
            install_dir,
            backup_dir,
            state_path,
            target_version,
            data_dir,
            verify_callback,
            rollback_verify_callback,
        )


def _default_run_installer(cmd: list[str], env: dict[str, str]) -> int:
    flags = get_platform().subprocess_creation_flags(detached=False, hide_console=True)
    res = subprocess.run(cmd, env=env, creationflags=flags, check=False)
    return int(res.returncode)


def _run_installed_and_verify(
    *,
    tx: UpdateTransaction,
    install_dir: Path,
    installer_path: Path,
    rollback_installer_path: Path,
    target_version: str,
    source_version: str,
    state_path: Path,
    data_dir: Path | None,
    rollback_expected_sha256: str,
    require_authenticode: bool,
    allowed_thumbprints: tuple[str, ...],
    runner: Callable[[list[str], dict[str, str]], int],
    verify_callback: Callable[[Path, Path | None], bool] | None,
    rollback_verify_callback: Callable[[Path, Path | None], bool] | None,
    env: dict[str, str],
) -> UpdateTransaction:
    silent_flags = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", f"/DIR={install_dir}"]
    rc = runner([str(installer_path), *silent_flags], env)
    verified = False
    if rc == 0:
        tx.state = UpdateState.VERIFYING_NEW
        _persist_tx(state_path, tx)
        verifier = verify_callback or (lambda tgt, dd: verify_updated_binary(tgt, target_version, dd))
        try:
            verified = bool(verifier(install_dir, data_dir))
        except Exception as exc:  # noqa: BLE001
            tx.error = str(exc)

    if rc != 0 or not verified:
        tx.state = UpdateState.ROLLING_BACK
        tx.error = tx.error or f"Installer exit={rc} or verification failed"
        _persist_tx(state_path, tx)
        reverify_staged_bundle(
            rollback_installer_path,
            rollback_expected_sha256,
            require_authenticode=require_authenticode,
            allowed_thumbprints=allowed_thumbprints,
        )
        rb_rc = runner([str(rollback_installer_path), *silent_flags], env)
        rb_verifier = rollback_verify_callback or (lambda tgt, dd: verify_updated_binary(tgt, source_version, dd))
        rb_ok = rb_rc == 0 and bool(rb_verifier(install_dir, data_dir))
        tx.state = UpdateState.ROLLED_BACK if rb_ok else UpdateState.FAILED
        _finalize_tx(state_path, tx)
        return tx

    tx.state = UpdateState.COMMITTED
    _finalize_tx(state_path, tx, highest_seen=target_version)
    return tx


def apply_installed_transaction(
    *,
    tx_id: str,
    install_dir: Path,
    installer_path: Path,
    rollback_installer_path: Path | None,
    source_version: str,
    target_version: str,
    state_path: Path,
    data_dir: Path | None = None,
    expected_sha256: str | None = None,
    rollback_expected_sha256: str | None = None,
    require_authenticode: bool = True,
    allowed_thumbprints: tuple[str, ...] = (),
    run_installer: Callable[[list[str], dict[str, str]], int] | None = None,
    verify_callback: Callable[[Path, Path | None], bool] | None = None,
    rollback_verify_callback: Callable[[Path, Path | None], bool] | None = None,
    _lock_already_held: bool = False,
) -> UpdateTransaction:
    """Execute non-elevated silent Inno Setup upgrade with verified rollback installer and post-rollback check."""
    _validate_install_target(install_dir)
    if rollback_installer_path is None or not rollback_installer_path.is_file():
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Missing rollback installer for installed mode")
    if not expected_sha256 or not rollback_expected_sha256:
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Missing expected SHA-256 for installer or rollback")
    if require_authenticode and not allowed_thumbprints:
        raise UpdateError(UpdateBlockReason.NO_AUTHENTICODE_POLICY, "No trusted Authenticode thumbprints configured")

    tx = UpdateTransaction(
        tx_id=tx_id,
        state=UpdateState.PREPARED,
        install_type="installed",
        source_version=source_version,
        target_version=target_version,
        install_dir=str(install_dir),
        rollback_installer=str(rollback_installer_path),
        data_dir=str(data_dir) if data_dir else "",
        created_at=_utc_now_iso(),
    )
    runner = run_installer or _default_run_installer
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"

    lock_cm = nullcontext() if _lock_already_held else acquire_updater_lock(state_path.parent / ".updater.lock")
    with lock_cm:
        _persist_tx(state_path, tx)
        reverify_staged_bundle(
            installer_path,
            expected_sha256,
            require_authenticode=require_authenticode,
            allowed_thumbprints=allowed_thumbprints,
        )
        reverify_staged_bundle(
            rollback_installer_path,
            rollback_expected_sha256,
            require_authenticode=require_authenticode,
            allowed_thumbprints=allowed_thumbprints,
        )
        tx.state = UpdateState.INSTALLING
        _persist_tx(state_path, tx)
        return _run_installed_and_verify(
            tx=tx,
            install_dir=install_dir,
            installer_path=installer_path,
            rollback_installer_path=rollback_installer_path,
            target_version=target_version,
            source_version=source_version,
            state_path=state_path,
            data_dir=data_dir,
            rollback_expected_sha256=rollback_expected_sha256,
            require_authenticode=require_authenticode,
            allowed_thumbprints=allowed_thumbprints,
            runner=runner,
            verify_callback=verify_callback,
            rollback_verify_callback=rollback_verify_callback,
            env=env,
        )


def _try_sanitize(raw: str, roots: tuple[Path, ...]) -> Path | None:
    if not raw:
        return None
    try:
        return _sanitize_confined_path(raw, roots)
    except UpdateError:
        return None


_BOOT_PORTABLE_STATES = frozenset(
    {
        UpdateState.PREPARED,
        UpdateState.BACKING_UP,
        UpdateState.SWAPPING,
        UpdateState.VERIFYING_NEW,
        UpdateState.ROLLING_BACK,
    }
)
_BOOT_INSTALLED_STATES = frozenset(
    {
        UpdateState.PREPARED,
        UpdateState.INSTALLING,
        UpdateState.VERIFYING_NEW,
        UpdateState.ROLLING_BACK,
    }
)


def _blocked_boot_tx(tx_id: str, error: str, *, tx: UpdateTransaction | None = None) -> UpdateTransaction:
    if tx is not None:
        tx.state = UpdateState.BLOCKED
        tx.error = error
        return tx
    return UpdateTransaction(
        tx_id=tx_id,
        state=UpdateState.BLOCKED,
        install_type="portable",
        source_version="",
        target_version="",
        install_dir="",
        error=error,
    )


def _finalize_blocked_tx(state_path: Path, tx: UpdateTransaction, error: str) -> UpdateTransaction:
    blocked = _blocked_boot_tx(tx.tx_id, error, tx=tx)
    _finalize_tx(state_path, blocked)
    return blocked


def _load_strict_boot_state(state_path: Path) -> tuple[UpdaterPersistentState | None, UpdateTransaction | None]:
    if is_reparse_or_symlink(state_path):
        return None, _blocked_boot_tx("", "Unsafe symlink/reparse state.json; refusing boot recovery")
    if not state_path.exists():
        return None, None
    if not state_path.is_file():
        return None, _blocked_boot_tx("", "Invalid state.json path; refusing boot recovery")
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, _blocked_boot_tx("", "Corrupted updater state.json; refusing automatic boot recovery")
    if not isinstance(raw, dict):
        return None, _blocked_boot_tx("", "Invalid updater state.json format; refusing boot recovery")
    tx_raw = raw.get("active_transaction")
    if tx_raw is None:
        return None, None
    if not isinstance(tx_raw, dict):
        return None, _blocked_boot_tx("", "Invalid active_transaction entry in state.json; refusing boot recovery")
    try:
        highest = str(raw.get("highest_seen_version") or "0.0.0")
        if highest != "0.0.0":
            parse_semver(highest)
    except ValueError:
        return None, _blocked_boot_tx("", "Invalid highest_seen_version in state.json; refusing boot recovery")
    return UpdaterPersistentState.load(state_path), None


def _validate_boot_tx(tx: UpdateTransaction) -> str:
    if not _TX_ID_RE.fullmatch(tx.tx_id):
        return "Untrusted or missing transaction id in state.json"
    allowed_states = _BOOT_PORTABLE_STATES if tx.install_type == "portable" else _BOOT_INSTALLED_STATES
    if tx.state not in allowed_states:
        return f"Unexpected interrupted transaction state: {tx.state}"
    try:
        src_v = parse_semver(tx.source_version)
        tgt_v = parse_semver(tx.target_version)
    except ValueError:
        return "Invalid source or target version in active transaction"
    if tgt_v <= src_v:
        return "Active transaction does not advance version cleanly"
    if not tx.install_dir or (tx.install_type == "portable" and tx.state != UpdateState.PREPARED and not tx.backup_dir):
        return "Missing target or backup path in active transaction"
    return ""


def _verify_boot_manifest(
    tx: UpdateTransaction,
    st: UpdaterPersistentState,
    updates_root: Path,
    policy: TrustPolicy,
) -> str:
    if not policy.auto_install_permitted():
        return "Automatic boot recovery blocked: production trust roots are not configured; inspect installation manually"
    if tx.staged_dir:
        staged_p = _try_sanitize(tx.staged_dir, (updates_root / "staged", updates_root / "downloads"))
        if staged_p is None or is_reparse_or_symlink(staged_p):
            return "Active transaction staged path escapes updates directory"
    manifest_dir = updates_root / "manifests" / tx.target_version
    manifest_path = manifest_dir / "update-manifest.json"
    sig_path = manifest_dir / "update-manifest.json.sig"
    if any(is_reparse_or_symlink(p) for p in (manifest_dir, manifest_path, sig_path)):
        return "Unsafe manifest path for boot recovery verification"
    if not (manifest_path.is_file() and sig_path.is_file()):
        return "Signed update manifest missing; refusing unverified boot recovery"
    try:
        sig_raw = json.loads(sig_path.read_text(encoding="utf-8"))
        manifest = verify_manifest_and_signature(
            manifest_bytes=manifest_path.read_bytes(),
            key_id=str(sig_raw.get("key_id") or ""),
            signature_b64=str(sig_raw.get("signature_b64") or ""),
            current_version=tx.source_version,
            highest_seen_version=st.highest_seen_version,
            policy=policy,
        )
    except (OSError, ValueError, UpdateError) as exc:
        return f"Boot recovery manifest verification failed: {exc}"
    if manifest.version != tx.target_version:
        return "Signed manifest version does not match active transaction"
    return ""


def _bind_boot_install_dir(tx: UpdateTransaction, install_dir: Path | None) -> tuple[Path | None, str]:
    bound = install_dir
    if bound is None and getattr(sys, "frozen", False):
        bound = Path(os.path.realpath(sys.executable)).parent
    if bound is None:
        return None, "Cannot bind boot recovery to a real installation directory"
    tx_dir = Path(tx.install_dir)
    if any(is_reparse_or_symlink(p) for p in (bound, bound.parent, tx_dir, tx_dir.parent)):
        return None, "Refusing boot recovery on symlink or reparse install directory"
    try:
        _validate_install_target(bound)
    except UpdateError as exc:
        return None, str(exc)
    if tx_dir.name != bound.name:
        return None, "Transaction install directory does not match current installation"
    if os.path.normcase(os.path.realpath(str(bound))) != os.path.normcase(os.path.realpath(str(tx_dir))):
        return None, "Transaction install path mismatch against active installation"
    return bound, ""


def _cleanup_after_boot_rollback(
    bound_dir: Path,
    displaced: Path | None,
    tx_id: str,
) -> None:
    if displaced is not None and displaced.exists() and not is_reparse_or_symlink(displaced):
        shutil.rmtree(displaced, ignore_errors=True)
    new_dir = bound_dir.parent / f".{bound_dir.name}-new-{tx_id}"
    if new_dir.is_dir() and not is_reparse_or_symlink(new_dir):
        shutil.rmtree(new_dir, ignore_errors=True)


def _recover_portable_boot(
    tx: UpdateTransaction,
    bound_dir: Path,
    state_path: Path,
    updates_root: Path,
    verifier: Callable[[Path, Path | None], bool],
) -> UpdateTransaction:
    if bound_dir.exists():
        if _has_any_reparse_inside(bound_dir):
            return _finalize_blocked_tx(state_path, tx, "Refusing portable recovery with reparse points in install dir")
        cur_env = detect_install_environment(frozen=True, app_dir=bound_dir)
        if cur_env.install_type != "portable" or UpdateBlockReason.FOREIGN_FILES_IN_INSTALL_DIR in cur_env.block_reasons:
            return _finalize_blocked_tx(state_path, tx, "Install directory failed portable integrity checks")

    data_dir = updates_root.parent
    expected_backup = bound_dir.parent / f".{bound_dir.name}-old-{tx.tx_id}"
    if tx.state == UpdateState.BACKING_UP and not expected_backup.exists() and bound_dir.is_dir():
        if _safe_verify_call(lambda d: verifier(d, data_dir), bound_dir):
            tx.state = UpdateState.ROLLED_BACK
            tx.error = "Verified intact installation after interrupted BACKING_UP"
            _finalize_tx(state_path, tx)
            return tx
        return _finalize_blocked_tx(state_path, tx, "Interrupted BACKING_UP failed post-recovery binary check")

    try:
        displaced = _restore_portable_backup(
            bound_dir,
            Path(tx.backup_dir),
            tx_id=tx.tx_id,
            verify_fn=lambda d: bool(verifier(d, data_dir)),
        )
    except UpdateError as exc:
        return _finalize_blocked_tx(state_path, tx, str(exc))

    tx.state = UpdateState.ROLLED_BACK
    tx.error = "Recovered interrupted swap on startup"
    _finalize_tx(state_path, tx)
    _cleanup_after_boot_rollback(bound_dir, displaced, tx.tx_id)
    return tx


def _recover_installed_tx(
    tx: UpdateTransaction,
    target_dir: Path,
    updates_root: Path,
    state_path: Path,
    policy: TrustPolicy,
    verifier: Callable[[Path, Path | None], bool],
) -> UpdateTransaction:
    cur_env = detect_install_environment(frozen=True, app_dir=target_dir)
    if cur_env.install_type != "installed":
        return _finalize_blocked_tx(state_path, tx, "Target directory is not a valid installed application root")
    verified = verify_cached_rollback_bundle(
        updates_root / "rollback",
        expected_version=tx.source_version,
        policy=policy,
    )
    if verified is None:
        return _finalize_blocked_tx(state_path, tx, "Verified cached rollback installer is missing; manual repair required")
    rb, _rb_sha = verified
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    rc = _default_run_installer(
        [str(rb), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", f"/DIR={target_dir}"],
        env,
    )
    rb_ok = rc == 0 and _safe_verify_call(lambda d: verifier(d, updates_root.parent), target_dir)
    if not rb_ok:
        return _finalize_blocked_tx(state_path, tx, "Installed rollback verification failed; inspect installation manually")
    tx.state = UpdateState.ROLLED_BACK
    tx.error = "Recovered interrupted installed update on startup"
    _finalize_tx(state_path, tx)
    return tx


def _recover_under_lock(
    state_path: Path,
    updates_root: Path,
    install_dir: Path | None,
    policy: TrustPolicy | None,
    verify_callback: Callable[[Path, Path | None], bool] | None,
) -> UpdateTransaction | None:
    st, early_blocked = _load_strict_boot_state(state_path)
    if early_blocked is not None or st is None or st.active_transaction is None:
        return early_blocked

    tx = st.active_transaction
    effective_policy = policy or TrustPolicy.production_default()
    err = _validate_boot_tx(tx) or _verify_boot_manifest(tx, st, updates_root, effective_policy)
    if err:
        return _finalize_blocked_tx(state_path, tx, err)

    bound_dir, bind_err = _bind_boot_install_dir(tx, install_dir)
    if bound_dir is None:
        return _finalize_blocked_tx(state_path, tx, bind_err)

    if tx.state == UpdateState.PREPARED:
        tx.state = UpdateState.FAILED
        tx.error = "Interrupted before file swap; no changes applied"
        _finalize_tx(state_path, tx)
        return tx

    verifier = verify_callback or (lambda d, dd: verify_updated_binary(d, tx.source_version, dd))
    if tx.install_type == "portable":
        return _recover_portable_boot(tx, bound_dir, state_path, updates_root, verifier)
    return _recover_installed_tx(tx, bound_dir, updates_root, state_path, effective_policy, verifier)


def recover_interrupted_update_on_boot(
    state_path: Path,
    updates_root: Path,
    install_dir: Path | None = None,
    *,
    policy: TrustPolicy | None = None,
    verify_callback: Callable[[Path, Path | None], bool] | None = None,
) -> UpdateTransaction | None:
    """Safely recover an interrupted update on startup under `.updater.lock` with strict trust and path checks."""
    lock_path = updates_root / ".updater.lock"
    if any(is_reparse_or_symlink(p) for p in (updates_root, state_path, lock_path)):
        return _blocked_boot_tx("", "Unsafe symlink/reparse updater state path")

    lock_cm = acquire_updater_lock(lock_path)
    try:
        lock_cm.__enter__()
    except UpdateError:
        return UpdateTransaction(
            tx_id="",
            state="ACTIVE_EXTERNAL",
            install_type="portable",
            source_version="",
            target_version="",
            install_dir="",
        )
    try:
        return _recover_under_lock(state_path, updates_root, install_dir, policy, verify_callback)
    finally:
        lock_cm.__exit__(None, None, None)


def _parse_plan_arg(argv: list[str]) -> str:
    if "--plan" not in argv:
        return ""
    idx = argv.index("--plan")
    return argv[idx + 1] if idx + 1 < len(argv) else ""


def _parse_parent_identity(raw: object) -> ProcessIdentity | None:
    if not isinstance(raw, dict):
        return None
    pid = int(raw.get("pid") or 0)
    ctime = float(raw.get("create_time") or 0.0)
    exe = str(raw.get("executable") or "").strip()
    if pid <= 0 or ctime <= 0.0 or not exe:
        return None
    return ProcessIdentity(pid=pid, create_time=ctime, executable=exe, captured_at=float(raw.get("captured_at") or 0.0))


def _maybe_restart_gui(plan: dict, install_dir: Path) -> None:
    exe = _sanitize_confined_path(str(install_dir / f"{APP_ID}.exe"), (install_dir,))
    if not plan.get("restart_gui") or not exe.is_file():
        return
    adapter = get_platform()
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    subprocess.Popen(
        [str(exe)],
        env=env,
        creationflags=adapter.subprocess_creation_flags(detached=True, hide_console=True),
    )


def _load_and_verify_helper_manifest(
    updates_root: Path,
    *,
    target_ver: str,
    actual_source_ver: str,
    highest_seen_version: str,
    policy: TrustPolicy,
) -> UpdateManifest:
    manifest_dir = updates_root / "manifests" / target_ver
    manifest_path = manifest_dir / "update-manifest.json"
    sig_path = manifest_dir / "update-manifest.json.sig"
    if not (manifest_path.is_file() and sig_path.is_file()):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Signed manifest missing for helper verification")
    sig_raw = json.loads(sig_path.read_text(encoding="utf-8"))
    manifest = verify_manifest_and_signature(
        manifest_bytes=manifest_path.read_bytes(),
        key_id=str(sig_raw.get("key_id") or ""),
        signature_b64=str(sig_raw.get("signature_b64") or ""),
        current_version=actual_source_ver,
        highest_seen_version=highest_seen_version,
        policy=policy,
    )
    if parse_semver(manifest.version) <= parse_semver(actual_source_ver):
        raise UpdateError(UpdateBlockReason.DOWNGRADE_BLOCKED, "Helper update must advance binary version")
    return manifest


def _execute_verified_installed_tx(
    *,
    data_dir: Path,
    updates_root: Path,
    install_dir: Path,
    tx_id: str,
    source_ver: str,
    manifest: UpdateManifest,
    policy: TrustPolicy,
) -> UpdateTransaction | None:
    if policy.require_authenticode_for_installer and not policy.allowed_thumbprints:
        return None
    installer_path = updates_root / "downloads" / manifest.installer.name
    if not installer_path.is_file() or installer_path.stat().st_size != manifest.installer.size:
        return None
    if policy.require_authenticode_for_installer:
        if not verify_windows_authenticode(installer_path, allowed_thumbprints=policy.allowed_thumbprints).verified:
            return None
    rb_bundle = verify_cached_rollback_bundle(
        updates_root / "rollback",
        expected_version=source_ver,
        policy=policy,
    )
    if rb_bundle is None:
        return None
    rb_exe, rb_sha = rb_bundle
    return apply_installed_transaction(
        tx_id=tx_id,
        install_dir=install_dir,
        installer_path=installer_path,
        rollback_installer_path=rb_exe,
        source_version=source_ver,
        target_version=manifest.version,
        state_path=updates_root / "state.json",
        data_dir=data_dir,
        expected_sha256=manifest.installer.sha256,
        rollback_expected_sha256=rb_sha,
        require_authenticode=policy.require_authenticode_for_installer,
        allowed_thumbprints=policy.allowed_thumbprints,
        _lock_already_held=True,
    )


def _execute_verified_cli_tx(
    *,
    plan: dict,
    data_dir: Path,
    updates_root: Path,
    install_dir: Path,
    tx_id: str,
    source_ver: str,
    manifest: UpdateManifest,
    policy: TrustPolicy,
) -> UpdateTransaction | None:
    install_type = str(plan.get("install_type") or "")
    env_info = detect_install_environment(
        frozen=True,
        app_dir=install_dir,
        current_version=source_ver,
        rollback_cache_dir=updates_root / "rollback",
        policy=policy,
    )
    if env_info.install_type != install_type or env_info.block_reasons:
        return None

    if install_type == "portable":
        dl_zip = updates_root / "downloads" / manifest.portable.name
        expected_hashes = verify_portable_zip_and_compute_map(
            dl_zip,
            expected_sha256=manifest.portable.sha256,
            expected_size=manifest.portable.size,
        )
        return apply_portable_transaction(
            tx_id=tx_id,
            install_dir=install_dir,
            staged_dir=updates_root / "staged" / manifest.version,
            expected_hashes=expected_hashes,
            source_version=source_ver,
            target_version=manifest.version,
            state_path=updates_root / "state.json",
            data_dir=data_dir,
            _lock_already_held=True,
        )
    if install_type == "installed":
        return _execute_verified_installed_tx(
            data_dir=data_dir,
            updates_root=updates_root,
            install_dir=install_dir,
            tx_id=tx_id,
            source_ver=source_ver,
            manifest=manifest,
            policy=policy,
        )
    return None


def _consume_single_use_plan(state_path: Path, tx_id: str, plan_path: Path) -> bool:
    """Reject replayed handoff ids and burn plan.json under the updater lock."""
    st = UpdaterPersistentState.load(state_path)
    if tx_id in st.consumed_handoff_ids:
        return False
    if st.active_transaction is not None and st.active_transaction.tx_id == tx_id:
        return False
    st.consumed_handoff_ids = (list(st.consumed_handoff_ids) + [tx_id])[-64:]
    st.save(state_path)
    try:
        plan_path.unlink(missing_ok=True)
    except OSError:
        pass
    return True


def _run_locked_cli_tx(
    *,
    plan: dict,
    plan_path: Path,
    data_dir: Path,
    updates_root: Path,
    install_dir: Path,
    tx_id: str,
    target_ver: str,
    policy: TrustPolicy,
) -> int:
    state_path = updates_root / "state.json"
    install_type = str(plan.get("install_type") or "")
    with acquire_updater_lock(updates_root / ".updater.lock"):
        if not _consume_single_use_plan(state_path, tx_id, plan_path):
            return 3
        if check_active_operations(data_dir, install_dir, check_gui_mutex=(install_type == "installed")) != UpdateBlockReason.OK:
            return 5
        actual_source = _query_binary_version(
            install_dir / f"{APP_ID}.exe",
            {**os.environ, "__COMPAT_LAYER": "RunAsInvoker"},
            get_platform().subprocess_creation_flags(detached=False, hide_console=True),
        )
        if not actual_source:
            return 6
        st = UpdaterPersistentState.load(state_path)
        try:
            manifest = _load_and_verify_helper_manifest(
                updates_root,
                target_ver=target_ver,
                actual_source_ver=actual_source,
                highest_seen_version=st.highest_seen_version,
                policy=policy,
            )
        except (OSError, ValueError, UpdateError):
            return 7
        tx = _execute_verified_cli_tx(
            plan=plan,
            data_dir=data_dir,
            updates_root=updates_root,
            install_dir=install_dir,
            tx_id=tx_id,
            source_ver=actual_source,
            manifest=manifest,
            policy=policy,
        )
        if tx is None:
            return 6
    _maybe_restart_gui(plan, install_dir)
    return 0 if tx.state == UpdateState.COMMITTED else 1


def _load_validated_plan(argv: list[str], updates_root: Path) -> tuple[Path, dict] | None:
    plan_path = _try_sanitize(_parse_plan_arg(argv), (updates_root / "helper_run",))
    if plan_path is None or not plan_path.is_file():
        return None
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return (plan_path, plan) if isinstance(plan, dict) else None


def run_apply_update_cli(
    argv: list[str],
    *,
    _policy_override: TrustPolicy | None = None,
    _data_dir_override: Path | None = None,
) -> int:
    """CLI handler for `MCPApp.exe --apply-update --plan <json>` with independent trust checks."""
    policy = _policy_override or TrustPolicy.production_default()
    if not policy.auto_install_permitted():
        return 7

    data_dir = Path(os.path.realpath(str(_data_dir_override or user_data_dir())))
    updates_root = data_dir / "updates"
    loaded = _load_validated_plan(argv, updates_root)
    if loaded is None:
        return 2
    plan_path, plan = loaded

    if not verify_handoff_token(
        str(plan.get("expected_token") or ""),
        os.environ.get("MCP_UPDATER_HANDOFF_TOKEN", ""),
        issued_at=float(plan.get("issued_at") or 0.0),
    ):
        return 3
    parent_id = _parse_parent_identity(plan.get("parent_identity"))
    if not wait_for_parent_exit(parent_id, timeout_s=20.0):
        return 4

    tx_id = str(plan.get("tx_id") or "")
    install_dir = _try_sanitize(str(plan.get("install_dir") or ""), _allowed_install_roots(parent_id))
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,48}", tx_id) or install_dir is None:
        return 6
    try:
        target_ver = parse_semver(str(plan.get("target_version") or "")).raw
        _validate_install_target(install_dir)
    except UpdateError:
        return 6

    return _run_locked_cli_tx(
        plan=plan,
        plan_path=plan_path,
        data_dir=data_dir,
        updates_root=updates_root,
        install_dir=install_dir,
        tx_id=tx_id,
        target_ver=target_ver,
        policy=policy,
    )
