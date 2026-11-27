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
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from app.paths import APP_ID, user_data_dir
from app.platform import get_platform
from app.platform.base import ProcessIdentity
from app.updater.models import (
    UpdateBlockReason,
    UpdateError,
    UpdaterPersistentState,
    UpdateState,
    UpdateTransaction,
    parse_semver,
)
from app.updater.staging import reverify_staged_bundle

UPDATER_MUTEX_NAME = "Local\\MCPApp-Updater"
_ACTIVE_TASK_STATUSES = ("queued", "pending", "running", "cancelling")


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


def _allowed_install_roots() -> tuple[Path, ...]:
    roots: list[Path] = [Path(sys.executable).resolve().parent.parent, Path(tempfile.gettempdir())]
    local_app = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app:
        roots.append(Path(local_app) / "Programs")
    roots.append(user_data_dir())
    return tuple(roots)


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
    """Return True if SQLite TaskStore reports any queued/running/cancelling background task."""
    if not task_db_path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{task_db_path}?mode=ro", uri=True, timeout=2.0)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('queued', 'pending', 'running', 'cancelling')"
            ).fetchone()
            return bool(row and int(row[0]) > 0)
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def wait_for_parent_exit(parent_identity: ProcessIdentity | None, timeout_s: float = 15.0) -> bool:
    """Wait until captured parent process exits cleanly (verified via ProcessIdentity)."""
    if parent_identity is None:
        return True
    adapter = get_platform()
    deadline = time.monotonic() + max(0.5, timeout_s)
    while time.monotonic() < deadline:
        if not adapter.verify_process_identity(parent_identity):
            return True
        time.sleep(0.2)
    return not adapter.verify_process_identity(parent_identity)


@contextmanager
def acquire_updater_lock(lock_path: Path) -> Iterator[None]:
    """Acquire non-blocking single-instance advisory lock for updater transactions."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+b")
    locked = False
    try:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            if lock_path.stat().st_size == 0:
                fh.write(b"0")
                fh.flush()
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            locked = True
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        yield
    except OSError as exc:
        raise UpdateError(UpdateBlockReason.ACTIVE_TASKS, f"Another updater transaction is already active: {exc}") from exc
    finally:
        if locked:
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
        ver_proc = subprocess.run(
            [str(exe), "--version"],
            env=env,
            creationflags=flags,
            timeout=10.0,
            capture_output=True,
            text=True,
            check=False,
        )
        if ver_proc.returncode != 0 or target_version not in (ver_proc.stdout or ""):
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


def _restore_portable_backup(install_dir: Path, backup_dir: Path) -> None:
    if not backup_dir.is_dir():
        return
    if install_dir.exists():
        broken = install_dir.with_name(f".{install_dir.name}-failed-{int(time.time())}")
        if broken.exists():
            shutil.rmtree(broken, ignore_errors=True)
        install_dir.replace(broken)
        backup_dir.replace(install_dir)
        shutil.rmtree(broken, ignore_errors=True)
    else:
        backup_dir.replace(install_dir)


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
) -> UpdateTransaction:
    """Execute atomic portable swap retaining `.MCPApp-old-<tx_id>` until health checks commit."""
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

    with acquire_updater_lock(state_path.parent / ".updater.lock"):
        _persist_tx(state_path, tx)
        reverify_staged_bundle(staged_dir, expected_hashes)

        if candidate_dir.exists():
            shutil.rmtree(candidate_dir, ignore_errors=True)
        shutil.copytree(staged_dir, candidate_dir, symlinks=False)

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
            tx.state = UpdateState.ROLLING_BACK
            tx.error = str(exc)
            _persist_tx(state_path, tx)
            _restore_portable_backup(install_dir, backup_dir)
            tx.state = UpdateState.ROLLED_BACK
            _finalize_tx(state_path, tx)
            return tx

        tx.state = UpdateState.VERIFYING_NEW
        _persist_tx(state_path, tx)
        verifier = verify_callback or (lambda tgt, dd: verify_updated_binary(tgt, target_version, dd))
        ok = False
        try:
            ok = bool(verifier(install_dir, data_dir))
        except Exception as exc:  # noqa: BLE001
            tx.error = str(exc)

        if not ok:
            tx.state = UpdateState.ROLLING_BACK
            tx.error = tx.error or "Post-upgrade verification failed"
            _persist_tx(state_path, tx)
            _restore_portable_backup(install_dir, backup_dir)
            tx.state = UpdateState.ROLLED_BACK
            _finalize_tx(state_path, tx)
            return tx

        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        tx.state = UpdateState.COMMITTED
        _finalize_tx(state_path, tx, highest_seen=target_version)
        return tx


def _default_run_installer(cmd: list[str], env: dict[str, str]) -> int:
    flags = get_platform().subprocess_creation_flags(detached=False, hide_console=True)
    res = subprocess.run(cmd, env=env, creationflags=flags, check=False)
    return int(res.returncode)


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
    require_authenticode: bool = False,
    allowed_thumbprints: tuple[str, ...] = (),
    run_installer: Callable[[list[str], dict[str, str]], int] | None = None,
    verify_callback: Callable[[Path, Path | None], bool] | None = None,
) -> UpdateTransaction:
    """Execute non-elevated silent Inno Setup upgrade with explicit rollback installer recovery."""
    if rollback_installer_path is None or not rollback_installer_path.is_file():
        raise UpdateError(UpdateBlockReason.NO_ROLLBACK_CONTRACT, "Missing rollback installer for installed mode")

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

    with acquire_updater_lock(state_path.parent / ".updater.lock"):
        _persist_tx(state_path, tx)
        if expected_sha256 is not None:
            reverify_staged_bundle(
                installer_path,
                expected_sha256,
                require_authenticode=require_authenticode,
                allowed_thumbprints=allowed_thumbprints,
            )

        tx.state = UpdateState.INSTALLING
        _persist_tx(state_path, tx)
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
            rb_rc = runner([str(rollback_installer_path), *silent_flags], env)
            tx.state = UpdateState.ROLLED_BACK if rb_rc == 0 else UpdateState.FAILED
            _finalize_tx(state_path, tx)
            return tx

        tx.state = UpdateState.COMMITTED
        _finalize_tx(state_path, tx, highest_seen=target_version)
        return tx


def _try_sanitize(raw: str, roots: tuple[Path, ...]) -> Path | None:
    if not raw:
        return None
    try:
        return _sanitize_confined_path(raw, roots)
    except UpdateError:
        return None


def _recover_installed_tx(
    tx: UpdateTransaction, target_dir: Path, updates_root: Path, state_path: Path
) -> UpdateTransaction | None:
    rb = _try_sanitize(tx.rollback_installer, (updates_root / "rollback",))
    if rb is None or not rb.is_file():
        return None
    env = dict(os.environ)
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    rc = _default_run_installer(
        [str(rb), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", f"/DIR={target_dir}"],
        env,
    )
    tx.state = UpdateState.ROLLED_BACK if rc == 0 else UpdateState.FAILED
    _finalize_tx(state_path, tx)
    return tx


def recover_interrupted_update_on_boot(
    state_path: Path,
    updates_root: Path,
    install_dir: Path | None = None,
) -> UpdateTransaction | None:
    """Recover cleanly from an interrupted crash/power-loss update transaction at startup."""
    st = UpdaterPersistentState.load(state_path)
    tx = st.active_transaction
    active_states = {
        UpdateState.BACKING_UP,
        UpdateState.SWAPPING,
        UpdateState.VERIFYING_NEW,
        UpdateState.ROLLING_BACK,
        UpdateState.INSTALLING,
    }
    if tx is None or tx.state not in active_states:
        return None

    target_dir = install_dir or _try_sanitize(tx.install_dir, _allowed_install_roots())
    backup_dir = _try_sanitize(tx.backup_dir, (target_dir.parent,)) if target_dir is not None else None

    if tx.install_type == "portable" and target_dir is not None and backup_dir is not None and backup_dir.is_dir():
        _restore_portable_backup(target_dir, backup_dir)
        tx.state = UpdateState.ROLLED_BACK
        tx.error = "Recovered interrupted swap on startup"
        _finalize_tx(state_path, tx)
        return tx

    if tx.install_type == "installed" and target_dir is not None:
        recovered = _recover_installed_tx(tx, target_dir, updates_root, state_path)
        if recovered is not None:
            return recovered

    tx.state = UpdateState.FAILED
    tx.error = "Interrupted update state could not be automatically recovered"
    _finalize_tx(state_path, tx)
    return tx


def _parse_plan_arg(argv: list[str]) -> str:
    if "--plan" not in argv:
        return ""
    idx = argv.index("--plan")
    return argv[idx + 1] if idx + 1 < len(argv) else ""


def _parse_parent_identity(raw: object) -> ProcessIdentity | None:
    if not isinstance(raw, dict):
        return None
    return ProcessIdentity(
        pid=int(raw["pid"]),
        create_time=float(raw["create_time"]),
        executable=str(raw.get("executable") or ""),
        captured_at=float(raw.get("captured_at") or 0.0),
    )


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


def _execute_cli_transaction(
    plan: dict,
    data_dir: Path,
    updates_root: Path,
    install_dir: Path,
    tx_id: str,
    source_ver: str,
    target_ver: str,
) -> UpdateTransaction | None:
    state_path = updates_root / "state.json"
    install_type = str(plan.get("install_type") or "")
    if install_type == "portable":
        return apply_portable_transaction(
            tx_id=tx_id,
            install_dir=install_dir,
            staged_dir=updates_root / "staged" / target_ver,
            expected_hashes=plan.get("expected_hashes"),
            source_version=source_ver,
            target_version=target_ver,
            state_path=state_path,
            data_dir=data_dir,
        )
    if install_type == "installed":
        installer_path = updates_root / "downloads" / f"{APP_ID}-Setup-{target_ver}.exe"
        rb_candidate = updates_root / "rollback" / f"{APP_ID}-Setup-{source_ver}.exe"
        return apply_installed_transaction(
            tx_id=tx_id,
            install_dir=install_dir,
            installer_path=installer_path,
            rollback_installer_path=rb_candidate if rb_candidate.is_file() else None,
            source_version=source_ver,
            target_version=target_ver,
            state_path=state_path,
            data_dir=data_dir,
            expected_sha256=plan.get("expected_sha256"),
            require_authenticode=bool(plan.get("require_authenticode", True)),
            allowed_thumbprints=tuple(plan.get("allowed_thumbprints") or ()),
        )
    return None


def run_apply_update_cli(argv: list[str]) -> int:
    """CLI handler for `MCPApp.exe --apply-update --plan <json> --handoff <token>`."""
    data_dir = Path(os.path.realpath(str(user_data_dir())))
    updates_root = data_dir / "updates"
    plan_path = _try_sanitize(_parse_plan_arg(argv), (updates_root / "helper_run",))
    if plan_path is None or not plan_path.is_file():
        return 2

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        return 2
    if not verify_handoff_token(
        str(plan.get("expected_token") or ""),
        os.environ.get("MCP_UPDATER_HANDOFF_TOKEN", ""),
        issued_at=float(plan.get("issued_at") or 0.0),
    ):
        return 3
    if not wait_for_parent_exit(_parse_parent_identity(plan.get("parent_identity")), timeout_s=20.0):
        return 4
    if has_active_tasks(data_dir / "tasks.sqlite3"):
        return 5

    tx_id = str(plan.get("tx_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,48}", tx_id):
        return 6
    try:
        source_ver = parse_semver(str(plan.get("source_version") or "")).raw
        target_ver = parse_semver(str(plan.get("target_version") or "")).raw
        install_dir = _sanitize_confined_path(str(plan.get("install_dir") or ""), _allowed_install_roots())
    except UpdateError:
        return 6

    tx = _execute_cli_transaction(plan, data_dir, updates_root, install_dir, tx_id, source_ver, target_ver)
    if tx is None:
        return 6
    _maybe_restart_gui(plan, install_dir)
    return 0 if tx.state == UpdateState.COMMITTED else 1
