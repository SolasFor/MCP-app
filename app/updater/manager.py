"""Coordinator tying GitHub checks, trust policy, staging, cancellation, and UI handoff together."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from app import __version__
from app.config import Settings
from app.core.atomic_io import atomic_write_json
from app.paths import tasks_db_path
from app.platform import get_platform
from app.updater.detector import InstallEnvironment, detect_install_environment
from app.updater.helper import check_active_operations, has_active_tasks
from app.updater.models import (
    UpdateBlockReason,
    UpdateError,
    UpdateManifest,
    UpdaterPersistentState,
    UpdateState,
    parse_semver,
)
from app.updater.network import (
    download_verified_asset,
    fetch_latest_release_info,
    fetch_release_text_asset,
)
from app.updater.staging import ensure_disk_headroom, extract_verified_portable_zip
from app.updater.trust import TrustPolicy, verify_manifest_and_signature, verify_windows_authenticode

AUTO_CHECK_COOLDOWN_SECONDS = 24 * 3600


@dataclass(frozen=True)
class UpdateCheckSnapshot:
    """Thread-safe immutable snapshot returned to UI and controllers."""

    state: str
    current_version: str
    latest_version: str = ""
    changelog: str = ""
    install_type: str = "dev"
    block_reason: str = UpdateBlockReason.OK
    block_detail: str = ""
    progress_done: int = 0
    progress_total: int = 0
    manifest: UpdateManifest | None = None
    staged_path: str = ""
    expected_hashes: dict[str, str] | str | None = None


@dataclass
class _StagedArtifact:
    manifest: UpdateManifest
    install_type: str
    staged_path: Path
    expected_hashes: dict[str, str] | str
    installer_url: str = ""


class UpdateManager:
    """Fail-closed updater lifecycle manager with opt-in downloads and explicit Quit handoff."""

    def __init__(
        self,
        settings: Settings,
        data_dir: Path,
        *,
        policy: TrustPolicy | None = None,
        current_version: str | None = None,
        environment: InstallEnvironment | None = None,
    ) -> None:
        self._settings = settings
        self._data_dir = Path(data_dir)
        self._updates_dir = self._data_dir / "updates"
        self._state_path = self._updates_dir / "state.json"
        self._policy = policy or TrustPolicy.production_default()
        self._current_version = current_version or __version__
        self._env_override = environment
        self._cancel_event = threading.Event()
        self._lock = threading.RLock()
        self._staged: _StagedArtifact | None = None
        self._latest_release_assets: dict[str, str] = {}
        self._snapshot = self._initial_snapshot()

    def _environment(self) -> InstallEnvironment:
        if self._env_override is not None:
            return self._env_override
        return detect_install_environment(
            current_version=self._current_version,
            rollback_cache_dir=self._updates_dir / "rollback",
            policy=self._policy,
        )

    def _initial_snapshot(self) -> UpdateCheckSnapshot:
        env = self._environment()
        reason = self.evaluate_block_reason(env)
        return UpdateCheckSnapshot(
            state=UpdateState.BLOCKED if reason != UpdateBlockReason.OK else UpdateState.IDLE,
            current_version=self._current_version,
            install_type=env.install_type,
            block_reason=reason,
        )

    def snapshot(self) -> UpdateCheckSnapshot:
        with self._lock:
            return self._snapshot

    def evaluate_block_reason(self, env: InstallEnvironment | None = None) -> str:
        """Return primary block reason preventing automatic install, or UpdateBlockReason.OK."""
        if not self._policy.auto_install_permitted():
            return self._policy.block_reason()
        cur_env = env or self._environment()
        if cur_env.block_reasons:
            return cur_env.block_reasons[0]
        if cur_env.install_type == "installed" and self._policy.require_authenticode_for_installer:
            if not self._policy.allowed_thumbprints:
                return UpdateBlockReason.NO_AUTHENTICODE_POLICY
        if has_active_tasks(tasks_db_path(self._data_dir)):
            return UpdateBlockReason.ACTIVE_TASKS
        active_op = check_active_operations(self._data_dir)
        if active_op != UpdateBlockReason.OK:
            return active_op
        return UpdateBlockReason.OK

    def can_auto_install(self) -> bool:
        """True only when user opted in AND policy/environment/tasks allow safe install."""
        return bool(self._settings.update_auto_install) and self.evaluate_block_reason() == UpdateBlockReason.OK

    def cancel(self) -> None:
        self._cancel_event.set()

    def should_auto_check(self, now: float | None = None) -> bool:
        if not self._settings.update_auto_check:
            return False
        st = UpdaterPersistentState.load(self._state_path)
        cur = time.time() if now is None else now
        return (cur - st.last_check_at) >= AUTO_CHECK_COOLDOWN_SECONDS

    def _fetch_verified_release_manifest(
        self,
        *,
        highest_seen_version: str,
        fetch_bytes: Callable[[str], bytes] | None,
    ) -> tuple[dict[str, str], Any]:
        release = fetch_latest_release_info(fetch_bytes=fetch_bytes)
        manifest_url = release.assets.get("update-manifest.json")
        sig_url = release.assets.get("update-manifest.json.sig")
        if not manifest_url or not sig_url:
            raise UpdateError(
                UpdateBlockReason.SIGNATURE_INVALID,
                "Release does not publish update-manifest.json and update-manifest.json.sig",
            )
        manifest_raw = fetch_release_text_asset(manifest_url, fetch_bytes=fetch_bytes)
        sig_text = fetch_release_text_asset(sig_url, fetch_bytes=fetch_bytes).decode("utf-8")
        sig_raw = json.loads(sig_text)
        manifest = verify_manifest_and_signature(
            manifest_bytes=manifest_raw,
            key_id=str(sig_raw.get("key_id") or ""),
            signature_b64=str(sig_raw.get("signature_b64") or ""),
            current_version=self._current_version,
            highest_seen_version=highest_seen_version,
            policy=self._policy,
        )
        manifest_dir = self._updates_dir / "manifests" / manifest.version
        manifest_dir.mkdir(parents=True, exist_ok=True)
        get_platform().restrict_path_acl(manifest_dir, is_dir=True)
        (manifest_dir / "update-manifest.json").write_bytes(manifest_raw)
        (manifest_dir / "update-manifest.json.sig").write_text(sig_text, encoding="utf-8")
        return dict(release.assets), manifest

    def check_for_updates(
        self,
        *,
        force: bool = True,
        fetch_bytes: Callable[[str], bytes] | None = None,
    ) -> UpdateCheckSnapshot:
        """Query official stable GitHub release, verify signed manifest, and update state."""
        env = self._environment()
        if not force and not self.should_auto_check():
            return self.snapshot()

        self._cancel_event.clear()
        st = UpdaterPersistentState.load(self._state_path)
        st.last_check_at = time.time()

        try:
            assets, manifest = self._fetch_verified_release_manifest(
                highest_seen_version=st.highest_seen_version,
                fetch_bytes=fetch_bytes,
            )
            st.last_known_version = manifest.version
            st.last_changelog = manifest.changelog
            st.save(self._state_path)

            newer = parse_semver(manifest.version) > parse_semver(self._current_version)
            reason = self.evaluate_block_reason(env)
            with self._lock:
                self._latest_release_assets = assets
                self._snapshot = UpdateCheckSnapshot(
                    state=UpdateState.AVAILABLE if newer else UpdateState.IDLE,
                    current_version=self._current_version,
                    latest_version=manifest.version,
                    changelog=manifest.changelog,
                    install_type=env.install_type,
                    block_reason=reason,
                    manifest=manifest,
                )
            return self._snapshot
        except UpdateError as exc:
            st.save(self._state_path)
            blocked_codes = {
                UpdateBlockReason.MISSING_TRUST_ROOTS,
                UpdateBlockReason.KEY_REVOKED,
                UpdateBlockReason.KEY_EXPIRED,
                UpdateBlockReason.DOWNGRADE_BLOCKED,
            }
            with self._lock:
                self._snapshot = UpdateCheckSnapshot(
                    state=UpdateState.BLOCKED if exc.code in blocked_codes else UpdateState.FAILED,
                    current_version=self._current_version,
                    install_type=env.install_type,
                    block_reason=exc.code,
                    block_detail=str(exc),
                )
            return self._snapshot

    def _stage_verified_asset(
        self,
        dl_path: Path,
        asset: Any,
        manifest: Any,
        env: Any,
    ) -> tuple[Path, dict[str, str] | str]:
        if env.install_type != "installed":
            staged = self._updates_dir / "staged" / manifest.version
            return staged, extract_verified_portable_zip(dl_path, staged)
        if asset.authenticode_required:
            thumbs = self._policy.allowed_thumbprints or manifest.publisher_thumbprints
            auth = verify_windows_authenticode(dl_path, allowed_thumbprints=thumbs)
            if not auth.verified:
                dl_path.unlink(missing_ok=True)
                raise UpdateError(UpdateBlockReason.AUTHENTICODE_FAILED, auth.reason)
        return dl_path, str(asset.sha256)

    def download_and_stage(
        self,
        *,
        on_progress: Callable[[int, int], None] | None = None,
        open_url: Callable[..., Any] | None = None,
    ) -> UpdateCheckSnapshot:
        """Download matching verified asset for install_type and stage securely without touching install dir."""
        snap = self.snapshot()
        manifest = snap.manifest
        env = self._environment()
        if manifest is None:
            raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "No verified manifest available to stage")
        if env.install_type == "dev":
            raise UpdateError(UpdateBlockReason.DEV_MODE, "Staging blocked in development workspace mode")

        asset = manifest.installer if env.install_type == "installed" else manifest.portable
        asset_url = self._latest_release_assets.get(asset.name, "")
        if not asset_url:
            raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"Release asset missing: {asset.name}")

        self._updates_dir.mkdir(parents=True, exist_ok=True)
        get_platform().restrict_path_acl(self._updates_dir, is_dir=True)
        ensure_disk_headroom(self._updates_dir, asset.size * 2)

        dl_path = self._updates_dir / "downloads" / asset.name
        self._cancel_event.clear()
        download_verified_asset(
            asset_url,
            dl_path,
            expected_sha256=asset.sha256,
            expected_size=asset.size,
            cancel_event=self._cancel_event,
            on_progress=on_progress,
            open_url=open_url,
        )

        staged, expected = self._stage_verified_asset(dl_path, asset, manifest, env)
        reason = self.evaluate_block_reason(env)
        with self._lock:
            self._staged = _StagedArtifact(
                manifest=manifest,
                install_type=env.install_type,
                staged_path=staged,
                expected_hashes=expected,
                installer_url=asset_url,
            )
            self._snapshot = UpdateCheckSnapshot(
                state=UpdateState.READY_TO_INSTALL if reason == UpdateBlockReason.OK else UpdateState.STAGED,
                current_version=self._current_version,
                latest_version=manifest.version,
                changelog=manifest.changelog,
                install_type=env.install_type,
                block_reason=reason,
                progress_done=asset.size,
                progress_total=asset.size,
                manifest=manifest,
                staged_path=str(staged),
                expected_hashes=expected,
            )
            return self._snapshot

    def launch_staged_install_handoff(self, *, restart_gui: bool = True) -> bool:
        """Spawn out-of-tree helper process in `%APPDATA%/MCPApp/updates/helper_run/<tx_id>` with RunAsInvoker."""
        with self._lock:
            staged = self._staged
        if staged is None:
            return False
        env_info = self._environment()
        block = self.evaluate_block_reason(env_info)
        if block != UpdateBlockReason.OK:
            return False

        tx_id = uuid.uuid4().hex[:12]
        helper_dir = self._updates_dir / "helper_run" / tx_id
        helper_dir.mkdir(parents=True, exist_ok=True)
        get_platform().restrict_path_acl(helper_dir, is_dir=True)

        # Copy runtime helper directory outside install_dir so parent folder swap has zero open locks.
        helper_exe = Path(sys.executable)
        if env_info.install_dir.exists() and (env_info.install_dir / "MCPApp.exe").is_file():
            shutil.copy2(env_info.install_dir / "MCPApp.exe", helper_dir / "MCPApp.exe")
            internal_src = env_info.install_dir / "_internal"
            if internal_src.is_dir():
                shutil.copytree(internal_src, helper_dir / "_internal", dirs_exist_ok=True)
            helper_exe = helper_dir / "MCPApp.exe"

        token = secrets.token_urlsafe(32)
        parent_id = get_platform().capture_process_identity(os.getpid())
        if parent_id is None:
            return False
        plan_path = helper_dir / "plan.json"
        plan = {
            "tx_id": tx_id,
            "install_type": staged.install_type,
            "install_dir": str(env_info.install_dir),
            "target_version": staged.manifest.version,
            "expected_token": token,
            "issued_at": time.time(),
            "parent_identity": {
                "pid": parent_id.pid,
                "create_time": parent_id.create_time,
                "executable": parent_id.executable,
                "captured_at": parent_id.captured_at,
            },
            "restart_gui": restart_gui,
        }
        atomic_write_json(plan_path, plan, restrict_acl=True)

        proc_env = dict(os.environ)
        proc_env["__COMPAT_LAYER"] = "RunAsInvoker"
        proc_env["MCP_UPDATER_HANDOFF_TOKEN"] = token
        adapter = get_platform()
        flags = adapter.subprocess_creation_flags(detached=True, hide_console=True, breakaway_from_job=True)
        subprocess.Popen(
            [str(helper_exe), "--apply-update", "--plan", str(plan_path)],
            cwd=str(helper_dir),
            env=proc_env,
            creationflags=flags,
        )
        return True
