"""Install environment detector (dev / installed / portable) and rollback contract validation."""
from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.paths import APP_ID, is_frozen, resource_dir
from app.updater.models import InstallType, UpdateBlockReason, UpdateError
from app.updater.staging import compute_file_sha256, is_reparse_or_symlink
from app.updater.trust import (
    TrustPolicy,
    verify_release_manifest_signature,
    verify_windows_authenticode,
)

_INNO_UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3C2A71-4D5E-4B9A-9C61-2E7A1D0B5F43}_is1"
_ALLOWED_PORTABLE_ENTRIES = frozenset(
    {
        "mcpapp.exe",
        "_internal",
        "bin",
        "assets",
        "extensions_official",
        "cloudflared.exe",
    }
)


@dataclass(frozen=True)
class InstallEnvironment:
    """Detected installation topology and pre-install capability checks."""

    install_type: InstallType
    install_dir: Path
    exe_path: Path
    uninstall_exe: Path | None
    writable: bool
    has_rollback_contract: bool
    rollback_installer: Path | None
    block_reasons: tuple[str, ...] = ()


def _is_dir_writable(path: Path) -> bool:
    if not path.is_dir():
        return False
    probe = path / f".mcpapp-write-probe-{uuid.uuid4().hex}"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _read_hkcu_install_location() -> Path | None:
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INNO_UNINSTALL_KEY) as key:
            val, _ = winreg.QueryValueEx(key, "InstallLocation")
            if isinstance(val, str) and val.strip():
                return Path(val.strip()).resolve()
    except OSError:
        return None
    return None


def _rollback_policy_ready(policy: TrustPolicy) -> bool:
    if not policy.auto_install_permitted():
        return False
    return not (policy.require_authenticode_for_installer and (not policy.allowed_thumbprints or sys.platform != "win32"))


def _verify_rollback_manifest_file(manifest_path: Path, sig_path: Path, expected_version: str, policy: TrustPolicy):
    if not (manifest_path.is_file() and sig_path.is_file()):
        return None
    if is_reparse_or_symlink(manifest_path) or is_reparse_or_symlink(sig_path):
        return None
    try:
        sig_raw = json.loads(sig_path.read_text(encoding="utf-8"))
        manifest = verify_release_manifest_signature(
            manifest_bytes=manifest_path.read_bytes(),
            key_id=str(sig_raw.get("key_id") or ""),
            signature_b64=str(sig_raw.get("signature_b64") or ""),
            policy=policy,
        )
    except (OSError, ValueError, TypeError, UpdateError):
        return None
    return manifest if manifest.version == expected_version else None


def verify_cached_rollback_bundle(
    rollback_cache_dir: Path | None,
    *,
    expected_version: str,
    policy: TrustPolicy,
) -> tuple[Path, str] | None:
    """Return `(installer_path, expected_sha256)` only for a cryptographically verified rollback installer."""
    if rollback_cache_dir is None or not expected_version or not _rollback_policy_ready(policy):
        return None
    ver_dir = rollback_cache_dir / expected_version
    base = ver_dir if ver_dir.is_dir() else rollback_cache_dir
    exe_path = base / f"{APP_ID}-Setup-{expected_version}.exe"
    if not exe_path.is_file() or is_reparse_or_symlink(exe_path):
        return None
    manifest = _verify_rollback_manifest_file(
        base / "update-manifest.json",
        base / "update-manifest.json.sig",
        expected_version,
        policy,
    )
    if manifest is None or manifest.installer.name != exe_path.name:
        return None
    if exe_path.stat().st_size != manifest.installer.size or compute_file_sha256(exe_path) != manifest.installer.sha256:
        return None
    if policy.require_authenticode_for_installer and not verify_windows_authenticode(
        exe_path, allowed_thumbprints=policy.allowed_thumbprints
    ).verified:
        return None
    return exe_path, manifest.installer.sha256


def _detect_installed_mode(
    base_dir: Path,
    exe_path: Path,
    unins_exe: Path,
    dir_writable: bool,
    blocks: list[str],
    current_version: str,
    rollback_cache_dir: Path | None,
    policy: TrustPolicy,
) -> InstallEnvironment:
    verified = verify_cached_rollback_bundle(
        rollback_cache_dir,
        expected_version=current_version,
        policy=policy,
    )
    rollback_exe = verified[0] if verified is not None else None
    has_rollback = rollback_exe is not None
    if not has_rollback:
        blocks.append(UpdateBlockReason.NO_ROLLBACK_CONTRACT)
    return InstallEnvironment(
        install_type="installed",
        install_dir=base_dir,
        exe_path=exe_path,
        uninstall_exe=unins_exe if unins_exe.is_file() else None,
        writable=dir_writable,
        has_rollback_contract=has_rollback,
        rollback_installer=rollback_exe,
        block_reasons=tuple(blocks),
    )


def _detect_portable_mode(
    base_dir: Path,
    exe_path: Path,
    dir_writable: bool,
    blocks: list[str],
) -> InstallEnvironment:
    parent_writable = _is_dir_writable(base_dir.parent)
    if not parent_writable and UpdateBlockReason.ELEVATION_REQUIRED not in blocks:
        blocks.append(UpdateBlockReason.ELEVATION_REQUIRED)
    has_foreign = any(
        child.name.lower() not in _ALLOWED_PORTABLE_ENTRIES
        and not child.name.lower().startswith(".mcpapp-write-probe-")
        for child in base_dir.iterdir()
    )
    if has_foreign:
        blocks.append(UpdateBlockReason.FOREIGN_FILES_IN_INSTALL_DIR)
    return InstallEnvironment(
        install_type="portable",
        install_dir=base_dir,
        exe_path=exe_path,
        uninstall_exe=None,
        writable=dir_writable and parent_writable,
        has_rollback_contract=True,
        rollback_installer=None,
        block_reasons=tuple(blocks),
    )


def detect_install_environment(
    *,
    frozen: bool | None = None,
    app_dir: Path | None = None,
    current_version: str = "",
    rollback_cache_dir: Path | None = None,
    policy: TrustPolicy | None = None,
) -> InstallEnvironment:
    """Classify runtime as dev, installed (Inno Setup), or portable, and collect safety blocks."""
    is_pkg = is_frozen() if frozen is None else frozen
    if app_dir is None:
        base_dir = Path(sys.executable).resolve().parent if is_pkg else resource_dir().resolve()
    else:
        base_dir = app_dir.resolve()
    exe_path = base_dir / f"{APP_ID}.exe"
    effective_policy = policy or TrustPolicy.production_default()

    if not is_pkg:
        return InstallEnvironment(
            install_type="dev",
            install_dir=base_dir,
            exe_path=exe_path,
            uninstall_exe=None,
            writable=False,
            has_rollback_contract=False,
            rollback_installer=None,
            block_reasons=(UpdateBlockReason.DEV_MODE,),
        )

    unins_exe = base_dir / "unins000.exe"
    unins_dat = base_dir / "unins000.dat"
    hkcu_loc = _read_hkcu_install_location()
    is_installed = (unins_exe.is_file() and unins_dat.is_file()) or (
        hkcu_loc is not None and os.path.normcase(str(hkcu_loc)) == os.path.normcase(str(base_dir))
    )

    blocks: list[str] = []
    dir_writable = _is_dir_writable(base_dir)
    if not dir_writable:
        blocks.append(UpdateBlockReason.ELEVATION_REQUIRED)

    if is_installed:
        return _detect_installed_mode(
            base_dir,
            exe_path,
            unins_exe,
            dir_writable,
            blocks,
            current_version,
            rollback_cache_dir,
            effective_policy,
        )
    return _detect_portable_mode(base_dir, exe_path, dir_writable, blocks)
