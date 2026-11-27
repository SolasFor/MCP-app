"""Install environment detector (dev / installed / portable) and rollback contract validation."""
from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.paths import APP_ID, is_frozen, resource_dir
from app.updater.models import InstallType, UpdateBlockReason

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


def _detect_installed_mode(
    base_dir: Path,
    exe_path: Path,
    unins_exe: Path,
    dir_writable: bool,
    blocks: list[str],
    current_version: str,
    rollback_cache_dir: Path | None,
) -> InstallEnvironment:
    rollback_exe: Path | None = None
    if rollback_cache_dir is not None and current_version:
        candidate = rollback_cache_dir / f"{APP_ID}-Setup-{current_version}.exe"
        if candidate.is_file():
            rollback_exe = candidate
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
) -> InstallEnvironment:
    """Classify runtime as dev, installed (Inno Setup), or portable, and collect safety blocks."""
    is_pkg = is_frozen() if frozen is None else frozen
    if app_dir is None:
        base_dir = Path(sys.executable).resolve().parent if is_pkg else resource_dir().resolve()
    else:
        base_dir = app_dir.resolve()
    exe_path = base_dir / f"{APP_ID}.exe"

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
            base_dir, exe_path, unins_exe, dir_writable, blocks, current_version, rollback_cache_dir
        )
    return _detect_portable_mode(base_dir, exe_path, dir_writable, blocks)
