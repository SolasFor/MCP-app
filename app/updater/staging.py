"""Hardened staging extraction, disk checks, ACLs, and pre-execution TOCTOU re-verification."""
from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
import stat
import zipfile
from pathlib import Path

from app.paths import APP_ID
from app.platform import get_platform
from app.updater.models import DEFAULT_DISK_RESERVE_BYTES, UpdateBlockReason, UpdateError
from app.updater.trust import verify_windows_authenticode

MAX_ZIP_ENTRIES = 5000
MAX_ZIP_UNCOMPRESSED_BYTES = 600 * 1024 * 1024
MAX_ZIP_RATIO = 50

_FORBIDDEN_EXACT_NAMES = frozenset(
    {
        "token.json",
        "settings.json",
        "schedules.json",
        ".env",
        "mcp_audit.log",
    }
)
_FORBIDDEN_ROOT_PREFIXES = ("oauth/", "secrets/", "logs/", "backups/", "updates/")
_FORBIDDEN_TOP_SCRIPT_EXTS = (".ps1", ".bat", ".cmd", ".vbs")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def ensure_disk_headroom(
    target_dir: Path,
    required_bytes: int,
    min_free_reserve: int = DEFAULT_DISK_RESERVE_BYTES,
) -> None:
    """Verify sufficient free space exists on the destination volume."""
    probe = target_dir if target_dir.exists() else target_dir.parent
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    needed = max(0, required_bytes) + max(0, min_free_reserve)
    if usage.free < needed:
        raise UpdateError(
            UpdateBlockReason.DISK_FULL,
            f"Insufficient free disk space: need {needed} bytes, available {usage.free} bytes",
        )


def compute_file_sha256(path: Path) -> str:
    """Compute lowercase SHA-256 digest of a regular file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def is_reparse_or_symlink(path: Path) -> bool:
    """Return True if path is a POSIX symlink or Windows reparse point/junction."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def _ensure_safe_tree_no_reparse(root: Path) -> None:
    """Verify directory tree contains no symlinks or Windows reparse points."""
    if is_reparse_or_symlink(root):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Symlink/reparse point rejected: {root}")
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur_path = Path(current)
        for name in dirs + files:
            item = cur_path / name
            if is_reparse_or_symlink(item):
                raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Symlink/reparse point rejected: {item}")


def _validate_zip_entry(info: zipfile.ZipInfo) -> str:
    raw_name = info.filename
    if "\x00" in raw_name or "\\" in raw_name or raw_name.startswith("/"):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Unsafe archive path syntax: {raw_name!r}")
    if ":" in raw_name:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Drive letter forbidden in archive path: {raw_name!r}")
    # Reject POSIX symlinks stored in external_attr upper 16 bits
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(unix_mode):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Symlink entry forbidden in archive: {raw_name!r}")
    # Reject DOS reparse point attribute bit in lower external_attr byte/word
    if (info.external_attr & 0xFFFF) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Reparse entry forbidden in archive: {raw_name!r}")

    norm = posixpath.normpath(raw_name.rstrip("/"))
    if norm in ("", ".") or norm.startswith("..") or "/../" in f"/{norm}/":
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Path traversal entry forbidden: {raw_name!r}")
    return norm


def _strip_optional_wrapper(entries: list[tuple[zipfile.ZipInfo, str]]) -> dict[zipfile.ZipInfo, str]:
    non_dirs = [norm for info, norm in entries if not info.is_dir()]
    unwrap = bool(non_dirs) and all(norm == "MCPApp" or norm.startswith("MCPApp/") for norm in non_dirs)
    mapped: dict[zipfile.ZipInfo, str] = {}
    for info, norm in entries:
        rel = norm[len("MCPApp/") :] if unwrap and norm.startswith("MCPApp/") else ("" if unwrap and norm == "MCPApp" else norm)
        if not rel or info.is_dir():
            continue
        mapped[info] = rel
    return mapped


def _check_forbidden_rel_path(rel: str) -> None:
    lowered = rel.lower()
    base = posixpath.basename(lowered)
    if base in _FORBIDDEN_EXACT_NAMES:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"User config/secret path forbidden in bundle: {rel}")
    for prefix in _FORBIDDEN_ROOT_PREFIXES:
        if lowered.startswith(prefix):
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Protected directory forbidden in bundle: {rel}")
    if "/" not in lowered and lowered.endswith(_FORBIDDEN_TOP_SCRIPT_EXTS):
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Top-level script forbidden in bundle: {rel}")


def _scan_zip_infos(infos: list[zipfile.ZipInfo]) -> tuple[list[tuple[zipfile.ZipInfo, str]], int]:
    if len(infos) > MAX_ZIP_ENTRIES:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Portable ZIP exceeds maximum entry count")
    validated: list[tuple[zipfile.ZipInfo, str]] = []
    total_uncompressed = 0
    for info in infos:
        norm = _validate_zip_entry(info)
        total_uncompressed += max(0, info.file_size)
        if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Portable ZIP exceeds uncompressed size cap")
        if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_ZIP_RATIO:
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Compression ratio anomaly in {info.filename!r}")
        validated.append((info, norm))
    return validated, total_uncompressed


def _check_rel_collisions(rel_map: dict[zipfile.ZipInfo, str]) -> None:
    seen_casefolded: set[str] = set()
    for rel in rel_map.values():
        key = rel.lower()
        if key in seen_casefolded:
            raise UpdateError(
                UpdateBlockReason.ZIP_SECURITY,
                f"Duplicate or NTFS case-collision entry in portable ZIP: {rel!r}",
            )
        seen_casefolded.add(key)
        _check_forbidden_rel_path(rel)


def _write_zip_entry(
    zf: zipfile.ZipFile,
    entry_info: zipfile.ZipInfo,
    rel: str,
    stage_tmp: Path,
    stage_root_resolved: Path,
) -> str:
    dest = (stage_tmp / rel).resolve()
    if stage_root_resolved not in dest.parents:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Resolved path escaped staging dir: {rel}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    written = 0
    with zf.open(entry_info, "r") as src, dest.open("wb") as out:
        while True:
            chunk = src.read(65536)
            if not chunk:
                return hasher.hexdigest().lower()
            written += len(chunk)
            if written > entry_info.file_size:
                raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"ZIP entry expanded past declared size: {rel}")
            out.write(chunk)
            hasher.update(chunk)


def extract_verified_portable_zip(zip_path: Path, stage_dir: Path) -> dict[str, str]:
    """Safely extract portable ZIP into a clean private staging directory and return `{rel_path: sha256}`."""
    if not zip_path.is_file():
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Portable archive not found: {zip_path}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        validated, total_uncompressed = _scan_zip_infos(zf.infolist())
        ensure_disk_headroom(stage_dir, total_uncompressed)
        rel_map = _strip_optional_wrapper(validated)
        _check_rel_collisions(rel_map)

        stage_tmp = stage_dir.with_name(f".{stage_dir.name}.extracting")
        if stage_tmp.exists():
            shutil.rmtree(stage_tmp, ignore_errors=True)
        stage_tmp.mkdir(parents=True, exist_ok=True)
        adapter = get_platform()
        adapter.restrict_path_acl(stage_tmp, is_dir=True)
        stage_root_resolved = stage_tmp.resolve()

        extracted_hashes: dict[str, str] = {}
        try:
            for entry_info, rel in rel_map.items():
                extracted_hashes[rel] = _write_zip_entry(zf, entry_info, rel, stage_tmp, stage_root_resolved)
            if stage_dir.exists():
                shutil.rmtree(stage_dir)
            stage_tmp.replace(stage_dir)
            adapter.restrict_path_acl(stage_dir, is_dir=True)
        except Exception:
            shutil.rmtree(stage_tmp, ignore_errors=True)
            raise

    return extracted_hashes


def _hash_zip_entry(zf: zipfile.ZipFile, entry_info: zipfile.ZipInfo, rel: str) -> str:
    h = hashlib.sha256()
    written = 0
    with zf.open(entry_info, "r") as src:
        for chunk in iter(lambda: src.read(65536), b""):
            written += len(chunk)
            if written > entry_info.file_size:
                raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"ZIP entry expanded past size: {rel}")
            h.update(chunk)
    return h.hexdigest().lower()


def verify_portable_zip_and_compute_map(
    zip_path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> dict[str, str]:
    """Verify portable ZIP digest/size against signed manifest and derive `{rel_path: sha256}` without disk writes."""
    if not zip_path.is_file() or is_reparse_or_symlink(zip_path):
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Verified portable ZIP missing: {zip_path}")
    if expected_size <= 0 or zip_path.stat().st_size != expected_size:
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Portable ZIP size mismatch: {zip_path.name}")
    if compute_file_sha256(zip_path) != expected_sha256.lower():
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Portable ZIP SHA-256 mismatch: {zip_path.name}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        validated, _ = _scan_zip_infos(zf.infolist())
        rel_map = _strip_optional_wrapper(validated)
        _check_rel_collisions(rel_map)
        hashes = {rel: _hash_zip_entry(zf, entry_info, rel) for entry_info, rel in rel_map.items()}

    if not hashes or f"{APP_ID.lower()}.exe" not in {k.lower() for k in hashes}:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Portable ZIP does not contain application executable")
    return hashes


def _reverify_installer_file(
    stage_path: Path,
    expected_sha256: str,
    *,
    expected_size: int | None = None,
    require_authenticode: bool,
    allowed_thumbprints: tuple[str, ...],
) -> None:
    if not expected_sha256 or not stage_path.is_file() or is_reparse_or_symlink(stage_path):
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Staged installer missing or unsafe: {stage_path}")
    if expected_size is not None and stage_path.stat().st_size != expected_size:
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, "Staged installer size mismatch before launch")
    if compute_file_sha256(stage_path) != expected_sha256.lower():
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, "Staged installer SHA-256 mismatch before launch")
    if require_authenticode:
        if not allowed_thumbprints:
            raise UpdateError(UpdateBlockReason.NO_AUTHENTICODE_POLICY, "No trusted Authenticode thumbprints configured")
        auth = verify_windows_authenticode(stage_path, allowed_thumbprints=allowed_thumbprints)
        if not auth.verified:
            raise UpdateError(UpdateBlockReason.AUTHENTICODE_FAILED, auth.reason)


def _validate_single_rel_entry(rel: object, digest: object) -> str:
    if not isinstance(rel, str) or not isinstance(digest, str) or not digest.strip():
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, "Malformed entry in staged hash map")
    if "\x00" in rel or "\\" in rel or rel.startswith("/") or ":" in rel:
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Unsafe relative path in hash map: {rel!r}")
    norm = posixpath.normpath(rel)
    if norm != rel or norm in ("", ".") or norm.startswith("..") or "/../" in f"/{norm}/":
        raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Path traversal in hash map: {rel!r}")
    _check_forbidden_rel_path(norm)
    return norm


def _validate_expected_hash_map(expected_hashes: dict[str, str] | None) -> dict[str, str]:
    if not isinstance(expected_hashes, dict) or not expected_hashes:
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, "Missing or empty staged file hash map")
    normalized: dict[str, str] = {}
    seen_low: set[str] = set()
    for rel, digest in expected_hashes.items():
        norm = _validate_single_rel_entry(rel, digest)
        low = norm.lower()
        if low in seen_low:
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Case-collision in staged hash map: {rel!r}")
        seen_low.add(low)
        normalized[norm] = str(digest).lower()
    if f"{APP_ID.lower()}.exe" not in seen_low:
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, "Staged bundle missing main application executable")
    return normalized


def _ensure_no_reparse_names(cur_dir: Path, names: list[str]) -> None:
    for name in names:
        if is_reparse_or_symlink(cur_dir / name):
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Symlink/reparse entry rejected: {name}")


def _collect_actual_stage_files(stage_path: Path) -> dict[str, Path]:
    actual: dict[str, Path] = {}
    seen_low: set[str] = set()
    for current, dirs, files in os.walk(stage_path, topdown=True, followlinks=False):
        cur_dir = Path(current)
        if is_reparse_or_symlink(cur_dir):
            raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Symlink/reparse dir rejected: {cur_dir}")
        _ensure_no_reparse_names(cur_dir, dirs)
        _ensure_no_reparse_names(cur_dir, files)
        for fname in files:
            fpath = cur_dir / fname
            if not fpath.is_file():
                raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Non-regular staged entry: {fpath}")
            rel = fpath.relative_to(stage_path).as_posix()
            low = rel.lower()
            if low in seen_low:
                raise UpdateError(UpdateBlockReason.ZIP_SECURITY, f"Duplicate staged path collision: {rel}")
            seen_low.add(low)
            actual[rel] = fpath
    return actual


def _reverify_portable_dir(stage_path: Path, expected_hashes: dict[str, str] | None) -> None:
    if not stage_path.is_dir():
        raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Staged directory missing: {stage_path}")
    expected = _validate_expected_hash_map(expected_hashes)
    actual = _collect_actual_stage_files(stage_path)
    missing = set(expected.keys()) - set(actual.keys())
    extra = set(actual.keys()) - set(expected.keys())
    if missing or extra:
        raise UpdateError(
            UpdateBlockReason.HASH_MISMATCH,
            f"Staged file set mismatch (missing={len(missing)}, extra={len(extra)})",
        )
    for rel, digest in expected.items():
        if compute_file_sha256(actual[rel]) != digest:
            raise UpdateError(UpdateBlockReason.HASH_MISMATCH, f"Staged payload modified before swap: {rel}")


def reverify_staged_bundle(
    stage_path: Path,
    expected_hashes: dict[str, str] | str | None,
    *,
    expected_size: int | None = None,
    require_authenticode: bool = False,
    allowed_thumbprints: tuple[str, ...] = (),
) -> None:
    """Re-verify staged directory or installer executable immediately prior to execution (TOCTOU guard)."""
    _ensure_safe_tree_no_reparse(stage_path)
    if isinstance(expected_hashes, str):
        _reverify_installer_file(
            stage_path,
            expected_hashes,
            expected_size=expected_size,
            require_authenticode=require_authenticode,
            allowed_thumbprints=allowed_thumbprints,
        )
        return
    _reverify_portable_dir(stage_path, expected_hashes)
