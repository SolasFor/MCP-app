"""Safe ZIP validation/extraction, SHA-256 checksums, and Ed25519 package signatures."""
from __future__ import annotations

import base64
import hashlib
import json
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from backend.extensions.models import ExtensionManifest

MAX_PACKAGE_FILES = 200
MAX_PACKAGE_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
MANIFEST_FILE = "manifest.json"
CHECKSUMS_FILE = "CHECKSUMS.sha256"
SIGNATURE_FILE = "SIGNATURE.ed25519"


@dataclass(frozen=True)
class PackageVerificationResult:
    """Result of validating and verifying an extension ZIP or directory."""

    manifest: ExtensionManifest
    package_sha256: str
    verified_by: str
    file_count: int
    total_bytes: int


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_rel_posix(member_name: str) -> PurePosixPath:
    norm = member_name.replace("\\", "/")
    if not norm or "\x00" in norm or norm.startswith("/") or ":" in norm:
        raise ValueError(f"Unsafe archive member path: {member_name!r}")
    p = PurePosixPath(norm)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise ValueError(f"Path traversal or empty segment in archive: {member_name!r}")
    return p


def _iter_directory_files(root: Path) -> list[tuple[str, Path]]:
    items: list[tuple[str, Path]] = []
    resolved_root = root.resolve()
    for p in sorted(resolved_root.rglob("*")):
        if p.is_symlink():
            raise ValueError(f"Symlink prohibited in extension directory: {p}")
        if p.is_file():
            rel = p.relative_to(resolved_root).as_posix()
            if "__pycache__/" in rel or rel.startswith("__pycache__") or rel.endswith(".pyc"):
                continue
            items.append((rel, p))
    return items


def build_checksums_payload(root: Path) -> bytes:
    """Build canonical CHECKSUMS.sha256 JSON payload excluding signature/checksum files."""
    digests: dict[str, str] = {}
    for rel, path in _iter_directory_files(root):
        if rel in (CHECKSUMS_FILE, SIGNATURE_FILE):
            continue
        digests[rel] = file_sha256(path)
    return json.dumps(digests, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_signing_keypair() -> tuple[str, str]:
    """Generate an Ed25519 `(private_key_b64, public_key_b64)` pair for extension signing."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_raw).decode("ascii"), base64.b64encode(pub_raw).decode("ascii")


def sign_extension_directory(root: Path, *, private_key_b64: str, key_id: str) -> None:
    """Write `CHECKSUMS.sha256` and `SIGNATURE.ed25519` into `root`."""
    payload = build_checksums_payload(root)
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    sig = priv.sign(payload)
    (root / CHECKSUMS_FILE).write_bytes(payload)
    sig_obj = {
        "key_id": key_id.strip(),
        "alg": "Ed25519",
        "sig_b64": base64.b64encode(sig).decode("ascii"),
    }
    (root / SIGNATURE_FILE).write_text(json.dumps(sig_obj, indent=2), encoding="utf-8")


def create_extension_zip(
    source_dir: Path,
    dest_zip: Path,
    *,
    private_key_b64: str = "",
    key_id: str = "",
) -> str:
    """Package `source_dir` into a deterministic extension ZIP and return its SHA-256 hex."""
    resolved = source_dir.resolve()
    if not (resolved / MANIFEST_FILE).is_file():
        raise ValueError(f"Missing {MANIFEST_FILE} in {resolved}")
    manifest_data = json.loads((resolved / MANIFEST_FILE).read_text(encoding="utf-8"))
    ExtensionManifest.from_dict(manifest_data)
    if private_key_b64:
        if not key_id.strip():
            raise ValueError("key_id is required when signing")
        sign_extension_directory(resolved, private_key_b64=private_key_b64, key_id=key_id)

    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, file_path in _iter_directory_files(resolved):
            zi = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, file_path.read_bytes())
    return file_sha256(dest_zip)


def _validate_zip_entries(zf: zipfile.ZipFile) -> tuple[list[zipfile.ZipInfo], int]:
    entries: list[zipfile.ZipInfo] = []
    total_size = 0
    seen: set[str] = set()
    for info in zf.infolist():
        if info.is_dir():
            continue
        posix = _safe_rel_posix(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError(f"Symlink entry prohibited in archive: {info.filename!r}")
        if len(entries) >= MAX_PACKAGE_FILES:
            raise ValueError(f"Archive exceeds maximum file limit ({MAX_PACKAGE_FILES})")
        if info.file_size < 0 or info.file_size > MAX_PACKAGE_UNCOMPRESSED_BYTES:
            raise ValueError(f"Archive entry exceeds uncompressed size limit: {info.filename!r}")
        total_size += info.file_size
        if total_size > MAX_PACKAGE_UNCOMPRESSED_BYTES:
            raise ValueError("Archive uncompressed total exceeds size limit")
        rel_str = posix.as_posix()
        if rel_str in seen:
            raise ValueError(f"Duplicate archive entry: {rel_str!r}")
        seen.add(rel_str)
        entries.append(info)
    if not entries:
        raise ValueError("Extension archive is empty")
    return entries, total_size


def verify_and_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    trusted_keys: dict[str, str],
    expected_sha256: str = "",
    owner_confirmed: bool = False,
) -> PackageVerificationResult:
    """Validate, verify signature or explicit SHA-256 pin, and safely extract an extension ZIP."""
    archive = Path(zip_path).resolve()
    if not archive.is_file():
        raise FileNotFoundError(f"Extension package not found: {archive}")

    pkg_sha = file_sha256(archive)
    pin = expected_sha256.strip().lower()
    if pin and pin != pkg_sha:
        raise PermissionError(f"Package SHA-256 mismatch: expected {pin}, got {pkg_sha}")

    with zipfile.ZipFile(archive, "r") as zf:
        entries, declared_bytes = _validate_zip_entries(zf)
        members: dict[str, bytes] = {}
        actual_bytes = 0
        for info in entries:
            data = zf.read(info.filename)
            actual_bytes += len(data)
            if actual_bytes > MAX_PACKAGE_UNCOMPRESSED_BYTES:
                raise ValueError("Decompressed archive payload exceeds size limit")
            members[_safe_rel_posix(info.filename).as_posix()] = data

    if MANIFEST_FILE not in members:
        raise ValueError(f"Extension package missing {MANIFEST_FILE}")
    try:
        manifest_obj: Any = json.loads(members[MANIFEST_FILE].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid {MANIFEST_FILE}: {exc}") from exc
    manifest = ExtensionManifest.from_dict(manifest_obj)
    if manifest.entrypoint not in members:
        raise ValueError(f"Extension package missing declared entrypoint: {manifest.entrypoint!r}")

    verified_by = _verify_trust(members, pkg_sha, pin=pin, trusted_keys=trusted_keys, owner_confirmed=owner_confirmed)

    target_root = dest_dir.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    for rel, raw in members.items():
        out = (target_root / rel).resolve()
        if not out.is_relative_to(target_root):
            raise ValueError(f"Resolved output escapes target directory: {rel!r}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)

    return PackageVerificationResult(
        manifest=manifest,
        package_sha256=pkg_sha,
        verified_by=verified_by,
        file_count=len(members),
        total_bytes=actual_bytes or declared_bytes,
    )


def _verify_trust(
    members: dict[str, bytes],
    pkg_sha: str,
    *,
    pin: str,
    trusted_keys: dict[str, str],
    owner_confirmed: bool,
) -> str:
    has_sig = CHECKSUMS_FILE in members and SIGNATURE_FILE in members
    if has_sig:
        checksum_raw = members[CHECKSUMS_FILE]
        try:
            sig_obj = json.loads(members[SIGNATURE_FILE].decode("utf-8"))
            checksums = json.loads(checksum_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError(f"Corrupt signature metadata: {exc}") from exc
        if not isinstance(sig_obj, dict) or not isinstance(checksums, dict):
            raise PermissionError("Malformed signature or checksum structure")
        key_id = str(sig_obj.get("key_id") or "").strip()
        alg = str(sig_obj.get("alg") or "").strip()
        sig_b64 = str(sig_obj.get("sig_b64") or "").strip()
        pub_b64 = trusted_keys.get(key_id, "")
        if alg != "Ed25519" or not pub_b64 or not sig_b64:
            raise PermissionError(f"Untrusted or unknown extension signing key: {key_id!r}")
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
            pub.verify(base64.b64decode(sig_b64), checksum_raw)
        except (ValueError, InvalidSignature) as exc:
            raise PermissionError("Invalid Ed25519 extension package signature") from exc

        expected_files = set(checksums.keys())
        actual_files = {k for k in members if k not in (CHECKSUMS_FILE, SIGNATURE_FILE)}
        if expected_files != actual_files:
            raise PermissionError("Signed checksum file list does not match archive contents")
        for rel in actual_files:
            if bytes_sha256(members[rel]) != str(checksums[rel]):
                raise PermissionError(f"Checksum mismatch for signed file: {rel}")
        return f"ed25519:{key_id}"

    if pin and owner_confirmed:
        return f"sha256:{pkg_sha[:16]}"
    raise PermissionError(
        "Refusing unverified extension archive: provide a trusted Ed25519 signature or explicit owner SHA-256 pin"
    )


def verify_extension_package(
    zip_path: Path,
    *,
    trusted_keys: dict[str, str],
    expected_sha256: str = "",
    owner_confirmed: bool = False,
) -> PackageVerificationResult:
    """Dry-run verification without extracting to registry."""
    archive = Path(zip_path).resolve()
    pkg_sha = file_sha256(archive)
    pin = expected_sha256.strip().lower()
    if pin and pin != pkg_sha:
        raise PermissionError(f"Package SHA-256 mismatch: expected {pin}, got {pkg_sha}")
    with zipfile.ZipFile(archive, "r") as zf:
        entries, declared = _validate_zip_entries(zf)
        members = {_safe_rel_posix(info.filename).as_posix(): zf.read(info.filename) for info in entries}
    manifest = ExtensionManifest.from_dict(json.loads(members[MANIFEST_FILE].decode("utf-8")))
    verified_by = _verify_trust(members, pkg_sha, pin=pin, trusted_keys=trusted_keys, owner_confirmed=owner_confirmed)
    return PackageVerificationResult(
        manifest=manifest,
        package_sha256=pkg_sha,
        verified_by=verified_by,
        file_count=len(members),
        total_bytes=declared,
    )
