"""Schema-versioned redacted config backup/restore and staged Ed25519 updater with rollback."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import stat
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app import __version__
from app.core.atomic_io import atomic_write_bytes

BACKUP_SCHEMA_VERSION = 1
_BACKUP_TARGETS = (
    "settings.json",
    "gateway/servers.json",
    "servers/managed_servers.json",
    "workspaces/workspaces.json",
    "desktop/policy.json",
    "extensions/registry.json",
    "remote/devices.json",
    "automation/schedules.json",
)
_EXCLUDED_SEGMENTS = frozenset({"secrets", "oauth", "token.json", "secrets.key", "secrets.vault.enc"})
MAX_BACKUP_FILES = 100
MAX_BACKUP_BYTES = 20 * 1024 * 1024


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_rel(name: str) -> PurePosixPath:
    norm = name.replace("\\", "/")
    if not norm or "\x00" in norm or norm.startswith("/") or ":" in norm:
        raise ValueError(f"Unsafe archive path: {name!r}")
    p = PurePosixPath(norm)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise ValueError(f"Traversal segment in archive: {name!r}")
    return p


class BackupManager:
    """Create and atomically restore non-secret configuration backups (DPAPI secrets excluded)."""

    @staticmethod
    def create_backup(config_root: Path, dest_zip: Path) -> dict[str, Any]:
        root = Path(config_root).resolve()
        files_map: dict[str, bytes] = {}
        digests: dict[str, str] = {}
        for rel in _BACKUP_TARGETS:
            src = (root / rel).resolve()
            if src.is_file() and src.is_relative_to(root):
                if any(part in _EXCLUDED_SEGMENTS for part in PurePosixPath(rel).parts):
                    continue
                raw = src.read_bytes()
                files_map[f"config/{rel}"] = raw
                digests[f"config/{rel}"] = _sha256_bytes(raw)

        manifest = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "app_version": __version__,
            "created_at": time.time(),
            "secrets_excluded": True,
            "dpapi_portability_notice": (
                "DPAPI-encrypted secrets and OAuth vaults are excluded by default and are not "
                "portable across Windows user accounts or different PCs."
            ),
            "checksums": digests,
        }
        dest = Path(dest_zip).resolve()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("backup_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
            for rel_key, raw in sorted(files_map.items()):
                zf.writestr(rel_key, raw)
        atomic_write_bytes(dest, buf.getvalue(), restrict_acl=True)
        return {
            "path": str(dest),
            "file_count": len(files_map),
            "schema_version": BACKUP_SCHEMA_VERSION,
            "secrets_excluded": True,
        }

    @staticmethod
    def restore_backup(zip_path: Path, config_root: Path) -> dict[str, Any]:
        archive = Path(zip_path).resolve()
        if not archive.is_file():
            raise FileNotFoundError(f"Backup archive not found: {archive}")
        root = Path(config_root).resolve()
        root.mkdir(parents=True, exist_ok=True)

        members: dict[str, bytes] = {}
        total = 0
        with zipfile.ZipFile(archive, "r") as zf:
            infolist = [i for i in zf.infolist() if not i.is_dir()]
            if len(infolist) > MAX_BACKUP_FILES:
                raise ValueError("Backup archive exceeds max file count")
            for info in infolist:
                rel = _safe_rel(info.filename).as_posix()
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ValueError(f"Symlink entry prohibited in backup archive: {rel!r}")
                raw = zf.read(info.filename)
                total += len(raw)
                if total > MAX_BACKUP_BYTES:
                    raise ValueError("Backup archive exceeds max uncompressed size")
                members[rel] = raw

        if "backup_manifest.json" not in members:
            raise ValueError("Backup archive missing backup_manifest.json")
        manifest = json.loads(members["backup_manifest.json"].decode("utf-8"))
        if int(manifest.get("schema_version") or 0) != BACKUP_SCHEMA_VERSION:
            raise ValueError(f"Unsupported backup schema_version: {manifest.get('schema_version')!r}")
        checksums = manifest.get("checksums") or {}
        if not isinstance(checksums, dict):
            raise ValueError("Invalid backup manifest checksums")

        # Never allow backup restore to overwrite vault/secrets/oauth files
        for rel_path, expected_hex in checksums.items():
            norm_rel = _safe_rel(str(rel_path)).as_posix()
            if not norm_rel.startswith("config/") or any(p in _EXCLUDED_SEGMENTS for p in PurePosixPath(norm_rel).parts):
                raise PermissionError(f"Backup attempts to restore prohibited target: {norm_rel!r}")
            if norm_rel not in members:
                raise ValueError(f"Missing archived file declared in manifest: {norm_rel!r}")
            if _sha256_bytes(members[norm_rel]) != str(expected_hex):
                raise PermissionError(f"Checksum mismatch for backup file: {norm_rel!r}")

        # Pre-restore rollback snapshot
        pre_backup = root / ".pre_restore_backup.zip"
        BackupManager.create_backup(root, pre_backup)
        restored: list[str] = []
        try:
            for norm_rel in checksums:
                target_sub = norm_rel[len("config/"):]
                out = (root / target_sub).resolve()
                if not out.is_relative_to(root):
                    raise ValueError(f"Resolved restore path escapes config root: {target_sub!r}")
                atomic_write_bytes(out, members[norm_rel], restrict_acl=True)
                restored.append(target_sub)
        except Exception:
            # Attempt best-effort rollback from pre_restore_backup
            try:
                if pre_backup.is_file():
                    with zipfile.ZipFile(pre_backup, "r") as prev_zf:
                        for info in prev_zf.infolist():
                            if info.is_dir():
                                continue
                            rel = _safe_rel(info.filename).as_posix()
                            if not rel.startswith("config/"):
                                continue
                            sub = rel[len("config/"):]
                            out = (root / sub).resolve()
                            if not out.is_relative_to(root):
                                continue
                            atomic_write_bytes(out, prev_zf.read(info.filename), restrict_acl=True)
            except Exception:  # noqa: BLE001
                pass
            raise
        return {
            "restored_files": restored,
            "rollback_snapshot": str(pre_backup),
            "schema_version": BACKUP_SCHEMA_VERSION,
        }


@dataclass(frozen=True)
class UpdateCandidate:
    """Release metadata inspected by StagedUpdater."""

    version: str
    changelog: str
    asset_url: str
    sha256: str
    sig_b64: str = ""
    key_id: str = ""
    authenticode_signed: bool = False


class StagedUpdater:
    """Check, stage, cryptographically verify, and safely roll back updates (auto-install disabled)."""

    def __init__(self, updates_dir: Path, *, trusted_pubkeys: dict[str, str] | None = None) -> None:
        self.updates_dir = Path(updates_dir).resolve()
        self.updates_dir.mkdir(parents=True, exist_ok=True)
        self.trusted_pubkeys = dict(trusted_pubkeys or {})
        self.auto_install_enabled = False  # Always disabled until real trusted signing is active

    def stage_bytes(self, candidate: UpdateCandidate, payload: bytes) -> Path:
        actual_sha = _sha256_bytes(payload)
        if actual_sha != candidate.sha256.strip().lower():
            raise PermissionError(f"Update SHA-256 mismatch: expected {candidate.sha256}, got {actual_sha}")
        pub_b64 = self.trusted_pubkeys.get(candidate.key_id, "")
        if not candidate.sig_b64 or not pub_b64:
            raise PermissionError(
                "Unsigned update rejected: trusted Ed25519/Authenticode signature required before staging"
            )
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
            pub.verify(base64.b64decode(candidate.sig_b64), actual_sha.encode("ascii"))
        except (ValueError, InvalidSignature) as exc:
            raise PermissionError("Corrupted or forged update signature") from exc

        stage_dir = self.updates_dir / "staged" / candidate.version
        stage_dir.mkdir(parents=True, exist_ok=True)
        out = stage_dir / f"MCPApp-update-{candidate.version}.zip"
        out.write_bytes(payload)
        return out

    def apply_staged(
        self,
        candidate: UpdateCandidate,
        staged_file: Path,
        *,
        install_dir: Path,
        owner_explicit_install: bool = False,
    ) -> dict[str, Any]:
        if not self.auto_install_enabled and not owner_explicit_install:
            raise PermissionError("Auto-install is disabled pending trusted release signing")
        if not staged_file.is_file() or _sha256_bytes(staged_file.read_bytes()) != candidate.sha256.lower():
            raise PermissionError("Staged update missing or tampered")

        target = Path(install_dir).resolve()
        backup_dir = self.updates_dir / "rollback" / candidate.version
        if target.exists():
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            shutil.copytree(target, backup_dir)
        try:
            with zipfile.ZipFile(staged_file, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    rel = _safe_rel(info.filename).as_posix()
                    out = (target / rel).resolve()
                    if not out.is_relative_to(target):
                        raise ValueError("Update payload escapes install directory")
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(zf.read(info.filename))
        except Exception:
            if backup_dir.is_dir():
                shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(backup_dir, target)
            raise
        return {"applied_version": candidate.version, "rollback_dir": str(backup_dir)}

    def rollback_last(self, version: str, *, install_dir: Path) -> bool:
        backup_dir = self.updates_dir / "rollback" / version
        if not backup_dir.is_dir():
            return False
        target = Path(install_dir).resolve()
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(backup_dir, target)
        return True

    @staticmethod
    def parse_github_release(payload: dict[str, Any]) -> UpdateCandidate:
        """Parse GitHub Release JSON payload without auto-downloading or trusting unsigned assets."""
        tag = str(payload.get("tag_name") or "").strip()
        if not tag:
            raise ValueError("GitHub release payload missing tag_name")
        version = tag[1:] if tag.startswith(("v", "V")) else tag
        body = str(payload.get("body") or "")
        raw_assets = payload.get("assets")
        assets: list[Any] = raw_assets if isinstance(raw_assets, list) else []
        asset_url = ""
        for item in assets:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").lower()
            url = str(item.get("browser_download_url") or "")
            if url and ("portable" in name and name.endswith(".zip")):
                asset_url = url
                break
        if not asset_url:
            for item in assets:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").lower()
                url = str(item.get("browser_download_url") or "")
                if url and name.endswith(".zip"):
                    asset_url = url
                    break
        sha_val = str(payload.get("sha256") or "").strip().lower()
        if not sha_val and body:
            m = re.search(r"SHA256:\s*([0-9a-fA-F]{64})", body)
            if m:
                sha_val = m.group(1).lower()
        return UpdateCandidate(
            version=version,
            changelog=body,
            asset_url=asset_url,
            sha256=sha_val,
            sig_b64=str(payload.get("sig_b64") or ""),
            key_id=str(payload.get("key_id") or ""),
            authenticode_signed=False,
        )

    def fetch_latest_github_release(
        self,
        repo: str = "SolasFor/MCP-app",
        *,
        timeout: float = 10.0,
    ) -> UpdateCandidate:
        """Query GitHub Releases API for latest release metadata (never downloads/installs automatically)."""
        clean_repo = (repo or "").strip()
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", clean_repo):
            raise ValueError(f"Invalid GitHub repository slug: {repo!r}")
        req = urllib.request.Request(
            f"https://api.github.com/repos/{clean_repo}/releases/latest",
            headers={"User-Agent": "MCP-app", "Accept": "application/vnd.github+json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:  # noqa: S310 - HTTPS fixed GitHub API host
            raw = resp.read().decode("utf-8", errors="replace")
        return self.parse_github_release(json.loads(raw))
