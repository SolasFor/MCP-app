"""Data models, state machine, strict SemVer, and persistent updater state."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from app.core.atomic_io import atomic_write_json

OFFICIAL_REPO = "SolasFor/MCP-app"
CHANNEL_STABLE = "stable"
UPDATER_MUTEX_NAME = "Local\\MCPApp-Updater"
INSTALLER_MUTEX_NAME = "MCPApp-Running"
MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_DISK_RESERVE_BYTES = 150 * 1024 * 1024

InstallType = Literal["dev", "installed", "portable"]

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "version",
        "channel",
        "published_at",
        "min_supported_version",
        "changelog",
        "installer",
        "portable",
        "publisher_thumbprints",
    }
)
_ALLOWED_ASSET_KEYS = frozenset({"name", "sha256", "size", "authenticode_required"})


class UpdateBlockReason:
    """Explicit machine-readable reasons why auto-install or update step is blocked."""

    OK = "ok"
    DEV_MODE = "dev_mode"
    MISSING_TRUST_ROOTS = "missing_trust_roots"
    NO_AUTHENTICODE_POLICY = "no_authenticode_policy"
    ELEVATION_REQUIRED = "elevation_required"
    NO_ROLLBACK_CONTRACT = "no_rollback_contract"
    FOREIGN_FILES_IN_INSTALL_DIR = "foreign_files_in_install_dir"
    DISK_FULL = "disk_full"
    ACTIVE_TASKS = "active_tasks"
    SCHEDULER_ACTIVE = "scheduler_active"
    DOWNGRADE_BLOCKED = "downgrade_blocked"
    KEY_REVOKED = "key_revoked"
    KEY_EXPIRED = "key_expired"
    SIGNATURE_INVALID = "signature_invalid"
    HASH_MISMATCH = "hash_mismatch"
    AUTHENTICODE_FAILED = "authenticode_failed"
    ZIP_SECURITY = "zip_security"
    NETWORK_POLICY = "network_policy"
    CANCELLED = "cancelled"
    INSTALL_FAILED = "install_failed"
    HEALTHCHECK_FAILED = "healthcheck_failed"


class UpdateState:
    """Lifecycle and transactional update states."""

    IDLE = "IDLE"
    CHECKING = "CHECKING"
    AVAILABLE = "AVAILABLE"
    DOWNLOADING = "DOWNLOADING"
    STAGED = "STAGED"
    READY_TO_INSTALL = "READY_TO_INSTALL"
    PREPARED = "PREPARED"
    BACKING_UP = "BACKING_UP"
    SWAPPING = "SWAPPING"
    INSTALLING = "INSTALLING"
    VERIFYING_NEW = "VERIFYING_NEW"
    COMMITTED = "COMMITTED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class UpdateError(RuntimeError):
    """Typed updater failure carrying an explicit UpdateBlockReason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, order=True)
class SemVer:
    """Strict numeric X.Y.Z semantic version (prerelease/dev builds excluded from stable)."""

    major: int
    minor: int
    patch: int

    @property
    def raw(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def parse_semver(version: str) -> SemVer:
    """Parse strict `X.Y.Z` semantic version without leading `v` or prerelease suffixes."""
    cleaned = str(version or "").strip()
    m = _SEMVER_RE.match(cleaned)
    if not m:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Invalid stable SemVer: {version!r}")
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)))


@dataclass(frozen=True)
class TrustRootKey:
    """Built-in pinned Ed25519 trust root with optional ISO-8601 validity window."""

    key_id: str
    public_key_b64: str
    not_before: str | None = None
    not_after: str | None = None


@dataclass(frozen=True)
class ManifestAsset:
    """Signed release artifact metadata."""

    name: str
    sha256: str
    size: int
    authenticode_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "authenticode_required": self.authenticode_required,
        }


def _parse_asset(raw: Any, *, expected_name: str) -> ManifestAsset:
    if not isinstance(raw, dict):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Manifest asset entry must be a mapping")
    extra = set(raw.keys()) - _ALLOWED_ASSET_KEYS
    if extra:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Unexpected asset fields: {sorted(extra)}")
    name = str(raw.get("name") or "")
    if name != expected_name:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Unexpected asset name {name!r}; expected {expected_name!r}")
    sha = str(raw.get("sha256") or "").lower()
    if not _SHA256_RE.match(sha):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Invalid SHA-256 hex for {name}")
    size = raw.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Invalid asset size for {name}")
    auth_req = raw.get("authenticode_required", False)
    if not isinstance(auth_req, bool):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Invalid authenticode_required flag for {name}")
    return ManifestAsset(name=name, sha256=sha, size=size, authenticode_required=auth_req)


def _parse_manifest_payload(payload: Any) -> UpdateManifest:
    if not isinstance(payload, dict):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Manifest root must be a JSON object")
    extra = set(payload.keys()) - _ALLOWED_MANIFEST_KEYS
    if extra:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Manifest contains disallowed fields: {sorted(extra)}")
    if payload.get("schema_version") != 1:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Unsupported manifest schema_version")
    channel = str(payload.get("channel") or "")
    if channel != CHANNEL_STABLE:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Unsupported release channel: {channel!r}")
    ver = parse_semver(str(payload.get("version") or "")).raw
    min_ver = parse_semver(str(payload.get("min_supported_version") or "")).raw
    published_at = str(payload.get("published_at") or "").strip()
    if not published_at:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Manifest missing published_at")
    raw_thumbs = payload.get("publisher_thumbprints") or []
    if not isinstance(raw_thumbs, list) or not all(isinstance(x, str) and x.strip() for x in raw_thumbs):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Invalid publisher_thumbprints list")
    return UpdateManifest(
        schema_version=1,
        version=ver,
        channel=CHANNEL_STABLE,
        published_at=published_at,
        min_supported_version=min_ver,
        changelog=str(payload.get("changelog") or ""),
        installer=_parse_asset(payload.get("installer"), expected_name=f"MCPApp-Setup-{ver}.exe"),
        portable=_parse_asset(payload.get("portable"), expected_name=f"MCPApp-{ver}-portable.zip"),
        publisher_thumbprints=tuple(x.strip().upper() for x in raw_thumbs),
    )


@dataclass(frozen=True)
class UpdateManifest:
    """Canonical signed update manifest (schema_version=1, stable channel only)."""

    schema_version: int
    version: str
    channel: str
    published_at: str
    min_supported_version: str
    changelog: str
    installer: ManifestAsset
    portable: ManifestAsset
    publisher_thumbprints: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "channel": self.channel,
            "published_at": self.published_at,
            "min_supported_version": self.min_supported_version,
            "changelog": self.changelog,
            "installer": self.installer.to_dict(),
            "portable": self.portable.to_dict(),
            "publisher_thumbprints": list(self.publisher_thumbprints),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw_bytes: bytes) -> "UpdateManifest":
        if len(raw_bytes) > MAX_MANIFEST_BYTES:
            raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Update manifest exceeds maximum size")
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Malformed JSON manifest: {exc}") from exc
        return _parse_manifest_payload(payload)


@dataclass
class UpdateTransaction:
    """Durable transaction journal entry for swap / install / rollback recovery."""

    tx_id: str
    state: str
    install_type: InstallType
    source_version: str
    target_version: str
    install_dir: str
    backup_dir: str = ""
    staged_dir: str = ""
    rollback_installer: str = ""
    data_dir: str = ""
    created_at: str = ""
    updated_at: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "UpdateTransaction":
        tx_id_raw = str(raw.get("tx_id") or "")
        tx_id = tx_id_raw if re.fullmatch(r"[A-Za-z0-9_-]{3,48}", tx_id_raw) else ""
        itype_raw = str(raw.get("install_type") or "portable")
        itype: InstallType = itype_raw if itype_raw in ("dev", "installed", "portable") else "portable"  # type: ignore[assignment]
        return cls(
            tx_id=tx_id,
            state=str(raw.get("state") or UpdateState.FAILED),
            install_type=itype,
            source_version=str(raw.get("source_version") or ""),
            target_version=str(raw.get("target_version") or ""),
            install_dir=_clean_state_path(raw.get("install_dir")),
            backup_dir=_clean_state_path(raw.get("backup_dir")),
            staged_dir=_clean_state_path(raw.get("staged_dir")),
            rollback_installer=_clean_state_path(raw.get("rollback_installer")),
            data_dir=_clean_state_path(raw.get("data_dir")),
            created_at=str(raw.get("created_at") or ""),
            updated_at=str(raw.get("updated_at") or ""),
            error=str(raw.get("error") or ""),
        )


def _clean_state_path(val: Any) -> str:
    text = str(val or "").strip()
    if not text or "\x00" in text:
        return ""
    if ".." in Path(text).parts:
        return ""
    return text


@dataclass
class UpdaterPersistentState:
    """Persistent state stored at `%APPDATA%/MCPApp/updates/state.json`."""

    highest_seen_version: str = "0.0.0"
    last_check_at: float = 0.0
    last_known_version: str = ""
    last_changelog: str = ""
    active_transaction: UpdateTransaction | None = None
    last_completed_tx: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "highest_seen_version": self.highest_seen_version,
            "last_check_at": self.last_check_at,
            "last_known_version": self.last_known_version,
            "last_changelog": self.last_changelog,
            "active_transaction": self.active_transaction.to_dict() if self.active_transaction else None,
            "last_completed_tx": self.last_completed_tx,
        }

    @classmethod
    def load(cls, path: Path) -> "UpdaterPersistentState":
        if not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return cls()
        if not isinstance(raw, dict):
            return cls()
        tx_raw = raw.get("active_transaction")
        active_tx = UpdateTransaction.from_dict(tx_raw) if isinstance(tx_raw, dict) else None
        last_tx = raw.get("last_completed_tx")
        return cls(
            highest_seen_version=str(raw.get("highest_seen_version") or "0.0.0"),
            last_check_at=float(raw.get("last_check_at") or 0.0),
            last_known_version=str(raw.get("last_known_version") or ""),
            last_changelog=str(raw.get("last_changelog") or ""),
            active_transaction=active_tx,
            last_completed_tx=last_tx if isinstance(last_tx, dict) else None,
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, self.to_dict(), restrict_acl=True)
