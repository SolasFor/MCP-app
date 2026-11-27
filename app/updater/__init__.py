"""Trusted auto-update subsystem for MCP App (N02)."""
from __future__ import annotations

from app.updater.detector import InstallEnvironment, detect_install_environment
from app.updater.manager import UpdateCheckSnapshot, UpdateManager
from app.updater.models import (
    CHANNEL_STABLE,
    OFFICIAL_REPO,
    ManifestAsset,
    SemVer,
    TrustRootKey,
    UpdateBlockReason,
    UpdateError,
    UpdateManifest,
    UpdaterPersistentState,
    UpdateState,
    UpdateTransaction,
    parse_semver,
)
from app.updater.trust import (
    PRODUCTION_REVOKED_KEY_IDS,
    PRODUCTION_TRUST_ROOTS,
    AuthenticodeResult,
    TrustPolicy,
    canonical_manifest_bytes,
    sign_manifest_bytes,
    verify_manifest_and_signature,
    verify_windows_authenticode,
)

__all__ = [
    "AuthenticodeResult",
    "CHANNEL_STABLE",
    "InstallEnvironment",
    "ManifestAsset",
    "OFFICIAL_REPO",
    "PRODUCTION_REVOKED_KEY_IDS",
    "PRODUCTION_TRUST_ROOTS",
    "SemVer",
    "TrustPolicy",
    "TrustRootKey",
    "UpdateBlockReason",
    "UpdateCheckSnapshot",
    "UpdateError",
    "UpdateManager",
    "UpdateManifest",
    "UpdateState",
    "UpdateTransaction",
    "UpdaterPersistentState",
    "canonical_manifest_bytes",
    "detect_install_environment",
    "parse_semver",
    "sign_manifest_bytes",
    "verify_manifest_and_signature",
    "verify_windows_authenticode",
]
