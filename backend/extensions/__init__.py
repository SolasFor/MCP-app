"""Stage 9 Extensions runtime, SDK, package verification, and registry."""
from __future__ import annotations

from backend.extensions.manager import ExtensionManager
from backend.extensions.models import (
    ALLOWED_EXTENSION_PERMISSIONS,
    SDK_API_VERSION,
    SUPPORTED_API_MAJOR,
    SUPPORTED_API_MINOR,
    DeclarativeUIComponent,
    ExtensionManifest,
    ExtensionRuntimeStatus,
    ExtensionToolSpec,
    InstalledExtension,
    check_api_compatibility,
)
from backend.extensions.packaging import (
    PackageVerificationResult,
    create_extension_zip,
    generate_signing_keypair,
    sign_extension_directory,
    verify_extension_package,
)
from backend.extensions.sdk import ExtensionApp
from backend.extensions.store import ExtensionStore, official_extensions_dir

__all__ = [
    "ALLOWED_EXTENSION_PERMISSIONS",
    "DeclarativeUIComponent",
    "ExtensionApp",
    "ExtensionManager",
    "ExtensionManifest",
    "ExtensionRuntimeStatus",
    "ExtensionStore",
    "ExtensionToolSpec",
    "InstalledExtension",
    "PackageVerificationResult",
    "SDK_API_VERSION",
    "SUPPORTED_API_MAJOR",
    "SUPPORTED_API_MINOR",
    "check_api_compatibility",
    "create_extension_zip",
    "generate_signing_keypair",
    "official_extensions_dir",
    "sign_extension_directory",
    "verify_extension_package",
]
