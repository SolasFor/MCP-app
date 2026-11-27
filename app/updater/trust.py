"""Cryptographic trust roots, Ed25519 signature checks, and Win32 Authenticode verification."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.updater.models import (
    TrustRootKey,
    UpdateBlockReason,
    UpdateError,
    UpdateManifest,
    parse_semver,
)

# Production built-in Ed25519 trust roots.
# Must NEVER contain test or ephemeral private-key material. When empty, auto-install is strictly BLOCKED.
PRODUCTION_TRUST_ROOTS: tuple[TrustRootKey, ...] = ()
PRODUCTION_REVOKED_KEY_IDS: frozenset[str] = frozenset()
PRODUCTION_PUBLISHER_THUMBPRINTS: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrustPolicy:
    """Pinned trust roots, revocation list, and Windows Authenticode constraints."""

    trust_roots: tuple[TrustRootKey, ...] = ()
    revoked_key_ids: frozenset[str] = frozenset()
    require_authenticode_for_installer: bool = True
    allowed_thumbprints: tuple[str, ...] = ()

    @classmethod
    def production_default(cls) -> "TrustPolicy":
        return cls(
            trust_roots=PRODUCTION_TRUST_ROOTS,
            revoked_key_ids=PRODUCTION_REVOKED_KEY_IDS,
            require_authenticode_for_installer=True,
            allowed_thumbprints=PRODUCTION_PUBLISHER_THUMBPRINTS,
        )

    def auto_install_permitted(self) -> bool:
        return bool(self.trust_roots)

    def block_reason(self) -> str:
        if not self.trust_roots:
            return UpdateBlockReason.MISSING_TRUST_ROOTS
        return UpdateBlockReason.OK


def canonical_manifest_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize manifest dictionary into exact canonical UTF-8 JSON bytes for signing/verification."""
    return UpdateManifest.from_json_bytes(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ).canonical_bytes()


def sign_manifest_bytes(canonical_bytes: bytes, private_key_raw32: bytes) -> str:
    """Create base64 detached Ed25519 signature over canonical manifest JSON bytes."""
    priv = Ed25519PrivateKey.from_private_bytes(private_key_raw32)
    return base64.b64encode(priv.sign(canonical_bytes)).decode("ascii")


def _parse_iso_utc(ts: str) -> datetime:
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _select_active_root(policy: TrustPolicy, key_id: str, published_at: str) -> TrustRootKey:
    if key_id in policy.revoked_key_ids:
        raise UpdateError(UpdateBlockReason.KEY_REVOKED, f"Signing key {key_id!r} has been revoked")
    match = next((root for root in policy.trust_roots if root.key_id == key_id), None)
    if match is None:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Unknown signing key id: {key_id!r}")
    ref_time = _parse_iso_utc(published_at)
    if match.not_before and ref_time < _parse_iso_utc(match.not_before):
        raise UpdateError(UpdateBlockReason.KEY_EXPIRED, f"Signing key {key_id!r} not valid yet for {published_at}")
    if match.not_after and ref_time > _parse_iso_utc(match.not_after):
        raise UpdateError(UpdateBlockReason.KEY_EXPIRED, f"Signing key {key_id!r} expired before {published_at}")
    return match


def verify_release_manifest_signature(
    *,
    manifest_bytes: bytes,
    key_id: str,
    signature_b64: str,
    policy: TrustPolicy,
) -> UpdateManifest:
    """Validate manifest schema, canonical form, trust root, revocation, and Ed25519 signature."""
    if not policy.trust_roots:
        raise UpdateError(
            UpdateBlockReason.MISSING_TRUST_ROOTS,
            "Auto-update trust roots are not provisioned in this build",
        )
    manifest = UpdateManifest.from_json_bytes(manifest_bytes)
    canonical = manifest.canonical_bytes()
    if canonical != manifest_bytes:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Manifest bytes are not in canonical UTF-8 form")

    root = _select_active_root(policy, key_id, manifest.published_at)
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(root.public_key_b64, validate=True))
        sig_bytes = base64.b64decode(signature_b64.strip(), validate=True)
        pub.verify(sig_bytes, canonical)
    except (ValueError, InvalidSignature) as exc:
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, f"Manifest Ed25519 verification failed: {exc}") from exc
    return manifest


def verify_manifest_and_signature(
    *,
    manifest_bytes: bytes,
    key_id: str,
    signature_b64: str,
    current_version: str,
    highest_seen_version: str,
    policy: TrustPolicy,
) -> UpdateManifest:
    """Validate manifest signature plus anti-downgrade and minimum-supported-version bounds."""
    manifest = verify_release_manifest_signature(
        manifest_bytes=manifest_bytes,
        key_id=key_id,
        signature_b64=signature_b64,
        policy=policy,
    )

    cur_v = parse_semver(current_version)
    target_v = parse_semver(manifest.version)
    seen_v = parse_semver(highest_seen_version) if highest_seen_version != "0.0.0" else cur_v
    min_v = parse_semver(manifest.min_supported_version)

    if target_v < seen_v or target_v < cur_v:
        raise UpdateError(
            UpdateBlockReason.DOWNGRADE_BLOCKED,
            f"Downgrade or replay blocked: target={manifest.version}, seen={seen_v.raw}, current={cur_v.raw}",
        )
    if cur_v < min_v:
        raise UpdateError(
            UpdateBlockReason.DOWNGRADE_BLOCKED,
            f"Current version {cur_v.raw} is below min_supported_version {min_v.raw}",
        )
    return manifest


@dataclass(frozen=True)
class AuthenticodeResult:
    """Result of Windows Authenticode validation."""

    verified: bool
    signer_subject: str = ""
    thumbprint: str = ""
    reason: str = ""


def verify_windows_authenticode(
    file_path: Path,
    allowed_thumbprints: tuple[str, ...] = (),
) -> AuthenticodeResult:
    """Verify PE Authenticode signature via WinVerifyTrust + CryptQueryObject signer certificate check."""
    if sys.platform != "win32":
        return AuthenticodeResult(verified=False, reason="Authenticode verification is Windows-only")
    if not file_path.is_file():
        return AuthenticodeResult(verified=False, reason=f"File not found: {file_path}")

    trust_status, err_code = _win_verify_trust(file_path)
    if not trust_status:
        return AuthenticodeResult(verified=False, reason=f"WinVerifyTrust failed (0x{err_code & 0xFFFFFFFF:08X})")

    thumbprint = _extract_pe_signer_thumbprint(file_path)
    if not thumbprint:
        return AuthenticodeResult(verified=False, reason="No embedded signer certificate found")

    norm_allowed = tuple(t.strip().upper() for t in allowed_thumbprints if t.strip())
    if norm_allowed and thumbprint.upper() not in norm_allowed:
        return AuthenticodeResult(
            verified=False,
            thumbprint=thumbprint,
            reason=f"Publisher certificate thumbprint {thumbprint} not in trusted allowlist",
        )
    return AuthenticodeResult(verified=True, thumbprint=thumbprint, reason="ok")


def _win_verify_trust(file_path: Path) -> tuple[bool, int]:
    """Invoke Windows wintrust!WinVerifyTrust using WINTRUST_ACTION_GENERIC_VERIFY_V2."""
    if sys.platform != "win32":
        return False, -1
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(_GUID)),
        ]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    action_guid = _GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = _WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
        pcwszFilePath=str(file_path),
        hFile=None,
        pgKnownSubject=None,
    )
    wtd = _WINTRUST_DATA(
        cbStruct=ctypes.sizeof(_WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=2,  # WTD_UI_NONE
        fdwRevocationChecks=0,  # WTD_REVOKE_NONE
        dwUnionChoice=1,  # WTD_CHOICE_FILE
        pFile=ctypes.pointer(file_info),
        dwStateAction=1,  # WTD_STATEACTION_VERIFY
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=0,
        dwUIContext=0,
        pSignatureSettings=None,
    )
    windll_obj = getattr(ctypes, "windll", None)
    if windll_obj is None:
        return False, -1
    wintrust = windll_obj.wintrust
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.POINTER(_WINTRUST_DATA)]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    res = int(wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd)))
    # Release verification state handle cleanly.
    wtd.dwStateAction = 2  # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
    return res == 0, res


def _extract_pe_signer_thumbprint(file_path: Path) -> str:
    """Query PKCS#7 embedded signer thumbprint (SHA-1 hex) via crypt32!CryptQueryObject."""
    if sys.platform != "win32":
        return ""
    from ctypes import wintypes

    class _CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", wintypes.HANDLE),
        ]

    windll_obj = getattr(ctypes, "windll", None)
    if windll_obj is None:
        return ""
    crypt32 = windll_obj.crypt32
    h_store = wintypes.HANDLE()
    h_msg = wintypes.HANDLE()
    ok = crypt32.CryptQueryObject(
        1,  # CERT_QUERY_OBJECT_FILE
        ctypes.c_wchar_p(str(file_path)),
        1 << 10,  # CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
        1 << 1,  # CERT_QUERY_FORMAT_FLAG_BINARY
        0,
        None,
        None,
        None,
        ctypes.byref(h_store),
        ctypes.byref(h_msg),
        None,
    )
    if not ok or not h_store:
        return ""

    try:
        crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(_CERT_CONTEXT)
        ctx = crypt32.CertEnumCertificatesInStore(h_store, None)
        if ctx:
            encoded = bytes(ctx.contents.pbCertEncoded[: ctx.contents.cbCertEncoded])
            thumb = hashlib.sha1(encoded, usedforsecurity=False).hexdigest().upper()
            crypt32.CertFreeCertificateContext(ctx)
            return thumb
        return ""
    finally:
        if h_msg:
            crypt32.CryptMsgClose(h_msg)
        if h_store:
            crypt32.CertCloseStore(h_store, 0)
