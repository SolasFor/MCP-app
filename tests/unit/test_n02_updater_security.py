"""TDD security & trust-policy tests for app.updater (N02)."""
from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.updater.models import (
    CHANNEL_STABLE,
    OFFICIAL_REPO,
    TrustRootKey,
    UpdateBlockReason,
    UpdateError,
    UpdateManifest,
)
from app.updater.network import (
    ALLOWED_GITHUB_HOSTS,
    download_verified_asset,
    fetch_latest_release_info,
    validate_github_url,
)
from app.updater.staging import (
    extract_verified_portable_zip,
    reverify_staged_bundle,
)
from app.updater.trust import (
    PRODUCTION_TRUST_ROOTS,
    TrustPolicy,
    canonical_manifest_bytes,
    sign_manifest_bytes,
    verify_manifest_and_signature,
    verify_windows_authenticode,
)


def _gen_keypair() -> tuple[bytes, str]:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, base64.b64encode(pub_raw).decode("ascii")


def _sample_manifest_dict(
    version: str = "1.0.3",
    *,
    min_supported: str = "1.0.0",
    channel: str = CHANNEL_STABLE,
    installer_sha: str | None = None,
    portable_sha: str | None = None,
    portable_size: int = 128,
    installer_size: int = 256,
) -> dict:
    return {
        "schema_version": 1,
        "version": version,
        "channel": channel,
        "published_at": "2026-11-27T12:00:00Z",
        "min_supported_version": min_supported,
        "changelog": "- Fix updater check\n- Improve diagnostics",
        "installer": {
            "name": f"MCPApp-Setup-{version}.exe",
            "sha256": installer_sha or ("a" * 64),
            "size": installer_size,
            "authenticode_required": True,
        },
        "portable": {
            "name": f"MCPApp-{version}-portable.zip",
            "sha256": portable_sha or ("b" * 64),
            "size": portable_size,
            "authenticode_required": False,
        },
        "publisher_thumbprints": ["0123456789ABCDEF0123456789ABCDEF01234567"],
    }


class UpdaterTrustAndManifestTests(unittest.TestCase):
    def test_production_trust_roots_never_contain_test_keys(self) -> None:
        self.assertEqual(PRODUCTION_TRUST_ROOTS, ())
        policy = TrustPolicy.production_default()
        self.assertFalse(policy.auto_install_permitted())
        self.assertEqual(policy.block_reason(), UpdateBlockReason.MISSING_TRUST_ROOTS)

    def test_manifest_rejects_self_signed_key_injection_and_unknown_fields(self) -> None:
        base = _sample_manifest_dict()
        for bad_field in ("public_key", "trusted_keys", "url", "download_url"):
            payload = dict(base)
            payload[bad_field] = "attacker-controlled"
            with self.assertRaises(UpdateError) as ctx:
                UpdateManifest.from_json_bytes(json.dumps(payload).encode("utf-8"))
            self.assertEqual(ctx.exception.code, UpdateBlockReason.SIGNATURE_INVALID)

        bad_schema = dict(base)
        bad_schema["schema_version"] = 2
        with self.assertRaises(UpdateError):
            UpdateManifest.from_json_bytes(json.dumps(bad_schema).encode("utf-8"))

        bad_channel = dict(base)
        bad_channel["channel"] = "beta"
        with self.assertRaises(UpdateError):
            UpdateManifest.from_json_bytes(json.dumps(bad_channel).encode("utf-8"))

    def test_signature_verification_and_key_rotation_revocation_rollback(self) -> None:
        priv1, pub1 = _gen_keypair()
        priv2, pub2 = _gen_keypair()
        payload = _sample_manifest_dict("1.0.3")
        raw = canonical_manifest_bytes(payload)
        sig1 = sign_manifest_bytes(raw, priv1)
        sig2 = sign_manifest_bytes(raw, priv2)

        policy = TrustPolicy(
            trust_roots=(
                TrustRootKey("root-old", pub1, not_before="2025-01-01T00:00:00Z", not_after="2026-06-01T00:00:00Z"),
                TrustRootKey("root-new", pub2, not_before="2026-01-01T00:00:00Z", not_after="2028-01-01T00:00:00Z"),
            ),
            revoked_key_ids=frozenset({"root-revoked"}),
            allowed_thumbprints=("0123456789ABCDEF0123456789ABCDEF01234567",),
        )

        # Valid key-2 signature passes
        manifest = verify_manifest_and_signature(
            manifest_bytes=raw,
            key_id="root-new",
            signature_b64=sig2,
            current_version="1.0.2",
            highest_seen_version="1.0.2",
            policy=policy,
        )
        self.assertEqual(manifest.version, "1.0.3")

        # Expired key-1 rejected (published_at is 2026-11-27 > 2026-06-01)
        with self.assertRaises(UpdateError) as ctx_exp:
            verify_manifest_and_signature(
                manifest_bytes=raw,
                key_id="root-old",
                signature_b64=sig1,
                current_version="1.0.2",
                highest_seen_version="1.0.2",
                policy=policy,
            )
        self.assertEqual(ctx_exp.exception.code, UpdateBlockReason.KEY_EXPIRED)

        # Revoked key rejected even if signature cryptographically matches
        priv_r, pub_r = _gen_keypair()
        sig_r = sign_manifest_bytes(raw, priv_r)
        policy_revoked = TrustPolicy(
            trust_roots=(TrustRootKey("root-revoked", pub_r),),
            revoked_key_ids=frozenset({"root-revoked"}),
        )
        with self.assertRaises(UpdateError) as ctx_rev:
            verify_manifest_and_signature(
                manifest_bytes=raw,
                key_id="root-revoked",
                signature_b64=sig_r,
                current_version="1.0.2",
                highest_seen_version="1.0.2",
                policy=policy_revoked,
            )
        self.assertEqual(ctx_rev.exception.code, UpdateBlockReason.KEY_REVOKED)

        # Tampered manifest rejected
        tampered = canonical_manifest_bytes({**payload, "changelog": "evil"})
        with self.assertRaises(UpdateError) as ctx_sig:
            verify_manifest_and_signature(
                manifest_bytes=tampered,
                key_id="root-new",
                signature_b64=sig2,
                current_version="1.0.2",
                highest_seen_version="1.0.2",
                policy=policy,
            )
        self.assertEqual(ctx_sig.exception.code, UpdateBlockReason.SIGNATURE_INVALID)

        # Rollback/replay protection: highest_seen_version 1.0.4 blocks 1.0.3 even if current=1.0.2
        with self.assertRaises(UpdateError) as ctx_down:
            verify_manifest_and_signature(
                manifest_bytes=raw,
                key_id="root-new",
                signature_b64=sig2,
                current_version="1.0.2",
                highest_seen_version="1.0.4",
                policy=policy,
            )
        self.assertEqual(ctx_down.exception.code, UpdateBlockReason.DOWNGRADE_BLOCKED)

    def test_unsigned_or_tampered_windows_exe_fails_authenticode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_exe = Path(tmp) / "fake_setup.exe"
            fake_exe.write_bytes(b"MZ" + b"\x00" * 512)
            res = verify_windows_authenticode(fake_exe)
            self.assertFalse(res.verified)
            self.assertTrue(res.reason)


class UpdaterNetworkAndStagingTests(unittest.TestCase):
    def test_network_allows_only_official_github_https_hosts(self) -> None:
        self.assertIn("api.github.com", ALLOWED_GITHUB_HOSTS)
        self.assertIn("objects.githubusercontent.com", ALLOWED_GITHUB_HOSTS)
        validate_github_url(f"https://api.github.com/repos/{OFFICIAL_REPO}/releases/latest")

        for bad_url in (
            f"http://api.github.com/repos/{OFFICIAL_REPO}/releases/latest",
            "https://evil.example.com/update-manifest.json",
            "https://user:pass@github.com/SolasFor/MCP-app/releases",
        ):
            with self.assertRaises(UpdateError) as ctx:
                validate_github_url(bad_url)
            self.assertEqual(ctx.exception.code, UpdateBlockReason.NETWORK_POLICY)

    def test_fetch_latest_ignores_body_markdown_urls_and_rejects_prerelease(self) -> None:
        def _fake_get_json(url: str) -> bytes:
            return json.dumps(
                {
                    "tag_name": "v1.0.3-rc1",
                    "draft": False,
                    "prerelease": True,
                    "body": "Download from https://evil.example.com/MCPApp.exe",
                    "assets": [],
                }
            ).encode("utf-8")

        with self.assertRaises(UpdateError):
            fetch_latest_release_info(fetch_bytes=_fake_get_json)

    def test_download_rejects_hash_mismatch_and_cleans_partial_file(self) -> None:
        data = b"hello-update-payload"
        wrong_sha = "0" * 64

        class _FakeResp:
            status = 200

            def __init__(self, payload: bytes) -> None:
                self._buf = io.BytesIO(payload)
                self.headers = {"Content-Length": str(len(payload))}

            def read(self, n: int = -1) -> bytes:
                return self._buf.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "asset.zip"
            with self.assertRaises(UpdateError) as ctx:
                download_verified_asset(
                    "https://objects.githubusercontent.com/mcp/asset.zip",
                    dest,
                    expected_sha256=wrong_sha,
                    expected_size=len(data),
                    open_url=lambda req, timeout=15: _FakeResp(data),
                )
            self.assertEqual(ctx.exception.code, UpdateBlockReason.HASH_MISMATCH)
            self.assertFalse(dest.exists())

    def test_zip_rejects_zip_slip_symlink_case_collision_and_forbidden_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # 1. Zip slip
            slip_zip = tmp_dir / "slip.zip"
            with zipfile.ZipFile(slip_zip, "w") as zf:
                zf.writestr("../../outside.txt", b"pwn")
            with self.assertRaises(UpdateError) as ctx1:
                extract_verified_portable_zip(slip_zip, tmp_dir / "s1")
            self.assertEqual(ctx1.exception.code, UpdateBlockReason.ZIP_SECURITY)

            # 2. POSIX symlink attribute (0o120777 << 16)
            sym_zip = tmp_dir / "sym.zip"
            with zipfile.ZipFile(sym_zip, "w") as zf:
                zi = zipfile.ZipInfo("MCPApp/link.txt")
                zi.external_attr = (0o120777) << 16
                zf.writestr(zi, b"C:\\Windows\\System32")
            with self.assertRaises(UpdateError) as ctx2:
                extract_verified_portable_zip(sym_zip, tmp_dir / "s2")
            self.assertEqual(ctx2.exception.code, UpdateBlockReason.ZIP_SECURITY)

            # 3. NTFS case-folding duplicate collision
            case_zip = tmp_dir / "case.zip"
            with zipfile.ZipFile(case_zip, "w") as zf:
                zf.writestr("MCPApp/Foo.dll", b"a")
                zf.writestr("MCPApp/foo.dll", b"b")
            with self.assertRaises(UpdateError) as ctx3:
                extract_verified_portable_zip(case_zip, tmp_dir / "s3")
            self.assertEqual(ctx3.exception.code, UpdateBlockReason.ZIP_SECURITY)

            # 4. Forbidden user secret / config path inside bundle
            sec_zip = tmp_dir / "sec.zip"
            with zipfile.ZipFile(sec_zip, "w") as zf:
                zf.writestr("MCPApp/MCPApp.exe", b"MZ")
                zf.writestr("MCPApp/token.json", b'{"token":"x"}')
            with self.assertRaises(UpdateError) as ctx4:
                extract_verified_portable_zip(sec_zip, tmp_dir / "s4")
            self.assertEqual(ctx4.exception.code, UpdateBlockReason.ZIP_SECURITY)

    def test_toctou_reverify_detects_tampered_staged_file_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            bundle_zip = tmp_dir / "ok.zip"
            with zipfile.ZipFile(bundle_zip, "w") as zf:
                zf.writestr("MCPApp/MCPApp.exe", b"ORIGINAL_EXE")
                zf.writestr("MCPApp/_internal/lib.txt", b"LIB_DATA")
            stage_dir = tmp_dir / "stage"
            file_hashes = extract_verified_portable_zip(bundle_zip, stage_dir)
            reverify_staged_bundle(stage_dir, file_hashes)

            # Mutate staged payload after extraction (TOCTOU attack)
            (stage_dir / "MCPApp.exe").write_bytes(b"TAMPERED_EXE")
            with self.assertRaises(UpdateError) as ctx:
                reverify_staged_bundle(stage_dir, file_hashes)
            self.assertEqual(ctx.exception.code, UpdateBlockReason.HASH_MISMATCH)


if __name__ == "__main__":
    unittest.main()
