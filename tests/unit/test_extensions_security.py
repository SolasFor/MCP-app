"""Security and packaging unit tests for Stage 9 Extensions."""
from __future__ import annotations

import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from app.core.secret_store import SecretStore
from backend.extensions.manager import ExtensionManager
from backend.extensions.models import ExtensionManifest, check_api_compatibility
from backend.extensions.packaging import (
    create_extension_zip,
    generate_signing_keypair,
    verify_and_extract_zip,
)
from backend.extensions.store import ExtensionStore


def _write_ext_dir(
    root: Path,
    *,
    ext_id: str = "demo_ext",
    version: str = "1.0.0",
    api_version: str = "1.0",
    body: str = "",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "id": ext_id,
        "name": "Demo Ext",
        "version": version,
        "api_version": api_version,
        "entrypoint": "main.py",
        "permissions": ["read_metrics", "git_write"],
        "min_profile": "allowlist",
        "secret_keys": ["API_KEY"],
        "tools": [
            {"name": "read_ping", "permission": "read_metrics", "read_only": True},
            {"name": "mutate_repo", "permission": "git_write", "read_only": False},
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "main.py").write_text(
        body
        or """
from backend.extensions.sdk import ExtensionApp
app = ExtensionApp("demo_ext", "1.0.0")
@app.tool("read_ping")
def read_ping():
    return {"ok": True, "secret": app.secret("API_KEY")}
@app.tool("mutate_repo")
def mutate_repo():
    return {"mutated": True}
if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
""",
        encoding="utf-8",
    )
    return root


class ExtensionsSecurityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = ExtensionStore(
            self.root / "extensions",
            secret_store=SecretStore(self.root / "secrets"),
        )
        self.mgr = ExtensionManager(self.store)

    def tearDown(self) -> None:
        self.mgr.shutdown_all()
        self.tmp.cleanup()

    def test_manifest_validation_and_api_compatibility(self) -> None:
        ok, _ = check_api_compatibility("1.0")
        self.assertTrue(ok)
        for bad in ("2.0", "0.9", "1.99", "invalid"):
            bad_ok, _ = check_api_compatibility(bad)
            self.assertFalse(bad_ok, bad)

        with self.assertRaises(ValueError):
            ExtensionManifest.from_dict({
                "id": "bad id!",
                "name": "Bad",
                "version": "1.0.0",
                "api_version": "1.0",
                "entrypoint": "main.py",
            })
        with self.assertRaises(ValueError):
            ExtensionManifest.from_dict({
                "id": "good_id",
                "name": "Traversal",
                "version": "1.0.0",
                "api_version": "1.0",
                "entrypoint": "../evil.py",
            })
        with self.assertRaises(ValueError):
            ExtensionManifest.from_dict({
                "id": "good_id",
                "name": "Undeclared Perm",
                "version": "1.0.0",
                "api_version": "1.0",
                "entrypoint": "main.py",
                "permissions": [],
                "tools": [{"name": "x", "permission": "git_write"}],
            })

    def test_zip_rejects_traversal_symlink_and_unverified_archives(self) -> None:
        bad_zip = self.root / "traversal.zip"
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../escape.py", "print(1)")
        with self.assertRaises(ValueError):
            verify_and_extract_zip(bad_zip, self.root / "out1", trusted_keys={}, expected_sha256="", owner_confirmed=True)

        sym_zip = self.root / "symlink.zip"
        with zipfile.ZipFile(sym_zip, "w") as zf:
            zi = zipfile.ZipInfo("link.py")
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, "target")
        with self.assertRaises(ValueError):
            verify_and_extract_zip(sym_zip, self.root / "out2", trusted_keys={}, expected_sha256="", owner_confirmed=True)

        # Unsigned ZIP without owner SHA-256 pin is rejected fail-closed
        src = _write_ext_dir(self.root / "src_unsigned")
        unsigned_zip = self.root / "unsigned.zip"
        sha = create_extension_zip(src, unsigned_zip)
        with self.assertRaises(PermissionError):
            self.mgr.install_zip(unsigned_zip, owner_confirmed=True)
        with self.assertRaises(PermissionError):
            self.mgr.install_zip(unsigned_zip, expected_sha256="0" * 64, owner_confirmed=True)
        # With exact pin + owner confirmation it succeeds
        info = self.mgr.install_zip(unsigned_zip, expected_sha256=sha, owner_confirmed=True)
        self.assertEqual(info["id"], "demo_ext")

    def test_ed25519_signature_and_tamper_detection(self) -> None:
        priv, pub = generate_signing_keypair()
        self.store.add_trusted_key("dev-key", pub)
        src = _write_ext_dir(self.root / "signed_src")
        signed_zip = self.root / "signed.zip"
        create_extension_zip(src, signed_zip, private_key_b64=priv, key_id="dev-key")

        # Tamper one byte inside ZIP without re-signing -> must fail
        tampered_zip = self.root / "tampered.zip"
        with zipfile.ZipFile(signed_zip, "r") as zin, zipfile.ZipFile(tampered_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "main.py":
                    data += b"\n# tampered\n"
                zout.writestr(item, data)
        with self.assertRaises(PermissionError):
            self.mgr.install_zip(tampered_zip)

        # Untrusted key_id must fail
        other_priv, _ = generate_signing_keypair()
        untrusted_zip = self.root / "untrusted.zip"
        create_extension_zip(src, untrusted_zip, private_key_b64=other_priv, key_id="unknown")
        with self.assertRaises(PermissionError):
            self.mgr.install_zip(untrusted_zip)

        # Valid signed package installs without manual SHA-256 pin
        res = self.mgr.install_zip(signed_zip)
        self.assertEqual(res["verified_by"], "ed25519:dev-key")

    def test_permissions_client_isolation_and_secret_scope(self) -> None:
        priv, pub = generate_signing_keypair()
        self.store.add_trusted_key("dev-key", pub)
        src = _write_ext_dir(self.root / "perm_src")
        pkg = self.root / "perm.zip"
        create_extension_zip(src, pkg, private_key_b64=priv, key_id="dev-key")
        self.mgr.install_zip(pkg, grant_permissions=("read_metrics",), enable_after_install=True, allowed_clients=("client-a",))

        with self.assertRaises(ValueError):
            self.mgr.set_secret("demo_ext", "UNDECLARED_SECRET", "val")

        # Safe profile & disallowed client both fail closed
        with self.assertRaises(PermissionError):
            self.mgr.call_tool("demo_ext", "read_ping", client_id="client-a", client_profile="safe")
        with self.assertRaises(PermissionError):
            self.mgr.call_tool("demo_ext", "read_ping", client_id="client-b", client_profile="allowlist")
        # Ungranted permission (`git_write`) denied even for owner
        with self.assertRaises(PermissionError):
            self.mgr.call_tool("demo_ext", "mutate_repo", client_id="owner", client_profile="full")
        # Even once permission is granted, allowlist client cannot call mutating tool without explicit approval
        self.mgr.set_permissions("demo_ext", ("read_metrics", "git_write"), allowed_clients=("client-a",))
        with self.assertRaises(PermissionError):
            self.mgr.call_tool("demo_ext", "mutate_repo", client_id="client-a", client_profile="allowlist")
        res = self.mgr.call_tool("demo_ext", "read_ping", client_id="client-a", client_profile="allowlist")
        self.assertTrue(res["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
