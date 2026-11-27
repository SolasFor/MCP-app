"""CLI utility to build, validate, and optionally sign canonical `update-manifest.json`."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.updater.models import CHANNEL_STABLE, UpdateManifest  # noqa: E402
from app.updater.trust import canonical_manifest_bytes, sign_manifest_bytes  # noqa: E402


def _sha256_and_size(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest().lower(), size


def build_manifest_payload(
    *,
    version: str,
    installer_path: Path,
    portable_path: Path,
    min_supported_version: str = "1.0.0",
    changelog: str = "",
    published_at: str | None = None,
    thumbprints: list[str] | None = None,
) -> tuple[UpdateManifest, bytes]:
    """Construct and validate canonical UpdateManifest bytes from built artifacts."""
    if not installer_path.is_file():
        raise FileNotFoundError(f"Installer artifact not found: {installer_path}")
    if not portable_path.is_file():
        raise FileNotFoundError(f"Portable artifact not found: {portable_path}")

    inst_sha, inst_size = _sha256_and_size(installer_path)
    port_sha, port_size = _sha256_and_size(portable_path)
    pub_iso = published_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "schema_version": 1,
        "version": version,
        "channel": CHANNEL_STABLE,
        "published_at": pub_iso,
        "min_supported_version": min_supported_version,
        "changelog": changelog or f"MCP App {version}",
        "installer": {
            "name": installer_path.name,
            "sha256": inst_sha,
            "size": inst_size,
            "authenticode_required": True,
        },
        "portable": {
            "name": portable_path.name,
            "sha256": port_sha,
            "size": port_size,
            "authenticode_required": False,
        },
        "publisher_thumbprints": thumbprints or [],
    }
    raw = canonical_manifest_bytes(payload)
    return UpdateManifest.from_json_bytes(raw), raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build canonical N02 update-manifest.json")
    parser.add_argument("--version", required=True)
    parser.add_argument("--installer", required=True, type=Path)
    parser.add_argument("--portable", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--min-supported", default="1.0.0")
    parser.add_argument("--changelog", default="")
    parser.add_argument("--key-id", default=os.environ.get("MCPAPP_UPDATER_KEY_ID", ""))
    parser.add_argument("--privkey-env", default="MCPAPP_UPDATER_ED25519_PRIV_B64")
    parser.add_argument("--thumbprint", action="append", default=[])
    args = parser.parse_args(argv)

    _, raw = build_manifest_payload(
        version=args.version,
        installer_path=args.installer,
        portable_path=args.portable,
        min_supported_version=args.min_supported,
        changelog=args.changelog,
        thumbprints=args.thumbprint,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)

    priv_b64 = os.environ.get(args.privkey_env, "").strip()
    if priv_b64 and args.key_id:
        priv_raw = base64.b64decode(priv_b64, validate=True)
        sig_b64 = sign_manifest_bytes(raw, priv_raw)
        sig_path = args.output.with_name(f"{args.output.name}.sig")
        sig_path.write_text(
            json.dumps({"key_id": args.key_id, "signature_b64": sig_b64}, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
