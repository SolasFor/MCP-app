"""CLI utility to build, validate, and optionally sign canonical `update-manifest.json`."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.updater.models import CHANNEL_STABLE, UpdateManifest, parse_semver  # noqa: E402
from app.updater.trust import canonical_manifest_bytes, sign_manifest_bytes  # noqa: E402


def _safe_cli_path(raw: Path, *, expected_suffix: str) -> Path:
    text = str(raw)
    if "\x00" in text:
        raise ValueError("Null byte forbidden in path")
    if raw.is_symlink():
        raise ValueError(f"Symlink forbidden: {raw}")
    resolved = os.path.realpath(os.path.abspath(text))
    if not resolved.lower().endswith(expected_suffix):
        raise ValueError(f"Unexpected extension for {resolved}; expected {expected_suffix}")
    allowed_roots = (
        os.path.realpath(str(ROOT)),
        os.path.realpath(str(Path.cwd())),
        os.path.realpath(tempfile.gettempdir()),
    )
    for base in allowed_roots:
        if resolved == base or resolved.startswith(base + os.sep):
            return Path(resolved)
    raise ValueError(f"Path outside allowed workspace/temp roots: {resolved}")


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
    ver = parse_semver(args.version).raw
    installer_path = _safe_cli_path(args.installer, expected_suffix=".exe")
    portable_path = _safe_cli_path(args.portable, expected_suffix=".zip")
    output_path = _safe_cli_path(args.output, expected_suffix=".json")

    _, raw = build_manifest_payload(
        version=ver,
        installer_path=installer_path,
        portable_path=portable_path,
        min_supported_version=parse_semver(args.min_supported).raw,
        changelog=args.changelog,
        thumbprints=args.thumbprint,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(raw)

    priv_b64 = os.environ.get(args.privkey_env, "").strip()
    if priv_b64 and args.key_id:
        priv_raw = base64.b64decode(priv_b64, validate=True)
        sig_b64 = sign_manifest_bytes(raw, priv_raw)
        sig_path = output_path.with_name(f"{output_path.name}.sig")
        sig_path.write_text(
            json.dumps({"key_id": args.key_id, "signature_b64": sig_b64}, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
