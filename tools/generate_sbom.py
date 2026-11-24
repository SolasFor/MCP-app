"""Generate CycloneDX 1.5 SBOM JSON for MCP-app runtime dependencies and cloudflared."""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import APP_NAME, __version__  # noqa: E402

LOCK_FILE = ROOT / "requirements.lock"
CLOUDFLARED_MANIFEST = ROOT / "packaging" / "cloudflared.json"


def _parse_lock(path: Path) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        spec = line.split(";", 1)[0].strip()
        if "==" in spec:
            name, ver = spec.split("==", 1)
            items.append((name.strip(), ver.strip()))
        else:
            name = re.split(r"[=<>!~\[]", spec, maxsplit=1)[0].strip()
            items.append((name, ""))
    return items


def _license_id(dist: md.Distribution | None, fallback: str = "") -> str:
    if dist is None:
        return fallback
    expr = (dist.metadata.get("License-Expression") or "").strip()
    if expr:
        return expr
    lic = (dist.metadata.get("License") or "").strip()
    if lic and lic.upper() != "UNKNOWN" and len(lic) <= 64:
        return lic
    classifiers = [
        c.split("::")[-1].strip()
        for c in dist.metadata.get_all("Classifier", [])
        if c.startswith("License ::")
    ]
    return classifiers[0] if classifiers else (fallback or "NOASSERTION")


def build_sbom() -> dict:
    components: list[dict] = []
    for name, locked_ver in _parse_lock(LOCK_FILE):
        dist = None
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            pass
        version = dist.version if dist is not None else (locked_ver or "0.0.0")
        canonical = dist.metadata["Name"] if dist is not None else name
        purl = f"pkg:pypi/{canonical.lower()}@{version}"
        comp: dict = {
            "type": "library",
            "bom-ref": purl,
            "name": canonical,
            "version": version,
            "purl": purl,
        }
        lic = _license_id(dist)
        if lic and lic != "NOASSERTION":
            comp["licenses"] = [{"license": {"name": lic}}]
        components.append(comp)

    cf = json.loads(CLOUDFLARED_MANIFEST.read_text(encoding="utf-8"))
    components.append({
        "type": "application",
        "bom-ref": f"pkg:github/cloudflare/cloudflared@{cf['version']}",
        "name": "cloudflared",
        "version": cf["version"],
        "licenses": [{"license": {"id": cf.get("license", "Apache-2.0")}}],
        "hashes": [{"alg": "SHA-256", "content": cf["sha256"]}],
    })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "component": {
                "type": "application",
                "name": APP_NAME,
                "version": __version__,
            },
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM for MCP-app")
    parser.add_argument("--output", default=str(ROOT / "dist" / "SBOM.cdx.json"))
    args = parser.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    sbom = build_sbom()
    out.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"SBOM written: {out} ({len(sbom['components'])} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
