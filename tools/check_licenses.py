"""Verify licenses of locked Python runtime dependencies and bundled cloudflared binary."""
from __future__ import annotations

import importlib.metadata as md
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK_FILE = ROOT / "requirements.lock"
CLOUDFLARED_MANIFEST = ROOT / "packaging" / "cloudflared.json"

ALLOWED_TOKENS = (
    "MIT",
    "MIT-0",
    "BSD",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "APACHE-2.0",
    "APACHE SOFTWARE LICENSE",
    "PSF",
    "PSF-2.0",
    "PYTHON SOFTWARE FOUNDATION",
    "ISC",
    "MPL-2.0",
    "LGPL-2.1",
    "LGPL-2.1-ONLY",
    "LGPL V3",
    "LGPL-3.0",
    "GPL-3.0",
    "GPL-3.0-ONLY",
    "GNU GENERAL PUBLIC LICENSE V3",
    "GNU LESSER GENERAL PUBLIC LICENSE V2",
)


def _parse_lock(path: Path) -> list[str]:
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "; sys_platform ==" in line and 'win32' in line and sys.platform != "win32":
            continue
        pkg = re.split(r"[=<>!;~\[]", line, maxsplit=1)[0].strip()
        if pkg:
            names.append(pkg)
    return names


def _dist_license(dist: md.Distribution) -> str:
    expr = (dist.metadata.get("License-Expression") or "").strip()
    if expr:
        return expr
    lic = (dist.metadata.get("License") or "").strip()
    if lic and lic.upper() != "UNKNOWN":
        return lic
    classifiers = [
        c.split("::")[-1].strip()
        for c in dist.metadata.get_all("Classifier", [])
        if c.startswith("License ::")
    ]
    return "; ".join(classifiers) if classifiers else "UNKNOWN"


def _is_allowed(lic: str) -> bool:
    upper = lic.upper()
    if upper == "UNKNOWN" or not upper.strip():
        return False
    return any(token in upper for token in ALLOWED_TOKENS)


def main() -> int:
    packages = _parse_lock(LOCK_FILE)
    failures: list[str] = []
    for pkg in packages:
        try:
            dist = md.distribution(pkg)
        except md.PackageNotFoundError:
            failures.append(f"{pkg}: not installed")
            continue
        lic = _dist_license(dist)
        ok = _is_allowed(lic)
        status = "OK" if ok else "FAIL"
        print(f"{status:4s} {dist.metadata['Name']}=={dist.version} | {lic}")
        if not ok:
            failures.append(f"{dist.metadata['Name']}=={dist.version}: disallowed/unknown license {lic!r}")

    cf = json.loads(CLOUDFLARED_MANIFEST.read_text(encoding="utf-8"))
    cf_lic = str(cf.get("license") or "")
    cf_ok = _is_allowed(cf_lic)
    print(f"{'OK' if cf_ok else 'FAIL':4s} cloudflared=={cf.get('version')} | {cf_lic}")
    if not cf_ok:
        failures.append(f"cloudflared: disallowed license {cf_lic!r}")

    if failures:
        print("\nLicense check failed:")
        for item in failures:
            print(" -", item)
        return 1
    print(f"\nAll {len(packages) + 1} components passed license check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
