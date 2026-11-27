"""Strict GitHub Releases HTTPS client and streaming asset downloader."""
from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from app.platform import get_platform
from app.updater.models import MAX_MANIFEST_BYTES, OFFICIAL_REPO, UpdateBlockReason, UpdateError

ALLOWED_GITHUB_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
MAX_REDIRECTS = 3


def validate_github_url(url: str) -> str:
    """Allow strictly HTTPS URLs to pinned official GitHub hosts without credentials."""
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme != "https":
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"Non-HTTPS URL blocked: {url!r}")
    if parsed.username or parsed.password:
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Credentials in update URL are forbidden")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_GITHUB_HOSTS:
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"Disallowed update host: {host!r}")
    return url


class _StrictGitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow up to 3 HTTPS redirects strictly within ALLOWED_GITHUB_HOSTS."""

    def __init__(self) -> None:
        super().__init__()
        self._redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_github_url(newurl)
        self._redirect_count += 1
        if self._redirect_count > MAX_REDIRECTS:
            raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Too many update HTTP redirects")
        next_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if next_req is None:
            return None
        if urlparse(req.full_url).hostname != urlparse(newurl).hostname:
            next_req.headers.pop("Authorization", None)
        return next_req


def _default_open_url(req: urllib.request.Request, timeout: float = 15.0) -> Any:
    validate_github_url(req.full_url)
    opener = urllib.request.build_opener(_StrictGitHubRedirectHandler())
    return opener.open(req, timeout=timeout)


def _fetch_bounded_bytes(url: str, *, max_bytes: int = MAX_MANIFEST_BYTES, timeout: float = 15.0) -> bytes:
    validate_github_url(url)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "MCPApp-Updater/1.0",
        },
    )
    with _default_open_url(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Update metadata response exceeded size bound")
        return data


@dataclass(frozen=True)
class ReleaseInfo:
    """Verified GitHub Release API metadata containing resolved asset download URLs."""

    tag_name: str
    assets: dict[str, str]


def _extract_release_assets(payload: dict[str, Any]) -> dict[str, str]:
    assets: dict[str, str] = {}
    for entry in payload.get("assets") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        dl_url = str(entry.get("browser_download_url") or "").strip()
        if name and dl_url:
            validate_github_url(dl_url)
            assets[name] = dl_url
    return assets


def fetch_latest_release_info(
    *,
    repo: str = OFFICIAL_REPO,
    fetch_bytes: Callable[[str], bytes] | None = None,
) -> ReleaseInfo:
    """Query official `/releases/latest` endpoint and extract verified asset URLs."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    validate_github_url(url)
    reader = fetch_bytes or (lambda target: _fetch_bounded_bytes(target))
    try:
        raw = reader(url)
    except UpdateError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"GitHub Releases request failed: {exc}") from exc

    if len(raw) > MAX_MANIFEST_BYTES:
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "GitHub release JSON exceeded limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"Invalid GitHub release JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Release API payload must be a mapping")
    if payload.get("draft") or payload.get("prerelease"):
        raise UpdateError(UpdateBlockReason.SIGNATURE_INVALID, "Draft or prerelease rejected on stable channel")

    return ReleaseInfo(tag_name=str(payload.get("tag_name") or ""), assets=_extract_release_assets(payload))


def fetch_release_text_asset(
    url: str,
    *,
    max_bytes: int = MAX_MANIFEST_BYTES,
    fetch_bytes: Callable[[str], bytes] | None = None,
) -> bytes:
    """Download bounded release metadata/signature asset strictly over pinned GitHub HTTPS."""
    validate_github_url(url)
    reader = fetch_bytes or (lambda target: _fetch_bounded_bytes(target, max_bytes=max_bytes))
    data = reader(url)
    if len(data) > max_bytes:
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, "Downloaded metadata exceeds maximum size")
    return data


def _stream_verified_chunks(
    resp: Any,
    out: Any,
    *,
    expected_size: int,
    dest_name: str,
    cancel_event: threading.Event | None,
    on_progress: Callable[[int, int], None] | None,
) -> tuple[int, str]:
    hasher = hashlib.sha256()
    received = 0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise UpdateError(UpdateBlockReason.CANCELLED, "Update download cancelled by user")
        chunk = resp.read(65536)
        if not chunk:
            return received, hasher.hexdigest().lower()
        received += len(chunk)
        if received > expected_size:
            raise UpdateError(
                UpdateBlockReason.HASH_MISMATCH,
                f"Downloaded bytes ({received}) exceeded manifest size ({expected_size})",
            )
        out.write(chunk)
        hasher.update(chunk)
        if on_progress is not None:
            on_progress(received, expected_size)


def download_verified_asset(
    url: str,
    dest: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    cancel_event: threading.Event | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    open_url: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> Path:
    """Stream release binary into a private temp file and commit only after exact size & SHA-256 match."""
    validate_github_url(url)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_name(f".{dest.name}.part")
    req = urllib.request.Request(url, headers={"User-Agent": "MCPApp-Updater/1.0"})
    opener = open_url or _default_open_url

    try:
        with opener(req, timeout=timeout) as resp, tmp_path.open("wb") as out:
            received, digest = _stream_verified_chunks(
                resp,
                out,
                expected_size=expected_size,
                dest_name=dest.name,
                cancel_event=cancel_event,
                on_progress=on_progress,
            )

        if received != expected_size or digest != expected_sha256.lower():
            raise UpdateError(
                UpdateBlockReason.HASH_MISMATCH,
                f"Downloaded asset hash/size mismatch for {dest.name}",
            )

        tmp_path.replace(dest)
        get_platform().restrict_path_acl(dest, is_dir=False)
        return dest
    except UpdateError:
        tmp_path.unlink(missing_ok=True)
        raise
    except Exception as exc:  # noqa: BLE001
        tmp_path.unlink(missing_ok=True)
        raise UpdateError(UpdateBlockReason.NETWORK_POLICY, f"Asset download error: {exc}") from exc
