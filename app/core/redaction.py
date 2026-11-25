"""Secret redaction, log filtering, and child-process environment sanitization."""
from __future__ import annotations

import logging
import os
import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

INTERNAL_SECRET_ENV_PREFIXES: tuple[str, ...] = ("MCP_",)
INTERNAL_SECRET_ENV_KEYS: frozenset[str] = frozenset({
    "MCP_SECRET_TOKEN",
    "MCP_ADMIN_TOKEN",
    "TUNNEL_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "CF_API_TOKEN",
    "NGROK_AUTHTOKEN",
    "OPENAI_API_KEY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
})

_SECRET_FIELD_NAMES = frozenset({
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "authtoken",
    "authorization",
    "proxy_authorization",
    "proxy-authorization",
    "private_key",
    "credential",
    "credentials",
    "tunnel_token",
    "cloudflare_api_token",
    "cloudflare_tunnel_token",
    "access_token",
    "refresh_token",
    "authorization_code",
    "code_verifier",
    "pkce_verifier",
    "client_secret",
    "owner_token",
    "bearer",
    "screenshot",
    "image_base64",
    "png_base64",
})

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)((?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|digest)\s+)[A-Za-z0-9\-._~+/=]{4,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{8,}"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)([?&](?:token|access_token|refresh_token|code|code_verifier|secret|api_key|owner_token|client_secret|password)=)[^&\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:MCP_SECRET_TOKEN|MCP_ADMIN_TOKEN|TUNNEL_TOKEN|CLOUDFLARE_API_TOKEN|CF_API_TOKEN|"
            r"NGROK_AUTHTOKEN|OPENAI_API_KEY)\s*[:=]\s*)[^\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([\"']?(?:owner_token|tunnel_token|access_token|refresh_token|code_verifier|"
            r"authorization_code|client_secret|authtoken|api_key|password|passwd|mcp_oauth_csrf)[\"']?\s*[:=]\s*[\"']?)([^\s\"',}&]{4,})"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(?<![A-Za-z0-9_])((?:code|state_secret|csrf_token)\s*[:=]\s*[\"']?)([^\s\"',}&]{4,})"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)((?:socks5h?|https?)://[^:/@\s]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
    (
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|cfut_[A-Za-z0-9_-]{16,}|eyJhIjoi[A-Za-z0-9+/=_-]{20,})\b"
        ),
        "[REDACTED]",
    ),
    (
        re.compile(r"data:image/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=]{16,}"),
        "[REDACTED SCREENSHOT DATA]",
    ),
    (
        re.compile(r"\biVBORw0KGgo[A-Za-z0-9+/=]{16,}"),
        "[REDACTED SCREENSHOT DATA]",
    ),
    (
        re.compile(r"\biVBORw0KGgo[A-Za-z0-9+/=]{64,}"),
        "[REDACTED SCREENSHOT DATA]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
        "[REDACTED PRIVATE KEY]",
    ),
)


class SecretRedactor:
    """Thread-safe secret scrubber for strings, mappings, and logs."""

    def __init__(self, initial_secrets: Iterable[str] = ()) -> None:
        self._lock = threading.RLock()
        self._secrets: set[str] = set()
        for item in initial_secrets:
            self.register(item)

    def register(self, secret: str) -> None:
        if isinstance(secret, str):
            val = secret.strip()
            if len(val) >= 8:
                with self._lock:
                    self._secrets.add(val)

    def unregister(self, secret: str) -> None:
        if isinstance(secret, str):
            with self._lock:
                self._secrets.discard(secret.strip())

    def redact_text(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            secrets_list = sorted(self._secrets, key=len, reverse=True)
        out = text
        for secret in secrets_list:
            if secret in out:
                out = out.replace(secret, "[REDACTED]")
        for pattern, replacement in _PATTERNS:
            out = pattern.sub(replacement, out)
        return out

    def redact_mapping(self, data: Any) -> Any:
        if isinstance(data, str):
            return self.redact_text(data)
        if isinstance(data, list):
            return [self.redact_mapping(item) for item in data]
        if isinstance(data, tuple):
            return [self.redact_mapping(item) for item in data]
        if isinstance(data, Mapping):
            result: dict[str, Any] = {}
            for key, value in data.items():
                key_str = str(key)
                lowered = key_str.casefold()
                if any(marker in lowered for marker in _SECRET_FIELD_NAMES) and isinstance(value, str) and value:
                    result[key_str] = "[REDACTED]"
                else:
                    result[key_str] = self.redact_mapping(value)
            return result
        return data


class RedactingLogFilter(logging.Filter):
    """Logging filter scrubbing registered secrets and bearer credentials from log records."""

    def __init__(self, redactor: SecretRedactor) -> None:
        super().__init__()
        self._redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # noqa: BLE001
            rendered = str(record.msg)
        scrubbed = self._redactor.redact_text(rendered)
        if scrubbed != rendered:
            record.msg = scrubbed
            record.args = ()
        return True


def sanitize_child_env(
    base_env: Mapping[str, str] | None = None,
    *,
    extra_env: Mapping[str, str] | None = None,
    extra_strip_keys: Iterable[str] = (),
) -> dict[str, str]:
    """Return a child process environment stripped of internal MCP/tunnel secrets."""
    source = os.environ if base_env is None else base_env
    strip_upper = {k.upper() for k in INTERNAL_SECRET_ENV_KEYS}
    strip_upper.update(k.upper() for k in extra_strip_keys)

    cleaned: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if any(upper.startswith(prefix) for prefix in INTERNAL_SECRET_ENV_PREFIXES):
            continue
        if upper in strip_upper:
            continue
        cleaned[key] = value

    if extra_env:
        for key, value in extra_env.items():
            cleaned[key] = value
    return cleaned
