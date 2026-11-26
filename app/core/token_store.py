"""Bearer-токен MCP-сервера: хранение в DPAPI SecretStore, генерация, проверка.

Хранится в зашифрованном SecretStore (`secret://owner/bearer_token`),
а `%APPDATA%\\MCPApp\\token.json` хранит только метаданные ссылки (версия 2).
Прежний открытый `token.json` переносится прозрачно при чтении.

Бэкенду токен передаётся переменной окружения MCP_SECRET_TOKEN (см. ServiceManager),
а НЕ аргументом командной строки: аргументы видны в Диспетчере задач и в wmic.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

from app.core.atomic_io import atomic_write_json
from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.platform import get_platform

TOKEN_FILE = "token.json"
RECOMMENDED_MIN_LENGTH = 12
_SECRET_NS = "owner"
_SECRET_KEY = "bearer_token"
_TRANSPORT_KEY = "transport_bearer_token"


class TokenStorageError(RuntimeError):
    """Raised when an existing persisted MCP Owner Token cannot be unlocked or read."""


@dataclass(frozen=True)
class TokenLoadStatus:
    """Non-destructive load status distinguishing first launch from unreadable storage."""

    token: str
    exists_on_disk: bool
    error: str = ""


def path() -> Path:
    return user_data_dir() / TOKEN_FILE


def _store(base_dir: Path | None = None) -> SecretStore:
    root = base_dir if base_dir is not None else path().parent
    return SecretStore(root / "secrets")


def generate(nbytes: int = 24) -> str:
    """Случайный токен (32 символа, 192 бита энтропии)."""
    return secrets.token_urlsafe(nbytes)


def is_http_bearer_compatible(token: str) -> bool:
    """True, если токен состоит только из видимых ASCII-символов без пробелов и управляющих символов."""
    return bool(token) and all(0x21 <= ord(ch) <= 0x7E for ch in token)


def load_status() -> TokenLoadStatus:
    """Inspect and load the persisted MCP Owner Token without ever regenerating or overwriting it."""
    target = path()
    marker_exists = target.exists()
    data: dict | None = None
    marker_read_error = ""
    if marker_exists:
        try:
            parsed = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                data = parsed
            else:
                marker_read_error = "Повреждён формат token.json"
        except (OSError, ValueError) as exc:
            marker_read_error = f"{type(exc).__name__}: {exc}"

    try:
        store = _store(target.parent)
    except (OSError, ValueError, RuntimeError) as exc:
        return TokenLoadStatus("", True, f"Хранилище секретов недоступно ({type(exc).__name__})")

    if isinstance(data, dict):
        legacy_token = data.get("token")
        if isinstance(legacy_token, str) and legacy_token != "":
            try:
                store.set_secret(_SECRET_NS, _SECRET_KEY, legacy_token)
                _write_marker(target)
            except OSError:
                pass
            return TokenLoadStatus(legacy_token, True, "")

    try:
        stored = store.get_secret(_SECRET_NS, _SECRET_KEY)
    except (OSError, ValueError, RuntimeError) as exc:
        return TokenLoadStatus(
            "",
            True,
            f"Не удалось расшифровать MCP Owner Token ({type(exc).__name__})",
        )

    if isinstance(stored, str) and stored != "":
        if marker_read_error:
            try:
                _write_marker(target)
            except OSError:
                pass
        return TokenLoadStatus(stored, True, "")

    if marker_exists:
        detail = marker_read_error or "запись owner/bearer_token отсутствует в SecretStore"
        return TokenLoadStatus(
            "",
            True,
            f"Сохранённый MCP Owner Token не удалось прочитать ({detail}). Автоматический сброс заблокирован.",
        )

    return TokenLoadStatus("", False, "")


def load(*, strict: bool = False) -> str:
    status = load_status()
    if status.error and strict:
        raise TokenStorageError(status.error)
    return status.token


def _write_marker(target: Path) -> None:
    marker = {
        "version": 2,
        "storage": "secret_store",
        "ref": SecretStore.secret_ref(_SECRET_NS, _SECRET_KEY),
    }
    atomic_write_json(target, marker, indent=2, restrict_acl=False)
    restrict(target)


def save(token: str) -> None:
    if not isinstance(token, str) or token == "":
        raise ValueError("Owner token must not be empty")
    target = path()
    store = _store(target.parent)
    store.set_secret(_SECRET_NS, _SECRET_KEY, token)
    # Rotate separate HTTP Bearer transport secret whenever the owner secret changes.
    if is_http_bearer_compatible(token):
        store.set_secret(_SECRET_NS, _TRANSPORT_KEY, token)
    else:
        store.set_secret(_SECRET_NS, _TRANSPORT_KEY, generate())
    _write_marker(target)


def transport_bearer_token(owner_token: str | None = None) -> str:
    """Return an HTTP-safe ASCII Bearer token corresponding to the active owner token.

    For standard visible-ASCII owner tokens, this equals the owner token for full
    compatibility. When the owner sets a token with Unicode, Cyrillic, spaces, or
    arbitrary control characters, HTTP Authorization headers use a separate DPAPI-stored
    ASCII transport token while /oauth/consent verifies the exact UTF-8 owner token.
    """
    tok = load() if owner_token is None else owner_token
    if not tok:
        return ""
    if is_http_bearer_compatible(tok):
        return tok
    target = path()
    store = _store(target.parent)
    try:
        stored = store.get_secret(_SECRET_NS, _TRANSPORT_KEY)
        if isinstance(stored, str) and is_http_bearer_compatible(stored) and stored != tok:
            return stored
    except (OSError, ValueError, RuntimeError):
        pass
    fresh = generate()
    try:
        store.set_secret(_SECRET_NS, _TRANSPORT_KEY, fresh)
    except OSError:
        pass
    return fresh


def problem(token: str) -> str | None:
    """Почему такой токен нельзя сохранить, или None. Непустой токен допустим в любом виде."""
    if not isinstance(token, str) or token == "":
        return "Токен не может быть пустым."
    return None


def weakness_warning(token: str, lang: str = "ru") -> str | None:
    """Необязательное предупреждение о слабом токене (не блокирует сохранение)."""
    if not token:
        return None
    is_en = str(lang).lower().startswith("en")
    notes: list[str] = []
    if len(token) < RECOMMENDED_MIN_LENGTH:
        notes.append(
            f"short token ({len(token)} chars; 12+ recommended)"
            if is_en
            else f"короткий токен ({len(token)} симв.; рекомендуется 12+)"
        )
    elif len(set(token)) < 4:
        notes.append(
            "low character variety"
            if is_en
            else "однообразные символы"
        )
    if not is_http_bearer_compatible(token):
        notes.append(
            "OAuth consent uses your exact token; direct Bearer clients should use the ASCII transport token from Diagnostics"
            if is_en
            else "форма OAuth использует ваш точный токен; для прямого заголовка Bearer применяйте ASCII-токен из «Диагностики»"
        )
    if not notes:
        return None
    prefix = "Notice: " if is_en else "Примечание: "
    return prefix + "; ".join(notes) + "."


def mask(token: str) -> str:
    """Для логов и подсказок: токен целиком никуда не попадает."""
    if not token:
        return "не задан"
    if len(token) <= 8:
        return "•" * max(4, len(token))
    return f"{token[:4]}…{token[-4:]} ({len(token)} симв.)"


def restrict(target: Path) -> None:
    """Доступ только текущему пользователю. Не критично, ошибки глотаем."""
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    if sys.platform != "win32":
        return
    get_platform().restrict_path_acl(target, is_dir=False)
