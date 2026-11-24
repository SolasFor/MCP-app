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
from pathlib import Path

from app.core.secret_store import SecretStore
from app.paths import user_data_dir
from app.platform import get_platform

TOKEN_FILE = "token.json"
MIN_LENGTH = 16
# Символы, допустимые в заголовке Authorization и в URL без кодирования.
_ALLOWED_EXTRA = "-._~+/="
_SECRET_NS = "owner"
_SECRET_KEY = "bearer_token"


def path() -> Path:
    return user_data_dir() / TOKEN_FILE


def _store(base_dir: Path | None = None) -> SecretStore:
    root = base_dir if base_dir is not None else path().parent
    return SecretStore(root / "secrets")


def generate(nbytes: int = 24) -> str:
    """Случайный токен (32 символа, 192 бита энтропии)."""
    return secrets.token_urlsafe(nbytes)


def load() -> str:
    target = path()
    store = _store(target.parent)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None

    if isinstance(data, dict):
        legacy_token = data.get("token")
        if isinstance(legacy_token, str) and legacy_token.strip():
            clean = legacy_token.strip()
            try:
                store.set_secret(_SECRET_NS, _SECRET_KEY, clean)
                _write_marker(target)
            except OSError:
                pass
            return clean

    try:
        stored = store.get_secret(_SECRET_NS, _SECRET_KEY)
        return stored.strip() if isinstance(stored, str) else ""
    except (OSError, ValueError, RuntimeError):
        return ""


def _write_marker(target: Path) -> None:
    tmp = target.with_suffix(".tmp")
    marker = {
        "version": 2,
        "storage": "secret_store",
        "ref": SecretStore.secret_ref(_SECRET_NS, _SECRET_KEY),
    }
    tmp.write_text(json.dumps(marker, indent=2), encoding="utf-8")
    tmp.replace(target)
    restrict(target)


def save(token: str) -> None:
    target = path()
    store = _store(target.parent)
    store.set_secret(_SECRET_NS, _SECRET_KEY, token)
    _write_marker(target)


def problem(token: str) -> str | None:
    """Почему такой токен нельзя сохранить, или None. Пустой допустим."""
    if not token:
        return None
    if any(ch.isspace() for ch in token):
        return "В токене не должно быть пробелов и переводов строки."
    if len(token) < MIN_LENGTH:
        return f"Слишком короткий токен: нужно не менее {MIN_LENGTH} символов (сейчас {len(token)})."
    if any(not (ch.isalnum() and ch.isascii()) and ch not in _ALLOWED_EXTRA for ch in token):
        return "Допустимы только латинские буквы, цифры и символы - . _ ~ + / ="
    return None


def mask(token: str) -> str:
    """Для логов и подсказок: токен целиком никуда не попадает."""
    if not token:
        return "не задан"
    if len(token) <= 8:
        return "•" * len(token)
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
