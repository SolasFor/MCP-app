"""Bearer-токен MCP-сервера: хранение, генерация, проверка.

Токен лежит ОТДЕЛЬНО от settings.json — в %APPDATA%\\SouronMCP\\token.json.
Так settings.json можно показать или скопировать без риска, а файл с токеном
на Windows получает ACL только для текущего пользователя.

Бэкенду токен передаётся переменной окружения MCP_SECRET_TOKEN (см. ServiceManager),
а НЕ аргументом командной строки: аргументы видны в Диспетчере задач и в wmic.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from app.paths import user_data_dir

TOKEN_FILE = "token.json"
MIN_LENGTH = 16
# Символы, допустимые в заголовке Authorization и в URL без кодирования.
_ALLOWED_EXTRA = "-._~+/="


def path() -> Path:
    return user_data_dir() / TOKEN_FILE


def generate(nbytes: int = 24) -> str:
    """Случайный токен (~32 символа, 192 бита энтропии)."""
    return secrets.token_urlsafe(nbytes)


def load() -> str:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    token = data.get("token") if isinstance(data, dict) else None
    return token.strip() if isinstance(token, str) else ""


def save(token: str) -> None:
    target = path()
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps({"token": token}, indent=2), encoding="utf-8")
    tmp.replace(target)  # атомарная замена: недописанный файл не затрёт рабочий
    _restrict(target)


def clear() -> None:
    try:
        path().unlink()
    except FileNotFoundError:
        pass


def problem(token: str) -> str | None:
    """Почему такой токен нельзя сохранить, или None. Пустой допустим."""
    if not token:
        return None  # пусто = сервер сгенерирует себе временный сам
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


def _restrict(target: Path) -> None:
    """Доступ только текущему пользователю. Не критично, ошибки глотаем."""
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    if sys.platform != "win32":
        return
    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        # /inheritance:r снимает наследование от %APPDATA%, дальше даём права только себе.
        subprocess.run(
            ["icacls", str(target), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            capture_output=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),  # без всплывающего окна
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass
