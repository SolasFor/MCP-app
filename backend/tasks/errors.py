"""Structured MCP error classification, redaction, and diagnostics for Task Manager tools."""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import sqlite3
import subprocess
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp.types import CallToolResult, TextContent

from app.core.logging_manager import get_logging_manager
from app.core.redaction import SecretRedactor

TASK_NOT_FOUND = "TASK_NOT_FOUND"
TASK_ACCESS_DENIED = "TASK_ACCESS_DENIED"
TASK_INVALID_ARGUMENT = "TASK_INVALID_ARGUMENT"
TASK_INVALID_TIMEOUT = "TASK_INVALID_TIMEOUT"
TASK_COMMAND_NOT_ALLOWED = "TASK_COMMAND_NOT_ALLOWED"
TASK_INVALID_STATE = "TASK_INVALID_STATE"
TASK_QUEUE_FULL = "TASK_QUEUE_FULL"
TASK_EXECUTABLE_NOT_FOUND = "TASK_EXECUTABLE_NOT_FOUND"
TASK_PROCESS_START_FAILED = "TASK_PROCESS_START_FAILED"
TASK_TIMEOUT = "TASK_TIMEOUT"
TASK_CANCELLED = "TASK_CANCELLED"
TASK_STORAGE_ERROR = "TASK_STORAGE_ERROR"
TASK_INTERNAL_ERROR = "TASK_INTERNAL_ERROR"

ALL_TASK_ERROR_CODES: frozenset[str] = frozenset({
    TASK_NOT_FOUND,
    TASK_ACCESS_DENIED,
    TASK_INVALID_ARGUMENT,
    TASK_INVALID_TIMEOUT,
    TASK_COMMAND_NOT_ALLOWED,
    TASK_INVALID_STATE,
    TASK_QUEUE_FULL,
    TASK_EXECUTABLE_NOT_FOUND,
    TASK_PROCESS_START_FAILED,
    TASK_TIMEOUT,
    TASK_CANCELLED,
    TASK_STORAGE_ERROR,
    TASK_INTERNAL_ERROR,
})

_ABS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s\"',;]+|/(?:home|Users|var|etc|tmp|opt|usr|srv)/[^\s\"',;]+)")


def sanitize_public_text(text: str, redactor: SecretRedactor | None = None) -> str:
    """Remove stack traces, secret tokens, and local filesystem paths from MCP error text."""
    cleaned = str(text or "").strip()
    if redactor is not None:
        cleaned = redactor.redact_text(cleaned)
    cleaned = _ABS_PATH_RE.sub("<path>", cleaned)
    # Collapse multi-line traceback text if any slipped through.
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:480]


def sanitize_details(details: dict[str, Any] | None, redactor: SecretRedactor | None = None) -> dict[str, Any]:
    """Produce JSON-safe, redacted, non-leaking details mapping."""
    if not isinstance(details, dict):
        return {}
    redacted = redactor.redact_mapping(details) if redactor is not None else dict(details)
    safe: dict[str, Any] = {}
    for k, v in redacted.items():
        key = str(k)
        if isinstance(v, (int, float, bool)) or v is None:
            safe[key] = v
        elif isinstance(v, str):
            safe[key] = sanitize_public_text(v, redactor=redactor)
        elif isinstance(v, (list, tuple)):
            safe[key] = [
                item if isinstance(item, (int, float, bool)) else sanitize_public_text(str(item), redactor=redactor)
                for item in v[:20]
            ]
        else:
            safe[key] = sanitize_public_text(str(v), redactor=redactor)
    return safe


@dataclass
class TaskToolError(Exception):
    """Structured error intended for MCP CallToolResult(isError=True) conversion."""

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    suggestion: str = ""
    internal_reason: str = ""

    def __post_init__(self) -> None:
        if self.code not in ALL_TASK_ERROR_CODES:
            self.code = TASK_INTERNAL_ERROR
        super().__init__(self.message)


def build_task_error_payload(
    err: TaskToolError,
    *,
    redactor: SecretRedactor | None = None,
) -> dict[str, Any]:
    return {
        "success": False,
        "error": {
            "code": err.code,
            "message": sanitize_public_text(err.message, redactor=redactor),
            "details": sanitize_details(err.details, redactor=redactor),
            "suggestion": sanitize_public_text(err.suggestion, redactor=redactor),
        },
    }


def build_task_error_result(
    err: TaskToolError,
    *,
    redactor: SecretRedactor | None = None,
) -> CallToolResult:
    payload = build_task_error_payload(err, redactor=redactor)
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
        is_error=True,
    )


def classify_task_exception(
    exc: BaseException,
    *,
    tool_name: str,
    task_id: str | None = None,
    profile: str | None = None,
    lookup_operation: bool = False,
) -> TaskToolError:
    """Map expected and unexpected task exceptions to strict MCP error codes.

    Never swallows ``asyncio.CancelledError`` (or BaseException signals like KeyboardInterrupt/SystemExit).
    """
    if isinstance(exc, asyncio.CancelledError):
        raise exc
    if isinstance(exc, TaskToolError):
        return exc

    msg = str(exc or "").strip()
    low = msg.lower()

    if isinstance(exc, KeyError):
        return TaskToolError(
            code=TASK_NOT_FOUND,
            message="Задача не найдена.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Проверьте идентификатор задачи через task_list и убедитесь, что он принадлежит текущему клиенту.",
            internal_reason=f"KeyError in {tool_name}: {msg}",
        )

    if isinstance(exc, PermissionError):
        # Prevent cross-client task ID enumeration on task lookup/control operations.
        if lookup_operation and ("does not belong" in low or "not found" in low):
            return TaskToolError(
                code=TASK_NOT_FOUND,
                message="Задача не найдена или недоступна для текущего клиента.",
                details={"task_id": task_id} if task_id else {},
                suggestion="Используйте task_list для просмотра доступных задач текущего клиента.",
                internal_reason=f"Cross-client access masked as TASK_NOT_FOUND in {tool_name}",
            )
        if "timeout" in low:
            return TaskToolError(
                code=TASK_INVALID_TIMEOUT,
                message=msg or "Таймаут превышает ограничение активного сценария доступа.",
                details={"profile": profile} if profile else {},
                suggestion="Уменьшите timeout до допустимого для профиля значения или не передавайте timeout, чтобы применился лимит по умолчанию.",
                internal_reason=msg,
            )
        if "command" in low or "allowlist" in low or "not permitted" in low or "ssh host" in low:
            return TaskToolError(
                code=TASK_COMMAND_NOT_ALLOWED,
                message="Команда или цель не разрешены политикой активного сценария доступа.",
                details={"profile": profile or "safe"},
                suggestion="Используйте команду/хост из белого списка владельца либо переключите клиента в режим full.",
                internal_reason=msg,
            )
        return TaskToolError(
            code=TASK_ACCESS_DENIED,
            message="Недостаточно прав для запуска или управления задачей в текущем профиле.",
            details={"profile": profile or "safe"},
            suggestion="Проверьте профиль доступа клиента и аварийную остановку (emergency stop) в MCP-app.",
            internal_reason=msg,
        )

    if isinstance(exc, RuntimeError):
        if "quota exceeded" in low or "too many" in low or "queue" in low:
            return TaskToolError(
                code=TASK_QUEUE_FULL,
                message="Очередь фоновых задач для клиента заполнена.",
                details={},
                suggestion="Дождитесь завершения активных задач или остановите ненужные через task_cancel.",
                internal_reason=msg,
            )
        if "only terminal" in low or "restart" in low or "state" in low or "cancel" in low:
            return TaskToolError(
                code=TASK_INVALID_STATE,
                message="Операция недопустима для текущего состояния задачи.",
                details={"task_id": task_id} if task_id else {},
                suggestion="Проверьте статус задачи через task_status.",
                internal_reason=msg,
            )

    if isinstance(exc, FileNotFoundError):
        return TaskToolError(
            code=TASK_EXECUTABLE_NOT_FOUND,
            message="Исполняемый файл или рабочий каталог не найден.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Убедитесь, что команда/shell и рабочий каталог существуют на целевой системе.",
            internal_reason=msg,
        )

    if isinstance(exc, TimeoutError):
        return TaskToolError(
            code=TASK_TIMEOUT,
            message="Истекло время ожидания операции задачи.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Увеличьте допустимый timeout или проверьте состояние задачи через task_status.",
            internal_reason=msg,
        )

    if isinstance(exc, sqlite3.Error):
        return TaskToolError(
            code=TASK_STORAGE_ERROR,
            message="Ошибка хранилища задач.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Повторите запрос или проверьте целостность хранилища задач в журнале tasks.log.",
            internal_reason=f"{type(exc).__name__}: {msg}",
        )

    if isinstance(exc, (ValueError, TypeError)):
        if "timeout" in low:
            return TaskToolError(
                code=TASK_INVALID_TIMEOUT,
                message=msg or "Недопустимое значение timeout.",
                details={"profile": profile} if profile else {},
                suggestion="Передайте положительное целое число секунд в допустимых пределах.",
                internal_reason=msg,
            )
        return TaskToolError(
            code=TASK_INVALID_ARGUMENT,
            message=msg or "Некорректный аргумент инструмента задач.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Проверьте имена, типы и значения параметров вызова.",
            internal_reason=msg,
        )

    if isinstance(exc, (OSError, subprocess.SubprocessError)):
        return TaskToolError(
            code=TASK_PROCESS_START_FAILED,
            message="Не удалось запустить процесс фоновой задачи.",
            details={"task_id": task_id} if task_id else {},
            suggestion="Проверьте корректность команды, прав запуска и рабочего каталога.",
            internal_reason=f"{type(exc).__name__}: {msg}",
        )

    return TaskToolError(
        code=TASK_INTERNAL_ERROR,
        message="Внутренняя ошибка обработчика фоновой задачи.",
        details={"task_id": task_id} if task_id else {},
        suggestion="Повторите запрос; если ошибка повторяется, проверьте журнал errors.log по request_id.",
        internal_reason=f"{type(exc).__name__}: {msg}",
    )


def log_task_tool_error(
    err: TaskToolError,
    *,
    tool_name: str,
    task_id: str | None = None,
    exc: BaseException | None = None,
    redactor: SecretRedactor | None = None,
    logging_mgr: Any = None,
) -> str:
    """Write structured redacted diagnostics to tasks.log and errors.log and return request_id."""
    req_id = f"req_{secrets.token_hex(6)}"
    err.details.setdefault("request_id", req_id)
    reason_raw = err.internal_reason or err.message
    safe_reason = (redactor.redact_text(reason_raw) if redactor is not None else reason_raw)[:360]
    exc_type = type(exc).__name__ if exc is not None else "TaskToolError"
    tid = task_id or str(err.details.get("task_id") or "-")
    line = (
        f"tool={tool_name} code={err.code} task_id={tid} exc={exc_type} reason={safe_reason}"
    )
    mgr = logging_mgr
    if mgr is None:
        try:
            mgr = get_logging_manager()
        except Exception:  # noqa: BLE001
            mgr = None
    if mgr is not None:
        lvl: Literal["WARNING", "ERROR"] = "ERROR" if err.code in (TASK_STORAGE_ERROR, TASK_INTERNAL_ERROR, TASK_PROCESS_START_FAILED) else "WARNING"
        try:
            mgr.log("tasks", lvl, line, event_code=err.code.lower(), request_id=req_id)
        except Exception:  # noqa: BLE001
            pass
        try:
            if lvl == "ERROR" or err.code in (TASK_EXECUTABLE_NOT_FOUND, TASK_INTERNAL_ERROR, TASK_STORAGE_ERROR, TASK_PROCESS_START_FAILED):
                mgr.log("errors", lvl, line, event_code=err.code.lower(), request_id=req_id)
        except Exception:  # noqa: BLE001
            pass
    return req_id
