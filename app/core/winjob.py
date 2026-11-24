"""Гарантия «никаких процессов-сирот».

1. Job Object с флагами KILL_ON_JOB_CLOSE и BREAKAWAY_OK:
   - все контролируемые дочерние процессы (server, cloudflared, команды)
     умирают автоматически, даже если GUI упал или был убит из Диспетчера задач;
   - явно независимые GUI-приложения могут запускаться с CREATE_BREAKAWAY_FROM_JOB.
2. kill_process_tree(): явная остановка процесса вместе со всеми потомками
   с проверкой идентичности процесса (create_time), чтобы не задеть чужой PID.
"""
from __future__ import annotations

import sys

from app.platform import ProcessJobHandle, get_platform

_job: ProcessJobHandle | None = None
_job_failed = False


def _ensure_job() -> ProcessJobHandle | None:
    global _job, _job_failed
    if _job is not None or _job_failed or sys.platform != "win32":
        return _job
    job = get_platform().create_job(name="", kill_on_close=True, allow_breakaway=True)
    if job is None:
        _job_failed = True
        return None
    _job = job
    return _job


def assign_to_job(pid: int) -> bool:
    """Поместить процесс в Job. Его будущие потомки попадут туда же автоматически."""
    job = _ensure_job()
    if job is None:
        return False
    return get_platform().assign_process_to_job(job, pid)


def kill_process_tree(pid: int, include_parent: bool = True) -> None:
    """Убить процесс и всех его потомков после проверки идентичности. Не бросает исключений."""
    platform = get_platform()
    identity = platform.capture_process_identity(pid)
    if identity is None:
        return
    platform.terminate_process_tree(identity, grace_seconds=0.0, include_parent=include_parent)
