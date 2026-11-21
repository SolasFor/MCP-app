"""Гарантия «никаких процессов-сирот».

1. Job Object с флагом KILL_ON_JOB_CLOSE: дочерние процессы (server, cloudflared)
   умирают автоматически, даже если GUI упал или был убит из Диспетчера задач:
   Windows закрывает дескриптор Job — и гасит всё, что в нём состоит.
2. kill_process_tree(): явная остановка процесса вместе со всеми потомками
   (например, команды, запущенные через run_local_command).

Без pywin32 модуль деградирует мягко: Job Object не создаётся, дерево убивается через psutil.
"""
from __future__ import annotations

import sys

import psutil

_job = None
_job_failed = False


def _ensure_job():
    global _job, _job_failed
    if _job is not None or _job_failed or sys.platform != "win32":
        return _job
    try:
        import win32job

        job = win32job.CreateJobObject(None, "")
        info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
        _job = job  # держим ссылку до конца жизни GUI — это и есть «предохранитель»
    except Exception:  # noqa: BLE001 — нет pywin32 / нет прав: работаем без Job
        _job_failed = True
    return _job


def assign_to_job(pid: int) -> bool:
    """Поместить процесс в Job. Его будущие потомки попадут туда же автоматически."""
    job = _ensure_job()
    if job is None:
        return False
    try:
        import win32api
        import win32con
        import win32job

        handle = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, pid)
        try:
            win32job.AssignProcessToJobObject(job, handle)
        finally:
            win32api.CloseHandle(handle)
        return True
    except Exception:  # noqa: BLE001 — процесс уже завершился или нет прав
        return False


def kill_process_tree(pid: int, include_parent: bool = True) -> None:
    """Убить процесс и всех его потомков. Не бросает исключений."""
    try:
        parent = psutil.Process(pid)
        victims = parent.children(recursive=True)
    except psutil.Error:
        return
    if include_parent:
        victims.append(parent)
    for proc in victims:
        try:
            proc.kill()
        except psutil.Error:
            pass
