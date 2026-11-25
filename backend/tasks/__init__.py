"""Durable background Task Manager for MCP-app."""
from __future__ import annotations

__all__ = [
    "STATUS_CANCELLED",
    "STATUS_FAILED",
    "STATUS_INTERRUPTED",
    "STATUS_QUEUED",
    "STATUS_RUNNING",
    "STATUS_SUCCEEDED",
    "TERMINAL_STATUSES",
    "TaskManager",
    "TaskRecord",
    "TaskSpec",
    "TaskStore",
]

from backend.tasks.manager import TaskManager
from backend.tasks.models import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    TERMINAL_STATUSES,
    TaskRecord,
    TaskSpec,
)
from backend.tasks.store import TaskStore
