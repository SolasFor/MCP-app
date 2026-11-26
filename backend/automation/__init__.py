"""Stage 11 Automation, Monitoring, Backup/Restore, Staged Updater, and Admin REST API."""
from __future__ import annotations

from backend.automation.admin_api import build_admin_app
from backend.automation.backup_updater import (
    BACKUP_SCHEMA_VERSION,
    BackupManager,
    StagedUpdater,
    UpdateCandidate,
)
from backend.automation.monitoring import (
    MetricsRegistry,
    collect_system_snapshot,
    export_redacted_diagnostics,
    filter_audit_entries,
    prune_audit_file,
)
from backend.automation.scheduler import (
    AutomationScheduler,
    ScheduleRunRecord,
    ScheduleSpec,
    next_cron_timestamp,
    parse_cron_expr,
    resolve_timezone,
)

__all__ = [
    "AutomationScheduler",
    "BACKUP_SCHEMA_VERSION",
    "BackupManager",
    "MetricsRegistry",
    "ScheduleRunRecord",
    "ScheduleSpec",
    "StagedUpdater",
    "UpdateCandidate",
    "build_admin_app",
    "collect_system_snapshot",
    "export_redacted_diagnostics",
    "filter_audit_entries",
    "next_cron_timestamp",
    "parse_cron_expr",
    "prune_audit_file",
    "resolve_timezone",
]
