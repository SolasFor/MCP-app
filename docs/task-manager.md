# Task Manager (`v0.9.3`)

MCP-app provides a durable background **Task Manager** built on SQLite (`WAL`), encrypted task payload specs, bounded disk output spooling, and per-client fail-closed authorization.

## Architecture & Module Layout

- [`backend/tasks/models.py`](file:///d:/Coding/MCP%20App/backend/tasks/models.py) — `TaskSpec`, `TaskRecord`, terminal/active lifecycle states (`queued`, `running`, `succeeded`, `failed`, `cancelled`, `interrupted`), redacted public summaries, and MCP Tasks protocol mapping (`to_mcp_task_dict()`).
- [`backend/tasks/store.py`](file:///d:/Coding/MCP%20App/backend/tasks/store.py) — durable `tasks.sqlite3` store with DPAPI (Windows) / POSIX `0600` key-wrapped Fernet encryption for task payloads (`spec_encrypted`), atomic `(owner_client_id, idempotency_key)` deduplication, priority & concurrency-quota dispatch (`pop_next_runnable`), restart `interrupted` recovery, and bounded retention cleanup (`enforce_retention`).
- [`backend/tasks/manager.py`](file:///d:/Coding/MCP%20App/backend/tasks/manager.py) — background async dispatcher detached from HTTP request lifetimes, live pre-dispatch permission recheck, process-tree cancellation (`ProcessRunner.cancel_run`), redacted `result.json` artifacts, and strict `owner_client_id` isolation.
- [`backend/server.py`](file:///d:/Coding/MCP%20App/backend/server.py) — 8 OAuth execution tools (`task_start`, `task_status`, `task_list`, `task_output`, `task_result`, `task_cancel`, `task_restart`, `task_artifacts`) registered alongside existing synchronous `oauth_windows_command` and `oauth_ssh_command`.
- [`app/ui/pages/tasks_page.py`](file:///d:/Coding/MCP%20App/app/ui/pages/tasks_page.py) & [`app/ui/tray.py`](file:///d:/Coding/MCP%20App/app/ui/tray.py) — Active/Queue/History table, redacted output & artifact viewers, Cancel/Restart controls, honest unknown progress (`—` unless known), and system tray completion notifications.

## MCP Tasks Protocol Compatibility

- `TaskRecord.to_mcp_task_dict()` aligns task status states (`working` / `completed` / `failed` / `cancelled`) and ISO timestamps with the `mcp==2.3.0` Tasks schema (`mcp.types.Task`), exposed alongside stable custom `task_*` tools so all MCP clients—even those without experimental `tasks/*` client capabilities—work reliably.

## Security & Operational Boundaries

1. **Per-Client Ownership**: Every `task_status`, `task_list`, `task_output`, `task_result`, `task_cancel`, `task_restart`, and `task_artifacts` call checks `owner_client_id == caller_client_id`. Cross-client access fails closed.
2. **Pre-Dispatch Permission Recheck**: Permissions, emergency stop, and allowlists are re-verified after queue dequeue immediately before spawning a subprocess or SSH session.
3. **No Secret Leakage**: Command specs are encrypted at rest inside `tasks.sqlite3`; metadata titles, output pages, `result.json`, and exported artifacts pass through `SecretRedactor`.
4. **Honest Reboot Behavior**: Background tasks continue across HTTP client disconnects, but **do not continue after host OS shutdown or backend process termination**. On restart, `recover_interrupted()` marks unfinished tasks as `interrupted` without auto-restarting non-idempotent commands.
