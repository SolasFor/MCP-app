# Server Manager (`v1.0.2` / integrated in Workspaces)

MCP-app Server Manager manages owner-configured local development servers and background services (`%APPDATA%\MCPApp\servers\managed_servers.json`) with encrypted secrets, health probes, metrics, dependency ordering, and bounded logs. Since stage **N03**, Server Manager UI lives directly inside **Workspaces** (Linked Servers per workspace + **Unlinked Servers** tab); the standalone **Servers** sidebar tab was removed while redirecting legacy `"servers"` / `"server_manager"` / `"managed_servers"` targets to Workspaces.

## Key Capabilities
- **Lossless Migration**: Reads legacy v1 `managed_servers.json` (`{name: {argv, cwd, lifecycle}}`) seamlessly and migrates to schema v2 without data loss or privilege widening (migrated entries default to `min_profile="full"`).
- **Templates (`backend/servers/templates.py`)**:
  - `python_fastapi`, `python_flask`, `node_express`, `vite_next`, `docker_compose`, `static_http`, and `custom`.
  - Validates parameters strictly, refuses shell metacharacters / path traversal / package-manager auto-installs (`pip`/`npm`/`npx`), and defaults to loopback binding (`127.0.0.1`).
- **Encrypted Secret Env Vars**: Secret environment variables (`env_secret_refs`) are stored under the `servers` namespace in DPAPI-protected `SecretStore` (`secret://servers/<server>__<KEY>`), never in JSON config, logs, or metadata responses.
- **Process & Port Ownership**:
  - Single authoritative runtime when backend is running: GUI (`WorkspacesPage`) delegates start/stop/restart/health/logs/metrics/autostart through loopback-only `LocalAdminClient` without repeating mutating calls on `AdminRequestAmbiguousError` or falling back locally while backend is active; `ServerManager` persists `managed_servers.runtime.json` (including `stop_requested` and `run_id`) under `.managed_servers.runtime.lock` so cross-instance concurrent starts never double-spawn, local supervisors respect remote stops/restarts, and `independent` processes retain verified `ProcessIdentity(pid, create_time)` across backend restarts.
  - Pre-launch port conflict check detects existing listeners without ever terminating foreign PIDs.
  - CPU/RAM/thread metrics verify `(pid, create_time)` via `ProcessIdentity` before querying `psutil`.
  - `controlled` servers run inside a process tree / Job Object and terminate cleanly on stop or owning-manager shutdown (closing GUI never kills backend-owned processes).
  - `independent` servers launch detached and are never forcibly killed by `stop` or app exit; MCP-app reports this honestly (automated tests track their own detached test PIDs and reap those test handles during fixture teardown).
- **Readiness, Dependencies & Restarts**:
  - Supports `none`, `tcp`, and `http` readiness probes with bounded timeouts.
  - Topological dependency ordering (`depends_on`) with DFS cycle detection aborts startup if a dependency fails readiness.
  - Restart policies (`never`, `on-failure`, `always`) use bounded exponential backoff and re-verify live OAuth approval/profile, Emergency Stop, fresh disk `ServerProfile`, and originating `owner_workspace_id` before each auto-restart.
- **MCP Tools (`backend/server.py`, `backend/tool_registry.py`)**:
  - `server_list`, `server_start`, `server_stop`, `server_restart`, `server_status`, `server_logs`, `server_metrics`, `server_health`, plus compatible `oauth_managed_server`.
  - All `server_*` tools accept an optional `workspace_id: str = ""` context parameter and enforce live cross-layer workspace permissions (`WorkspaceServerCoordinator.authorize_server_operation`, `workspace_scoped` no-implicit-widening guard) and confused-deputy checks before every step spawn.
  - Per-server `min_profile` (`allowlist` | `full`), `allowed_clients`, `workspace_scoped`, live re-authorization before restarts, and optional `TaskManager` linkage (`linked_task_id` / `run_pre_start_task`), plus transactional stopped-server ID renaming (`RenameServerDialog` / `rename_server`) syncing `depends_on`, SecretStore refs (retired only after durable commit), `linked_servers`, and `AutomationScheduler` `schedules.json`.
