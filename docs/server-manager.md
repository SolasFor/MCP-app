# Server Manager (`v0.9.4`)

MCP-app Server Manager manages owner-configured local development servers and background services (`%APPDATA%\MCPApp\servers\managed_servers.json`) with encrypted secrets, health probes, metrics, dependency ordering, and bounded logs.

## Key Capabilities
- **Lossless Migration**: Reads legacy v1 `managed_servers.json` (`{name: {argv, cwd, lifecycle}}`) seamlessly and migrates to schema v2 without data loss or privilege widening (migrated entries default to `min_profile="full"`).
- **Templates (`backend/servers/templates.py`)**:
  - `python_fastapi`, `python_flask`, `node_express`, `vite_next`, `docker_compose`, `static_http`, and `custom`.
  - Validates parameters strictly, refuses shell metacharacters / path traversal / package-manager auto-installs (`pip`/`npm`/`npx`), and defaults to loopback binding (`127.0.0.1`).
- **Encrypted Secret Env Vars**: Secret environment variables (`env_secret_refs`) are stored under the `servers` namespace in DPAPI-protected `SecretStore` (`secret://servers/<server>__<KEY>`), never in JSON config, logs, or metadata responses.
- **Process & Port Ownership**:
  - Pre-launch port conflict check detects existing listeners without ever terminating foreign PIDs.
  - CPU/RAM/thread metrics verify `(pid, create_time)` via `ProcessIdentity` before querying `psutil`.
  - `controlled` servers run inside a process tree / Job Object and terminate cleanly on stop or shutdown.
  - `independent` servers launch detached and are never forcibly killed by `stop` or app exit; MCP-app reports this honestly.
- **Readiness, Dependencies & Restarts**:
  - Supports `none`, `tcp`, and `http` readiness probes with bounded timeouts.
  - Topological dependency ordering (`depends_on`) with DFS cycle detection aborts startup if a dependency fails readiness.
  - Restart policies (`never`, `on-failure`, `always`) use bounded exponential backoff.
- **MCP Tools (`backend/server.py`, `backend/tool_registry.py`)**:
  - `server_list`, `server_start`, `server_stop`, `server_restart`, `server_status`, `server_logs`, `server_metrics`, `server_health`, plus compatible `oauth_managed_server`.
  - Per-server `min_profile` (`allowlist` | `full`), `allowed_clients`, live re-authorization before restarts, and optional `TaskManager` linkage (`linked_task_id` / `run_pre_start_task`).
