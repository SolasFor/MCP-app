"""Unified MCP ToolRegistry: single source of truth for discovery and call authorization."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

if __package__:
    from .oauth_execution import ExecutionApprovals
    from .oauth_store import OAuthStore
else:
    from oauth_execution import ExecutionApprovals  # type: ignore[no-redef]
    from oauth_store import OAuthStore  # type: ignore[no-redef]

EXEC_WINDOWS = "oauth_windows_command"
EXEC_SSH = "oauth_ssh_command"
EXEC_MANAGED = "oauth_managed_server"
TASK_START = "task_start"
TASK_STATUS = "task_status"
TASK_LIST = "task_list"
TASK_OUTPUT = "task_output"
TASK_RESULT = "task_result"
TASK_CANCEL = "task_cancel"
TASK_RESTART = "task_restart"
TASK_ARTIFACTS = "task_artifacts"
TASK_TOOLS = frozenset({
    TASK_START,
    TASK_STATUS,
    TASK_LIST,
    TASK_OUTPUT,
    TASK_RESULT,
    TASK_CANCEL,
    TASK_RESTART,
    TASK_ARTIFACTS,
})
SERVER_LIST = "server_list"
SERVER_START = "server_start"
SERVER_STOP = "server_stop"
SERVER_RESTART = "server_restart"
SERVER_STATUS = "server_status"
SERVER_LOGS = "server_logs"
SERVER_METRICS = "server_metrics"
SERVER_HEALTH = "server_health"
SERVER_TOOLS = frozenset({
    SERVER_LIST,
    SERVER_START,
    SERVER_STOP,
    SERVER_RESTART,
    SERVER_STATUS,
    SERVER_LOGS,
    SERVER_METRICS,
    SERVER_HEALTH,
})
WS_LIST = "workspace_list"
WS_INFO = "workspace_info"
WS_TREE = "workspace_tree"
WS_READ = "workspace_read_file"
WS_WRITE = "workspace_write_file"
WS_SEARCH = "workspace_search"
WS_PATCH = "workspace_apply_patch"
WS_MOVE = "workspace_move_file"
WS_DELETE = "workspace_delete_file"
WS_DIFF = "workspace_diff"
WS_HISTORY = "workspace_history"
WS_RUN_TASK = "workspace_run_task"
WORKSPACE_TOOLS = frozenset({
    WS_LIST,
    WS_INFO,
    WS_TREE,
    WS_READ,
    WS_WRITE,
    WS_SEARCH,
    WS_PATCH,
    WS_MOVE,
    WS_DELETE,
    WS_DIFF,
    WS_HISTORY,
    WS_RUN_TASK,
})
GIT_STATUS = "git_status"
GIT_DIFF = "git_diff"
GIT_LOG = "git_log"
GIT_BRANCHES = "git_branches"
GIT_CHECKOUT = "git_checkout"
GIT_COMMIT = "git_commit"
GIT_TOOLS = frozenset({
    GIT_STATUS,
    GIT_DIFF,
    GIT_LOG,
    GIT_BRANCHES,
    GIT_CHECKOUT,
    GIT_COMMIT,
})
DT_SCREENSHOT = "desktop_screenshot"
DT_LIST_WINDOWS = "desktop_list_windows"
DT_LIST_MONITORS = "desktop_list_monitors"
DT_OPEN_APP = "desktop_open_app"
DT_CLOSE_WINDOW = "desktop_close_window"
DT_FOCUS_WINDOW = "desktop_focus_window"
DT_GET_UI_TREE = "desktop_get_ui_tree"
DT_CLICK = "desktop_click"
DT_TYPE = "desktop_type"
DT_KEYPRESS = "desktop_keypress"
DT_SCROLL = "desktop_scroll"
DT_DRAG = "desktop_drag"
DT_WAIT_FOR_ELEMENT = "desktop_wait_for_element"
DESKTOP_TOOLS = frozenset({
    DT_SCREENSHOT,
    DT_LIST_WINDOWS,
    DT_LIST_MONITORS,
    DT_OPEN_APP,
    DT_CLOSE_WINDOW,
    DT_FOCUS_WINDOW,
    DT_GET_UI_TREE,
    DT_CLICK,
    DT_TYPE,
    DT_KEYPRESS,
    DT_SCROLL,
    DT_DRAG,
    DT_WAIT_FOR_ELEMENT,
})
EXT_LIST = "extension_list"
EXT_INFO = "extension_info"
EXT_CALL_TOOL = "extension_call_tool"
EXT_ENABLE = "extension_enable"
EXT_DISABLE = "extension_disable"
EXT_LOGS = "extension_logs"
EXTENSION_TOOLS = frozenset({
    EXT_LIST,
    EXT_INFO,
    EXT_CALL_TOOL,
    EXT_ENABLE,
    EXT_DISABLE,
    EXT_LOGS,
})
EXTENSION_ALLOWLIST_TOOLS = frozenset({EXT_LIST, EXT_INFO, EXT_CALL_TOOL, EXT_LOGS})
EXTENSION_FULL_TOOLS = frozenset({EXT_ENABLE, EXT_DISABLE})
RM_DEVICE_LIST = "device_list"
RM_DEVICE_INFO = "device_info"
RM_DEVICE_HEALTH = "device_health"
RM_SSH_EXECUTE = "ssh_execute"
RM_SSH_TASK_START = "ssh_task_start"
RM_SFTP_LIST = "sftp_list"
RM_SFTP_DOWNLOAD = "sftp_download"
RM_SFTP_UPLOAD = "sftp_upload"
RM_SVC_LIST = "remote_service_list"
RM_SVC_START = "remote_service_start"
RM_SVC_STOP = "remote_service_stop"
RM_METRICS = "remote_metrics"
REMOTE_TOOLS = frozenset({
    RM_DEVICE_LIST,
    RM_DEVICE_INFO,
    RM_DEVICE_HEALTH,
    RM_SSH_EXECUTE,
    RM_SSH_TASK_START,
    RM_SFTP_LIST,
    RM_SFTP_DOWNLOAD,
    RM_SFTP_UPLOAD,
    RM_SVC_LIST,
    RM_SVC_START,
    RM_SVC_STOP,
    RM_METRICS,
})
BASIC_TOOLS = frozenset({"server_info"})
EXEC_TOOLS = (
    frozenset({EXEC_WINDOWS, EXEC_SSH, EXEC_MANAGED})
    | TASK_TOOLS
    | SERVER_TOOLS
    | WORKSPACE_TOOLS
    | GIT_TOOLS
    | DESKTOP_TOOLS
    | EXTENSION_TOOLS
    | REMOTE_TOOLS
)
OAUTH_TOOLS = (
    BASIC_TOOLS
    | {EXEC_WINDOWS, EXEC_SSH}
    | TASK_TOOLS
    | SERVER_TOOLS
    | WORKSPACE_TOOLS
    | GIT_TOOLS
    | DESKTOP_TOOLS
    | EXTENSION_ALLOWLIST_TOOLS
    | REMOTE_TOOLS
)
FULL_TOOLS = OAUTH_TOOLS | {EXEC_MANAGED} | EXTENSION_FULL_TOOLS

_PROFILE_RANK = {"safe": 0, "allowlist": 1, "full": 2}


@dataclass(frozen=True)
class ToolSpec:
    """Metadata describing a registered MCP tool and its minimum access profile."""

    name: str
    category: str
    min_profile: str = "safe"
    requires_execution: bool = False
    description: str = ""


class ToolRegistry:
    """Fail-closed registry enforcing profile, temporary grants, and emergency stop."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self.register(ToolSpec("server_info", "core", min_profile="safe", requires_execution=False))
        self.register(
            ToolSpec(EXEC_WINDOWS, "execution", min_profile="allowlist", requires_execution=True)
        )
        self.register(
            ToolSpec(EXEC_SSH, "execution", min_profile="allowlist", requires_execution=True)
        )
        self.register(
            ToolSpec(EXEC_MANAGED, "execution", min_profile="full", requires_execution=True)
        )
        for task_tool in sorted(TASK_TOOLS):
            self.register(
                ToolSpec(task_tool, "tasks", min_profile="allowlist", requires_execution=True)
            )
        for server_tool in sorted(SERVER_TOOLS):
            self.register(
                ToolSpec(server_tool, "servers", min_profile="allowlist", requires_execution=True)
            )
        for ws_tool in sorted(WORKSPACE_TOOLS):
            self.register(
                ToolSpec(ws_tool, "workspaces", min_profile="allowlist", requires_execution=True)
            )
        for git_tool in sorted(GIT_TOOLS):
            self.register(
                ToolSpec(git_tool, "git", min_profile="allowlist", requires_execution=True)
            )
        for dt_tool in sorted(DESKTOP_TOOLS):
            self.register(
                ToolSpec(dt_tool, "desktop", min_profile="allowlist", requires_execution=True)
            )
        for ext_tool in sorted(EXTENSION_ALLOWLIST_TOOLS):
            self.register(
                ToolSpec(ext_tool, "extensions", min_profile="allowlist", requires_execution=True)
            )
        for ext_full_tool in sorted(EXTENSION_FULL_TOOLS):
            self.register(
                ToolSpec(ext_full_tool, "extensions", min_profile="full", requires_execution=True)
            )
        for remote_tool in sorted(REMOTE_TOOLS):
            self.register(
                ToolSpec(remote_tool, "remote", min_profile="allowlist", requires_execution=True)
            )

    def register(self, spec: ToolSpec) -> None:
        if spec.min_profile not in _PROFILE_RANK:
            raise ValueError(f"Unknown min_profile: {spec.min_profile!r}")
        self._specs[spec.name] = spec

    def registered_names(self) -> frozenset[str]:
        return frozenset(self._specs)

    def allowed_tools(
        self,
        store: OAuthStore | None,
        principal: Any,
        execution: ExecutionApprovals | None = None,
    ) -> frozenset[str]:
        if store is None or execution is None or principal is None:
            return BASIC_TOOLS
        if execution.emergency_stopped():
            return BASIC_TOOLS
        client_id = getattr(principal, "client_id", None)
        scopes = getattr(principal, "scopes", None) or []
        if not isinstance(client_id, str) or "mcp:read" not in scopes:
            return BASIC_TOOLS
        if not execution.client_approved(client_id):
            return BASIC_TOOLS

        profile = execution.profile_for(client_id)
        rank = _PROFILE_RANK.get(profile, 0)
        allowed = {
            name
            for name, spec in self._specs.items()
            if _PROFILE_RANK.get(spec.min_profile, 99) <= rank
        }
        for grant in execution.active_temporary_grants(client_id):
            for tool_name in grant.get("tool_names", ()):
                if tool_name in self._specs:
                    allowed.add(tool_name)
        return frozenset(allowed)

    def authorize_call(
        self,
        tool_name: str,
        store: OAuthStore | None,
        principal: Any,
        execution: ExecutionApprovals | None,
    ) -> str:
        """Verify live authorization at call time or post-queue dispatch."""
        if execution is not None and execution.emergency_stopped():
            raise PermissionError("Emergency stop is active")
        allowed = self.allowed_tools(store, principal, execution)
        if tool_name not in self._specs or tool_name not in allowed:
            raise PermissionError("OAuth client is not authorized to request execution")
        client_id = getattr(principal, "client_id", None)
        if not isinstance(client_id, str) or not client_id:
            raise PermissionError("Missing OAuth client identity")
        return client_id


DEFAULT_REGISTRY = ToolRegistry()
