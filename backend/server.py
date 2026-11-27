import asyncio
import base64
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import weakref
from contextlib import asynccontextmanager
from typing import Any, Literal
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import paramiko
from pydantic import AnyHttpUrl
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var, get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull
from mcp.types import CallToolResult, ImageContent, TextContent
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

if __package__:
    from .transport_config import transport_allowlists, validate_mcp_path, validate_public_url
    from .oauth_provider import (
        SECURITY_HEADERS,
        LocalConsentOAuthProvider,
        READ_SCOPE,
        _render_error_html,
        oauth_t,
        resolve_oauth_language,
    )
    from .oauth_store import canonical_oauth_urls, default_store_path
    from .oauth_execution import (
        ExecutionApprovals,
        PROFILE_ALLOWLIST,
        PROFILE_FULL,
        PROFILE_SAFE,
        PROFILES,
        windows_whitelisted,
    )
    from .execution_audit import ExecutionAudit, classify_command_output
    from .gateway import GatewayConfigStore, GatewayRouter
    from .gateway.security import check_loop_headers
    from .managed_servers import ManagedServers
    from .output_stream import decode_process_bytes
    from .process_runner import CommandResult, ProcessRunner
    from .tasks import (
        TERMINAL_STATUSES,
        TaskManager,
        TaskRecord,
        TaskSpec,
        TaskStore,
        TaskToolError,
        build_task_error_result,
        classify_task_exception,
        log_task_tool_error,
    )
    from .tasks.errors import (
        TASK_ACCESS_DENIED,
        TASK_COMMAND_NOT_ALLOWED,
        TASK_EXECUTABLE_NOT_FOUND,
        TASK_INVALID_ARGUMENT,
        TASK_INVALID_STATE,
        TASK_INVALID_TIMEOUT,
        TASK_NOT_FOUND,
        TASK_QUEUE_FULL,
    )
    from .workspaces import (
        FileVersionConflictError,
        PathSecurityError,
        WorkspaceHistory,
        WorkspaceManager,
        WorkspaceServerCoordinator,
        WorkspaceStore,
    )
    from .desktop import (
        DesktopBackend,
        DesktopManager,
        DesktopPolicyStore,
        UnavailableDesktopBackend,
        Win32DesktopBackend,
    )
    from .desktop.models import effective_desktop_access
    from .extensions import ExtensionManager, ExtensionStore
    from .remote import DeviceStore, RemoteManager, SSHConnectionError
    from .automation import (
        AutomationScheduler,
        MetricsRegistry,
        ScheduleSpec,
        build_admin_app,
        collect_system_snapshot,
        export_redacted_diagnostics,
    )
    from .tool_registry import (
        DEFAULT_REGISTRY,
        DESKTOP_CONTROL_TOOLS,
        DESKTOP_TOOLS,
        DESKTOP_VIEW_TOOLS,
        DT_CLICK,
        DT_CLOSE_WINDOW,
        DT_DRAG,
        DT_FOCUS_WINDOW,
        DT_GET_UI_TREE,
        DT_KEYPRESS,
        DT_LIST_MONITORS,
        DT_LIST_WINDOWS,
        DT_OPEN_APP,
        DT_SCREENSHOT,
        DT_SCROLL,
        DT_TYPE,
        DT_WAIT_FOR_ELEMENT,
        EXT_CALL_TOOL,
        EXT_DISABLE,
        EXT_ENABLE,
        EXT_INFO,
        EXT_LIST,
        EXT_LOGS,
        RM_DEVICE_HEALTH,
        RM_DEVICE_INFO,
        RM_DEVICE_LIST,
        RM_METRICS,
        RM_SFTP_DOWNLOAD,
        RM_SFTP_LIST,
        RM_SFTP_UPLOAD,
        RM_SSH_EXECUTE,
        RM_SSH_TASK_START,
        RM_SVC_LIST,
        RM_SVC_START,
        RM_SVC_STOP,
        GIT_BRANCHES,
        GIT_CHECKOUT,
        GIT_COMMIT,
        GIT_DIFF,
        GIT_LOG,
        GIT_STATUS,
        SERVER_HEALTH,
        SERVER_LIST,
        SERVER_LOGS,
        SERVER_METRICS,
        SERVER_RESTART,
        SERVER_START,
        SERVER_STATUS,
        SERVER_STOP,
        TASK_ARTIFACTS,
        TASK_CANCEL,
        TASK_LIST,
        TASK_OUTPUT,
        TASK_RESTART,
        TASK_RESULT,
        TASK_START,
        TASK_STATUS,
        WS_DELETE,
        WS_DIFF,
        WS_HISTORY,
        WS_INFO,
        WS_LIST,
        WS_MOVE,
        WS_PATCH,
        WS_READ,
        WS_RUN_TASK,
        WS_SEARCH,
        WS_TREE,
        WS_WRITE,
    )
    from app.core.secret_store import SecretStore
    from .tool_permissions import (
        EXEC_WINDOWS, EXEC_SSH, EXEC_MANAGED, allowed_tools, make_tool_middleware,
        require_execution_permission,
    )
    from .security_policy import (
        MAX_WRITE_BYTES, allowed_ssh_host, enabled, exact_allowlist,
        parse_allowed_command, workspace_path,
    )
else:
    from transport_config import transport_allowlists, validate_mcp_path, validate_public_url
    from oauth_provider import (
        SECURITY_HEADERS,
        LocalConsentOAuthProvider,
        READ_SCOPE,
        _render_error_html,
        oauth_t,
        resolve_oauth_language,
    )
    from oauth_store import canonical_oauth_urls, default_store_path
    from oauth_execution import (
        ExecutionApprovals,
        PROFILE_ALLOWLIST,
        PROFILE_FULL,
        PROFILE_SAFE,
        PROFILES,
        windows_whitelisted,
    )
    from execution_audit import ExecutionAudit, classify_command_output
    from gateway import GatewayConfigStore, GatewayRouter
    from gateway.security import check_loop_headers
    from managed_servers import ManagedServers
    from output_stream import decode_process_bytes
    from process_runner import CommandResult, ProcessRunner
    from tasks import (
        TERMINAL_STATUSES,
        TaskManager,
        TaskRecord,
        TaskSpec,
        TaskStore,
        TaskToolError,
        build_task_error_result,
        classify_task_exception,
        log_task_tool_error,
    )
    from tasks.errors import (
        TASK_ACCESS_DENIED,
        TASK_COMMAND_NOT_ALLOWED,
        TASK_EXECUTABLE_NOT_FOUND,
        TASK_INVALID_ARGUMENT,
        TASK_INVALID_STATE,
        TASK_INVALID_TIMEOUT,
        TASK_NOT_FOUND,
        TASK_QUEUE_FULL,
    )
    from workspaces import (
        FileVersionConflictError,
        PathSecurityError,
        WorkspaceHistory,
        WorkspaceManager,
        WorkspaceServerCoordinator,
        WorkspaceStore,
    )
    from desktop import (
        DesktopBackend,
        DesktopManager,
        DesktopPolicyStore,
        UnavailableDesktopBackend,
        Win32DesktopBackend,
    )
    from desktop.models import effective_desktop_access
    from extensions import ExtensionManager, ExtensionStore
    from remote import DeviceStore, RemoteManager, SSHConnectionError
    from automation import (
        AutomationScheduler,
        MetricsRegistry,
        ScheduleSpec,
        build_admin_app,
        collect_system_snapshot,
        export_redacted_diagnostics,
    )
    from tool_registry import (
        DEFAULT_REGISTRY,
        DESKTOP_CONTROL_TOOLS,
        DESKTOP_TOOLS,
        DESKTOP_VIEW_TOOLS,
        DT_CLICK,
        DT_CLOSE_WINDOW,
        DT_DRAG,
        DT_FOCUS_WINDOW,
        DT_GET_UI_TREE,
        DT_KEYPRESS,
        DT_LIST_MONITORS,
        DT_LIST_WINDOWS,
        DT_OPEN_APP,
        DT_SCREENSHOT,
        DT_SCROLL,
        DT_TYPE,
        DT_WAIT_FOR_ELEMENT,
        EXT_CALL_TOOL,
        EXT_DISABLE,
        EXT_ENABLE,
        EXT_INFO,
        EXT_LIST,
        EXT_LOGS,
        RM_DEVICE_HEALTH,
        RM_DEVICE_INFO,
        RM_DEVICE_LIST,
        RM_METRICS,
        RM_SFTP_DOWNLOAD,
        RM_SFTP_LIST,
        RM_SFTP_UPLOAD,
        RM_SSH_EXECUTE,
        RM_SSH_TASK_START,
        RM_SVC_LIST,
        RM_SVC_START,
        RM_SVC_STOP,
        GIT_BRANCHES,
        GIT_CHECKOUT,
        GIT_COMMIT,
        GIT_DIFF,
        GIT_LOG,
        GIT_STATUS,
        SERVER_HEALTH,
        SERVER_LIST,
        SERVER_LOGS,
        SERVER_METRICS,
        SERVER_RESTART,
        SERVER_START,
        SERVER_STATUS,
        SERVER_STOP,
        TASK_ARTIFACTS,
        TASK_CANCEL,
        TASK_LIST,
        TASK_OUTPUT,
        TASK_RESTART,
        TASK_RESULT,
        TASK_START,
        TASK_STATUS,
        WS_DELETE,
        WS_DIFF,
        WS_HISTORY,
        WS_INFO,
        WS_LIST,
        WS_MOVE,
        WS_PATCH,
        WS_READ,
        WS_RUN_TASK,
        WS_SEARCH,
        WS_TREE,
        WS_WRITE,
    )
    from app.core.secret_store import SecretStore
    from tool_permissions import (
        EXEC_WINDOWS, EXEC_SSH, EXEC_MANAGED, allowed_tools, make_tool_middleware,
        require_execution_permission,
    )
    from security_policy import (
        MAX_WRITE_BYTES, allowed_ssh_host, enabled, exact_allowlist,
        parse_allowed_command, workspace_path,
    )

from app.core.logging_manager import (
    LogConfig,
    configure_logging,
    default_logs_dir,
)
from app.core.redaction import RedactingLogFilter, SecretRedactor

# ==========================================
# 1. КОНФИГУРАЦИЯ И ЛОГИРОВАНИЕ
# ==========================================
# Все параметры приходят из переменных окружения. Их задаёт GUI (ServiceManager);
# при ручном запуске `python backend/server.py` работают значения по умолчанию.

SERVER_NAME = "MCP app"
AUDIT_LOG = "mcp_audit.log"  # в рабочей папке сервера (в .exe — %APPDATA%\MCPApp\server)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(AUDIT_LOG, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("MCPApp")
# The dedicated audit log stays local to the server's user data directory.
# It contains no commands/arguments, stdout, OAuth tokens or SSH credentials.
EXEC_AUDIT = ExecutionAudit(
    os.environ.get("MCP_EXEC_AUDIT_PATH")
    or Path(AUDIT_LOG).with_name("mcp_execution_audit.jsonl")
)


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _load_owner_secret(fallback_transport_token: str) -> str:
    raw_b64 = os.environ.get("MCP_OWNER_SECRET_B64", "")
    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64.encode("ascii")).decode("utf-8")
            if decoded:
                return decoded
        except Exception:  # noqa: BLE001
            pass
    return fallback_transport_token


SECRET_TOKEN = os.environ.get("MCP_SECRET_TOKEN", "").strip()
TOKEN_FROM_ENV = bool(SECRET_TOKEN)
if not SECRET_TOKEN:
    SECRET_TOKEN = secrets.token_urlsafe(24)
    # Только при ручном запуске без GUI: иначе временный токен негде узнать.
    logger.warning("MCP_SECRET_TOKEN not set: temporary token generated (never logged). Set a token before remote use.")
OWNER_SECRET = _load_owner_secret(SECRET_TOKEN)

REDACTOR = SecretRedactor()
REDACTOR.register(SECRET_TOKEN, allow_short=True)
REDACTOR.register(OWNER_SECRET, allow_short=True)
_REDACT_FILTER = RedactingLogFilter(REDACTOR)
logger.addFilter(_REDACT_FILTER)
for _handler in logging.getLogger().handlers:
    _handler.addFilter(_REDACT_FILTER)

_LOGGING_MGR = configure_logging(
    base_dir=default_logs_dir(),
    config=LogConfig(
        enabled=_env_flag("MCP_LOGGING_ENABLED", True),
        level=os.environ.get("MCP_LOG_LEVEL", "INFO"),
    ),
    redactor=REDACTOR,
)
_LOGGING_MGR.install_exception_hooks(chain_previous=False)
_BACKEND_LOG_HANDLER = _LOGGING_MGR.std_logging_handler("backend", event_code="backend_log")
_BACKEND_LOG_HANDLER.addFilter(_REDACT_FILTER)
logger.addHandler(_BACKEND_LOG_HANDLER)
for _uv_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    _uv_logger = logging.getLogger(_uv_name)
    _uv_logger.addFilter(_REDACT_FILTER)
    _uv_logger.addHandler(_BACKEND_LOG_HANDLER)

# The GUI passes the active Quick Tunnel URL and MCP path for each server start.
MCP_PATH = validate_mcp_path(os.environ.get("MCP_PATH", "/mcp"))
# Local loopback only by default; cloudflared exposes the public HTTPS endpoint.
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))
_base_domain = os.environ.get("MCP_BASE_DOMAIN", "").rstrip("/")
PUBLIC_URL = validate_public_url(
    os.environ.get("MCP_PUBLIC_URL")
    or (f"{_base_domain}{MCP_PATH}" if _base_domain else f"http://127.0.0.1:{PORT}{MCP_PATH}"),
    MCP_PATH,
)
_public = urlsplit(PUBLIC_URL)
PUBLIC_HOST = (_public.hostname or "").lower()
_canon_base, _canon_resource = canonical_oauth_urls(str(AnyHttpUrl(PUBLIC_URL)))
BASE_URL = _canon_base or f"{_public.scheme}://{_public.netloc}"
RESOURCE_URL = _canon_resource or str(AnyHttpUrl(PUBLIC_URL))

# Проверка живости для GUI (HealthMonitor раз в 2 с). Без токена и без записи в аудит.
HEALTH_PATH = os.environ.get("MCP_HEALTH_PATH", "/health")
# ?token=… в ссылке — для клиентов, в которых нельзя задать заголовок Authorization.
ALLOW_QUERY_TOKEN = False  # OAuth or Bearer header only; forbid ?token= in public URLs
# Quick Tunnels (trycloudflare.com) не поддерживают SSE — там отвечаем обычным JSON.
JSON_RESPONSE = _env_flag("MCP_JSON_RESPONSE", PUBLIC_HOST.endswith(".trycloudflare.com"))

WORKSPACE_DIR = Path(os.environ.get("MCP_WORKSPACE_DIR", os.getcwd())).resolve()
PROCESS_RUNNER = ProcessRunner(
    spool_dir=Path(os.environ.get("MCP_SPOOL_DIR") or (WORKSPACE_DIR / "spool")),
    redactor=REDACTOR,
)
_SERVERS_DEFAULT_PATH = (
    WORKSPACE_DIR / "managed_servers.json"
    if (WORKSPACE_DIR / "managed_servers.json").is_file()
    else (
        Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
        / "servers"
        / "managed_servers.json"
    )
)
_SERVER_SECRET_STORE = (
    SecretStore(Path(os.environ["MCP_SECRETS_DIR"]))
    if os.environ.get("MCP_SECRETS_DIR")
    else None
)
_TASKS_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "tasks"
)
_GATEWAY_DEFAULT_PATH = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "gateway"
    / "servers.json"
)
GATEWAY_STORE = GatewayConfigStore(
    Path(os.environ.get("MCP_GATEWAY_CONFIG_PATH") or _GATEWAY_DEFAULT_PATH)
)
TASK_STORE = TaskStore(
    Path(os.environ.get("MCP_TASKS_DB_PATH") or (_TASKS_DEFAULT_DIR / "tasks.sqlite3"))
)
TASK_STORE.recover_interrupted()
_WORKSPACES_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "workspaces"
)
WORKSPACE_STORE = WorkspaceStore(
    Path(os.environ.get("MCP_WORKSPACES_CONFIG_PATH") or (_WORKSPACES_DEFAULT_DIR / "workspaces.json")),
    secret_store=_SERVER_SECRET_STORE,
)
WORKSPACE_HISTORY = WorkspaceHistory(
    Path(os.environ.get("MCP_WORKSPACES_HISTORY_DIR") or (_WORKSPACES_DEFAULT_DIR / "history"))
)
_AUTOMATION_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "automation"
)
AUTOMATION_DIR = Path(os.environ.get("MCP_AUTOMATION_DIR") or _AUTOMATION_DEFAULT_DIR)
MANAGED_SERVERS = ManagedServers(
    Path(os.environ.get("MCP_MANAGED_SERVERS_PATH") or _SERVERS_DEFAULT_PATH),
    runner=PROCESS_RUNNER,
    redactor=REDACTOR,
    task_store=TASK_STORE,
    secret_store=_SERVER_SECRET_STORE,
)
SERVER_MANAGER = MANAGED_SERVERS.manager
WORKSPACE_SERVER_COORDINATOR = WorkspaceServerCoordinator(
    WORKSPACE_STORE,
    MANAGED_SERVERS.store,
    automation_dir=AUTOMATION_DIR,
)
try:
    WORKSPACE_SERVER_COORDINATOR.ensure_migrated()
except Exception as _mig_exc:  # noqa: BLE001
    logger.warning("Workspace/Server migration check failed closed: %s", type(_mig_exc).__name__)
SERVER_MANAGER.workspace_authorizer = WORKSPACE_SERVER_COORDINATOR.authorize_server_operation
WORKSPACE_MANAGER = WorkspaceManager(
    WORKSPACE_STORE,
    WORKSPACE_HISTORY,
    runner=PROCESS_RUNNER,
    redactor=REDACTOR,
    task_store=TASK_STORE,
    spool_dir=PROCESS_RUNNER.spool.spool_dir,
    artifacts_dir=Path(os.environ.get("MCP_TASKS_ARTIFACTS_DIR") or (_TASKS_DEFAULT_DIR / "artifacts")),
    coordinator=WORKSPACE_SERVER_COORDINATOR,
    server_manager=SERVER_MANAGER,
)
_DESKTOP_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "desktop"
)
DESKTOP_POLICY_STORE = DesktopPolicyStore(
    Path(os.environ.get("MCP_DESKTOP_POLICY_PATH") or (_DESKTOP_DEFAULT_DIR / "policy.json"))
)
_DESKTOP_BACKEND: DesktopBackend = (
    Win32DesktopBackend() if sys.platform == "win32" else UnavailableDesktopBackend()
)
DESKTOP_MANAGER = DesktopManager(
    DESKTOP_POLICY_STORE,
    _DESKTOP_BACKEND,
    redactor=REDACTOR,
)
_EXTENSIONS_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "extensions"
)
EXTENSION_STORE = ExtensionStore(
    Path(os.environ.get("MCP_EXTENSIONS_DIR") or _EXTENSIONS_DEFAULT_DIR),
    secret_store=_SERVER_SECRET_STORE,
)
EXTENSION_MANAGER = ExtensionManager(
    EXTENSION_STORE,
    redactor=REDACTOR,
)
_REMOTE_DEFAULT_DIR = (
    Path(os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path()).parent.parent
    / "remote"
)
REMOTE_STORE = DeviceStore(
    Path(os.environ.get("MCP_DEVICES_CONFIG_PATH") or (_REMOTE_DEFAULT_DIR / "devices.json")),
    secret_store=_SERVER_SECRET_STORE,
)
REMOTE_MANAGER = RemoteManager(
    REMOTE_STORE,
    redactor=REDACTOR,
)
GATEWAY_ROUTER = GatewayRouter(
    GATEWAY_STORE,
    self_urls=(
        PUBLIC_URL,
        f"http://127.0.0.1:{PORT}{MCP_PATH}",
        f"http://localhost:{PORT}{MCP_PATH}",
    ),
    redactor=REDACTOR,
)
METRICS_REGISTRY = MetricsRegistry()
ADMIN_HOST = "127.0.0.1"
ADMIN_PORT = int(os.environ.get("MCP_ADMIN_PORT", "0") or "0")
ADMIN_TOKEN = (os.environ.get("MCP_ADMIN_TOKEN") or "").strip() or secrets.token_urlsafe(24)
_SCHEDULER_POLL_SECONDS = max(0.05, float(os.environ.get("MCP_SCHEDULER_TICK_SECONDS", "1.0") or "1.0"))
REDACTOR.register(ADMIN_TOKEN)
# All remote tools use one server-wide Bearer token at present. Keep privileged
# tools unregistered unless an administrator explicitly opts in.
OAUTH_ENABLED = _env_flag("MCP_ENABLE_OAUTH", True)
# The existing Bearer token is shared across clients. Advanced tools cannot be
# co-hosted with this first-stage read-only OAuth authorization server.
ADVANCED_TOOLS = enabled(os.environ.get("MCP_ENABLE_ADVANCED")) and not OAUTH_ENABLED
EXECUTION_TOOLS = ADVANCED_TOOLS and enabled(os.environ.get("MCP_ENABLE_EXECUTION"))
if OAUTH_ENABLED and enabled(os.environ.get("MCP_ENABLE_ADVANCED")):
    logger.warning(
        "OAuth mode overrides legacy Advanced tools; Windows/SSH commands "
        "are controlled separately by each OAuth client's access profile."
    )
ALLOWED_HOSTS = exact_allowlist(os.environ.get("MCP_ALLOWED_HOSTS"))
ALLOWED_EXECUTABLES = exact_allowlist(os.environ.get("MCP_ALLOWED_EXECUTABLES"))
MAX_OUTPUT_LEN = 8000

def truncate_output(text: str) -> str:
    if len(text) <= MAX_OUTPUT_LEN:
        return text
    half = MAX_OUTPUT_LEN // 2
    return f"{text[:half]}\n\n... [ВЫВОД ОБРЕЗАН: пропущено {len(text) - MAX_OUTPUT_LEN} симв.] ...\n\n{text[-half:]}"

# ==========================================
# 2. АУТЕНТИФИКАЦИЯ (ASGI-middleware + TokenVerifier)
# ==========================================

def _token_ok(token: str) -> bool:
    return hmac.compare_digest(token.encode(), SECRET_TOKEN.encode())


class HybridAuthMiddleware:
    """Стоит ПЕРЕД авторизацией MCP SDK.

    * /health — отвечает сразу, без токена и без записи в лог. По пути, а НЕ по IP:
      через туннель ВСЕ запросы приходят с 127.0.0.1 (cloudflared подключается локально).
    * ?token=… запрещён и удаляется из query string до передачи в SDK
      и access-логи Uvicorn; OAuth и Bearer работают через заголовок.
    * Проверку OAuth Bearer выполняет SDK. Нельзя объявлять токен
      "неверным" только потому, что он отличается от токена владельца.
      Пишем предупреждение лишь после фактического HTTP 401/403.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == HEALTH_PATH:
            await JSONResponse({"status": "ok"})(scope, receive, send)
            return
        # GET streams are optional in Streamable HTTP. Cloudflare Quick Tunnel
        # does not support SSE; avoid hanging clients in JSON-only mode.
        if JSON_RESPONSE and path.rstrip("/") == MCP_PATH and scope.get("method") == "GET":
            await Response(
                "SSE unavailable on JSON-only transport",
                status_code=405,
                headers={"Allow": "POST, DELETE"},
            )(scope, receive, send)
            return

        client = scope.get("client") or ("?", 0)
        headers = Headers(scope=scope)
        loop_error = check_loop_headers(dict(headers.items()), GATEWAY_ROUTER.instance_id)
        if loop_error is not None:
            logger.warning("Gateway loop blocked on %s: %s", path, loop_error)
            await JSONResponse(
                {"error": "gateway_loop_detected", "detail": loop_error},
                status_code=400,
            )(scope, receive, send)
            return
        auth_header = headers.get("authorization", "")

        is_bearer = auth_header.lower().startswith("bearer ")
        # A standard OAuth access token necessarily differs from the local
        # owner's token. Only the installed SDK can validate its signature,
        # expiry, resource and client consent. Watch the final HTTP response.
        # Query-string credentials stay forbidden, even on old installs.
        if not is_bearer:
            query_token = self._pop_query_token(scope)
            if query_token is not None:
                logger.warning("Токен в ссылке запрещён ← %s %s", client[0], path)

        is_oauth_path = path in ("/authorize", "/oauth/consent", "/token", "/register") or path.startswith("/.well-known/")
        accept_hdr = (headers.get("accept") or "").lower()
        intercept_authorize_html = (
            path == "/authorize"
            and scope.get("method") == "GET"
            and "text/html" in accept_hdr
        )
        buffered_start = None
        buffered_body = bytearray()

        async def observe_auth_result(message):
            nonlocal buffered_start
            if message["type"] == "http.response.start":
                status = message["status"]
                if path.rstrip("/") == MCP_PATH and status in (401, 403):
                    if is_bearer:
                        logger.warning(
                            "MCP авторизация отклонена HTTP %d ← %s %s %s",
                            status, client[0], scope.get("method"), path,
                        )
                        _LOGGING_MGR.warning(
                            "oauth",
                            f"MCP Bearer rejected HTTP {status} method={scope.get('method')} path={path}",
                            event_code="mcp_auth_rejected",
                        )
                    elif scope.get("method") not in ("HEAD", "OPTIONS"):
                        logger.info(
                            "MCP запрос без Bearer отклонён HTTP %d ← %s %s",
                            status, client[0], scope.get("method"),
                        )
                elif is_oauth_path and status >= 400:
                    lvl = "ERROR" if status >= 500 else "WARNING"
                    _LOGGING_MGR.log(
                        "oauth",
                        lvl,
                        f"OAuth endpoint HTTP {status} method={scope.get('method')} path={path}",
                        event_code="oauth_http_error",
                    )
                if intercept_authorize_html and status >= 400:
                    resp_headers = {
                        k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in message.get("headers", [])
                    }
                    ctype = resp_headers.get("content-type", "").lower()
                    if "application/json" in ctype or "text/plain" in ctype:
                        buffered_start = message
                        return
            elif message["type"] == "http.response.body" and buffered_start is not None:
                buffered_body.extend(message.get("body", b""))
                if message.get("more_body", False):
                    return
                err_code = "invalid_request"
                err_desc = "Invalid OAuth authorization request."
                raw_text = buffered_body.decode("utf-8", errors="replace").strip()
                try:
                    parsed = json.loads(raw_text)
                    if isinstance(parsed, dict):
                        err_code = str(parsed.get("error") or err_code)
                        err_desc = REDACTOR.redact_text(str(parsed.get("error_description") or err_desc))
                except Exception:  # noqa: BLE001
                    if raw_text:
                        err_desc = REDACTOR.redact_text(raw_text)
                _LOGGING_MGR.warning(
                    "oauth",
                    f"Browser /authorize error {buffered_start['status']} ({err_code}): {err_desc}",
                    event_code="oauth_authorize_browser_error",
                )
                req_lang = resolve_oauth_language(Request(scope))
                hint_key = (
                    "err_authorize_hint_client"
                    if "not found" in err_desc.lower() or "client" in err_desc.lower()
                    else "err_authorize_hint_generic"
                )
                html_resp = HTMLResponse(
                    _render_error_html(
                        oauth_t(req_lang, "err_authorize_title"),
                        oauth_t(req_lang, "err_authorize_heading", code=err_code),
                        err_desc,
                        hint=oauth_t(req_lang, hint_key),
                        lang=req_lang,
                    ),
                    status_code=buffered_start["status"],
                    headers=SECURITY_HEADERS,
                )
                await html_resp(scope, receive, send)
                return
            await send(message)

        await self.app(scope, receive, observe_auth_result)

    @staticmethod
    def _pop_query_token(scope) -> str | None:
        """Извлечь token из query string и удалить его оттуда (меняем scope на месте:
        так его не увидит и access-лог uvicorn, который читает тот же словарь)."""
        raw = scope.get("query_string", b"")
        if b"token=" not in raw:
            return None
        pairs = parse_qsl(raw.decode("latin-1"), keep_blank_values=True)
        token = None
        rest = []
        for key, value in pairs:
            if key == "token" and token is None:
                token = value
            else:
                rest.append((key, value))
        if token is None:
            return None
        scope["query_string"] = urlencode(rest).encode("latin-1")
        return token.strip()


class SimpleTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        if _token_ok(token):
            # resource обязателен при validate_token_resource=True: без него SDK отклонит
            # даже верный токен. Наш токен выпускается только для этого сервера.
            return AccessToken(token=token, client_id="mcp-app-user", scopes=[], resource=RESOURCE_URL)
        return None

# ==========================================
# 3. ИНИЦИАЛИЗАЦИЯ СЕРВЕРА
# ==========================================

auth_settings = AuthSettings(
    # Pass raw strings: AuthSettings.url_preserve_empty_path keeps the root
    # issuer EXACTLY equal to BASE_URL. AnyHttpUrl(BASE_URL) adds a slash and
    # breaks strict RFC 8414 issuer comparison in browser clients.
    issuer_url=BASE_URL,
    resource_server_url=RESOURCE_URL,
    required_scopes=[READ_SCOPE] if OAUTH_ENABLED else [],
    client_registration_options=(
        ClientRegistrationOptions(enabled=True, valid_scopes=[READ_SCOPE], default_scopes=[READ_SCOPE])
        if OAUTH_ENABLED else None
    ),
    revocation_options=RevocationOptions(enabled=True) if OAUTH_ENABLED else None,
    validate_token_resource=True,
)
_raw_default_profile = os.environ.get("MCP_DEFAULT_ACCESS_PROFILE", "").strip()
DEFAULT_ACCESS_PROFILE = (
    PROFILE_ALLOWLIST
    if not _raw_default_profile
    else (_raw_default_profile if _raw_default_profile in PROFILES else PROFILE_SAFE)
)

oauth_provider = (
    LocalConsentOAuthProvider(
        BASE_URL, RESOURCE_URL, OWNER_SECRET,
        store_path=os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path(),
        default_profile=DEFAULT_ACCESS_PROFILE,
        transport_secret=SECRET_TOKEN,
        bind_owner=TOKEN_FROM_ENV,
    )
    if OAUTH_ENABLED else None
)
oauth_execution = (
    ExecutionApprovals(oauth_provider.store, default_profile=DEFAULT_ACCESS_PROFILE)
    if oauth_provider is not None else None
)
if oauth_execution is not None:
    DESKTOP_MANAGER.emergency_stop_checker = oauth_execution.emergency_stopped


class _ActiveSessionToolTracker:
    """Tracks live MCP sessions and emits notifications/tools/list_changed when permissions shift."""

    def __init__(self) -> None:
        self._sessions: weakref.WeakKeyDictionary[Any, tuple[Any, frozenset[str]]] = weakref.WeakKeyDictionary()

    def observe(self, session: Any, principal: Any, allowed_names: frozenset[str]) -> None:
        if session is not None:
            self._sessions[session] = (principal, frozenset(allowed_names))

    async def check_and_notify(self) -> None:
        if oauth_provider is None or oauth_execution is None:
            return
        for session, (principal, previous) in list(self._sessions.items()):
            current = allowed_tools(
                oauth_provider.store,
                principal,
                oauth_execution,
                DEFAULT_REGISTRY,
                desktop_policy_store=DESKTOP_POLICY_STORE,
            )
            try:
                gw_names = frozenset(
                    t.name for t in GATEWAY_ROUTER.list_authorized_tools(principal, oauth_execution)
                )
            except Exception:  # noqa: BLE001
                gw_names = frozenset()
            effective = current | gw_names
            if effective != previous:
                self._sessions[session] = (principal, effective)
                try:
                    await session.send_tool_list_changed()
                except Exception:  # noqa: BLE001
                    pass


SESSION_TRACKER = _ActiveSessionToolTracker()


_SCHED_PROFILE_RANK = {PROFILE_SAFE: 0, PROFILE_ALLOWLIST: 1, PROFILE_FULL: 2}
_SCHED_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,251}$")


def _scheduler_validate_int_arg(value: Any, *, default: int, minimum: int, maximum: int) -> int | None:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not (minimum <= value <= maximum):
        return None
    return value


def _scheduler_check_windows_args(spec: ScheduleSpec, profile: str, *, is_owner: bool) -> str | None:
    args = spec.arguments or {}
    cmd = args.get("command")
    shell = args.get("shell", "cmd")
    max_to = 600 if profile == PROFILE_FULL else 15
    timeout = _scheduler_validate_int_arg(args.get("timeout"), default=15, minimum=1, maximum=max_to)
    if not isinstance(cmd, str) or not cmd.strip() or shell not in ("cmd", "powershell") or timeout is None:
        return f"Invalid Windows command arguments in schedule {spec.schedule_id}"
    if profile != PROFILE_FULL and shell != "cmd":
        return f"PowerShell execution requires Full Access in schedule {spec.schedule_id}"
    if is_owner:
        if profile == PROFILE_SAFE:
            return f"Profile 'safe' forbids command execution in {spec.schedule_id}"
        if profile == PROFILE_ALLOWLIST and oauth_execution is not None:
            if not windows_whitelisted(cmd, oauth_execution.policy()["windows"]):
                return f"Owner allowlist forbids Windows command in {spec.schedule_id}"
        return None
    assert oauth_execution is not None
    if not oauth_execution.can_request(spec.client_id, "windows", command=cmd, expected_profile=profile):
        return f"Client {spec.client_id!r} is not authorized for Windows command in {spec.schedule_id}"
    return None


def _scheduler_check_ssh_args(spec: ScheduleSpec, profile: str, *, is_owner: bool) -> str | None:
    args = spec.arguments or {}
    cmd = args.get("command")
    host = args.get("host")
    user = args.get("user", "")
    port = _scheduler_validate_int_arg(args.get("port"), default=22, minimum=1, maximum=65535)
    max_to = 600 if profile == PROFILE_FULL else 12
    timeout = _scheduler_validate_int_arg(args.get("timeout"), default=12, minimum=1, maximum=max_to)
    if (
        not isinstance(cmd, str)
        or not cmd.strip()
        or not isinstance(host, str)
        or not _SCHED_SSH_HOST_RE.fullmatch(host)
        or not isinstance(user, str)
        or port is None
        or timeout is None
    ):
        return f"Invalid SSH arguments in schedule {spec.schedule_id}"
    if is_owner:
        if profile == PROFILE_SAFE:
            return f"Profile 'safe' forbids SSH execution in {spec.schedule_id}"
        if profile == PROFILE_ALLOWLIST and oauth_execution is not None:
            pol = oauth_execution.policy()
            if host not in pol["hosts"] or cmd.strip() not in pol["ssh_commands"]:
                return f"Owner allowlist forbids SSH target/command in {spec.schedule_id}"
        return None
    assert oauth_execution is not None
    if not oauth_execution.can_request(
        spec.client_id, "ssh", command=cmd, host=host, user=user, port=port, expected_profile=profile
    ):
        return f"Client {spec.client_id!r} is not authorized for SSH target/command in {spec.schedule_id}"
    return None


def _scheduler_check_task_start_args(spec: ScheduleSpec, profile: str, *, is_owner: bool) -> str | None:
    if profile == PROFILE_SAFE:
        return f"Background tasks are forbidden in 'safe' profile ({spec.schedule_id})"
    args = spec.arguments or {}
    kind = args.get("kind", "windows")
    cmd = args.get("command")
    shell = args.get("shell", "cmd")
    host = args.get("host", "")
    user = args.get("user", "")
    port = _scheduler_validate_int_arg(args.get("port"), default=22, minimum=1, maximum=65535)
    max_to = 600 if profile == PROFILE_FULL else (12 if kind == "ssh" else 15)
    timeout = _scheduler_validate_int_arg(args.get("timeout"), default=max_to, minimum=1, maximum=max_to)
    if kind not in ("windows", "ssh") or not isinstance(cmd, str) or not cmd.strip() or shell not in ("cmd", "powershell"):
        return f"Invalid task_start arguments in schedule {spec.schedule_id}"
    if timeout is None or port is None:
        return f"Invalid timeout or port in task_start schedule {spec.schedule_id}"
    if profile != PROFILE_FULL and kind == "windows" and shell != "cmd":
        return f"PowerShell background task requires Full Access in {spec.schedule_id}"
    if kind == "ssh" and (not isinstance(host, str) or not _SCHED_SSH_HOST_RE.fullmatch(host) or not isinstance(user, str)):
        return f"Invalid SSH task target in schedule {spec.schedule_id}"
    if is_owner:
        if profile == PROFILE_ALLOWLIST and oauth_execution is not None:
            pol = oauth_execution.policy()
            if kind == "windows" and not windows_whitelisted(cmd, pol["windows"]):
                return f"Owner allowlist forbids Windows task command in {spec.schedule_id}"
            if kind == "ssh" and (host not in pol["hosts"] or cmd.strip() not in pol["ssh_commands"]):
                return f"Owner allowlist forbids SSH task in {spec.schedule_id}"
        return None
    assert oauth_execution is not None
    ok = (
        oauth_execution.can_request(
            spec.client_id, "ssh", command=cmd, host=host, user=user, port=port, expected_profile=profile
        )
        if kind == "ssh"
        else oauth_execution.can_request(spec.client_id, "windows", command=cmd, expected_profile=profile)
    )
    if not ok:
        return f"Client {spec.client_id!r} is not authorized for task_start command in {spec.schedule_id}"
    return None


def _scheduler_check_command_args(spec: ScheduleSpec, profile: str, *, is_owner: bool) -> str | None:
    """Validate command, shell, timeout, and target arguments for scheduled exec/task tools."""
    if spec.tool_name == EXEC_WINDOWS:
        return _scheduler_check_windows_args(spec, profile, is_owner=is_owner)
    if spec.tool_name == EXEC_SSH:
        return _scheduler_check_ssh_args(spec, profile, is_owner=is_owner)
    if spec.tool_name == TASK_START:
        return _scheduler_check_task_start_args(spec, profile, is_owner=is_owner)
    return None


def _scheduler_check_desktop_policy(tool_name: str) -> str | None:
    if tool_name not in DESKTOP_TOOLS:
        return None
    if tool_name in DESKTOP_CONTROL_TOOLS:
        return "Desktop input control tools are forbidden in unattended schedules"
    dt_policy = DESKTOP_POLICY_STORE.load()
    if dt_policy.emergency_stop or not dt_policy.enabled:
        return "Computer Use is disabled by owner policy"
    if tool_name in DESKTOP_VIEW_TOOLS and not dt_policy.allow_screen_capture:
        return "Screen capture is disabled by owner policy"
    return None


def _scheduler_check_owner_gateway(tool_name: str, owner_profile: str) -> str | None:
    catalog = getattr(GATEWAY_ROUTER, "_catalog", None)
    if not isinstance(catalog, dict):
        return None
    entry = catalog.get(tool_name)
    if entry is None:
        return f"Unknown gateway tool: {tool_name}"
    prof = GATEWAY_ROUTER.store.get(entry.server_id)
    if prof is None or not prof.enabled or not prof.approved_by_owner:
        return "Upstream gateway server is disabled or unapproved"
    if _SCHED_PROFILE_RANK.get(owner_profile, 0) < _SCHED_PROFILE_RANK.get(prof.min_profile, 99):
        return f"Owner profile '{owner_profile}' cannot invoke gateway tool {tool_name}"
    if entry.raw_name in prof.denied_tools or (prof.allowed_tools and entry.raw_name not in prof.allowed_tools):
        return f"Gateway tool {tool_name} is disallowed by server policy"
    return None


def _scheduler_permission_check(spec: ScheduleSpec) -> tuple[bool, str]:
    try:
        if oauth_execution is not None and oauth_execution.emergency_stopped():
            return (False, "Emergency stop is active")
        desktop_err = _scheduler_check_desktop_policy(spec.tool_name)
        if desktop_err:
            return (False, desktop_err)
        if spec.client_id == "owner":
            owner_profile = oauth_execution.profile() if oauth_execution is not None else PROFILE_SAFE
            reg_spec = DEFAULT_REGISTRY._specs.get(spec.tool_name)
            if reg_spec is not None:
                if _SCHED_PROFILE_RANK.get(owner_profile, 0) < _SCHED_PROFILE_RANK.get(reg_spec.min_profile, 99):
                    return (False, f"Owner profile '{owner_profile}' cannot run {spec.tool_name}")
            elif GATEWAY_ROUTER.is_gateway_tool(spec.tool_name):
                gw_err = _scheduler_check_owner_gateway(spec.tool_name, owner_profile)
                if gw_err:
                    return (False, gw_err)
            else:
                return (False, f"Unknown scheduled tool: {spec.tool_name}")
            cmd_err = _scheduler_check_command_args(spec, owner_profile, is_owner=True)
            return (False, cmd_err) if cmd_err else (True, "")

        if not OAUTH_ENABLED or oauth_provider is None or oauth_execution is None:
            return (False, "OAuth store unavailable")
        if not oauth_execution.client_approved(spec.client_id):
            return (False, f"Client {spec.client_id!r} is not approved")
        tok = AccessToken(
            token=secrets.token_urlsafe(12),
            client_id=spec.client_id,
            scopes=[READ_SCOPE],
            resource=RESOURCE_URL,
        )
        allowed = set(
            DEFAULT_REGISTRY.allowed_tools(
                oauth_provider.store, tok, oauth_execution, desktop_policy_store=DESKTOP_POLICY_STORE
            )
        )
        try:
            allowed.update(
                t.name for t in GATEWAY_ROUTER.list_authorized_tools(tok, oauth_execution)
            )
        except Exception:  # noqa: BLE001
            pass
        if spec.tool_name not in allowed:
            return (False, f"Client {spec.client_id!r} is not authorized for {spec.tool_name}")
        profile = oauth_execution.profile_for(spec.client_id)
        cmd_err = _scheduler_check_command_args(spec, profile, is_owner=False)
        return (False, cmd_err) if cmd_err else (True, "")
    except Exception as exc:  # noqa: BLE001
        # Fail closed on any storage/policy error during scheduled authorization.
        return (False, f"Authorization check failed: {type(exc).__name__}")


AUTOMATION_SCHEDULER = AutomationScheduler(
    AUTOMATION_DIR,
    permission_checker=_scheduler_permission_check,
    redactor=REDACTOR,
)

# The SDK's localhost-only defaults reject public Cloudflare Host headers
# with HTTP 421. Keep DNS-rebinding defense enabled and allow only the current
# tunnel hostname (never a wildcard for trycloudflare.com).
_allowed_hosts, _allowed_origins = transport_allowlists(
    PUBLIC_URL, PORT, os.environ.get("MCP_ALLOWED_ORIGINS", "")
)
TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=_allowed_hosts,
    allowed_origins=_allowed_origins,
)

# The SDK derives ProviderTokenVerifier automatically from auth_server_provider.
# Do NOT also pass token_verifier: the two arguments are mutually exclusive.
mcp = (
    MCPServer(
        SERVER_NAME,
        auth=auth_settings,
        auth_server_provider=oauth_provider,
        middleware=[
            make_tool_middleware(
                oauth_provider.store,
                oauth_execution,
                gateway_router=GATEWAY_ROUTER,
                metrics_registry=METRICS_REGISTRY,
                desktop_policy_store=DESKTOP_POLICY_STORE,
                session_tracker=SESSION_TRACKER,
            )
        ],
    )
    if oauth_provider is not None
    else MCPServer(SERVER_NAME, auth=auth_settings, token_verifier=SimpleTokenVerifier())
)
_orig_get_capabilities = mcp._lowlevel_server.get_capabilities


def _get_capabilities_with_tools_list_changed(
    notification_options: NotificationOptions | None = None, *args: Any, **kwargs: Any
):
    opts = notification_options or NotificationOptions()
    return _orig_get_capabilities(
        NotificationOptions(
            prompts_changed=opts.prompts_changed,
            resources_changed=opts.resources_changed,
            tools_changed=True,
        ),
        *args,
        **kwargs,
    )


mcp._lowlevel_server.get_capabilities = _get_capabilities_with_tools_list_changed  # type: ignore[method-assign]
if oauth_provider is not None:
    @mcp.custom_route("/oauth/consent", methods=["GET", "POST"])
    async def oauth_consent(request):
        return await oauth_provider.consent(request)

# ==========================================
# 4. MCP-РЕСУРСЫ (Контекст)
# ==========================================

def _advanced_resource(uri: str):
    def decorator(func):
        return mcp.resource(uri)(func) if ADVANCED_TOOLS else func
    return decorator


def _conditional_tool(should_register: bool):
    def decorator(func):
        return mcp.tool()(func) if should_register else func
    return decorator


def _current_client_effective_state() -> tuple[str, str]:
    """Return ``(profile, computer_use)`` for the current caller using fail-closed rules."""
    if not OAUTH_ENABLED or oauth_provider is None or oauth_execution is None:
        return PROFILE_SAFE, "disabled"
    if oauth_execution.emergency_stopped():
        return PROFILE_SAFE, "disabled"
    principal = get_access_token()
    if principal is None:
        return PROFILE_SAFE, "disabled"
    client_id = getattr(principal, "client_id", None)
    scopes = getattr(principal, "scopes", None) or []
    if not isinstance(client_id, str) or "mcp:read" not in scopes:
        return PROFILE_SAFE, "disabled"
    if not oauth_execution.client_approved(client_id):
        return PROFILE_SAFE, "disabled"
    profile = oauth_execution.profile_for(client_id)
    if profile == PROFILE_SAFE:
        return PROFILE_SAFE, "disabled"
    cu_level = effective_desktop_access(
        DESKTOP_POLICY_STORE.load(),
        client_id,
        profile,
        emergency_stopped=False,
    )
    return profile, cu_level


@mcp.tool()
def server_info() -> str:
    """Safe read-only connectivity check; returns effective client profile without secrets or paths."""
    server_mode = "advanced" if ADVANCED_TOOLS else "standard"
    profile, computer_use = _current_client_effective_state()
    return (
        f"MCP app ready; transport=streamable-http; profile={profile}; "
        f"computer_use={computer_use}; server_mode={server_mode}"
    )


@_advanced_resource("system://environment")
def get_environment_info() -> str:
    ssh_config_hosts = []
    ssh_cfg_path = Path.home() / ".ssh" / "config"
    if ssh_cfg_path.exists():
        for line in ssh_cfg_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().lower().startswith("host "):
                ssh_config_hosts.append(line.strip().split(maxsplit=1)[1])

    return (
        f"OS: {os.name} ({os.sys.platform})\n"
        f"Workspace: {WORKSPACE_DIR}\n"
        f"Allowed SSH Hosts: {list(ALLOWED_HOSTS) if ALLOWED_HOSTS else 'All'}\n"
        f"SSH Config Aliases: {ssh_config_hosts}"
    )

# ==========================================
# 5. ИНСТРУМЕНТЫ (Tools)
# ==========================================

def _restricted_windows_argv(command: str) -> list[str]:
    """Translate safe Windows built-ins without executing a command shell."""
    from pathlib import Path

    # Allowed command lines have already passed the current SQLite allowlist.
    program = command.strip().split(" ", 1)[0].lower()
    builtin = {"dir", "ls", "pwd", "echo"}
    if program in builtin:
        return []
    import shlex
    program_name = shlex.split(command, posix=os.name != "nt")[0].strip('"')
    argv = parse_allowed_command(command, frozenset({program_name.casefold()}))
    # Built-in OS utilities are resolved from System32 explicitly to avoid
    # running a malicious executable from the app's working directory.
    stem = Path(argv[0]).stem.lower()
    if os.name == "nt" and stem in {"whoami", "ipconfig", "systeminfo", "hostname"}:
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        executable = system_root / "System32" / (stem + ".exe")
        if not executable.is_file():
            raise ValueError("Windows system executable is missing")
        argv[0] = str(executable)
    return argv


def _prepare_windows_argv(
    command: str,
    *,
    full: bool,
    shell: str = "cmd",
    timeout: int = 15,
) -> tuple[list[str] | None, str | None, Path | None]:
    """Validate and build argv for Windows/allowlist command execution without duplicating logic."""
    if shell not in ("cmd", "powershell") or not (1 <= timeout <= 600):
        return None, "❌ Invalid shell or timeout (1–600 seconds).", None
    if not full and (shell != "cmd" or timeout > 15):
        return None, "❌ Shell and extended timeout require Full Access.", None
    script_path: Path | None = None
    program = command.strip().split(" ", 1)[0].lower()
    if not full:
        if program == "pwd" and command.strip().lower() == "pwd":
            return None, str(WORKSPACE_DIR), None
        if program in ("ls", "dir") and command.strip().lower() == program:
            return None, truncate_output("\n".join(sorted(p.name for p in WORKSPACE_DIR.iterdir()))), None
        if program == "echo":
            val = command.strip()[5:] if command.strip().lower().startswith("echo ") else ""
            return None, truncate_output(val), None
        try:
            argv = _restricted_windows_argv(command)
        except (OSError, ValueError, IndexError) as exc:
            return None, f"❌ Недопустимая команда белого списка: {type(exc).__name__}", None
        if not argv:
            return None, "❌ Недопустимые аргументы встроенной команды.", None
        return argv, None, None

    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        if shell == "powershell":
            executable = str(system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
            if len(command) <= 8000:
                argv = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
            else:
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w", encoding="utf-8-sig", suffix=".ps1", delete=False,
                    ) as script:
                        script_path = Path(script.name)
                        script.write(command)
                except OSError:
                    if script_path:
                        script_path.unlink(missing_ok=True)
                    return None, "❌ Could not prepare PowerShell script.", None
                argv = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script_path)]
        else:
            if len(command) > 8000:
                return None, "❌ CMD command line too long; use PowerShell.", None
            executable = str(system_root / "System32" / "cmd.exe")
            argv = [executable, "/d", "/s", "/c", command]
    else:
        if shell != "cmd":
            return None, "❌ Windows PowerShell is only available on Windows.", None
        import shlex
        try:
            argv = shlex.split(command)
        except ValueError:
            return None, "❌ Invalid command syntax.", None
    if not argv:
        return None, "❌ Пустая команда.", None
    return argv, None, script_path


async def _oauth_windows_run(
    command: str,
    *,
    full: bool,
    shell: str = "cmd",
    timeout: int = 15,
    client_id: str = "system",
    pre_dispatch_check=None,
    output_offset: int = 0,
    output_limit: int = MAX_OUTPUT_LEN,
    run_id: str | None = None,
) -> str:
    """Bounded execution via ProcessRunner, with shell semantics only in explicit full mode."""
    argv, immediate, script_path = _prepare_windows_argv(
        command, full=full, shell=shell, timeout=timeout,
    )
    if immediate is not None or argv is None:
        if immediate is not None and not immediate.startswith("❌") and pre_dispatch_check is not None:
            pre_dispatch_check()
        if run_id and immediate is not None and not immediate.startswith("❌"):
            writer = PROCESS_RUNNER.spool.create_spool(run_id)
            writer.write("stdout", immediate.encode("utf-8", errors="replace"))
        return immediate or "❌ Пустая команда."

    try:
        result = await PROCESS_RUNNER.run_command(
            argv,
            cwd=WORKSPACE_DIR,
            timeout=timeout,
            client_id=client_id,
            kind="windows",
            spawn_fn=asyncio.create_subprocess_exec,
            output_offset=output_offset,
            output_limit=output_limit,
            pre_dispatch_check=pre_dispatch_check,
            run_id=run_id,
        )
        if result.timed_out:
            return f"❌ Команда превысила лимит {timeout} секунд."
        return (
            f"Exit code: {result.exit_code}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
    except PermissionError:
        return "❌ Эта Windows-команда недоступна в выбранном режиме."
    except (OSError, ValueError, RuntimeError) as exc:
        return f"❌ Не удалось выполнить Windows-команду: {type(exc).__name__}"
    finally:
        if script_path:
            try:
                script_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary PowerShell script")


@_conditional_tool(OAUTH_ENABLED)
async def oauth_windows_command(
    command: str, shell: Literal["cmd", "powershell"] = "cmd", timeout: int = 15,
) -> str:
    """Run a Windows command immediately in allowlist/full access mode.

    In safe mode this tool is hidden and blocked. Allowlist matches exact
    owner entries with no command shell; full mode allows arbitrary commands.
    Full mode supports shell='powershell' for scripts and timeout=1–600 seconds.
    Allowlist mode retains the original direct execution and 15-second limit.
    """
    client_id = require_execution_permission(
        EXEC_WINDOWS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile = oauth_execution.profile_for(client_id)
    if (not oauth_execution.can_request(client_id, "windows", command=command, expected_profile=profile)
            or not 1 <= timeout <= 600
            or (profile != "full" and (shell != "cmd" or timeout > 15))):
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile,
            event="denied", command=command,
        )
        return "❌ Эта Windows-команда недоступна в выбранном режиме."

    def recheck_before_spawn() -> None:
        live_client = require_execution_permission(
            EXEC_WINDOWS, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        if not oauth_execution.can_request(
            live_client, "windows", command=command, expected_profile=profile
        ):
            raise PermissionError("Execution access revoked before dispatch")

    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile,
        event="started", command=command, action_id=action_id,
    )
    try:
        async with PROCESS_RUNNER.request_slot():
            output = await _oauth_windows_run(
                command,
                full=profile == "full",
                shell=shell,
                timeout=timeout,
                client_id=client_id,
                pre_dispatch_check=recheck_before_spawn,
            )
    except PermissionError:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile,
            event="denied", command=command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return "❌ Эта Windows-команда недоступна в выбранном режиме."
    except BaseException:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile,
            event="failed", command=command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        raise
    outcome, exit_code = classify_command_output(output)
    if profile == "allowlist" and command.strip().split(" ", 1)[0].lower() in (
        "pwd", "ls", "dir", "echo",
    ) and not output.startswith("❌"):
        outcome = "completed"
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile,
        event=outcome, command=command, action_id=action_id,
        exit_code=exit_code,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return output


@_conditional_tool(OAUTH_ENABLED)
async def oauth_managed_server(
    action: Literal["list", "start", "stop"] = "list", name: str = "",
) -> dict:
    """List, start or stop locally configured development servers (Full only).

    Only the owner can create named profiles in managed_servers.json.
    A client may stop only a direct process it started via this tool.
    No arbitrary executable paths or arguments are accepted here.
    """
    client_id = require_execution_permission(
        EXEC_MANAGED, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    if oauth_execution.profile_for(client_id) != "full":
        raise PermissionError("Managed servers require Full Access")
    if action == "list":
        try:
            return {"servers": await asyncio.to_thread(MANAGED_SERVERS.list, client_id)}
        except (OSError, ValueError):
            return {"error": "Invalid local managed server configuration"}
    audit_command = f"managed:{action}:{name}"
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(client_id=client_id, kind="windows", profile="full",
                      event="started", command=audit_command, action_id=action_id)
    try:
        async with PROCESS_RUNNER.request_slot():
            operation = MANAGED_SERVERS.start if action == "start" else MANAGED_SERVERS.stop
            if action not in ("start", "stop"):
                raise ValueError("Invalid operation")
            # Recheck current privileges just before dispatch.
            require_execution_permission(
                EXEC_MANAGED, oauth_provider.store if oauth_provider else None, oauth_execution
            )
            if oauth_execution.profile_for(client_id) != "full":
                raise PermissionError("Access changed")
            result = await asyncio.to_thread(operation, client_id, name)
            EXEC_AUDIT.record(client_id=client_id, kind="windows", profile="full",
                              event="completed", command=audit_command, action_id=action_id,
                              duration_ms=int((time.monotonic() - started) * 1000))
            return result
    except (OSError, ValueError, PermissionError, RuntimeError, subprocess.TimeoutExpired) as exc:
        EXEC_AUDIT.record(client_id=client_id, kind="windows", profile="full",
                          event="failed", command=audit_command, action_id=action_id,
                          duration_ms=int((time.monotonic() - started) * 1000))
        detail = REDACTOR.redact_text(str(exc)) or type(exc).__name__
        return {"error": f"Managed server operation failed: {detail}"}


def _authorize_managed_server(
    client_id: str,
    tool_name: str,
    server_name: str = "",
    *,
    mode: Literal["read", "control"] = "control",
    workspace_id: str = "",
) -> str:
    """Verify OAuth client authorization, active profile, and workspace-server intersection."""
    verified_client = require_execution_permission(
        tool_name, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(verified_client)
    if server_name:
        srv_profile = MANAGED_SERVERS.store.get_profile(server_name)
        if srv_profile is not None:
            SERVER_MANAGER._authorize_profile(
                srv_profile, client_id=verified_client, client_profile=profile_mode
            )
        WORKSPACE_SERVER_COORDINATOR.authorize_server_operation(
            server_name,
            client_id=verified_client,
            client_profile=profile_mode,
            mode=mode,
            workspace_id=workspace_id,
        )
    return profile_mode


def _live_client_authorizer(client_id: str | None, tool_name: str) -> str:
    """Re-verify live OAuth client approval, Emergency Stop, and active profile before spawn."""
    if client_id in (None, "", "owner"):
        return "full"
    if not OAUTH_ENABLED or oauth_provider is None or oauth_execution is None:
        raise PermissionError("OAuth execution is unavailable")
    if oauth_execution.emergency_stopped():
        raise PermissionError("Emergency stop is active")
    if not oauth_execution.client_approved(client_id):
        raise PermissionError("OAuth client is not approved")
    profile_mode = oauth_execution.profile_for(client_id)
    tok = AccessToken(
        token="live-auth-check",
        client_id=client_id,
        scopes=[READ_SCOPE],
        resource=RESOURCE_URL,
    )
    allowed = allowed_tools(
        oauth_provider.store,
        tok,
        oauth_execution,
        DEFAULT_REGISTRY,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    if tool_name not in allowed:
        raise PermissionError(f"Client {client_id!r} is not authorized for {tool_name}")
    return profile_mode


def _server_auth_rechecker(client_id: str, srv_profile, workspace_id: str = "") -> None:
    if oauth_provider is None or oauth_execution is None:
        raise PermissionError("OAuth server management is unavailable")
    if oauth_execution.emergency_stopped():
        raise PermissionError("Emergency stop is active")
    if not oauth_execution.client_approved(client_id):
        raise PermissionError("OAuth client is not approved")
    profile_mode = oauth_execution.profile_for(client_id)
    SERVER_MANAGER._authorize_profile(
        srv_profile, client_id=client_id, client_profile=profile_mode
    )
    WORKSPACE_SERVER_COORDINATOR.authorize_server_operation(
        srv_profile.name,
        client_id=client_id,
        client_profile=profile_mode,
        mode="control",
        workspace_id=workspace_id,
    )


SERVER_MANAGER.auth_rechecker = _server_auth_rechecker
SERVER_MANAGER.live_client_authorizer = _live_client_authorizer
WORKSPACE_MANAGER.live_client_authorizer = _live_client_authorizer


@_conditional_tool(OAUTH_ENABLED)
async def server_list(workspace_id: str = "") -> dict:
    """List owner-configured managed servers visible to the caller's access profile."""
    client_id = require_execution_permission(
        SERVER_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        items = await asyncio.to_thread(
            SERVER_MANAGER.list_servers,
            client_id=client_id,
            client_profile=profile_mode,
            workspace_id=workspace_id,
        )
        return {"servers": items}
    except PermissionError as exc:
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Server list failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


async def _resolve_server_start_task_id(
    client_id: str,
    name: str,
    linked_task_id: str,
    run_pre_start_task: bool,
) -> str | None:
    if linked_task_id:
        require_execution_permission(
            TASK_STATUS, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        trec = TASK_STORE.get_task(linked_task_id)
        if trec is None or trec.owner_client_id != client_id:
            raise PermissionError("Linked task not found for this client")
        return trec.task_id
    if not run_pre_start_task:
        return None
    require_execution_permission(
        TASK_START, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    srv_profile = MANAGED_SERVERS.store.get_profile(name)
    if srv_profile is None or not srv_profile.pre_start_task_command:
        return None
    pre_spec = TaskSpec(kind="windows", command=srv_profile.pre_start_task_command)
    pre_spec.validate()
    task_prof = _authorize_task_spec(client_id, pre_spec)
    trec, _ = await TASK_MANAGER.submit(
        owner_client_id=client_id,
        profile=task_prof,
        spec=pre_spec,
        title=f"pre-start:{name}",
    )
    return trec.task_id


@_conditional_tool(OAUTH_ENABLED)
async def server_start(
    name: str,
    start_dependencies: bool = True,
    wait_readiness: bool = True,
    linked_task_id: str = "",
    run_pre_start_task: bool = False,
    workspace_id: str = "",
) -> dict:
    """Start an owner-configured managed server, resolving dependencies and readiness checks."""
    client_id = require_execution_permission(
        SERVER_START, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    audit_command = f"server:start:{name}"
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile_mode,
        event="started", command=audit_command, action_id=action_id,
    )
    try:
        async with PROCESS_RUNNER.request_slot():
            profile_mode = _authorize_managed_server(
                client_id, SERVER_START, name, mode="control", workspace_id=workspace_id
            )
            effective_task_id = await _resolve_server_start_task_id(
                client_id, name, linked_task_id, run_pre_start_task
            )

            result = await asyncio.to_thread(
                SERVER_MANAGER.start_server,
                name,
                client_id=client_id,
                client_profile=profile_mode,
                start_dependencies=start_dependencies,
                wait_readiness=wait_readiness,
                linked_task_id=effective_task_id,
                workspace_id=workspace_id,
            )
            EXEC_AUDIT.record(
                client_id=client_id, kind="windows", profile=profile_mode,
                event="completed", command=audit_command, action_id=action_id,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return result
    except PermissionError as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="denied", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="failed", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server start failed: {REDACTOR.redact_text(str(exc))}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_stop(name: str, workspace_id: str = "") -> dict:
    """Stop a controlled managed server owned by this client; independent servers stay detached."""
    client_id = require_execution_permission(
        SERVER_STOP, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    audit_command = f"server:stop:{name}"
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile_mode,
        event="started", command=audit_command, action_id=action_id,
    )
    try:
        async with PROCESS_RUNNER.request_slot():
            profile_mode = _authorize_managed_server(
                client_id, SERVER_STOP, name, mode="control", workspace_id=workspace_id
            )
            result = await asyncio.to_thread(
                SERVER_MANAGER.stop_server,
                name,
                client_id=client_id,
                client_profile=profile_mode,
                workspace_id=workspace_id,
            )
            EXEC_AUDIT.record(
                client_id=client_id, kind="windows", profile=profile_mode,
                event="completed", command=audit_command, action_id=action_id,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return result
    except PermissionError as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="denied", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="failed", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server stop failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_restart(name: str, wait_readiness: bool = True, workspace_id: str = "") -> dict:
    """Restart an owned controlled managed server and wait for readiness if configured."""
    client_id = require_execution_permission(
        SERVER_RESTART, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    audit_command = f"server:restart:{name}"
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile_mode,
        event="started", command=audit_command, action_id=action_id,
    )
    try:
        async with PROCESS_RUNNER.request_slot():
            profile_mode = _authorize_managed_server(
                client_id, SERVER_RESTART, name, mode="control", workspace_id=workspace_id
            )
            result = await asyncio.to_thread(
                SERVER_MANAGER.restart_server,
                name,
                client_id=client_id,
                client_profile=profile_mode,
                wait_readiness=wait_readiness,
                workspace_id=workspace_id,
            )
            EXEC_AUDIT.record(
                client_id=client_id, kind="windows", profile=profile_mode,
                event="completed", command=audit_command, action_id=action_id,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return result
    except PermissionError as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="denied", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="failed", command=audit_command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return {"error": f"Server restart failed: {REDACTOR.redact_text(str(exc))}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_status(name: str, workspace_id: str = "") -> dict:
    """Inspect runtime status, uptime, restarts, and linked task for an authorized server."""
    client_id = require_execution_permission(
        SERVER_STATUS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            SERVER_MANAGER.status_server,
            name,
            client_id=client_id,
            client_profile=profile_mode,
            workspace_id=workspace_id,
        )
    except PermissionError as exc:
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Server status failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_logs(
    name: str,
    stream: Literal["stdout", "stderr"] = "stdout",
    offset: int = 0,
    limit: int = 8000,
    workspace_id: str = "",
) -> dict:
    """Read bounded, secret-redacted stdout or stderr logs for an authorized managed server."""
    client_id = require_execution_permission(
        SERVER_LOGS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            SERVER_MANAGER.logs_server,
            name,
            client_id=client_id,
            client_profile=profile_mode,
            stream=stream,
            offset=offset,
            limit=limit,
            workspace_id=workspace_id,
        )
    except PermissionError as exc:
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Server logs failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_metrics(name: str, workspace_id: str = "") -> dict:
    """Collect identity-verified CPU/RAM/thread metrics for an authorized managed server."""
    client_id = require_execution_permission(
        SERVER_METRICS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            SERVER_MANAGER.metrics_server,
            name,
            client_id=client_id,
            client_profile=profile_mode,
            workspace_id=workspace_id,
        )
    except PermissionError as exc:
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Server metrics failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


@_conditional_tool(OAUTH_ENABLED)
async def server_health(name: str, run_probe: bool = True, workspace_id: str = "") -> dict:
    """Run or inspect readiness health probe results for an authorized managed server."""
    client_id = require_execution_permission(
        SERVER_HEALTH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            SERVER_MANAGER.health_server,
            name,
            client_id=client_id,
            client_profile=profile_mode,
            run_probe=run_probe,
            workspace_id=workspace_id,
        )
    except PermissionError as exc:
        return {"error": f"Server access denied: {exc}"}
    except (OSError, ValueError) as exc:
        return {"error": f"Server health failed: {REDACTOR.redact_text(str(exc)) or type(exc).__name__}"}


def _ws_call_error(exc: Exception) -> dict:
    if isinstance(exc, FileVersionConflictError):
        return {
            "error": str(exc),
            "conflict": True,
            "current_sha256": exc.current_sha256,
            "expected_sha256": exc.expected_sha256,
        }
    if isinstance(exc, (PermissionError, PathSecurityError)):
        return {"error": f"Workspace access denied: {exc}"}
    return {"error": REDACTOR.redact_text(str(exc)) or type(exc).__name__}


@_conditional_tool(OAUTH_ENABLED)
async def workspace_list() -> dict:
    """List owner-registered workspaces visible to the caller's OAuth client profile."""
    client_id = require_execution_permission(
        WS_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        items = await asyncio.to_thread(
            WORKSPACE_MANAGER.list_workspaces, client_id=client_id, client_profile=profile_mode
        )
        return {"workspaces": items}
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_info(workspace_id: str) -> dict:
    """Inspect metadata, detected language/Git/venv/Node, commands, and caller permissions."""
    client_id = require_execution_permission(
        WS_INFO, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.workspace_info,
            workspace_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_tree(
    workspace_id: str,
    relative_path: str = "",
    max_depth: int = 3,
    include_ignored: bool = False,
) -> dict:
    """List bounded workspace directory tree respecting .gitignore, exclusions, and sensitive paths."""
    client_id = require_execution_permission(
        WS_TREE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.workspace_tree,
            workspace_id,
            relative_path=relative_path,
            max_depth=max_depth,
            include_ignored=include_ignored,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_read_file(
    workspace_id: str,
    relative_path: str,
    offset_line: int = 1,
    max_lines: int = 400,
) -> dict:
    """Read bounded, secret-redacted file lines with verified OS handle and SHA-256."""
    client_id = require_execution_permission(
        WS_READ, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.read_file,
            workspace_id,
            relative_path,
            offset_line=offset_line,
            max_lines=max_lines,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_write_file(
    workspace_id: str,
    relative_path: str,
    content: str,
    expected_sha256: str = "",
    create_only: bool = False,
) -> dict:
    """Atomically write a workspace file with version SHA-256 precondition and local snapshot."""
    client_id = require_execution_permission(
        WS_WRITE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.write_file,
            workspace_id,
            relative_path,
            content,
            expected_sha256=expected_sha256,
            create_only=create_only,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"workspace:write:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, FileVersionConflictError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_search(
    workspace_id: str,
    query: str,
    relative_path: str = "",
    regex: bool = False,
    case_sensitive: bool = False,
    max_matches: int = 100,
) -> dict:
    """Search non-ignored workspace files with bounded output and secret redaction."""
    client_id = require_execution_permission(
        WS_SEARCH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.search_files,
            workspace_id,
            query,
            relative_path=relative_path,
            regex=regex,
            case_sensitive=case_sensitive,
            max_matches=max_matches,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_apply_patch(
    workspace_id: str,
    relative_path: str,
    expected_sha256: str,
    edits: list[dict] | None = None,
    unified_diff: str = "",
) -> dict:
    """Apply exact edits or unified diff atomically under SHA-256 version precondition."""
    client_id = require_execution_permission(
        WS_PATCH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.apply_patch,
            workspace_id,
            relative_path,
            expected_sha256=expected_sha256,
            edits=edits,
            unified_diff=unified_diff,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"workspace:patch:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, FileVersionConflictError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_move_file(
    workspace_id: str,
    src_path: str,
    dst_path: str,
    expected_sha256: str = "",
) -> dict:
    """Move or rename a guarded file inside a workspace (requires write + delete)."""
    client_id = require_execution_permission(
        WS_MOVE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.move_file,
            workspace_id,
            src_path,
            dst_path,
            expected_sha256=expected_sha256,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"workspace:move:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, FileVersionConflictError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_delete_file(
    workspace_id: str,
    relative_path: str,
    expected_sha256: str,
) -> dict:
    """Delete a workspace file under SHA-256 precondition and save rollback snapshot."""
    client_id = require_execution_permission(
        WS_DELETE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.delete_file,
            workspace_id,
            relative_path,
            expected_sha256=expected_sha256,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"workspace:delete:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, FileVersionConflictError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_diff(
    workspace_id: str,
    relative_path: str = "",
    snapshot_id: str = "",
    staged: bool = False,
) -> dict:
    """Show Git diff or diff against a local edit history snapshot."""
    client_id = require_execution_permission(
        WS_DIFF, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.workspace_diff,
            workspace_id,
            relative_path=relative_path,
            snapshot_id=snapshot_id,
            staged=staged,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_history(
    workspace_id: str,
    relative_path: str = "",
    limit: int = 20,
    rollback_snapshot_id: str = "",
) -> dict:
    """List workspace edit snapshots or roll back a file to a previous snapshot."""
    client_id = require_execution_permission(
        WS_HISTORY, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.workspace_history,
            workspace_id,
            relative_path=relative_path,
            limit=limit,
            rollback_snapshot_id=rollback_snapshot_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, FileVersionConflictError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def workspace_run_task(
    workspace_id: str,
    command_name: str,
    timeout: int = 120,
) -> dict:
    """Run an owner-defined named workspace command in the workspace venv/toolchain."""
    client_id = require_execution_permission(
        WS_RUN_TASK, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        async with PROCESS_RUNNER.request_slot():
            res = await WORKSPACE_MANAGER.run_workspace_task(
                workspace_id,
                command_name,
                timeout=timeout,
                client_id=client_id,
                client_profile=profile_mode,
            )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"workspace:run:{workspace_id}:{command_name}",
            exit_code=res.get("exit_code"),
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_status(workspace_id: str) -> dict:
    """Inspect Git branch and working tree status with untrusted hooks suppressed."""
    client_id = require_execution_permission(
        GIT_STATUS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.git_status, workspace_id, client_id=client_id, client_profile=profile_mode
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_diff(workspace_id: str, staged: bool = False, relative_path: str = "") -> dict:
    """Show bounded, redacted Git diff inside an authorized workspace."""
    client_id = require_execution_permission(
        GIT_DIFF, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.git_diff,
            workspace_id,
            staged=staged,
            relative_path=relative_path,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_log(workspace_id: str, limit: int = 20) -> dict:
    """Show recent Git commits inside an authorized workspace."""
    client_id = require_execution_permission(
        GIT_LOG, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.git_log, workspace_id, limit=limit, client_id=client_id, client_profile=profile_mode
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_branches(workspace_id: str) -> dict:
    """List local Git branches inside an authorized workspace."""
    client_id = require_execution_permission(
        GIT_BRANCHES, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            WORKSPACE_MANAGER.git_branches, workspace_id, client_id=client_id, client_profile=profile_mode
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_checkout(workspace_id: str, branch: str, create: bool = False) -> dict:
    """Switch or create a local Git branch inside an authorized workspace."""
    client_id = require_execution_permission(
        GIT_CHECKOUT, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.git_checkout,
            workspace_id,
            branch,
            create=create,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"git:checkout:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def git_commit(workspace_id: str, message: str, paths: list[str] | None = None) -> dict:
    """Stage explicit workspace files and create a Git commit with untrusted hooks suppressed."""
    client_id = require_execution_permission(
        GIT_COMMIT, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            WORKSPACE_MANAGER.git_commit,
            workspace_id,
            message,
            paths=paths or [],
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"git:commit:{workspace_id}",
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ws_call_error(exc)


def _desktop_call_error(exc: Exception) -> dict:
    if isinstance(exc, PermissionError):
        return {"error": f"Computer Use denied: {exc}"}
    return {"error": REDACTOR.redact_text(str(exc)) or type(exc).__name__}


@_conditional_tool(OAUTH_ENABLED)
async def desktop_screenshot(
    monitor_index: int | None = None,
    hwnd: int | None = None,
    max_width: int | None = None,
) -> CallToolResult:
    """Capture a bounded in-memory PNG screenshot when screen access is opted in by owner."""
    client_id = require_execution_permission(
        DT_SCREENSHOT, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        shot = await asyncio.to_thread(
            DESKTOP_MANAGER.screenshot,
            client_id=client_id,
            client_profile=profile_mode,
            monitor_index=monitor_index,
            hwnd=hwnd,
            max_width=max_width,
        )
        b64 = base64.b64encode(shot.png_bytes).decode("ascii")
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command="desktop:screenshot",
        )
        return CallToolResult(
            content=[
                TextContent(type="text", text=json.dumps(shot.metadata())),
                ImageContent(type="image", data=b64, mimeType="image/png"),
            ],
            isError=False,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(_desktop_call_error(exc)))],
            isError=True,
        )


@_conditional_tool(OAUTH_ENABLED)
async def desktop_list_windows(include_minimized: bool = False) -> dict:
    """List visible top-level windows (elevated/protected titles are masked)."""
    client_id = require_execution_permission(
        DT_LIST_WINDOWS, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.list_windows,
            client_id=client_id,
            client_profile=profile_mode,
            include_minimized=include_minimized,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_list_monitors() -> dict:
    """List displays, virtual desktop bounds, and per-monitor DPI scale percentages."""
    client_id = require_execution_permission(
        DT_LIST_MONITORS, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.list_monitors, client_id=client_id, client_profile=profile_mode
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_open_app(
    executable: str, args: list[str] | None = None, cwd: str = ""
) -> dict:
    """Launch an approved interactive Windows executable without shell interpolation."""
    client_id = require_execution_permission(
        DT_OPEN_APP, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            DESKTOP_MANAGER.open_app,
            executable,
            args=tuple(args or ()),
            cwd=cwd,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile_mode,
            event="completed", command=f"desktop:open_app:{Path(executable).name}",
        )
        return res
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_close_window(hwnd: int) -> dict:
    """Request window closure via WM_CLOSE (never touches elevated or credential windows)."""
    client_id = require_execution_permission(
        DT_CLOSE_WINDOW, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.close_window, hwnd, client_id=client_id, client_profile=profile_mode
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_focus_window(
    hwnd: int,
    x: int | None = None,
    y: int | None = None,
    width: int | None = None,
    height: int | None = None,
) -> dict:
    """Focus/restore an authorized window and optionally move/resize it."""
    client_id = require_execution_permission(
        DT_FOCUS_WINDOW, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.focus_window,
            hwnd,
            x=x,
            y=y,
            width=width,
            height=height,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_get_ui_tree(
    hwnd: int | None = None, max_depth: int = 4, max_nodes: int = 200
) -> dict:
    """Inspect bounded Windows UI Automation tree with password controls redacted."""
    client_id = require_execution_permission(
        DT_GET_UI_TREE, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.get_ui_tree,
            hwnd=hwnd,
            max_depth=max_depth,
            max_nodes=max_nodes,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_click(
    hwnd: int | None = None,
    name: str = "",
    automation_id: str = "",
    control_type: str = "",
    x: int | None = None,
    y: int | None = None,
    button: Literal["left", "right", "middle"] = "left",
    double: bool = False,
) -> dict:
    """Click a UI element (preferring UIA InvokePattern over raw coordinates)."""
    client_id = require_execution_permission(
        DT_CLICK, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.click,
            hwnd=hwnd,
            name=name,
            automation_id=automation_id,
            control_type=control_type,
            x=x,
            y=y,
            button=button,
            double=double,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, LookupError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_type(
    text: str,
    hwnd: int | None = None,
    name: str = "",
    automation_id: str = "",
) -> dict:
    """Type Unicode text into a UIA input or focused window (blocks password/secret inputs unless opted in)."""
    client_id = require_execution_permission(
        DT_TYPE, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.type_text,
            text,
            hwnd=hwnd,
            name=name,
            automation_id=automation_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, LookupError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_keypress(keys: str, hwnd: int | None = None) -> dict:
    """Send a named key or key combo (e.g. 'Enter', 'Ctrl+S'; blocks SAS/Win+L)."""
    client_id = require_execution_permission(
        DT_KEYPRESS, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.keypress,
            keys,
            hwnd=hwnd,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_scroll(
    delta: int,
    x: int | None = None,
    y: int | None = None,
    horizontal: bool = False,
    hwnd: int | None = None,
) -> dict:
    """Scroll vertically or horizontally via SendInput mouse wheel."""
    client_id = require_execution_permission(
        DT_SCROLL, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.scroll,
            delta,
            x=x,
            y=y,
            horizontal=horizontal,
            hwnd=hwnd,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_drag(
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    button: Literal["left", "right"] = "left",
    steps: int = 10,
    hwnd: int | None = None,
) -> dict:
    """Drag pointer smoothly between virtual screen coordinates."""
    client_id = require_execution_permission(
        DT_DRAG, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.drag,
            start_x,
            start_y,
            end_x,
            end_y,
            button=button,
            steps=steps,
            hwnd=hwnd,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def desktop_wait_for_element(
    hwnd: int | None = None,
    name: str = "",
    automation_id: str = "",
    control_type: str = "",
    timeout_seconds: float = 5.0,
) -> dict:
    """Poll boundedly until a matching UI Automation element appears."""
    client_id = require_execution_permission(
        DT_WAIT_FOR_ELEMENT, oauth_provider.store if oauth_provider else None, oauth_execution,
        desktop_policy_store=DESKTOP_POLICY_STORE,
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            DESKTOP_MANAGER.wait_for_element,
            hwnd=hwnd,
            name=name,
            automation_id=automation_id,
            control_type=control_type,
            timeout_seconds=timeout_seconds,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _desktop_call_error(exc)


def _ext_call_error(exc: Exception) -> dict:
    if isinstance(exc, PermissionError):
        return {"error": f"Extension denied: {exc}"}
    return {"error": REDACTOR.redact_text(str(exc)) or type(exc).__name__}


@_conditional_tool(OAUTH_ENABLED)
async def extension_list(query: str = "") -> dict:
    """List installed extensions and the local official catalog."""
    require_execution_permission(
        EXT_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    try:
        return await asyncio.to_thread(
            lambda: {
                "installed": EXTENSION_MANAGER.list_extensions(query=query),
                "catalog": EXTENSION_MANAGER.list_catalog(query=query),
            }
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _ext_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def extension_info(extension_id: str) -> dict:
    """Inspect metadata, permissions, tools, and worker status for one installed extension."""
    require_execution_permission(
        EXT_INFO, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    try:
        return await asyncio.to_thread(EXTENSION_MANAGER.info, extension_id)
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ext_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def extension_call_tool(
    extension_id: str,
    tool_name: str,
    arguments: dict | None = None,
) -> dict:
    """Invoke a tool provided by an enabled extension under client and permission checks."""
    client_id = require_execution_permission(
        EXT_CALL_TOOL, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            EXTENSION_MANAGER.call_tool,
            extension_id,
            tool_name,
            arguments or {},
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, TimeoutError) as exc:
        return _ext_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def extension_enable(extension_id: str) -> dict:
    """Enable an installed extension and start its isolated worker process (Full profile)."""
    require_execution_permission(
        EXT_ENABLE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    try:
        return await asyncio.to_thread(EXTENSION_MANAGER.enable, extension_id)
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ext_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def extension_disable(extension_id: str) -> dict:
    """Disable an installed extension and stop its worker process (Full profile)."""
    require_execution_permission(
        EXT_DISABLE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    try:
        return await asyncio.to_thread(EXTENSION_MANAGER.disable, extension_id)
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ext_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def extension_logs(extension_id: str, tail: int = 80) -> dict:
    """Read redacted logs from an installed extension worker process."""
    require_execution_permission(
        EXT_LOGS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    try:
        lines = await asyncio.to_thread(EXTENSION_MANAGER.get_logs, extension_id, tail=tail)
        return {"extension_id": extension_id, "lines": lines}
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _ext_call_error(exc)


def _remote_call_error(exc: Exception) -> dict:
    if isinstance(exc, PermissionError):
        return {"error": f"Remote access denied: {exc}"}
    return {"error": REDACTOR.redact_text(str(exc)) or type(exc).__name__}


@_conditional_tool(OAUTH_ENABLED)
async def device_list(group: str = "") -> dict:
    """List remote SSH/SFTP device profiles accessible to the caller."""
    client_id = require_execution_permission(
        RM_DEVICE_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.list_devices,
            group=group,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def device_info(device_id: str) -> dict:
    """Inspect a configured remote device profile and recent redacted logs."""
    client_id = require_execution_permission(
        RM_DEVICE_INFO, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.device_info,
            device_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def device_health(device_id: str) -> dict:
    """Probe remote SSH reachability with strict known_hosts host-key verification."""
    client_id = require_execution_permission(
        RM_DEVICE_HEALTH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.device_health,
            device_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, TimeoutError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def ssh_execute(device_id: str, command: str, timeout: int = 12) -> dict:
    """Execute an SSH command on a named device profile under strict host-key & profile checks."""
    client_id = require_execution_permission(
        RM_SSH_EXECUTE, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        res = await asyncio.to_thread(
            REMOTE_MANAGER.ssh_execute,
            device_id,
            command,
            timeout=timeout,
            client_id=client_id,
            client_profile=profile_mode,
        )
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile_mode,
            event="completed", command=command, host=device_id,
            exit_code=res.get("exit_code"),
        )
        return res
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, TimeoutError, SSHConnectionError) as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile_mode,
            event="denied" if isinstance(exc, PermissionError) else "failed",
            command=command, host=device_id,
        )
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def ssh_task_start(device_id: str, command: str, timeout: int = 60) -> dict:
    """Start an asynchronous remote SSH job (disconnects fail honestly without fake resume)."""
    client_id = require_execution_permission(
        RM_SSH_TASK_START, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.ssh_task_start,
            device_id,
            command,
            timeout=timeout,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def sftp_list(device_id: str, path: str) -> dict:
    """List remote directory contents inside configured allowed SFTP roots."""
    client_id = require_execution_permission(
        RM_SFTP_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.sftp_list,
            device_id,
            path,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def sftp_download(device_id: str, path: str, as_base64: bool = False) -> dict:
    """Download a bounded file inside allowed SFTP roots (symlinks rejected)."""
    client_id = require_execution_permission(
        RM_SFTP_DOWNLOAD, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.sftp_download,
            device_id,
            path,
            as_base64=as_base64,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def sftp_upload(device_id: str, path: str, content: str, encoding: str = "utf-8") -> dict:
    """Upload bounded content into an allowed remote SFTP directory."""
    client_id = require_execution_permission(
        RM_SFTP_UPLOAD, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.sftp_upload,
            device_id,
            path,
            content,
            encoding=encoding,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def remote_service_list(device_id: str) -> dict:
    """List remote OS services (without automatic sudo elevation)."""
    client_id = require_execution_permission(
        RM_SVC_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.remote_service_list,
            device_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def remote_service_start(device_id: str, service_name: str) -> dict:
    """Start an allowed remote service using configured device user rights."""
    client_id = require_execution_permission(
        RM_SVC_START, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.remote_service_action,
            device_id,
            service_name,
            "start",
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def remote_service_stop(device_id: str, service_name: str) -> dict:
    """Stop an allowed remote service using configured device user rights."""
    client_id = require_execution_permission(
        RM_SVC_STOP, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.remote_service_action,
            device_id,
            service_name,
            "stop",
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def remote_metrics(device_id: str) -> dict:
    """Read remote host CPU/RAM/disk/uptime metrics over strict SSH."""
    client_id = require_execution_permission(
        RM_METRICS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile_mode = oauth_execution.profile_for(client_id)
    try:
        return await asyncio.to_thread(
            REMOTE_MANAGER.remote_metrics,
            device_id,
            client_id=client_id,
            client_profile=profile_mode,
        )
    except (OSError, ValueError, KeyError, PermissionError, RuntimeError, SSHConnectionError) as exc:
        return _remote_call_error(exc)


@_conditional_tool(OAUTH_ENABLED)
async def oauth_ssh_command(
    host: str, command: str, user: str = "", port: int = 22, timeout: int = 12,
) -> str:
    """Run SSH command immediately when the access scenario permits it.

    The default safe mode blocks SSH. Allowlist requires exact host+command.
    Full access allows arbitrary hosts/commands with timeout=1–600 seconds,
    but still rejects unknown SSH host keys (Paramiko RejectPolicy).
    """
    client_id = require_execution_permission(
        EXEC_SSH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile = oauth_execution.profile_for(client_id)
    if (not oauth_execution.can_request(
        client_id, "ssh", command=command, host=host, user=user, port=port,
        expected_profile=profile,
    ) or not 1 <= timeout <= (600 if profile == "full" else 12)):
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile,
            event="denied", command=command, host=host, port=port,
        )
        return "❌ SSH-хост или команда недоступны в выбранном режиме."

    def recheck_before_spawn() -> None:
        live_client = require_execution_permission(
            EXEC_SSH, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        if not oauth_execution.can_request(
            live_client, "ssh", command=command, host=host, user=user, port=port,
            expected_profile=profile,
        ):
            raise PermissionError("SSH access revoked before dispatch")

    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="ssh", profile=profile,
        event="started", command=command, host=host, port=port,
        action_id=action_id,
    )
    try:
        async with PROCESS_RUNNER.request_slot():
            output = await PROCESS_RUNNER.run_ssh(
                lambda cancel_ev, reg_cb: _sync_ssh_exec(
                    host, user, command, port, timeout,
                    cancel_event=cancel_ev, register_transport=reg_cb,
                ),
                client_id=client_id,
                pre_dispatch_check=recheck_before_spawn,
            )
    except PermissionError:
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile,
            event="denied", command=command, host=host, port=port,
            action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return "❌ SSH-хост или команда недоступны в выбранном режиме."
    except BaseException as exc:
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile,
            event="failed", command=command, host=host, port=port,
            action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        if isinstance(exc, Exception):
            logger.warning("[OAUTH SSH] failed: %s", type(exc).__name__)
            return "❌ SSH-команда не выполнена; подробности в локальном журнале."
        raise
    outcome, exit_code = classify_command_output(output)
    EXEC_AUDIT.record(
        client_id=client_id, kind="ssh", profile=profile,
        event=outcome, command=command, host=host, port=port,
        action_id=action_id, exit_code=exit_code,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return output


def _authorize_task_spec(client_id: str, spec: TaskSpec) -> str:
    """Fail-closed live check for task submission, dispatch, and restart."""
    if oauth_provider is None or oauth_execution is None:
        raise PermissionError("OAuth task execution is unavailable")
    if oauth_execution.emergency_stopped():
        raise PermissionError("Emergency stop is active")
    if not oauth_execution.client_approved(client_id):
        raise PermissionError("OAuth client is not approved")
    profile = oauth_execution.profile_for(client_id)
    if profile not in ("allowlist", "full"):
        raise PermissionError("Background tasks are disabled in safe mode")
    if spec.workspace_id and spec.workspace_command:
        _live_client_authorizer(client_id, WS_RUN_TASK)
        WORKSPACE_MANAGER._authorize_live(
            spec.workspace_id,
            client_id=client_id,
            fallback_profile=profile,
            required=("read", "execute"),
            tool_name=WS_RUN_TASK,
        )
        return profile
    if spec.kind == "windows":
        max_to = 600 if profile == "full" else 15
        if not (1 <= spec.timeout <= max_to) or (profile != "full" and spec.shell != "cmd"):
            raise PermissionError("Windows task timeout or shell is outside the active profile")
        if not oauth_execution.can_request(
            client_id, "windows", command=spec.command, expected_profile=profile
        ):
            raise PermissionError("Windows command is not permitted in the active profile")
    else:
        max_to = 600 if profile == "full" else 12
        if not (1 <= spec.timeout <= max_to):
            raise PermissionError("SSH task timeout is outside the active profile")
        if not oauth_execution.can_request(
            client_id, "ssh", command=spec.command, host=spec.host,
            user=spec.user, port=spec.port, expected_profile=profile,
        ):
            raise PermissionError("SSH host or command is not permitted in the active profile")
    return profile


def _task_auth_rechecker(rec: TaskRecord, spec: TaskSpec) -> None:
    _authorize_task_spec(rec.owner_client_id, spec)


async def _task_command_executor(rec: TaskRecord, spec: TaskSpec) -> CommandResult | str:
    profile = _authorize_task_spec(rec.owner_client_id, spec)

    def pre_dispatch() -> None:
        _authorize_task_spec(rec.owner_client_id, spec)

    if spec.kind == "windows":
        full = profile == "full"
        argv, immediate, script_path = _prepare_windows_argv(
            spec.command, full=full, shell=spec.shell, timeout=spec.timeout,
        )
        if immediate is not None or argv is None:
            if immediate and not immediate.startswith("❌"):
                writer = PROCESS_RUNNER.spool.create_spool(rec.spool_run_id or rec.task_id)
                writer.write("stdout", immediate.encode("utf-8", errors="replace"))
            return immediate or "❌ Пустая команда."
        try:
            async with PROCESS_RUNNER.request_slot():
                return await PROCESS_RUNNER.run_command(
                    argv,
                    cwd=WORKSPACE_DIR,
                    timeout=spec.timeout,
                    client_id=rec.owner_client_id,
                    kind="windows",
                    spawn_fn=asyncio.create_subprocess_exec,
                    output_offset=0,
                    output_limit=MAX_OUTPUT_LEN,
                    pre_dispatch_check=pre_dispatch,
                    run_id=rec.spool_run_id or rec.task_id,
                )
        finally:
            if script_path:
                script_path.unlink(missing_ok=True)

    async with PROCESS_RUNNER.request_slot():
        out = await PROCESS_RUNNER.run_ssh(
            lambda cancel_ev, reg_cb: _sync_ssh_exec(
                spec.host, spec.user, spec.command, spec.port, spec.timeout,
                cancel_event=cancel_ev, register_transport=reg_cb,
            ),
            client_id=rec.owner_client_id,
            pre_dispatch_check=pre_dispatch,
            run_id=rec.spool_run_id or rec.task_id,
        )
    writer = PROCESS_RUNNER.spool.create_spool(rec.spool_run_id or rec.task_id)
    writer.write("stdout", out.encode("utf-8", errors="replace"))
    return out


TASK_MANAGER = TaskManager(
    TASK_STORE,
    PROCESS_RUNNER,
    artifacts_dir=Path(os.environ.get("MCP_TASKS_ARTIFACTS_DIR") or (_TASKS_DEFAULT_DIR / "artifacts")),
    redactor=REDACTOR,
    auth_rechecker=_task_auth_rechecker,
    command_executor=_task_command_executor,
    workspace_task_executor=WORKSPACE_MANAGER.execute_restarted_task,
)


def _task_tool_error_response(
    exc: BaseException,
    *,
    tool_name: str,
    task_id: str | None = None,
    profile: str | None = None,
    lookup_operation: bool = False,
) -> Any:
    """Convert task tool failures into structured MCP CallToolResult(isError=True) with safe logging."""
    err = classify_task_exception(
        exc,
        tool_name=tool_name,
        task_id=task_id,
        profile=profile,
        lookup_operation=lookup_operation,
    )
    log_task_tool_error(
        err,
        tool_name=tool_name,
        task_id=task_id,
        exc=exc,
        redactor=REDACTOR,
        logging_mgr=_LOGGING_MGR,
    )
    return build_task_error_result(err, redactor=REDACTOR)


def _resolve_windows_shell_executable(shell: str) -> str:
    """Resolve full path to cmd.exe or powershell.exe cleanly even under minimal frozen PATH."""
    import shutil

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    if shell == "powershell":
        candidates = [
            str(system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
            shutil.which("powershell") or "",
            shutil.which("pwsh") or "",
        ]
    else:
        candidates = [
            str(system_root / "System32" / "cmd.exe"),
            shutil.which("cmd") or "",
        ]
    for cand in candidates:
        if cand and Path(cand).is_file():
            return cand
    raise TaskToolError(
        code=TASK_EXECUTABLE_NOT_FOUND,
        message=f"Не найден исполняемый файл оболочки '{shell}'.",
        details={"shell": shell},
        suggestion="Проверьте наличие системной оболочки Windows или выберите другой поддерживаемый shell.",
        internal_reason=f"Missing Windows shell executable for {shell!r}",
    )


@_conditional_tool(OAUTH_ENABLED)
async def task_start(
    command: str,
    kind: Literal["windows", "ssh"] = "windows",
    shell: Literal["cmd", "powershell"] = "cmd",
    timeout: int | None = None,
    host: str = "",
    user: str = "",
    port: int = 22,
    priority: int = 0,
    idempotency_key: str = "",
    title: str = "",
) -> dict[str, Any]:
    """Queue a durable background task whose execution continues across client disconnects."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_START, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        if oauth_provider is None or oauth_execution is None:
            raise TaskToolError(
                code=TASK_ACCESS_DENIED,
                message="Менеджер задач OAuth недоступен в текущей конфигурации сервера.",
                suggestion="Включите OAuth-авторизацию в настройках MCP-app.",
            )
        if oauth_execution.emergency_stopped():
            raise TaskToolError(
                code=TASK_ACCESS_DENIED,
                message="Запуск фоновых задач заблокирован активной аварийной остановкой.",
                details={"emergency_stop": True},
                suggestion="Снимите аварийную остановку в приложении MCP-app во вкладке «Безопасность».",
            )
        if not oauth_execution.client_approved(client_id):
            raise TaskToolError(
                code=TASK_ACCESS_DENIED,
                message="OAuth-клиент не подтверждён владельцем.",
                suggestion="Пройдите подтверждение доступа в браузере или в приложении MCP-app.",
            )
        profile = oauth_execution.profile_for(client_id)
        if profile not in ("allowlist", "full"):
            raise TaskToolError(
                code=TASK_ACCESS_DENIED,
                message="Запуск фоновых задач запрещён в безопасном режиме (safe).",
                details={"profile": profile},
                suggestion="Переключите сценарий доступа клиента на «Белый список» (allowlist) или «Полный доступ» (full).",
            )
        if kind not in ("windows", "ssh"):
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message=f"Неподдерживаемый тип задачи kind={kind!r}.",
                details={"kind": kind, "allowed_kinds": ["windows", "ssh"]},
                suggestion="Укажите kind='windows' или kind='ssh'.",
            )
        if not isinstance(command, str) or not command.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Команда задачи не может быть пустой.",
                details={"kind": kind},
                suggestion="Передайте непустую команду в параметре command.",
            )
        if len(command) > 32000:
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Длина команды превышает лимит 32000 символов.",
                details={"length": len(command), "max_length": 32000},
                suggestion="Сократите команду или вынесите логику в скрипт внутри рабочего каталога.",
            )
        if shell not in ("cmd", "powershell"):
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message=f"Неподдерживаемая оболочка shell={shell!r}.",
                details={"shell": shell, "allowed_shells": ["cmd", "powershell"]},
                suggestion="Укажите shell='cmd' или shell='powershell'.",
            )
        if profile != "full" and kind == "windows" and shell != "cmd":
            raise TaskToolError(
                code=TASK_COMMAND_NOT_ALLOWED,
                message="Оболочка PowerShell в фоновых задачах доступна только при полном доступе (full).",
                details={"profile": profile, "shell": shell},
                suggestion="Используйте shell='cmd' с разрешённой командой или переключите клиента в режим full.",
            )
        max_to = 600 if profile == "full" else (12 if kind == "ssh" else 15)
        if timeout is None:
            resolved_timeout = 60 if profile == "full" else max_to
        else:
            if isinstance(timeout, bool) or not isinstance(timeout, int):
                raise TaskToolError(
                    code=TASK_INVALID_TIMEOUT,
                    message="Параметр timeout должен быть целым числом секунд.",
                    details={"profile": profile, "max_timeout": max_to},
                    suggestion=f"Передайте целое число от 1 до {max_to} или не указывайте timeout.",
                )
            resolved_timeout = timeout
            if not (1 <= resolved_timeout <= max_to):
                raise TaskToolError(
                    code=TASK_INVALID_TIMEOUT,
                    message=f"Значение timeout={resolved_timeout} сек. выходит за допустимый диапазон 1–{max_to} сек. для профиля '{profile}'.",
                    details={
                        "requested_timeout": resolved_timeout,
                        "min_timeout": 1,
                        "max_timeout": max_to,
                        "profile": profile,
                        "kind": kind,
                    },
                    suggestion=f"Укажите timeout от 1 до {max_to} сек. либо опустите параметр, чтобы использовать значение по умолчанию ({max_to if profile != 'full' else 60} сек.).",
                )
        if kind == "ssh":
            if not isinstance(host, str) or not host.strip():
                raise TaskToolError(
                    code=TASK_INVALID_ARGUMENT,
                    message="Для SSH-задачи требуется непустой параметр host.",
                    details={"kind": kind},
                    suggestion="Укажите имя или адрес SSH-хоста из настроенного списка.",
                )
            if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
                raise TaskToolError(
                    code=TASK_INVALID_ARGUMENT,
                    message="SSH-порт должен быть целым числом в диапазоне 1–65535.",
                    details={"port": port},
                    suggestion="Укажите корректный TCP-порт (обычно 22).",
                )
        if kind == "windows" and os.name == "nt" and profile == "full":
            _resolve_windows_shell_executable(shell)
        spec = TaskSpec(
            kind=kind,
            command=command,
            shell=shell,
            timeout=resolved_timeout,
            host=host,
            user=user,
            port=port,
        )
        spec.validate()
        profile = _authorize_task_spec(client_id, spec)
        try:
            rec, deduplicated = await TASK_MANAGER.submit(
                owner_client_id=client_id,
                profile=profile,
                spec=spec,
                priority=priority,
                idempotency_key=idempotency_key,
                title=title,
            )
        except RuntimeError as exc:
            if "quota exceeded" in str(exc).lower():
                raise TaskToolError(
                    code=TASK_QUEUE_FULL,
                    message="Превышена квота активных и ожидающих задач для текущего клиента.",
                    details={"max_queued_per_client": TASK_MANAGER.max_queued_per_client},
                    suggestion="Дождитесь завершения текущих задач или отмените ненужные через task_cancel.",
                    internal_reason=str(exc),
                ) from exc
            raise
        try:
            EXEC_AUDIT.record(
                client_id=client_id, kind=kind, profile=profile,
                event="started", command=command, host=host or None, port=port if host else None,
                action_id=rec.task_id,
            )
            _LOGGING_MGR.info(
                "tasks",
                f"Task queued task_id={rec.task_id} kind={kind} profile={profile} timeout={resolved_timeout}s deduplicated={deduplicated}",
                event_code="task_queued",
            )
        except Exception as log_exc:  # noqa: BLE001
            # Never turn an already-queued task into a failed tool response because of telemetry I/O.
            logger.warning("Post-submit task audit/log failed for %s: %s", rec.task_id, type(log_exc).__name__)
        return {**rec.to_public_dict(REDACTOR), "deduplicated": deduplicated, "mcp_task": rec.to_mcp_task_dict(REDACTOR)}
    except BaseException as exc:
        return _task_tool_error_response(exc, tool_name=TASK_START, profile=profile)


@_conditional_tool(OAUTH_ENABLED)
async def task_status(task_id: str) -> dict[str, Any]:
    """Inspect status, elapsed time, and optional known progress for an owned background task."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_STATUS, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор задачи, полученный от task_start или task_list.",
            )
        return TASK_MANAGER.status_dict(task_id.strip(), owner_client_id=client_id)
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_STATUS, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(OAUTH_ENABLED)
async def task_list(status: str = "", limit: int = 50) -> dict[str, Any]:
    """List durable background tasks owned by this OAuth client."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_LIST, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if status:
            from .tasks.models import ALL_STATUSES
            if status not in ALL_STATUSES:
                raise TaskToolError(
                    code=TASK_INVALID_ARGUMENT,
                    message=f"Недопустимый фильтр status={status!r}.",
                    details={"status": status, "allowed_statuses": sorted(ALL_STATUSES)},
                    suggestion="Передайте пустую строку или один из допустимых статусов: queued, running, succeeded, failed, cancelled, interrupted.",
                )
        return {"tasks": TASK_MANAGER.list_dicts(owner_client_id=client_id, status=status or None, limit=limit)}
    except BaseException as exc:
        return _task_tool_error_response(exc, tool_name=TASK_LIST, profile=profile)


@_conditional_tool(OAUTH_ENABLED)
async def task_output(
    task_id: str,
    stream: Literal["stdout", "stderr"] = "stdout",
    offset: int = 0,
    limit: int = 8000,
) -> dict[str, Any]:
    """Read paginated, redacted stdout or stderr output from disk spool for an owned task."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_OUTPUT, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор задачи, полученный от task_start или task_list.",
            )
        if stream not in ("stdout", "stderr"):
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message=f"Недопустимый поток вывода stream={stream!r}.",
                details={"stream": stream},
                suggestion="Используйте stream='stdout' или stream='stderr'.",
            )
        return TASK_MANAGER.read_output(
            task_id.strip(), owner_client_id=client_id, stream=stream, offset=offset, limit=limit,
        )
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_OUTPUT, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(OAUTH_ENABLED)
async def task_result(task_id: str) -> dict[str, Any]:
    """Return final outcome, exit code, and redacted summary artifact for an owned task."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_RESULT, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор задачи, полученный от task_start или task_list.",
            )
        return TASK_MANAGER.result_dict(task_id.strip(), owner_client_id=client_id)
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_RESULT, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(OAUTH_ENABLED)
async def task_cancel(task_id: str) -> dict[str, Any]:
    """Cancel an owned queued or running task, terminating its controlled process tree."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_CANCEL, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор активной задачи из task_list.",
            )
        clean_id = task_id.strip()
        cur = TASK_MANAGER._require_owned_task(clean_id, client_id)
        if cur.status in TERMINAL_STATUSES:
            raise TaskToolError(
                code=TASK_INVALID_STATE,
                message=f"Задачу нельзя отменить в состоянии '{cur.status}'.",
                details={"task_id": clean_id, "status": cur.status},
                suggestion="Отменять можно только задачи в состоянии queued или running.",
            )
        return TASK_MANAGER.cancel(clean_id, owner_client_id=client_id)
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_CANCEL, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(OAUTH_ENABLED)
async def task_restart(task_id: str) -> dict[str, Any]:
    """Explicitly re-enqueue an owned completed, failed, cancelled, or interrupted task."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_RESTART, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор завершённой задачи из task_list.",
            )
        clean_id = task_id.strip()
        old = TASK_MANAGER._require_owned_task(clean_id, client_id)
        if old.status not in TERMINAL_STATUSES:
            raise TaskToolError(
                code=TASK_INVALID_STATE,
                message=f"Нельзя перезапустить задачу в состоянии '{old.status}'.",
                details={"task_id": clean_id, "status": old.status},
                suggestion="Дождитесь завершения задачи или сначала остановите её через task_cancel.",
            )
        spec = TASK_STORE.get_spec(clean_id)
        if spec is None:
            raise TaskToolError(
                code=TASK_NOT_FOUND,
                message="Спецификация задачи не найдена.",
                details={"task_id": clean_id},
                suggestion="Запустите задачу заново через task_start.",
            )
        profile = _authorize_task_spec(client_id, spec)
        return await TASK_MANAGER.restart(clean_id, owner_client_id=client_id, new_profile=profile)
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_RESTART, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(OAUTH_ENABLED)
async def task_artifacts(
    task_id: str,
    artifact_name: str = "",
    offset: int = 0,
    limit: int = 16000,
) -> dict[str, Any]:
    """List or read paginated redacted output artifacts for an owned background task."""
    profile: str | None = None
    try:
        client_id = require_execution_permission(
            TASK_ARTIFACTS, oauth_provider.store if oauth_provider else None, oauth_execution
        )
        profile = oauth_execution.profile_for(client_id) if oauth_execution else None
        if not isinstance(task_id, str) or not task_id.strip():
            raise TaskToolError(
                code=TASK_INVALID_ARGUMENT,
                message="Параметр task_id не может быть пустым.",
                suggestion="Укажите идентификатор задачи, полученный от task_start или task_list.",
            )
        clean_id = task_id.strip()
        try:
            return TASK_MANAGER.read_artifacts(
                clean_id, owner_client_id=client_id, artifact_name=artifact_name, offset=offset, limit=limit,
            )
        except FileNotFoundError as exc:
            raise TaskToolError(
                code=TASK_NOT_FOUND,
                message="Запрошенный артефакт задачи не найден.",
                details={"task_id": clean_id, "artifact_name": artifact_name},
                suggestion="Вызовите task_artifacts без artifact_name, чтобы увидеть список доступных артефактов.",
                internal_reason=str(exc),
            ) from exc
    except BaseException as exc:
        return _task_tool_error_response(
            exc, tool_name=TASK_ARTIFACTS, task_id=task_id if isinstance(task_id, str) else None, profile=profile, lookup_operation=True
        )


@_conditional_tool(EXECUTION_TOOLS and bool(ALLOWED_EXECUTABLES))
async def run_local_command(command: str, timeout: int = 30, cwd: str | None = None) -> str:
    """Execute one explicitly allowlisted executable, without a command shell."""
    try:
        argv = parse_allowed_command(command, ALLOWED_EXECUTABLES)
        work_dir = workspace_path(WORKSPACE_DIR, cwd) if cwd else WORKSPACE_DIR
        if not work_dir.is_dir():
            return "❌ Рабочая директория не существует."
    except ValueError as exc:
        return f"❌ Команда запрещена: {exc}"
    timeout = min(max(timeout, 1), 120)
    logger.info("[LOCAL] executable=%s (arguments redacted)", Path(argv[0]).name)
    try:
        result = await PROCESS_RUNNER.run_command(
            argv,
            cwd=work_dir,
            timeout=timeout,
            client_id="legacy",
            kind="local",
            spawn_fn=asyncio.create_subprocess_exec,
            output_limit=MAX_OUTPUT_LEN,
        )
        if result.timed_out:
            return f"❌ Таймаут: команда превысила лимит {timeout} сек."
        return (
            f"Exit code: {result.exit_code}\n✅ STDOUT:\n{result.stdout}"
            f"\n❌ STDERR:\n{result.stderr}"
        )
    except OSError as exc:
        return f"❌ Не удалось запустить разрешённую программу: {type(exc).__name__}"

def _sync_ssh_exec(
    host: str,
    user: str,
    command: str,
    port: int,
    timeout: int,
    *,
    cancel_event=None,
    register_transport=None,
) -> str:
    client = paramiko.SSHClient()
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    client.load_system_host_keys()
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    # Never trust unknown SSH hosts silently, even in Advanced mode.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    actual_host, actual_user, actual_port, key_filename = host, user or None, port, None
    ssh_cfg_path = Path.home() / ".ssh" / "config"
    if ssh_cfg_path.exists():
        cfg = paramiko.SSHConfig.from_path(str(ssh_cfg_path))
        host_cfg = cfg.lookup(host)
        actual_host = host_cfg.get("hostname", host)
        if not actual_user:
            actual_user = host_cfg.get("user")
        if port == 22 and "port" in host_cfg:
            actual_port = int(host_cfg["port"])
        key_filename = host_cfg.get("identityfile")

    try:
        if cancel_event is not None and cancel_event.is_set():
            return "❌ SSH command cancelled."
        if register_transport is not None:
            register_transport(client, None)
        client.connect(hostname=actual_host, port=actual_port, username=actual_user, key_filename=key_filename, timeout=10, banner_timeout=10)
        if cancel_event is not None and cancel_event.is_set():
            return "❌ SSH command cancelled."
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        deadline = time.monotonic() + min(max(timeout, 1), 600)
        channel = stdout.channel
        if register_transport is not None:
            register_transport(client, channel)
        out, err = bytearray(), bytearray()
        while True:
            if cancel_event is not None and cancel_event.is_set():
                channel.close()
                return "❌ SSH command cancelled."
            if time.monotonic() >= deadline:
                channel.close()
                return "❌ SSH command timed out."
            progressed = False
            if channel.recv_ready():
                chunk = channel.recv(32768)
                out.extend(chunk[:max(0, MAX_OUTPUT_LEN * 4 - len(out))])
                progressed = True
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(32768)
                err.extend(chunk[:max(0, MAX_OUTPUT_LEN * 4 - len(err))])
                progressed = True
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if not progressed:
                time.sleep(0.05)
        exit_status = channel.recv_exit_status()
        out_str = REDACTOR.redact_text(truncate_output(decode_process_bytes(bytes(out))))
        err_str = REDACTOR.redact_text(truncate_output(decode_process_bytes(bytes(err))))
        return f"Exit code: {exit_status}\n✅ STDOUT:\n{out_str}\n❌ STDERR:\n{err_str}"
    finally:
        client.close()

@_conditional_tool(EXECUTION_TOOLS and bool(ALLOWED_HOSTS))
async def run_ssh_command(host: str, command: str, user: str = "", port: int = 22, timeout: int = 30) -> str:
    if not allowed_ssh_host(host, ALLOWED_HOSTS):
        return "❌ Отказано: SSH-хост отсутствует в разрешённом списке."
    if not (1 <= port <= 65535) or len(command) > 2000 or not command.strip():
        return "❌ Отказано: недопустимый порт или команда."
    timeout = min(max(timeout, 1), 120)
    logger.info("[SSH] host=%s port=%s (command redacted)", host, port)
    try:
        return await asyncio.to_thread(_sync_ssh_exec, host, user, command, port, timeout)
    except Exception as exc:
        logger.warning("SSH call failed: %s", type(exc).__name__)
        return "❌ SSH операция не выполнена; подробности в журнале администратора."

@_conditional_tool(ADVANCED_TOOLS)
def read_workspace_file(relative_path: str) -> str:
    try:
        target = workspace_path(WORKSPACE_DIR, relative_path)
        if not target.is_file():
            return "❌ Файл не найден."
        if target.stat().st_size > 1024 * 1024:
            return "❌ Файл превышает допустимый размер."
        return truncate_output(target.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError) as exc:
        return f"❌ Доступ к файлу запрещён: {type(exc).__name__}"


@_conditional_tool(ADVANCED_TOOLS)
def write_workspace_file(relative_path: str, content: str) -> str:
    if len(content.encode("utf-8")) > MAX_WRITE_BYTES:
        return "❌ Файл превышает допустимый размер."
    try:
        target = workspace_path(WORKSPACE_DIR, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Resolve again after mkdir to reject paths moved outside the workspace.
        target = workspace_path(WORKSPACE_DIR, relative_path)
        target.write_text(content, encoding="utf-8")
    except (ValueError, OSError) as exc:
        return f"❌ Запись файла запрещена: {type(exc).__name__}"
    logger.info("[FILE WRITE] bytes=%d (path redacted)", len(content.encode("utf-8")))
    return "✅ Файл сохранён в разрешённой рабочей папке."


def _purge_stale_ephemeral_oauth_clients() -> int:
    """Remove any orphaned sched-owner-* or playground-ephemeral-* OAuth clients."""
    if oauth_provider is None or oauth_provider.store is None:
        return 0
    try:
        return oauth_provider.store.purge_ephemeral_clients()
    except Exception:  # noqa: BLE001
        return 0


def _extract_scheduled_tool_output(res: Any) -> dict[str, Any]:
    """Normalize MCP CallToolResult/list/dict/tuple and raise RuntimeError on tool-level errors."""
    is_err = bool(getattr(res, "isError", False) or getattr(res, "is_error", False))
    structured = getattr(res, "structuredContent", None) or getattr(res, "structured_content", None)
    raw_items = getattr(res, "content", None)
    if isinstance(res, tuple) and len(res) == 2:
        raw_items, structured = res
    elif isinstance(res, list):
        raw_items = res
    elif isinstance(res, dict):
        structured = res

    texts: list[str] = []
    for item in raw_items or ():
        if isinstance(item, TextContent) or hasattr(item, "text"):
            texts.append(REDACTOR.redact_text(str(getattr(item, "text", ""))))
        else:
            texts.append(REDACTOR.redact_text(str(item)))

    if structured is None and len(texts) == 1:
        try:
            parsed = json.loads(texts[0])
            if isinstance(parsed, dict):
                structured = parsed
        except json.JSONDecodeError:
            pass

    if isinstance(structured, dict):
        if structured.get("error"):
            is_err = True
        elif structured.get("ok") is False:
            is_err = True
    if any(t.lstrip().startswith("❌") for t in texts):
        is_err = True

    if is_err:
        err_msg = ""
        if isinstance(structured, dict) and structured.get("error"):
            err_msg = str(structured.get("error"))
        elif texts:
            err_msg = texts[0]
        raise RuntimeError(REDACTOR.redact_text(err_msg or "Scheduled tool returned an error"))

    out: dict[str, Any] = {"ok": True}
    if texts:
        out["text"] = "\n".join(texts)
    if structured is not None:
        out["result"] = structured
    return out


async def _invoke_owner_scheduled_tool_async(spec: ScheduleSpec, args: dict[str, Any]) -> Any:
    """Execute owner-owned schedule strictly capped at the configured owner global profile."""
    if spec.tool_name == "server_info":
        return await mcp.call_tool("server_info", {})
    owner_profile = oauth_execution.profile() if oauth_execution is not None else PROFILE_SAFE
    if GATEWAY_ROUTER.is_gateway_tool(spec.tool_name):
        await GATEWAY_ROUTER.ensure_initialized()
        await GATEWAY_ROUTER.sync_dirty()
        gw_err = _scheduler_check_owner_gateway(spec.tool_name, owner_profile)
        if gw_err:
            raise PermissionError(gw_err)
        entry = GATEWAY_ROUTER._catalog[spec.tool_name]
        prof = GATEWAY_ROUTER.store.get(entry.server_id)
        assert prof is not None
        handle = await GATEWAY_ROUTER._get_or_connect(prof, "owner")
        raw_res = await handle.call_tool(entry.raw_name, args)
        return GATEWAY_ROUTER._sanitize_result(raw_res, prof.max_response_bytes)

    if oauth_provider is None or oauth_execution is None:
        raise PermissionError("OAuth store unavailable for scheduled execution")
    ephemeral_id = f"sched-owner-{secrets.token_hex(4)}"
    client_info = OAuthClientInformationFull(
        client_id=ephemeral_id,
        client_name="MCP Scheduler (owner ephemeral)",
        redirect_uris=[AnyHttpUrl("http://127.0.0.1/callback")],
    )
    tok = AccessToken(
        token=secrets.token_urlsafe(12),
        client_id=ephemeral_id,
        scopes=[READ_SCOPE],
        resource=RESOURCE_URL,
    )
    token_ctx = None
    try:
        oauth_provider.store.save_client(client_info)
        oauth_provider.store.mark_approved(ephemeral_id)
        oauth_execution.set_client_profile(ephemeral_id, owner_profile)
        token_ctx = auth_context_var.set(AuthenticatedUser(tok))
        return await mcp.call_tool(spec.tool_name, args)
    finally:
        if token_ctx is not None:
            auth_context_var.reset(token_ctx)
        try:
            oauth_provider.store.revoke_client(ephemeral_id)
        except Exception:  # noqa: BLE001
            pass


async def _invoke_scheduled_tool_async(spec: ScheduleSpec) -> Any:
    args = dict(spec.arguments or {})
    if spec.client_id == "owner":
        return await _invoke_owner_scheduled_tool_async(spec, args)
    tok = AccessToken(
        token=secrets.token_urlsafe(12),
        client_id=spec.client_id,
        scopes=[READ_SCOPE],
        resource=RESOURCE_URL,
    )
    token_ctx = auth_context_var.set(AuthenticatedUser(tok))
    try:
        await GATEWAY_ROUTER.ensure_initialized()
        await GATEWAY_ROUTER.sync_dirty()
        if GATEWAY_ROUTER.is_gateway_tool(spec.tool_name):
            return await GATEWAY_ROUTER.call_authorized_tool(
                spec.tool_name, args, tok, oauth_execution
            )
        return await mcp.call_tool(spec.tool_name, args)
    finally:
        auth_context_var.reset(token_ctx)


async def _execute_scheduled_tool_async(spec: ScheduleSpec, idem_key: str) -> dict[str, Any]:
    """Authorize and execute one due scheduled MCP/Gateway tool on the active server event loop."""
    t0 = time.monotonic()
    allowed, reason = _scheduler_permission_check(spec)
    if not allowed:
        METRICS_REGISTRY.record_call(spec.tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        raise PermissionError(reason or f"Unauthorized scheduled execution for {spec.tool_name}")
    try:
        res = await _invoke_scheduled_tool_async(spec)
        out = _extract_scheduled_tool_output(res)
        METRICS_REGISTRY.record_call(spec.tool_name, (time.monotonic() - t0) * 1000.0, error=False)
        out["idempotency_key"] = idem_key
        return out
    except Exception:
        METRICS_REGISTRY.record_call(spec.tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        raise


AUTOMATION_SCHEDULER._async_executor = _execute_scheduled_tool_async


# ==========================================
# 6. ЗАПУСК
# ==========================================

def _policy_fingerprint() -> tuple[Any, ...]:
    oauth_stat = None
    if oauth_provider is not None and oauth_provider.store is not None:
        try:
            st = oauth_provider.store.path.stat()
            oauth_stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            oauth_stat = None
    desktop_stat = None
    try:
        st = DESKTOP_POLICY_STORE.path.stat()
        desktop_stat = (st.st_mtime_ns, st.st_size)
    except OSError:
        desktop_stat = None
    gw_stat = None
    try:
        st = GATEWAY_STORE.path.stat()
        gw_stat = (st.st_mtime_ns, st.st_size)
    except OSError:
        gw_stat = None
    return (oauth_stat, desktop_stat, gw_stat)


def build_app():
    """Starlette-приложение MCP с нашим middleware снаружи."""
    app = mcp.streamable_http_app(
        json_response=JSON_RESPONSE,
        streamable_http_path=MCP_PATH,
        transport_security=TRANSPORT_SECURITY,
    )
    orig_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan_with_policy_watcher(asgi_app):
        async with orig_lifespan(asgi_app):
            stop_event = asyncio.Event()

            async def _watch() -> None:
                last_fp = _policy_fingerprint()
                while not stop_event.is_set():
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=0.4)
                        break
                    except asyncio.TimeoutError:
                        pass
                    cur_fp = _policy_fingerprint()
                    if cur_fp != last_fp:
                        last_fp = cur_fp
                        await SESSION_TRACKER.check_and_notify()

            watcher_task = asyncio.create_task(_watch())
            _purge_stale_ephemeral_oauth_clients()
            AUTOMATION_SCHEDULER.start_background_loop(
                poll_interval=_SCHEDULER_POLL_SECONDS,
                startup_hook=_purge_stale_ephemeral_oauth_clients,
            )
            try:
                yield
            finally:
                await AUTOMATION_SCHEDULER.stop_background_loop()
                _purge_stale_ephemeral_oauth_clients()
                stop_event.set()
                watcher_task.cancel()
                try:
                    await watcher_task
                except asyncio.CancelledError:
                    pass

    app.router.lifespan_context = _lifespan_with_policy_watcher
    # add_middleware ставит наш слой СНАРУЖИ middleware SDK: заголовок из ?token=
    # появляется до того, как SDK проверит авторизацию.
    app.add_middleware(HybridAuthMiddleware)
    return app


def _admin_upsert_schedule(body: dict[str, Any]) -> dict[str, Any]:
    payload = dict(body)
    payload["client_id"] = "owner"
    spec = ScheduleSpec.from_dict(payload)
    return AUTOMATION_SCHEDULER.upsert_schedule(spec, actor_id="owner", actor_profile="full")


async def _admin_emit_event(event_name: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    return await AUTOMATION_SCHEDULER.emit_event_async(event_name, payload=payload)


def build_local_admin_app(*, read_only_token: str = ""):
    """Strictly separate localhost-only Admin REST API (never mounted on public tunnels)."""
    tokens: dict[str, frozenset[str]] = {ADMIN_TOKEN: frozenset({"admin:read", "admin:write"})}
    if read_only_token.strip():
        tokens[read_only_token.strip()] = frozenset({"admin:read"})

    def _snapshot() -> dict[str, Any]:
        clients = oauth_provider.store.list_clients() if oauth_provider is not None else []
        return collect_system_snapshot(
            METRICS_REGISTRY,
            clients=clients,
            tunnel_status={"public_url": PUBLIC_URL, "json_response": JSON_RESPONSE},
            gateway_status={"servers": len(GATEWAY_STORE.list_profiles())},
            scheduler_stats={"schedules": len(AUTOMATION_SCHEDULER.list_schedules())},
        )

    def _export_diag() -> str:
        log_path = Path(AUDIT_LOG)
        lines: list[str] = []
        if log_path.is_file():
            try:
                lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
            except OSError:
                lines = []
        return export_redacted_diagnostics(_snapshot(), audit_lines=lines, redactor=REDACTOR)

    return build_admin_app(
        admin_tokens=tokens,
        snapshot_provider=_snapshot,
        scheduler_list_provider=AUTOMATION_SCHEDULER.list_schedules,
        scheduler_trigger_fn=lambda sid: AUTOMATION_SCHEDULER.trigger_now_async(sid, trigger="admin_api"),
        diagnostics_export_fn=_export_diag,
        scheduler_history_provider=AUTOMATION_SCHEDULER.list_history,
        scheduler_upsert_fn=_admin_upsert_schedule,
        scheduler_delete_fn=lambda sid: AUTOMATION_SCHEDULER.remove_schedule(
            sid, actor_id="owner", actor_profile="full"
        ),
        scheduler_enable_fn=lambda sid, en: AUTOMATION_SCHEDULER.set_schedule_enabled(
            sid, en, actor_id="owner", actor_profile="full"
        ),
        scheduler_event_fn=_admin_emit_event,
        server_list_provider=lambda: SERVER_MANAGER.list_servers(client_id="owner"),
        server_status_fn=lambda n: SERVER_MANAGER.status_server(n, client_id="owner"),
        server_start_fn=lambda n, wid, wait_r: SERVER_MANAGER.start_server(
            n, client_id="owner", workspace_id=wid, wait_readiness=wait_r
        ),
        server_stop_fn=lambda n: SERVER_MANAGER.stop_server(n, client_id="owner"),
        server_restart_fn=lambda n, wid, wait_r: SERVER_MANAGER.restart_server(
            n, client_id="owner", workspace_id=wid, wait_readiness=wait_r
        ),
        server_health_fn=lambda n: SERVER_MANAGER.health_server(n, client_id="owner", run_probe=True),
        server_logs_fn=lambda n, st, off, lim: SERVER_MANAGER.logs_server(
            n, client_id="owner", stream=st, offset=off, limit=lim
        ),
        server_metrics_fn=lambda n: SERVER_MANAGER.metrics_server(n, client_id="owner"),
        server_autostart_fn=SERVER_MANAGER.start_autostart_servers,
        workspace_run_task_fn=lambda wid, cname: WORKSPACE_MANAGER.run_workspace_task(
            wid, cname, client_id="owner"
        ),
    )


async def invoke_playground_tool(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    profile: str = "safe",
    client_id: str = "playground-ephemeral",
) -> dict[str, Any]:
    """Execute a real MCP tool in Playground with explicit profile gating and metrics tracking."""
    t0 = time.monotonic()
    ranks = {"safe": 0, "allowlist": 1, "full": 2}
    if profile not in ranks:
        METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": f"Unknown profile: {profile!r}",
        }
    spec = DEFAULT_REGISTRY._specs.get(tool_name)
    if spec is None:
        METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": f"Unknown tool: {tool_name}",
        }
    if tool_name != "server_info" and oauth_execution is not None and oauth_execution.emergency_stopped():
        METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": "Denied: Emergency stop is active",
        }
    if ranks[profile] < ranks.get(spec.min_profile, 99):
        METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        return {
            "allowed": False,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "error": (
                f"Denied: tool '{tool_name}' requires profile '{spec.min_profile}' "
                f"(selected: '{profile}')"
            ),
        }
    if tool_name in DESKTOP_TOOLS:
        dt_policy = DESKTOP_POLICY_STORE.load()
        if dt_policy.emergency_stop or not dt_policy.enabled:
            METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
            return {
                "allowed": False,
                "live_execution": True,
                "profile": profile,
                "tool_name": tool_name,
                "error": "Denied: Computer Use is disabled by owner",
            }
        if tool_name in DESKTOP_VIEW_TOOLS and not dt_policy.allow_screen_capture:
            METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
            return {
                "allowed": False,
                "live_execution": True,
                "profile": profile,
                "tool_name": tool_name,
                "error": "Denied: Screen capture is disabled by owner",
            }
        if tool_name in DESKTOP_CONTROL_TOOLS and not dt_policy.allow_input_control:
            METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
            return {
                "allowed": False,
                "live_execution": True,
                "profile": profile,
                "tool_name": tool_name,
                "error": "Denied: Desktop input control is disabled by owner",
            }

    ephemeral_id = f"{client_id}-{secrets.token_hex(4)}"
    provider = oauth_provider
    exec_approvals = oauth_execution
    need_ephemeral = tool_name != "server_info" and provider is not None and exec_approvals is not None
    tok = AccessToken(
        token=secrets.token_urlsafe(12),
        client_id=ephemeral_id if need_ephemeral else client_id,
        scopes=[READ_SCOPE],
        resource=RESOURCE_URL,
    )
    created_ephemeral = False
    auth_token = None
    try:
        if need_ephemeral and provider is not None and exec_approvals is not None:
            client_info = OAuthClientInformationFull(
                client_id=ephemeral_id,
                client_name="MCP Playground (ephemeral)",
                redirect_uris=[AnyHttpUrl("http://127.0.0.1/callback")],
            )
            created_ephemeral = True
            provider.store.save_client(client_info)
            provider.store.mark_approved(ephemeral_id)
            exec_approvals.set_client_profile(ephemeral_id, profile)
        auth_token = auth_context_var.set(AuthenticatedUser(tok))
        res = await mcp.call_tool(tool_name, dict(arguments or {}))
        elapsed = (time.monotonic() - t0) * 1000.0
        is_err = bool(getattr(res, "isError", False) or getattr(res, "is_error", False))
        METRICS_REGISTRY.record_call(tool_name, elapsed, error=is_err)
        raw_items = getattr(res, "content", None)
        if raw_items is None and isinstance(res, list):
            raw_items = res
        items_out: list[dict[str, Any]] = []
        for item in raw_items or ():
            if isinstance(item, TextContent) or hasattr(item, "text"):
                items_out.append({"type": "text", "text": REDACTOR.redact_text(str(getattr(item, "text", "")))})
            elif isinstance(item, ImageContent) or hasattr(item, "mimeType"):
                data_val = str(getattr(item, "data", ""))
                items_out.append({
                    "type": "image",
                    "mimeType": str(getattr(item, "mimeType", "image/png")),
                    "bytes": len(data_val),
                })
            else:
                items_out.append({"type": "raw", "value": REDACTOR.redact_text(str(item))})
        structured = getattr(res, "structuredContent", None) or getattr(res, "structured_content", None)
        if structured is None and isinstance(res, dict):
            structured = res
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": is_err,
            "content": items_out,
            "structured": structured,
        }
    except Exception as exc:  # noqa: BLE001
        METRICS_REGISTRY.record_call(tool_name, (time.monotonic() - t0) * 1000.0, error=True)
        return {
            "allowed": True,
            "live_execution": True,
            "profile": profile,
            "tool_name": tool_name,
            "is_error": True,
            "error": REDACTOR.redact_text(str(exc)) or type(exc).__name__,
        }
    finally:
        if auth_token is not None:
            auth_context_var.reset(auth_token)
        if created_ephemeral and oauth_provider is not None:
            try:
                oauth_provider.store.revoke_client(ephemeral_id)
            except Exception:  # noqa: BLE001
                pass


async def _serve_with_local_admin(main_server: Any, admin_server: Any | None) -> None:
    """Run main MCP server and strictly loopback Admin API server on the same asyncio loop."""
    admin_task: asyncio.Task[None] | None = None
    if admin_server is not None:
        admin_server.install_signal_handlers = lambda: None
        admin_task = asyncio.create_task(admin_server.serve(), name="mcp-local-admin-api")
    try:
        await main_server.serve()
    finally:
        if admin_server is not None:
            admin_server.should_exit = True
        if admin_task is not None:
            try:
                await asyncio.wait_for(admin_task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                admin_task.cancel()


def main() -> None:
    """Точка входа: и для `python backend/server.py`, и для GUI (`main.py --backend`)."""
    logger.info(f"{SERVER_NAME}: {RESOURCE_URL} (слушает {HOST}:{PORT})")
    if OAUTH_ENABLED:
        logger.info(
            "OAuth authorization server: enabled (local owner consent required; "
            "client-specific Windows/SSH access profiles)"
        )
        _LOGGING_MGR.info(
            "oauth",
            f"OAuth server initialized issuer={BASE_URL} default_profile={oauth_execution.profile()}",
            event_code="oauth_init",
        )
        _LOGGING_MGR.info("gateway", f"Gateway initialized profiles={len(GATEWAY_STORE.list_profiles())}", event_code="gateway_init")
        _LOGGING_MGR.info("tasks", "TaskManager initialized", event_code="tasks_init")
        _LOGGING_MGR.info("servers", "ManagedServers initialized", event_code="servers_init")
        _LOGGING_MGR.info("workspaces", "WorkspaceManager initialized", event_code="workspaces_init")
        _LOGGING_MGR.info("extensions", "ExtensionManager initialized", event_code="extensions_init")
        _LOGGING_MGR.info("ssh", "RemoteManager initialized", event_code="ssh_init")
        _LOGGING_MGR.info("automation", "Automation subsystem initialized", event_code="automation_init")
        _LOGGING_MGR.info(
            "computer_use",
            f"DesktopManager initialized enabled={DESKTOP_POLICY_STORE.load().enabled}",
            event_code="computer_use_init",
        )
        logger.info(
            "OAuth command policies: global_default=%s; registered_clients=%d; "
            "Windows allowlist=%d; SSH hosts=%d; SSH commands=%d; "
            "commands are not enabled for Safe clients",
            oauth_execution.profile(), len(oauth_provider.store.list_clients()),
            len(oauth_execution.policy()["windows"]),
            len(oauth_execution.policy()["hosts"]),
            len(oauth_execution.policy()["ssh_commands"]),
        )
        logger.info("OAuth execution audit: %s (no plaintext commands or tokens)", EXEC_AUDIT.path)
    else:
        logger.info("OAuth authorization server: disabled")
        logger.info(
            "Legacy tool profile: %s; execution tools: %s; SSH targets: %d; executables: %d",
            "advanced" if ADVANCED_TOOLS else "standard",
            "enabled" if EXECUTION_TOOLS else "disabled",
            len(ALLOWED_HOSTS) if EXECUTION_TOOLS else 0,
            len(ALLOWED_EXECUTABLES) if EXECUTION_TOOLS else 0,
        )
    mode = "JSON (временный адрес без SSE)" if JSON_RESPONSE else "SSE"
    query = "разрешён" if ALLOW_QUERY_TOKEN else "выключен"
    logger.info(f"Ответы: {mode}; токен в ссылке: {query}")
    if TOKEN_FROM_ENV:
        # Токен целиком не пишем: короткий токен маскируем полностью без раскрытия символов.
        masked = "•" * max(4, len(SECRET_TOKEN)) if len(SECRET_TOKEN) <= 8 else f"…{SECRET_TOKEN[-4:]}"
        logger.info(f"Токен: из MCP_SECRET_TOKEN ({masked})")

    import uvicorn
    main_server = uvicorn.Server(uvicorn.Config(build_app(), host=HOST, port=PORT))
    admin_server = (
        uvicorn.Server(
            uvicorn.Config(
                build_local_admin_app(),
                host=ADMIN_HOST,
                port=ADMIN_PORT,
                access_log=False,
                log_level="warning",
            )
        )
        if ADMIN_PORT > 0
        else None
    )
    try:
        asyncio.run(_serve_with_local_admin(main_server, admin_server))
    finally:
        _purge_stale_ephemeral_oauth_clients()
        try:
            asyncio.run(TASK_MANAGER.close())
        except Exception:
            pass
        try:
            asyncio.run(GATEWAY_ROUTER.close_all())
        except Exception:
            pass
        REMOTE_MANAGER.close()
        EXTENSION_MANAGER.shutdown_all()
        WORKSPACE_MANAGER.close()
        MANAGED_SERVERS.close()
        PROCESS_RUNNER.close()
        _LOGGING_MGR.shutdown(timeout=1.5)


if __name__ == "__main__":
    main()
