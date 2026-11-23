import asyncio
import hmac
import logging
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import paramiko
from pydantic import AnyHttpUrl
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response

if __package__:
    from .transport_config import transport_allowlists, validate_mcp_path, validate_public_url
    from .oauth_provider import LocalConsentOAuthProvider, READ_SCOPE
    from .oauth_store import default_store_path
    from .oauth_execution import ExecutionApprovals
    from .execution_audit import ExecutionAudit, classify_command_output
    from .tool_permissions import (
        EXEC_WINDOWS, EXEC_SSH, make_tool_middleware,
        require_execution_permission,
    )
    from .security_policy import (
        MAX_WRITE_BYTES, allowed_ssh_host, enabled, exact_allowlist,
        parse_allowed_command, workspace_path,
    )
else:
    from transport_config import transport_allowlists, validate_mcp_path, validate_public_url
    from oauth_provider import LocalConsentOAuthProvider, READ_SCOPE
    from oauth_store import default_store_path
    from oauth_execution import ExecutionApprovals
    from execution_audit import ExecutionAudit, classify_command_output
    from tool_permissions import (
        EXEC_WINDOWS, EXEC_SSH, make_tool_middleware,
        require_execution_permission,
    )
    from security_policy import (
        MAX_WRITE_BYTES, allowed_ssh_host, enabled, exact_allowlist,
        parse_allowed_command, workspace_path,
    )

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
EXEC_AUDIT = ExecutionAudit(Path(AUDIT_LOG).with_name("mcp_execution_audit.jsonl"))


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


SECRET_TOKEN = os.environ.get("MCP_SECRET_TOKEN", "").strip()
TOKEN_FROM_ENV = bool(SECRET_TOKEN)
if not SECRET_TOKEN:
    SECRET_TOKEN = secrets.token_urlsafe(24)
    # Только при ручном запуске без GUI: иначе временный токен негде узнать.
    logger.warning("MCP_SECRET_TOKEN not set: temporary token generated (never logged). Set a token before remote use.")

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
BASE_URL = f"{_public.scheme}://{_public.netloc}"
RESOURCE_URL = str(AnyHttpUrl(PUBLIC_URL))

# Проверка живости для GUI (HealthMonitor раз в 2 с). Без токена и без записи в аудит.
HEALTH_PATH = os.environ.get("MCP_HEALTH_PATH", "/health")
# ?token=… в ссылке — для клиентов, в которых нельзя задать заголовок Authorization.
ALLOW_QUERY_TOKEN = False  # OAuth or Bearer header only; forbid ?token= in public URLs
# Quick Tunnels (trycloudflare.com) не поддерживают SSE — там отвечаем обычным JSON.
JSON_RESPONSE = _env_flag("MCP_JSON_RESPONSE", PUBLIC_HOST.endswith(".trycloudflare.com"))

WORKSPACE_DIR = Path(os.environ.get("MCP_WORKSPACE_DIR", os.getcwd())).resolve()
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

        async def observe_auth_result(message):
            if message["type"] == "http.response.start" and path.rstrip("/") == MCP_PATH:
                status = message["status"]
                if status in (401, 403):
                    if is_bearer:
                        logger.warning(
                            "MCP авторизация отклонена HTTP %d ← %s %s %s",
                            status, client[0], scope.get("method"), path,
                        )
                    elif scope.get("method") not in ("HEAD", "OPTIONS"):
                        # Anonymous HEAD is a common OAuth discovery probe.
                        logger.info(
                            "MCP запрос без Bearer отклонён HTTP %d ← %s %s",
                            status, client[0], scope.get("method"),
                        )
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
oauth_provider = (
    LocalConsentOAuthProvider(
        BASE_URL, RESOURCE_URL, SECRET_TOKEN,
        store_path=os.environ.get("MCP_OAUTH_STORE_PATH") or default_store_path(),
    )
    if OAUTH_ENABLED else None
)
oauth_execution = ExecutionApprovals(oauth_provider.store) if oauth_provider is not None else None

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
        middleware=[make_tool_middleware(oauth_provider.store, oauth_execution)],
    )
    if oauth_provider is not None
    else MCPServer(SERVER_NAME, auth=auth_settings, token_verifier=SimpleTokenVerifier())
)
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


@mcp.tool()
def server_info() -> str:
    """Safe read-only connectivity check; returns no machine paths or secrets."""
    return "MCP app ready; transport=streamable-http; profile=standard" if not ADVANCED_TOOLS else (
        "MCP app ready; transport=streamable-http; profile=advanced"
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


async def _oauth_windows_run(command: str, *, full: bool) -> str:
    """Bounded execution, with shell semantics only in explicit full mode."""
    program = command.strip().split(" ", 1)[0].lower()
    if not full:
        if program == "pwd" and command.strip().lower() == "pwd":
            return str(WORKSPACE_DIR)
        if program in ("ls", "dir") and command.strip().lower() == program:
            return truncate_output("\n".join(sorted(
                path.name for path in WORKSPACE_DIR.iterdir()
            )))
        if program == "echo":
            return truncate_output(
                command.strip()[5:] if command.strip().lower().startswith("echo ") else ""
            )
        try:
            argv = _restricted_windows_argv(command)
        except (OSError, ValueError, IndexError) as exc:
            return f"❌ Недопустимая команда белого списка: {type(exc).__name__}"
        if not argv:
            return "❌ Недопустимые аргументы встроенной команды."
    else:
        # Full mode deliberately permits Windows command interpreter syntax:
        # pipes, built-ins, redirection, chained commands. This is an
        # explicit high-risk owner choice, not the default or allowlist path.
        if os.name == "nt":
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            executable = str(system_root / "System32" / "cmd.exe")
            argv = [executable, "/d", "/s", "/c", command]
        else:
            import shlex
            argv = shlex.split(command)
        if not argv:
            return "❌ Пустая команда."
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=str(WORKSPACE_DIR), stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return "❌ Команда превысила лимит 15 секунд."
        return (
            f"Exit code: {process.returncode}\n"
            f"STDOUT:\n{truncate_output(stdout.decode(errors='replace'))}\n"
            f"STDERR:\n{truncate_output(stderr.decode(errors='replace'))}"
        )
    except (OSError, ValueError) as exc:
        return f"❌ Не удалось выполнить Windows-команду: {type(exc).__name__}"


@_conditional_tool(OAUTH_ENABLED)
async def oauth_windows_command(command: str) -> str:
    """Run a Windows command immediately in allowlist/full access mode.

    In safe mode this tool is hidden and blocked. Allowlist matches exact
    owner entries with no command shell; full mode allows arbitrary commands.
    There is NO extra per-command confirmation or approval ticket.
    """
    client_id = require_execution_permission(
        EXEC_WINDOWS, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile = oauth_execution.profile_for(client_id)
    if not oauth_execution.can_request(client_id, "windows", command=command):
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile,
            event="denied", command=command,
        )
        return "❌ Эта Windows-команда недоступна в выбранном режиме."
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="windows", profile=profile,
        event="started", command=command, action_id=action_id,
    )
    try:
        output = await _oauth_windows_run(command, full=profile == "full")
    except BaseException:
        EXEC_AUDIT.record(
            client_id=client_id, kind="windows", profile=profile,
            event="failed", command=command, action_id=action_id,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        raise
    outcome, exit_code = classify_command_output(output)
    # Shell-free builtins return their output without an exit-code prefix.
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
async def oauth_ssh_command(
    host: str, command: str, user: str = "", port: int = 22,
) -> str:
    """Run SSH command immediately when the access scenario permits it.

    The default safe mode blocks SSH. Allowlist requires exact host+command.
    Full access allows arbitrary hosts/commands, but still rejects unknown
    SSH host keys (Paramiko RejectPolicy).
    """
    client_id = require_execution_permission(
        EXEC_SSH, oauth_provider.store if oauth_provider else None, oauth_execution
    )
    assert oauth_execution is not None
    profile = oauth_execution.profile_for(client_id)
    if not oauth_execution.can_request(
        client_id, "ssh", command=command, host=host, user=user, port=port
    ):
        EXEC_AUDIT.record(
            client_id=client_id, kind="ssh", profile=profile,
            event="denied", command=command, host=host, port=port,
        )
        return "❌ SSH-хост или команда недоступны в выбранном режиме."
    action_id = secrets.token_hex(8)
    started = time.monotonic()
    EXEC_AUDIT.record(
        client_id=client_id, kind="ssh", profile=profile,
        event="started", command=command, host=host, port=port,
        action_id=action_id,
    )
    try:
        output = await asyncio.to_thread(_sync_ssh_exec, host, user, command, port, 12)
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


@_conditional_tool(EXECUTION_TOOLS and bool(ALLOWED_EXECUTABLES))
async def run_local_command(command: str, timeout: int = 30, cwd: str | None = None) -> str:
    """Execute one explicitly allowlisted executable, without a command shell.

    This is an administrator-only capability. The allowlist must not contain
    interpreters or programs that can run arbitrary scripts.
    """
    try:
        argv = parse_allowed_command(command, ALLOWED_EXECUTABLES)
        work_dir = workspace_path(WORKSPACE_DIR, cwd) if cwd else WORKSPACE_DIR
        if not work_dir.is_dir():
            return "❌ Рабочая директория не существует."
    except ValueError as exc:
        return f"❌ Команда запрещена: {exc}"
    timeout = min(max(timeout, 1), 120)
    logger.info("[LOCAL] executable=%s (arguments redacted)", Path(argv[0]).name)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=str(work_dir), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            f"Exit code: {proc.returncode}\n✅ STDOUT:\n{truncate_output(stdout.decode(errors='replace'))}"
            f"\n❌ STDERR:\n{truncate_output(stderr.decode(errors='replace'))}"
        )
    except asyncio.TimeoutError:
        if proc:
            proc.kill()
            await proc.wait()
        return f"❌ Таймаут: команда превысила лимит {timeout} сек."
    except OSError as exc:
        return f"❌ Не удалось запустить разрешённую программу: {type(exc).__name__}"

def _sync_ssh_exec(host: str, user: str, command: str, port: int, timeout: int) -> str:
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
        if not actual_user: actual_user = host_cfg.get("user")
        if port == 22 and "port" in host_cfg: actual_port = int(host_cfg["port"])
        key_filename = host_cfg.get("identityfile")

    try:
        client.connect(hostname=actual_host, port=actual_port, username=actual_user, key_filename=key_filename, timeout=10, banner_timeout=10)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        # Paramiko recv_exit_status() alone can wait forever if the remote
        # program never exits. Enforce a total deadline before reading output.
        deadline = time.monotonic() + min(max(timeout, 1), 30)
        while not stdout.channel.exit_status_ready():
            if time.monotonic() >= deadline:
                stdout.channel.close()
                return "❌ SSH command timed out."
            time.sleep(0.1)
        exit_status = stdout.channel.recv_exit_status()
        out_str = truncate_output(stdout.read().decode(errors="replace"))
        err_str = truncate_output(stderr.read().decode(errors="replace"))
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

# ==========================================
# 6. ЗАПУСК
# ==========================================

def build_app():
    """Starlette-приложение MCP с нашим middleware снаружи."""
    app = mcp.streamable_http_app(
        json_response=JSON_RESPONSE,
        streamable_http_path=MCP_PATH,
        transport_security=TRANSPORT_SECURITY,
    )
    # add_middleware ставит наш слой СНАРУЖИ middleware SDK: заголовок из ?token=
    # появляется до того, как SDK проверит авторизацию.
    app.add_middleware(HybridAuthMiddleware)
    return app


def main() -> None:
    """Точка входа: и для `python backend/server.py`, и для GUI (`main.py --backend`)."""
    logger.info(f"{SERVER_NAME}: {RESOURCE_URL} (слушает {HOST}:{PORT})")
    if OAUTH_ENABLED:
        logger.info(
            "OAuth authorization server: enabled (local owner consent required; "
            "client-specific Windows/SSH access profiles)"
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
        # Токен целиком не пишем: лог уходит в mcp_audit.log и в окно GUI.
        logger.info(f"Токен: из MCP_SECRET_TOKEN (…{SECRET_TOKEN[-4:]})")

    import uvicorn
    uvicorn.run(build_app(), host=HOST, port=PORT)


if __name__ == "__main__":
    main()
