import asyncio
import hmac
import logging
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import paramiko
from pydantic import AnyHttpUrl
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response

if __package__:
    from .transport_config import transport_allowlists, validate_mcp_path, validate_public_url
    from .security_policy import (
        MAX_WRITE_BYTES, allowed_ssh_host, enabled, exact_allowlist,
        parse_allowed_command, workspace_path,
    )
else:
    from transport_config import transport_allowlists, validate_mcp_path, validate_public_url
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
ALLOW_QUERY_TOKEN = _env_flag("MCP_ALLOW_QUERY_TOKEN", False)
# Quick Tunnels (trycloudflare.com) не поддерживают SSE — там отвечаем обычным JSON.
JSON_RESPONSE = _env_flag("MCP_JSON_RESPONSE", PUBLIC_HOST.endswith(".trycloudflare.com"))

WORKSPACE_DIR = Path(os.environ.get("MCP_WORKSPACE_DIR", os.getcwd())).resolve()
# All remote tools use one server-wide Bearer token at present. Keep privileged
# tools unregistered unless an administrator explicitly opts in.
ADVANCED_TOOLS = enabled(os.environ.get("MCP_ENABLE_ADVANCED"))
EXECUTION_TOOLS = ADVANCED_TOOLS and enabled(os.environ.get("MCP_ENABLE_EXECUTION"))
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
    * ?token=… — если разрешено и токен верный, превращается в заголовок
      Authorization: Bearer. Только так SDK его примет: его проверка смотрит
      исключительно в заголовок. Сам токен вырезается из query string, чтобы не
      попасть в access-лог uvicorn (а значит, в окно GUI).
    * Всё остальное проверяет SDK: без верного токена /mcp ответит 401 с правильным
      WWW-Authenticate. Мы только пишем в аудит неудачные попытки.
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

        if auth_header.lower().startswith("bearer "):
            if not _token_ok(auth_header[7:].strip()):
                logger.warning(f"Неверный токен в заголовке ← {client[0]} {scope.get('method')} {path}")
        else:
            query_token = self._pop_query_token(scope)
            if query_token is not None:
                if not ALLOW_QUERY_TOKEN:
                    logger.warning(f"Токен в ссылке отключён в настройках ← {client[0]} {path}")
                elif _token_ok(query_token):
                    scope["headers"] = [(k, v) for k, v in scope["headers"] if k.lower() != b"authorization"]
                    scope["headers"].append((b"authorization", f"Bearer {query_token}".encode()))
                else:
                    logger.warning(f"Неверный токен в ссылке ← {client[0]} {scope.get('method')} {path}")
            elif path.startswith(MCP_PATH):
                # Общедоступные /.well-known/… (поиск OAuth-метаданных) не логируем.
                logger.warning(f"Запрос без токена ← {client[0]} {scope.get('method')} {path} (ответ 401)")

        await self.app(scope, receive, send)

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
    issuer_url=AnyHttpUrl(BASE_URL),
    resource_server_url=AnyHttpUrl(RESOURCE_URL),
    required_scopes=[],
    validate_token_resource=True,  # убирает MCPDeprecationWarning; токены для чужого адреса отклоняются
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

mcp = MCPServer(
    SERVER_NAME,
    token_verifier=SimpleTokenVerifier(),
    auth=auth_settings,
)

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
    logger.info("Tool profile: %s; execution tools: %s; SSH targets: %d; executables: %d",
                "advanced" if ADVANCED_TOOLS else "standard",
                "enabled" if EXECUTION_TOOLS else "disabled",
                len(ALLOWED_HOSTS) if EXECUTION_TOOLS else 0,
                len(ALLOWED_EXECUTABLES) if EXECUTION_TOOLS else 0)
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
