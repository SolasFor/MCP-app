import asyncio
import hmac
import inspect
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
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

# ==========================================
# 1. КОНФИГУРАЦИЯ И ЛОГИРОВАНИЕ
# ==========================================
# Все параметры приходят из переменных окружения. Их задаёт GUI (ServiceManager);
# при ручном запуске `python backend/server.py` работают значения по умолчанию.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("souron_audit.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("SouronControl")


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
    logger.warning(f"MCP_SECRET_TOKEN не задан! Сгенерирован временный токен: {SECRET_TOKEN}")

MCP_PATH = "/mcp"  # путь streamable-http эндпоинта MCP SDK
_base_domain = os.environ.get("MCP_BASE_DOMAIN", "https://mcp.souron.space").rstrip("/")
# Полный публичный адрес: свой домен или временный *.trycloudflare.com от GUI.
PUBLIC_URL = (os.environ.get("MCP_PUBLIC_URL") or f"{_base_domain}{MCP_PATH}").rstrip("/")
_public = urlsplit(PUBLIC_URL)
PUBLIC_HOST = (_public.netloc or "").lower()
BASE_URL = f"{_public.scheme}://{_public.netloc}"
# Ровно та же строка, что и в AuthSettings.resource_server_url: при validate_token_resource=True
# SDK сравнивает с ней AccessToken.resource, и любое расхождение даст 401.
RESOURCE_URL = str(AnyHttpUrl(PUBLIC_URL))

# Слушаем только localhost: cloudflared работает на этой же машине, а 0.0.0.0 открыл бы
# run_local_command всей локальной сети. MCP_HOST=0.0.0.0 — если нужен доступ из LAN.
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))

# Проверка живости для GUI (HealthMonitor раз в 2 с). Без токена и без записи в аудит.
HEALTH_PATH = os.environ.get("MCP_HEALTH_PATH", "/health")
# ?token=… в ссылке — для клиентов, в которых нельзя задать заголовок Authorization.
ALLOW_QUERY_TOKEN = _env_flag("MCP_ALLOW_QUERY_TOKEN", True)
# Quick Tunnels (trycloudflare.com) не поддерживают SSE — там отвечаем обычным JSON.
JSON_RESPONSE = _env_flag("MCP_JSON_RESPONSE", PUBLIC_HOST.endswith(".trycloudflare.com"))

WORKSPACE_DIR = Path(os.environ.get("MCP_WORKSPACE_DIR", os.getcwd())).resolve()
ALLOWED_HOSTS = {h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()}

MAX_OUTPUT_LEN = 8000
DANGEROUS_PATTERNS = [
    r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(/|\*|~)",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r":\(\)\{\s*:\|:&\s*\};:",
]

def check_command_safety(command: str) -> str | None:
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return "❌ Заблокировано политикой безопасности (совпадение с запрещенным паттерном)."
    return None

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
            return AccessToken(token=token, client_id="souron-user", scopes=[], resource=RESOURCE_URL)
        return None

# ==========================================
# 3. ИНИЦИАЛИЗАЦИЯ СЕРВЕРА
# ==========================================

def _accepts(func, name: str) -> bool:
    """Принимает ли функция SDK такой аргумент (параметры меняются между версиями)."""
    try:
        return name in inspect.signature(func).parameters
    except (TypeError, ValueError):
        return False


auth_settings = AuthSettings(
    issuer_url=AnyHttpUrl(BASE_URL),
    resource_server_url=AnyHttpUrl(RESOURCE_URL),
    required_scopes=[],
    validate_token_resource=True,  # убирает MCPDeprecationWarning; токены для чужого адреса отклоняются
)

# Проверку Host/Origin оставляем SDK по умолчанию (с ней всё уже работало): явный
# белый список Origin мог бы отсечь настоящих клиентов. Защита — Bearer-токен.
# json_response в зависимости от версии SDK принимает либо конструктор,
# либо streamable_http_app() — передаём туда, где он есть.
_transport_options = {"json_response": JSON_RESPONSE}
_ctor_options = {k: v for k, v in _transport_options.items() if _accepts(MCPServer.__init__, k)}

mcp = MCPServer(
    "SouronControl",
    token_verifier=SimpleTokenVerifier(),
    auth=auth_settings,
    **_ctor_options,
)

# ==========================================
# 4. MCP-РЕСУРСЫ (Контекст)
# ==========================================

@mcp.resource("system://environment")
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

@mcp.tool()
async def run_local_command(command: str, timeout: int = 30, cwd: str | None = None) -> str:
    if err := check_command_safety(command):
        return err
    timeout = min(max(timeout, 1), 120)
    work_dir = Path(cwd).resolve() if cwd else WORKSPACE_DIR
    logger.info(f"[LOCAL] cwd={work_dir} | cmd={command}")

    proc = None
    try:
        proc = await asyncio.create_subprocess_shell(
            command, cwd=str(work_dir), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out_str = truncate_output(stdout.decode(errors="replace"))
        err_str = truncate_output(stderr.decode(errors="replace"))
        return f"Exit code: {proc.returncode}\n✅ STDOUT:\n{out_str}\n❌ STDERR:\n{err_str}"
    except asyncio.TimeoutError:
        if proc: proc.kill(); await proc.wait()
        return f"❌ Таймаут: команда превысила лимит {timeout} сек."
    except Exception as e:
        return f"❌ Ошибка выполнения: {e}"

def _sync_ssh_exec(host: str, user: str, command: str, port: int, timeout: int) -> str:
    client = paramiko.SSHClient()
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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

@mcp.tool()
async def run_ssh_command(host: str, command: str, user: str = "", port: int = 22, timeout: int = 30) -> str:
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        return f"❌ Отказано: хост '{host}' отсутствует в белом списке."
    if len(command) > 2000:
        return "❌ Отказано: команда слишком длинная."
    if err := check_command_safety(command):
        return err

    timeout = min(max(timeout, 1), 120)
    logger.info(f"[SSH] {user or '<from-ssh-config>'}@{host}:{port} | cmd={command}")
    try:
        return await asyncio.to_thread(_sync_ssh_exec, host, user, command, port, timeout)
    except Exception as e:
        return f"❌ SSH Ошибка: {e}"

@mcp.tool()
def read_workspace_file(relative_path: str) -> str:
    target = (WORKSPACE_DIR / relative_path).resolve()
    if not target.is_relative_to(WORKSPACE_DIR):
        return "❌ Доступ запрещен: выход за пределы WORKSPACE_DIR."
    if not target.is_file():
        return f"❌ Файл не найден: {relative_path}"
    return truncate_output(target.read_text(encoding="utf-8", errors="replace"))

@mcp.tool()
def write_workspace_file(relative_path: str, content: str) -> str:
    target = (WORKSPACE_DIR / relative_path).resolve()
    if not target.is_relative_to(WORKSPACE_DIR):
        return "❌ Доступ запрещен: выход за пределы WORKSPACE_DIR."
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    logger.info(f"[FILE WRITE] {target} ({len(content)} bytes)")
    return f"✅ Файл сохранен: {relative_path} ({len(content)} байт)"

# ==========================================
# 6. ЗАПУСК
# ==========================================

def build_app():
    """Starlette-приложение MCP с нашим middleware снаружи."""
    app_options = {
        k: v for k, v in _transport_options.items()
        if k not in _ctor_options and _accepts(mcp.streamable_http_app, k)
    }
    if JSON_RESPONSE and "json_response" not in _ctor_options and "json_response" not in app_options:
        logger.warning("Эта версия MCP SDK не поддерживает json_response — через временный адрес "
                       "потоковые (SSE) ответы могут зависать.")
    app = mcp.streamable_http_app(**app_options)
    # add_middleware ставит наш слой СНАРУЖИ middleware SDK: заголовок из ?token=
    # появляется до того, как SDK проверит авторизацию.
    app.add_middleware(HybridAuthMiddleware)
    return app


def main() -> None:
    """Точка входа: и для `python backend/server.py`, и для GUI (`main.py --backend`)."""
    logger.info(f"Сервер запущен: {RESOURCE_URL} (слушает {HOST}:{PORT})")
    mode = "JSON (временный адрес без SSE)" if JSON_RESPONSE else "SSE"
    query = "разрешён" if ALLOW_QUERY_TOKEN else "выключен"
    logger.info(f"Ответы: {mode}; токен в ссылке (?token=): {query}")
    if TOKEN_FROM_ENV:
        # Токен целиком не пишем: лог уходит в souron_audit.log и в окно GUI.
        logger.info(f"Токен: из MCP_SECRET_TOKEN (…{SECRET_TOKEN[-4:]})")

    import uvicorn
    uvicorn.run(build_app(), host=HOST, port=PORT)


if __name__ == "__main__":
    main()
