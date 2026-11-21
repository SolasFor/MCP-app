import asyncio
import hmac
import logging
import os
import re
import secrets
from pathlib import Path
import paramiko
from pydantic import AnyHttpUrl
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

# Импорты для перехвата HTTP-запросов
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# ==========================================
# 1. КОНФИГУРАЦИЯ И ЛОГИРОВАНИЕ
# ==========================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("souron_audit.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("SouronControl")

SECRET_TOKEN = os.environ.get("MCP_SECRET_TOKEN")
TOKEN_FROM_ENV = bool(SECRET_TOKEN)
if not SECRET_TOKEN:
    SECRET_TOKEN = secrets.token_urlsafe(24)
    logger.warning(f"MCP_SECRET_TOKEN не задан! Сгенерирован временный токен: {SECRET_TOKEN}")

BASE_DOMAIN = os.environ.get("MCP_BASE_DOMAIN", "https://mcp.souron.space").rstrip("/")
# Ровно та же строка, что и в AuthSettings.resource_server_url: при validate_token_resource=True
# SDK сравнивает с ней AccessToken.resource, и любое расхождение даст 401.
RESOURCE_URL = str(AnyHttpUrl(f"{BASE_DOMAIN}/mcp"))

# Слушаем только localhost: cloudflared работает на этой же машине, а 0.0.0.0 открыл бы
# run_local_command всей локальной сети. MCP_HOST=0.0.0.0 — если нужен доступ из LAN.
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))  # должен совпадать с server_port в settings.json

# Проверка живости для GUI (HealthMonitor раз в 2 с). Без токена и без записи в аудит.
HEALTH_PATH = "/health"

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
# 2. ГИБРИДНАЯ АУТЕНТИФИКАЦИЯ (Middleware + TokenVerifier)
# ==========================================

class HybridAuthMiddleware(BaseHTTPMiddleware):
    """Перехватывает запросы ДО MCP. Проверяет токен в заголовке или URL."""
    async def dispatch(self, request: Request, call_next):
        # 0. Health-check: отвечаем сразу, до проверки токена и логирования.
        # Именно по пути, а НЕ по IP 127.0.0.1: через туннель ВСЕ внешние запросы
        # тоже приходят с 127.0.0.1 (cloudflared подключается локально).
        # Эндпоинт ничего не раскрывает, поэтому его доступность снаружи безопасна.
        if request.url.path == HEALTH_PATH:
            return JSONResponse({"status": "ok"})

        # 1. Проверка заголовка Authorization
        auth_header = request.headers.get("Authorization", "")
        token = None
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            
        # 2. Если в заголовке нет, проверяем query-параметр ?token=
        if not token:
            token = request.query_params.get("token")

        # 3. Валидация
        if token:
            if not hmac.compare_digest(token.encode(), SECRET_TOKEN.encode()):
                logger.warning(f"Неудачная авторизация (неверный токен) с IP: {request.client.host}")
                return JSONResponse({"error": "Unauthorized: Invalid token"}, status_code=401)
            # Если токен верный, пропускаем запрос дальше
            return await call_next(request)
        
        # 4. Если токена нет вообще (например, ChatGPT в режиме No Auth)
        # ВНИМАНИЕ: Здесь мы пропускаем запрос, чтобы ChatGPT мог работать.
        # Если вы хотите запретить анонимный доступ, верните 401 (см. ниже).
        logger.warning(f"Запрос без токена с IP: {request.client.host} → {request.method} {request.url.path}")
        
        # Раскомментируйте строку ниже, если хотите ЗАБЛОКИРОВАТЬ анонимные запросы
        # return JSONResponse({"error": "Unauthorized: Token required"}, status_code=401)
        
        return await call_next(request)

class SimpleTokenVerifier(TokenVerifier):
    """Оставлен для клиентов, которые используют OAuth2-интроспекцию."""
    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token.encode(), SECRET_TOKEN.encode()):
            # resource обязателен при validate_token_resource=True: без него SDK отклонит
            # даже верный токен. Наш токен выпускается только для этого сервера.
            return AccessToken(token=token, client_id="souron-user", scopes=[], resource=RESOURCE_URL)
        return None

# ==========================================
# 3. ИНИЦИАЛИЗАЦИЯ СЕРВЕРА
# ==========================================

mcp = MCPServer(
    "SouronControl",
    token_verifier=SimpleTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_DOMAIN),
        resource_server_url=AnyHttpUrl(RESOURCE_URL),
        required_scopes=[],
        validate_token_resource=True,
    ),
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

def main() -> None:
    """Точка входа: и для `python backend/server.py`, и для GUI (`main.py --backend`)."""
    logger.info(f"Сервер запущен: {RESOURCE_URL} (слушает {HOST}:{PORT})")
    if TOKEN_FROM_ENV:
        # Токен целиком не пишем: лог уходит в souron_audit.log и в окно GUI.
        logger.info(f"Токен: из MCP_SECRET_TOKEN (…{SECRET_TOKEN[-4:]})")

    # Получаем базовое приложение Starlette из MCP
    app = mcp.streamable_http_app()
    
    # Оборачиваем его в наш Middleware для проверки токена (и /health)
    app.add_middleware(HybridAuthMiddleware)
    
    # Запускаем через uvicorn
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()
