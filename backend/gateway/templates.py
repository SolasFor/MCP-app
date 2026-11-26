"""Verified, real-world MCP Gateway upstream server templates across 7 categories."""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.gateway.models import (
    AUTH_BEARER,
    AUTH_NONE,
    ISOLATION_PER_CLIENT,
    ISOLATION_SHARED,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    UpstreamServerProfile,
)

TEMPLATE_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("filesystem", "Файловая система", "Filesystem"),
    ("git_github", "Git и GitHub", "Git & GitHub"),
    ("databases", "Базы данных", "Databases"),
    ("browser", "Браузер", "Browser"),
    ("development", "Разработка", "Development"),
    ("cad_engineering", "CAD и инженерия", "CAD & Engineering"),
    ("office", "Офис и документы", "Office & Documents"),
)


@dataclass(frozen=True)
class TemplateField:
    key: str
    label_ru: str
    label_en: str
    placeholder: str = ""
    default: str = ""
    secret: bool = False
    required: bool = True
    kind: str = "text"  # text | dir | file | secret


@dataclass(frozen=True)
class GatewayServerTemplate:
    template_id: str
    category: str
    title_ru: str
    title_en: str
    description_ru: str
    description_en: str
    transport: str
    command: str = ""
    args_template: tuple[str, ...] = ()
    url: str = ""
    auth_mode: str = AUTH_NONE
    required_runtime: str = ""
    package_source: str = ""
    session_isolation: str = ISOLATION_PER_CLIENT
    min_profile: str = "allowlist"
    timeout_seconds: float = 45.0
    notes_ru: str = ""
    notes_en: str = ""
    fields: tuple[TemplateField, ...] = field(default_factory=tuple)

    def build_profile(
        self,
        *,
        server_id: str | None = None,
        values: dict[str, str] | None = None,
    ) -> tuple[UpstreamServerProfile, dict[str, str], str | None]:
        """Materialize UpstreamServerProfile + secret env dict + optional bearer token."""
        vals = dict(values or {})
        resolved_args = []
        for raw in self.args_template:
            resolved_args.append(raw.format(**vals) if "{" in raw else raw)

        secret_env: dict[str, str] = {}
        bearer_token: str | None = None
        for fld in self.fields:
            v = str(vals.get(fld.key) or fld.default or "").strip()
            if fld.secret and v:
                if fld.key == "__bearer__":
                    bearer_token = v
                else:
                    secret_env[fld.key] = v

        prof = UpstreamServerProfile(
            server_id=(server_id or self.template_id).strip().lower(),
            name=self.title_en,
            transport=self.transport,
            enabled=True,
            autostart=False,
            command=self.command,
            args=tuple(resolved_args),
            cwd=str(vals.get("__cwd__") or "").strip(),
            url=self.url.format(**vals) if self.url and "{" in self.url else self.url,
            auth_mode=self.auth_mode if bearer_token else AUTH_NONE,
            allow_local_endpoint=False,
            session_isolation=self.session_isolation,
            min_profile=self.min_profile,
            timeout_seconds=self.timeout_seconds,
            approved_by_owner=True,
            notes=self.notes_en,
        )
        return prof, secret_env, bearer_token


VERIFIED_GATEWAY_TEMPLATES: tuple[GatewayServerTemplate, ...] = (
    # 1. Filesystem
    GatewayServerTemplate(
        template_id="filesystem",
        category="filesystem",
        title_ru="Filesystem MCP (Официальный)",
        title_en="Filesystem MCP (Official)",
        description_ru="Безопасный доступ только к указанному каталогу через @modelcontextprotocol/server-filesystem.",
        description_en="Scoped filesystem access to an explicitly allowed directory via @modelcontextprotocol/server-filesystem.",
        transport=TRANSPORT_STDIO,
        command="npx",
        args_template=("-y", "@modelcontextprotocol/server-filesystem", "{allowed_dir}"),
        required_runtime="npx",
        package_source="npm:@modelcontextprotocol/server-filesystem",
        notes_ru="Требуется Node.js (npx). Разрешает работу только внутри выбранного каталога.",
        notes_en="Requires Node.js (npx). Restricts operations strictly to the chosen directory.",
        fields=(
            TemplateField(
                key="allowed_dir",
                label_ru="Разрешённый каталог",
                label_en="Allowed directory",
                placeholder=r"C:\Users\...",
                kind="dir",
            ),
        ),
    ),
    # 2. Git & GitHub
    GatewayServerTemplate(
        template_id="git_local",
        category="git_github",
        title_ru="Git MCP (Локальный репозиторий)",
        title_en="Git MCP (Local Repository)",
        description_ru="Чтение истории, diff, статуса и веток локального Git-репозитория (mcp-server-git).",
        description_en="Inspect commits, diffs, status, and branches on a local Git repository (mcp-server-git).",
        transport=TRANSPORT_STDIO,
        command="uvx",
        args_template=("mcp-server-git", "--repository", "{repo_dir}"),
        required_runtime="uvx",
        package_source="pypi:mcp-server-git",
        notes_ru="Требуется uv (uvx). Выполняет операции только в выбранном репозитории.",
        notes_en="Requires uv (uvx). Scoped to the selected Git repository.",
        fields=(
            TemplateField(
                key="repo_dir",
                label_ru="Путь к Git-репозиторию",
                label_en="Git repository path",
                placeholder=r"D:\Coding\project",
                kind="dir",
            ),
        ),
    ),
    GatewayServerTemplate(
        template_id="github_remote",
        category="git_github",
        title_ru="GitHub MCP (Удалённый Streamable HTTP)",
        title_en="GitHub MCP (Remote Streamable HTTP)",
        description_ru="Официальный удалённый GitHub MCP endpoint (https://api.githubcopilot.com/mcp/).",
        description_en="Official GitHub remote MCP endpoint (https://api.githubcopilot.com/mcp/).",
        transport=TRANSPORT_STREAMABLE_HTTP,
        url="https://api.githubcopilot.com/mcp/",
        auth_mode=AUTH_BEARER,
        package_source="https://api.githubcopilot.com/mcp/",
        notes_ru="Укажите GitHub Personal Access Token (PAT) или авторизуйтесь через OAuth.",
        notes_en="Provide a GitHub Personal Access Token (PAT) or complete OAuth sign-in.",
        fields=(
            TemplateField(
                key="__bearer__",
                label_ru="GitHub PAT / Bearer-токен",
                label_en="GitHub PAT / Bearer token",
                placeholder="ghp_... / github_pat_...",
                secret=True,
                required=False,
                kind="secret",
            ),
        ),
    ),
    # 3. Databases
    GatewayServerTemplate(
        template_id="sqlite",
        category="databases",
        title_ru="SQLite MCP",
        title_en="SQLite MCP",
        description_ru="SQL-запросы и анализ схемы к локальному файлу SQLite через mcp-server-sqlite.",
        description_en="Query and inspect a local SQLite database file via mcp-server-sqlite.",
        transport=TRANSPORT_STDIO,
        command="uvx",
        args_template=("mcp-server-sqlite", "--db-path", "{db_path}"),
        required_runtime="uvx",
        package_source="pypi:mcp-server-sqlite",
        notes_ru="Требуется uv (uvx).",
        notes_en="Requires uv (uvx).",
        fields=(
            TemplateField(
                key="db_path",
                label_ru="Файл базы данных (.db / .sqlite3)",
                label_en="SQLite database file",
                placeholder=r"D:\data\app.sqlite3",
                kind="file",
            ),
        ),
    ),
    GatewayServerTemplate(
        template_id="postgres",
        category="databases",
        title_ru="PostgreSQL MCP",
        title_en="PostgreSQL MCP",
        description_ru="Только чтение и анализ схемы PostgreSQL через @modelcontextprotocol/server-postgres.",
        description_en="Read-only PostgreSQL queries and schema inspection via @modelcontextprotocol/server-postgres.",
        transport=TRANSPORT_STDIO,
        command="npx",
        args_template=("-y", "@modelcontextprotocol/server-postgres"),
        required_runtime="npx",
        package_source="npm:@modelcontextprotocol/server-postgres",
        notes_ru="Строка подключения хранится в зашифрованном SecretStore.",
        notes_en="Connection string is stored in encrypted SecretStore.",
        fields=(
            TemplateField(
                key="POSTGRES_URL",
                label_ru="Строка подключения PostgreSQL (в SecretStore)",
                label_en="PostgreSQL connection URI (SecretStore)",
                placeholder="postgresql://readonly:***@localhost:5432/db",
                secret=True,
                kind="secret",
            ),
        ),
    ),
    # 4. Browser
    GatewayServerTemplate(
        template_id="playwright",
        category="browser",
        title_ru="Playwright MCP (Браузер)",
        title_en="Playwright MCP (Browser)",
        description_ru="Автоматизация веб-страниц и DOM через официальный @playwright/mcp.",
        description_en="Web page automation and accessibility snapshots via official @playwright/mcp.",
        transport=TRANSPORT_STDIO,
        command="npx",
        args_template=("-y", "@playwright/mcp@latest"),
        required_runtime="npx",
        package_source="npm:@playwright/mcp",
        timeout_seconds=60.0,
        notes_ru="Требуется Node.js (npx) и установленные браузеры Playwright.",
        notes_en="Requires Node.js (npx) and Playwright browser binaries.",
        fields=(),
    ),
    # 5. Development
    GatewayServerTemplate(
        template_id="fetch",
        category="development",
        title_ru="Fetch MCP (Веб-страницы и документация)",
        title_en="Fetch MCP (Web & Docs)",
        description_ru="Загрузка и преобразование веб-страниц в Markdown через mcp-server-fetch.",
        description_en="Fetch web documentation and convert HTML to Markdown via mcp-server-fetch.",
        transport=TRANSPORT_STDIO,
        command="uvx",
        args_template=("mcp-server-fetch",),
        required_runtime="uvx",
        package_source="pypi:mcp-server-fetch",
        notes_ru="Требуется uv (uvx).",
        notes_en="Requires uv (uvx).",
    ),
    GatewayServerTemplate(
        template_id="memory",
        category="development",
        title_ru="Memory MCP (Граф знаний)",
        title_en="Memory MCP (Knowledge Graph)",
        description_ru="Локальный граф сущностей и заметок через @modelcontextprotocol/server-memory.",
        description_en="Local knowledge graph persistence via @modelcontextprotocol/server-memory.",
        transport=TRANSPORT_STDIO,
        command="npx",
        args_template=("-y", "@modelcontextprotocol/server-memory"),
        required_runtime="npx",
        package_source="npm:@modelcontextprotocol/server-memory",
    ),
    # 6. CAD & Engineering
    GatewayServerTemplate(
        template_id="solidworks",
        category="cad_engineering",
        title_ru="SolidWorks MCP (COM-сессия Windows)",
        title_en="SolidWorks MCP (Windows COM Session)",
        description_ru="Интеграция с установленным SolidWorks через COM API в сессии текущего пользователя.",
        description_en="Connect to SolidWorks in the interactive Windows user session via COM API.",
        transport=TRANSPORT_STDIO,
        command="python",
        args_template=("-m", "solidworks_mcp"),
        required_runtime="python",
        package_source="pypi:solidworks_mcp",
        session_isolation=ISOLATION_SHARED,
        timeout_seconds=60.0,
        notes_ru="Требует активной сессии Windows, установленного SolidWorks и явного подтверждения владельца.",
        notes_en="Requires interactive Windows session, installed SolidWorks, and explicit owner approval.",
    ),
    # 7. Office & Documents
    GatewayServerTemplate(
        template_id="markitdown",
        category="office",
        title_ru="MarkItDown MCP (Word / Excel / PDF / PPTX)",
        title_en="MarkItDown MCP (Office & PDF)",
        description_ru="Конвертация документов Office и PDF в структурированный Markdown через markitdown-mcp.",
        description_en="Convert Office documents and PDFs to Markdown via official markitdown-mcp.",
        transport=TRANSPORT_STDIO,
        command="uvx",
        args_template=("markitdown-mcp",),
        required_runtime="uvx",
        package_source="pypi:markitdown-mcp",
        notes_ru="Требуется uv (uvx).",
        notes_en="Requires uv (uvx).",
    ),
)


def list_templates(category: str | None = None) -> list[GatewayServerTemplate]:
    if not category:
        return list(VERIFIED_GATEWAY_TEMPLATES)
    return [tpl for tpl in VERIFIED_GATEWAY_TEMPLATES if tpl.category == category]


def get_template(template_id: str) -> GatewayServerTemplate | None:
    for tpl in VERIFIED_GATEWAY_TEMPLATES:
        if tpl.template_id == template_id:
            return tpl
    return None
