# MCP-app — технический аудит (PR-01)

**Дата:** 2026-11-23 · **База:** `main` @ `ceca2c6` (v0.6.x, PR #1–#4) · **SDK для сверки:** `mcp` 2.3.0 (PyPI)

**Метод:** статический анализ исходников и сверка с кодом и документацией официального MCP Python SDK.
Приложение **не запускалось**, реальные клиенты не подключались. Воспроизведение на проводе —
`tools/mcp_probe.py` (§5); после его запуска статусы в таблицах обновляются.

| Статус | Значение |
|---|---|
| **Код** | Подтверждено чтением исходника (цитата приведена) |
| **Гипотеза** | Следует из кода/документации, нужен прогон `mcp_probe.py` |
| **Verified** | Подтверждено на живом сервере (пока ни одной находки) |
| **Blocked** | Нельзя проверить без внешнего аккаунта/сервиса |

---

## 1. Краткий вывод

Две независимые причины могут объяснять отказ Gemini, Notion и других облачных клиентов:

1. **Сервер авторизации объявлен, но не реализован (A1, Код).** Protected Resource Metadata указывает
   `authorization_servers` на тот же хост, где нет ни метаданных AS, ни `/authorize`, `/token`, `/register`.
   Клиенты, которые умеют только OAuth, не могут получить токен. Статический Bearer работает
   только там, где заголовок или `?token=` задаётся вручную.
2. **Возможный отказ по заголовку Host (B4, Гипотеза).** В SDK v2 есть логика «Auto-enable DNS
   rebinding protection» (`mcp/server/lowlevel/server.py`, `mcp/server/mcpserver/server.py`) и проверка Host/Origin
   в `mcp/server/transport_security.py`. Сервер слушает `127.0.0.1`, а cloudflared по умолчанию передаёт
   исходный `Host: <name>.trycloudflare.com`. Если защита включается с списком только localhost, локально
   всё работает, а через туннель — нет. `server.py` не задаёт `transport_security` явно. Проверка: `SEC-01`
   в `mcp_probe.py`.

Независимо от подключения: **любой обладатель токена получает выполнение произвольных команд
на Windows и SSH на любые хосты** (F1–F6). Открывать сервер облачным клиентам в текущем виде нельзя.

Индикаторы в GUI не проверяют MCP (C1–C4): «зелёный» = uvicorn ответил чем угодно и cloudflared
подключён к Cloudflare. Автоматических тестов в репозитории нет (есть только `app/selftest.py` для exe).

---

## 2. Таблица проблем

Формат: Проблема → Доказательство → Причина → Риск → Решение → Тест подтверждения.

### A. Авторизация

| ID | Проблема | Доказательство | Причина | Риск | Решение | Тест | Статус |
|---|---|---|---|---|---|---|---|
| A1 | AS объявлен, но не реализован | `backend/server.py`: `AuthSettings(issuer_url=AnyHttpUrl(BASE_URL), resource_server_url=AnyHttpUrl(RESOURCE_URL), required_scopes=[])`, `MCPServer(..., token_verifier=SimpleTokenVerifier(), auth=auth_settings)`; `auth_server_provider` не передан | Режим «только resource server» с issuer = собственный хост | **Критический** для OAuth-клиентов | PR-04: AS через `OAuthAuthorizationServerProvider` SDK (создаёт маршруты через `create_auth_routes`) + постоянное хранилище клиентов/токенов | probe `AUTH-02`, `AUTH-03*` (ожидаем `AS_MISSING`) | Код |
| A2 | Нет scopes | `required_scopes=[]`; `AccessToken(..., client_id="mcp-app-user", scopes=[], ...)` | Один статический токен = все права | Высокий | PR-03/04: `files:read`, `files:write`, `cmd:exec`, `ssh:exec`, проверка перед каждым вызовом | Unit: токен `files:read` → отказ на запись | Код |
| A3 | Токен в URL включён по умолчанию | `ALLOW_QUERY_TOKEN = _env_flag("MCP_ALLOW_QUERY_TOKEN", True)`; `config.py`: `allow_query_token: bool = True` | Совместимость с клиентами без заголовков | Средний: токен в истории, скриншотах, настройках клиентов. Из access-лога uvicorn он вырезается (сделано верно) | Выключить для новых установок; у существующих — предупреждение, без молчаливой поломки | Unit на миграцию настроек | Код |
| A4 | Запасной домен автора | `os.environ.get("MCP_BASE_DOMAIN", "https://mcp.souron.space")` | Остаток ранних версий (в `config.py` уже вычищается) | Средний: ручной запуск без `MCP_PUBLIC_URL` → resource на чужом домене | Без дефолта: localhost, а в публичном режиме без URL — отказ старта | Unit | Код |
| A5 | Токен в файле журнала | `logger.warning(f"...Сгенерирован временный токен: {SECRET_TOKEN}")`, журнал `mcp_audit.log` | Только при запуске без GUI | Средний (см. F7) | Только в stderr | Unit | Код |
| A6 | Токен открытым текстом | `token_store.py`: JSON + `icacls`, ошибки `restrict()` проглатываются | Нет DPAPI | Средний | DPAPI (`pywin32` уже зависимость SDK на Windows) с миграцией без потери токена | Windows-тест миграции | Код |

### B. Транспорт

| ID | Проблема | Доказательство | Причина | Риск | Решение | Тест | Статус |
|---|---|---|---|---|---|---|---|
| B1 | GET-поток SSE в JSON-режиме | В `server.py` нет обработки GET; `json_response` влияет на ответы POST | Неизвестно, открывает ли SDK GET-поток при `json_response=True` | Высокий: зависание клиента через Quick Tunnel | В Quick-режиме `405` на `GET /mcp` (допускается Streamable HTTP) | probe `MCP-04` | Гипотеза |
| B2 | Сессии теряются при ротации адреса | `stateless_http` не задан; `service_manager.py` перезапускает сервер на новый quick-адрес | Сессии в памяти | Средний | Оценить stateless для Quick: SDK v2 поддерживает ревизию 2026-07-28 без сессии и старую схему с `initialize` (`serve_dual_era_loop`) — проверить обе | Integration: initialize → рестарт → tools/list | Гипотеза |
| B3 | Параметры транспорта через интроспекцию | `_accepts(MCPServer.__init__, k)` / `_accepts(mcp.streamable_http_app, k)`; при неудаче только `logger.warning` | Версия SDK не закреплена (D1) | Высокий: JSON-режим может молча не примениться | Явные параметры после закрепления версии; ошибка старта вместо warning | probe `MCP-01`: Content-Type = `application/json` через Quick | Код |
| B4 | Host/Origin не заданы явно | Комментарий в `server.py`: «Проверку Host/Origin оставляем SDK по умолчанию»; в SDK v2 — «Auto-enable DNS rebinding protection» | Поведение по умолчанию зависит от версии SDK и host | **Высокий**: либо 421 через туннель, либо нет защиты от DNS rebinding | `TransportSecuritySettings` явно: текущий публичный хост + `127.0.0.1:<port>`, Origin по спецификации | probe `SEC-01`, `SEC-02` | Гипотеза |
| B5 | Ошибки инструментов как обычный текст | `return "❌ Доступ запрещен: ..."` | Не используется `ToolError` SDK (даёт `isError=true`) | Средний | `raise ToolError(...)` | Integration: `isError: true` | Код |

### C. Health checks

| ID | Проблема | Доказательство | Риск | Решение | Тест | Статус |
|---|---|---|---|---|---|---|
| C1 | «Жив» при любом HTTP-статусе | `health.py`: «Жив = пришёл ЛЮБОЙ HTTP-ответ (200, 404, 401, 405…)» | 500/404 показываются зелёным | `/health` = liveness (только 200), отдельный `/ready` | Unit | Код |
| C2 | Туннель «жив» = cloudflared подключён к Cloudflare | `_ready_url = QUrl(f"http://127.0.0.1:{metrics_port}/ready")` | Публичный URL извне не проверяется | MCP Doctor уровень 3 | probe `HTTP-01` | Код |
| C3 | `/health` не затрагивает MCP | `HybridAuthMiddleware` отвечает `{"status": "ok"}` до MCP-приложения | Зелёный при сломанном MCP | `/ready` + настоящий `initialize`/`tools/list` | probe `MCP-01..03` | Код |
| C4 | `Overall.RUNNING` без протокола | `RUNNING = "running"  # сервер отвечает И туннель подключён к Cloudflare` | «Работает» при нерабочем подключении | Состояния `HTTP_OK` / `MCP_READY_LOCAL` / `JSON_MCP_READY_PUBLIC` / `FULL_SSE_READY` по результатам Doctor | Unit | Код |

### D. Зависимости

| ID | Проблема | Доказательство | Риск | Решение | Статус |
|---|---|---|---|---|---|
| D1 | Версии не закреплены | `requirements.txt`: `mcp`, `uvicorn`, `starlette`, `pydantic`, `paramiko` без ограничений; `requirements.lock` в репозитории отсутствует | Высокий: SDK v2 несовместим с v1, сборка зависит от дня | `mcp>=2.3,<3` (код уже на v2: `from mcp.server import MCPServer`); lock с хэшами; Dependabot + протокольные тесты | Код |
| D2 | Транзитивные зависимости v2 | `mcp` 2.3.0 требует `httpx2`, `mcp-types==2.3.0`, `opentelemetry-api`, `pyjwt[crypto]`, `sse-starlette>=3`, `pywin32` (win32) | Средний: PyInstaller может не подхватить модули | Проверить `packaging/mcp_app.spec` + `MCPApp.exe --selftest` | Гипотеза |

### E. Конфигурация endpoint

| ID | Проблема | Доказательство | Риск | Решение | Статус |
|---|---|---|---|---|---|
| E1 | `mcp_path` не доходит до сервера | `config.py`: `mcp_path` используется в `normalize_public_url(...)`; `server.py`: `MCP_PATH = "/mcp"` захардкожен | При `mcp_path` ≠ `/mcp` — 404 | `MCP_PATH` из окружения для маршрута, PRM и middleware — либо убрать настройку | Код |

### F. Безопасность инструментов

| ID | Проблема | Доказательство | Риск | Решение | Статус |
|---|---|---|---|---|---|
| F1 | Произвольные команды через shell | `asyncio.create_subprocess_shell(command, ...)`; блоклист из 4 Unix-шаблонов (`rm -rf`, `mkfs`, `dd if=`, fork bomb) | **Критический**: RCE; на Windows блоклист не действует (`del /s /q`, `format`, `reg delete`, `powershell -enc`) | Выключено по умолчанию; allowlist программ, `create_subprocess_exec`, проверка аргументов, локальное подтверждение | Код |
| F2 | `cwd` не ограничен | `work_dir = Path(cwd).resolve() if cwd else WORKSPACE_DIR` | Высокий | Только внутри разрешённых папок | Код |
| F3 | По таймауту убивается только shell | `proc.kill(); await proc.wait()` | Средний: осиротевшие дочерние процессы (Job Object из `app/core/winjob.py` действует на весь бэкенд, не на команду) | Job Object на команду или `taskkill /T` | Гипотеза |
| F4 | Доверие неизвестным SSH host keys | `client.set_missing_host_key_policy(paramiko.AutoAddPolicy())` | Высокий: MITM | `RejectPolicy` + отпечатки | Код |
| F5 | Пустой allowlist SSH = все хосты | `if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:` | Высокий | Пустой список = SSH выключен | Код |
| F6 | Удалённый клиент использует SSH-ключи пользователя | `key_filename = host_cfg.get("identityfile")` из `~/.ssh/config` | Высокий: боковое перемещение | Разрешения по хостам, политика команд, подтверждение | Код |
| F7 | Файлы: нет лимитов, журнал в рабочей папке | `read_text()` целиком, `write_text(content)` без лимита; рабочая папка по умолчанию `os.getcwd()`, там же `mcp_audit.log`. Защита от `..`/symlink (`resolve()` + `is_relative_to`) реализована верно | Средний: чтение/подмена аудита, исчерпание памяти/диска | Журнал вне рабочей папки, лимиты, запрет служебных файлов | Код |
| F8 | Разведка через ресурс | `system://environment`: абсолютный путь (имя пользователя Windows), SSH-алиасы, список хостов | Средний | Убрать из Standard; безопасный `server_info` | Код |
| F9 | Полный текст команд в журнале | `logger.info(f"[LOCAL] cwd={work_dir} \| cmd={command}")` | Средний: секреты из командной строки в журнале и GUI | Маскирование | Код |
| F10 | Нет описаний и annotations | `run_local_command`, `run_ssh_command`, `read_workspace_file`, `write_workspace_file` без docstring | Средний: клиенты не запрашивают подтверждение для опасных действий | Описания, `readOnlyHint`/`destructiveHint`, ограничения в схеме | Код (probe `MCP-03` покажет) |
| F11 | Нет rate limiting | В коде приложения отсутствует. Лимит тела запроса в SDK есть (`DEFAULT_MAX_REQUEST_BODY_SIZE` в `transport_security.py`) | Средний: перебор токена, DoS | Middleware с лимитами; отдельные лимиты для OAuth-регистрации | Код |

### G. Внешние клиенты

| ID | Наблюдение | Источник | Статус |
|---|---|---|---|
| G1 | Gemini app: пользовательский MCP через Settings → Connected Apps → Add a custom app; нужен OAuth, подключение по одному URL — только с DCR. Ограничения: личные аккаунты Google, 18+, США, английский | Документация стороннего вендора (Scrive), сверить с Google | **Blocked** вне США; требование OAuth согласуется с A1 |
| G2 | Notion: пользовательские MCP для Notion Agent включаются в настройках рабочего пространства; тариф и типы авторизации официально не подтверждены | Обсуждения сообщества | Не проверено |

---

## 3. Модель угроз (кратко)

**Активы:** файлы пользователя; выполнение команд Windows; SSH-ключи и удалённые хосты; Bearer-токен;
будущие OAuth-клиенты и токены.

**Точки входа:** `https://<host>/mcp`, `/.well-known/*`, будущие `/authorize` `/token` `/register` `/revoke`,
локальный порт (процессы и браузер на той же машине).

**Границы доверия:** Интернет → Cloudflare edge → cloudflared → `127.0.0.1:<port>` → инструменты → ОС/SSH.
Через туннель все запросы приходят с `127.0.0.1`, поэтому IP нельзя использовать для авторизации
(в текущем коде это учтено).

| Угроза | Сценарий | Сейчас | Нужно |
|---|---|---|---|
| Утечка токена | `?token=` в ссылке, скриншот, журнал | Вырезание из access-лога | Токен в URL выключен, срок действия, отзыв |
| Prompt injection → RCE | Модель прочитала вредоносную страницу и вызвала `run_local_command` | Unix-блоклист | Advanced выключен для публичных клиентов, локальное подтверждение |
| Боковое перемещение | SSH на любой хост с ключами пользователя | Нет | Запрет по умолчанию, `RejectPolicy` |
| DNS rebinding | Страница в браузере пользователя обращается к локальному порту | Дефолт SDK (не проверено) | Явные `allowed_hosts`/`allowed_origins` |
| Перебор / DoS | Массовые запросы | Лимит тела SDK | Rate limiting |
| Подмена аудита | `write_workspace_file("mcp_audit.log", ...)` | Нет | Журнал вне рабочей папки |
| Токены старого адреса | После ротации quick-URL | `validate_token_resource=True` | Сохранить; для OAuth — привязка к issuer/resource и переподключение |

---

## 4. Охват аудита

**Прочитано:** `backend/server.py`, `app/config.py`, `app/core/health.py`, `app/core/service_manager.py`,
`app/core/token_store.py`, `app/backend_entry.py`, `app/selftest.py`, `requirements.txt`, `.github/workflows/build.yml`,
`packaging/mcp_app.spec`, дерево репозитория, PR #1–#4.

**Не прочитано (следующий шаг):** `app/core/process.py`, `proxy.py`, `edge_relay.py`, `netcheck.py`, `cf_api.py`,
`winjob.py`, `domain_state.py`, `autostart.py`, `app/migrate.py`, `app/paths.py`, `app/ui/*`, `packaging/build.ps1`,
`packaging/installer.iss`, `docs/custom-domain.md`. Особенно важны `proxy.py` и `edge_relay.py`: если они
переписывают Host или буферизуют ответы, это меняет оценку B1 и B4.

---

## 5. Воспроизведение — `tools/mcp_probe.py`

Только стандартная библиотека. Токен из `MCP_TOKEN`, в вывод и JSON-отчёт не попадает.

```bat
set MCP_TOKEN=<токен из приложения>
python tools\mcp_probe.py https://<host>.trycloudflare.com/mcp --local http://127.0.0.1:8000/mcp --json probe-report.json
```

| Check | Уровень | Что проверяет | Находка |
|---|---|---|---|
| `HTTP-01` | 2–3 | Публичный `/health`, ошибки Cloudflare, редиректы | C2 |
| `AUTH-01` | 5 | 401 без токена + `WWW-Authenticate: resource_metadata` | A1 |
| `AUTH-02` | 5 | PRM: `resource` = текущий URL, `authorization_servers` | A1, 3.5 ТЗ |
| `AUTH-03*` | 5 | Метаданные AS (RFC 8414 / OIDC), issuer, PKCE S256, DCR | **A1** |
| `MCP-01` | 4 | `initialize` с Bearer: Content-Type, версия, сессия, зависание SSE | B3 |
| `MCP-02` | 4 | `notifications/initialized` → 202 | — |
| `MCP-03` | 4 | `tools/list`, description/annotations | F10 |
| `TOOL-01` | 6 | `tools/call` (только с `--call`) | — |
| `MCP-04` | 4 | `GET /mcp`: 405 / поток / зависание | **B1** |
| `MCP-05` | 4 | `DELETE` сессии | B2 |
| `SEC-01` | 3 | Локальный сервер принимает публичный Host | **B4** |
| `SEC-02` | 3 | Локальный сервер отклоняет чужой Host | B4 |

Вердикт не объединяет разные вещи: `Bearer MCP` (initialize + tools/list), `OAuth discovery`
(только метаданные — сам поток не тестируется) и `SSE: NOT VERIFIED`. Через Quick Tunnel успех Bearer
показывается как `JSON MCP Ready`, не `Full SSE Compatible`.

---

## 6. План до завершения PR-01

1. Прогнать `mcp_probe.py` на реальном quick-адресе, приложить JSON-отчёт, обновить статусы → **Verified**.
2. Дочитать файлы из §4 (`proxy.py`, `edge_relay.py` — первыми).
3. После подтверждения — правки кода отдельными коммитами:
   - `requirements.txt`: `mcp>=2.3,<3` + lock-файл (D1);
   - `server.py`: `/ready`, `MCP_PATH` из окружения (E1), без запасного домена (A4), без токена в журнале (A5),
     явные `TransportSecuritySettings` (B4), `server_info` + описания инструментов (F8, F10);
   - **временная мера безопасности:** флаг `MCP_ENABLE_ADVANCED` (по умолчанию выкл.) — без него
     `run_local_command`, `run_ssh_command`, `write_workspace_file` не регистрируются; SSH — `RejectPolicy`.
     Это меняет поведение для текущих пользователей — нужно решение владельца (п. 11 ТЗ);
   - `health.py`: только 200 = здоров (C1), отдельный сигнал `/ready`;
   - `app/core/doctor.py`: перенести логику probe в приложение (уровни 1–6).
4. Перенести `packaging/ci/ci.yml` → `.github/workflows/ci.yml` (токену автора PR не хватает права `workflow`).

Если подтвердится A1, клиенты с ручным заголовком (MCP Inspector, Cursor, VS Code) заработают после PR-02,
а Gemini / Notion / Claude / ChatGPT — только после PR-04 (OAuth). Это сразу отражается в матрице совместимости.

---

## 7. Источники

- MCP Python SDK, What's new in v2: https://py.sdk.modelcontextprotocol.io/whats-new/
- MCP Python SDK, Migration Guide v1 → v2: https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md
- SDK: `src/mcp/server/lowlevel/server.py`, `src/mcp/server/transport_security.py`, `src/mcp/server/mcpserver/exceptions.py`
- `mcp` 2.3.0 на PyPI: https://pypi.org/project/mcp/2.3.0/
- Gemini custom app (сторонний вендор): https://mcpdocs.scrive.com/mcp/install/gemini/
