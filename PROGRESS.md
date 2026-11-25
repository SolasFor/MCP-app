# MCP-app — журнал выполнения

База плана: `v0.8.5` (`89deaa4`). Аудит репозитория и запуск baseline-тестов проведены.

| Этап | Целевая версия | Статус | PR / CI / доказательства |
|---|---|---|---|
| 1. Stability & Security | v0.8.6 | VERIFIED | [PR #20](https://github.com/SolasFor/MCP-app/pull/20), коммит `f6c0dd7`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45514910047), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45514910385) |
| 2. UI Redesign | v0.9.0 | VERIFIED | [PR #21](https://github.com/SolasFor/MCP-app/pull/21), коммит `2ab3ddd`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45518398422), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45518398349) |
| 3. Connection Manager | v0.9.1 | VERIFIED | [PR #22](https://github.com/SolasFor/MCP-app/pull/22), коммит `424481a`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45522273057), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45522273017) |
| 4. MCP Gateway | v0.9.2 | VERIFIED | [PR #23](https://github.com/SolasFor/MCP-app/pull/23), коммит `87e7fef`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45563300320), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45563300338) |
| 5. Task Manager | v0.9.3 | VERIFIED | [PR #24](https://github.com/SolasFor/MCP-app/pull/24), коммит `2ccd259`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45567201054), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45567201051) |
| 6. Server Manager | v0.9.4 | VERIFIED | [PR #25](https://github.com/SolasFor/MCP-app/pull/25), коммит `f5c87b1`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45571994338), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45571994344) |
| 7. Workspaces | v0.9.5 | VERIFIED | [PR #26](https://github.com/SolasFor/MCP-app/pull/26), коммит `d8f7f7a`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45574728778), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45574728818) |
| 8. Computer Use | v0.9.6 | TODO | — |
| 9. Extensions | v0.9.7 | TODO | — |
| 10. Remote Management | v0.9.8 | TODO | — |
| 11. Automation & Monitoring | v0.9.9 | TODO | — |
| 12. Stable Release | v1.0.0 | TODO | — |

Статусы: TODO / IN_PROGRESS / BLOCKED / VERIFIED / MERGED / RELEASED. Отдельные проверки: PASS / FAIL / NOT_RUN / BLOCKED / N/A. Не менять TODO на VERIFIED без доказательств приёмки.

## Последняя рабочая сессия
- Дата, ветка, HEAD: 2026-11-25, ветка `feat/workspaces`, `d8f7f7a` (stacked на `feat/server-manager` / PR #25).
- Статус Этапа 7 (`v0.9.5 — Workspaces`): `VERIFIED` (ожидает одобрения владельца для последовательного merge PR #20–#26 в `main`).
- Окружение: Windows 11 Pro 25H2 (x86_64), Python 3.13.15 (`.venv`), `cloudflared 2026.11.2`, `tailscale 1.104.2`, SolidWorks (`SLDWORKS.exe`), `ngrok` и `openai/tunnel-client` локально не установлены, `gh` авторизован (`SolasFor`), `iscc` в GitHub Actions `windows-latest`.
- Следующее действие: отвести ветку `feat/computer-use` от `feat/workspaces` и реализовать Этап 8 (`v0.9.6 — Computer Use`).

## Этап 7: v0.9.5 — Workspaces (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 7 / `v0.9.5` / `feat/workspaces` / `d8f7f7a`
- Реализованные задачи:
  - Реализован пакет `backend/workspaces/` (`{__init__,models,path_security,history,store,git_ops,manager}.py`): реестр `workspaces.json` с автоопределением языка/Git root/Python `.venv`/Node и команд (`detect_workspace_metadata`), DPAPI-секретами env (`secret://workspaces/<ws>__<KEY>`, namespace `workspaces` в `app/core/secret_store.py`), экспортом/импортом без секретов и связью с серверами/задачами/расширениями.
  - Безопасность путей Windows/POSIX (`backend/workspaces/path_security.py`): запрет `..` traversal, абсолютных путей, UNC (`\\...`), префиксов устройств (`\\?\`, `\\.\`), зарезервированных имён Windows (`CON`, `NUL`, `COM1..9`, `LPT1..9`), NTFS ADS (`:`), чувствительных файлов (`.env*`, `.git`, ключи/сертификаты), symlink и Windows NTFS junctions (`FILE_ATTRIBUTE_REPARSE_POINT`) на каждом сегменте; проверка фактически открытого дескриптора (`GetFinalPathNameByHandleW` на Windows и `fstat`/`lstat` на POSIX); атомарная запись (`os.replace`) с обязательным `expected_sha256` precondition для защиты от перезаписи пользовательских правок, `.gitignore` и пользовательские исключения, локальные снимки и откат (`WorkspaceHistory`).
  - Безопасный Git (`backend/workspaces/git_ops.py`): запуск без окон консоли (`CREATE_NO_WINDOW`) и с подавлением недоверенных hooks/filters (`core.hooksPath`, `core.fsmonitor=false`, `credential.helper=`, `--no-verify`) при `trust_git_hooks=False` (по умолчанию).
  - Гранулярные права по проектам и клиентам (`read`, `write`, `delete`, `execute`, `git`), добавление 18 OAuth-инструментов (`12 workspace_*` + `6 git_*`) в `backend/tool_registry.py` и `backend/server.py`, изоляция `ServiceManager` и `app/selftest.py`.
  - Создана страница `app/ui/pages/workspaces_page.py` (`WorkspacesPage`, `WorkspaceProfileDialog` с автоопределением, дерево файлов, поиск по файлам, статус Git, запуск именованных задач, экспорт без секретов), раздел переведён в активное меню `Ctrl+7` (исправлена привязка горячих клавиш для >9 вкладок в `app/ui/main_window.py`, RU/EN `app/ui/i18n.py`), добавлена документация `docs/workspaces.md` (с честным указанием, что Full Access CMD/PowerShell не изолирован) и ссылка в `README.md`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #26](https://github.com/SolasFor/MCP-app/pull/26) после PR #20–#25.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.5`), `packaging/mcp_app.spec`, `app/core/{secret_store,service_manager}.py`, `app/selftest.py`, `app/ui/{i18n,main_window}.py`, `app/ui/pages/{__init__,workspaces_page}.py`, `backend/workspaces/`, `backend/{tool_registry,server}.py`, `docs/workspaces.md`, `README.md`, `tests/unit/{test_workspaces_security,test_tool_permissions}.py`, `tests/integration/{test_workspaces,test_tool_registry,test_oauth_http,test_ui_redesign_gui,test_unified_home_gui}.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend tests main.py`, `mypy` (win32 + `--platform linux`): PASS (44 файла, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (145/145 за 10.729s — включая traversal, UNC, ADS, reserved names, `.env`/`.git`, Windows NTFS junction escape `mklink /J`, конфликт `expected_sha256` без потери правки пользователя, откат, `.gitignore`, подавление Git pre-commit hook)
    - `tests/integration`: PASS (34/34 за 144.946s; всего 179/179 — включая реальный Python-проект + реальный `venv.create` + реальный `git init`, поиск, `apply_patch`, diff снимка, запуск unit-тестов в `.venv` с редактированием секрета, `move`/`delete`, `git_checkout`/`git_commit`/`git_log`, кросс-клиентскую изоляцию и headless `WorkspacesPage` GUI)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.5-portable.zip` 66.8 MB)
  - GitHub Actions CI на `d8f7f7a`:
    - `Verify & Test (ubuntu-latest)`: PASS (`1m29s`) — https://github.com/SolasFor/MCP-app/actions/runs/45574728778/job/139069717418
    - `Verify & Test (windows-latest)`: PASS (`4m25s`) — https://github.com/SolasFor/MCP-app/actions/runs/45574728778/job/139069716931
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m30s`) — https://github.com/SolasFor/MCP-app/actions/runs/45574728818/job/139069717623
- Live tests отдельно от mocks: реальные локальные файлы, реальные Windows NTFS junctions (`mklink /J`), реальные Python venv, `git`, и headless Qt `WorkspacesPage` — **PASS**.
- Риски / ограничения / блокеры: специализированные инструменты защищены каноническими проверками путей и открытых дескрипторов, однако режим `full` (`oauth_windows_command`) выполняется с правами текущего пользователя Windows и не является OS-песочницей; сборка без Authenticode-сертификата.
- PR / релиз: [PR #26](https://github.com/SolasFor/MCP-app/pull/26) (`feat/workspaces` → `feat/server-manager`).
- Следующий точный шаг: Этап 8 (`v0.9.6 — Computer Use`) на ветке `feat/computer-use`.

## Этап 6: v0.9.4 — Server Manager (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 6 / `v0.9.4` / `feat/server-manager` / `f5c87b1`
- Реализованные задачи:
  - Реализован пакет `backend/servers/` (`{__init__,models,templates,store,probes,manager}.py`) и сохранён полностью совместимый фасад `backend/managed_servers.py`: бесшовная миграция legacy v1 `managed_servers.json` в схему v2 (`ServerConfigStore.migrate_legacy_file` с сохранением `.v1.bak` и дефолтом `min_profile="full"`), хранение секретных env-переменных в DPAPI `SecretStore` (`secret://servers/<server>__<KEY>`, namespace `servers` в `app/core/secret_store.py`), граф зависимостей `depends_on` с топологической сортировкой и отклонением циклов.
  - Реализованы проверенные встроенные шаблоны (`python_fastapi`, `python_flask`, `node_express`, `vite_next`, `docker_compose`, `static_http`, `custom`) без shell-инъекций, path traversal, автоустановки зависимостей (`pip`/`npm`/`npx`) и автоматического внешнего биндинга (loopback `127.0.0.1` по умолчанию).
  - Обеспечены проверка конфликтов портов без убийства чужих PID (`check_port_conflict`), identity-проверенные метрики CPU/RAM/threads через `psutil` (`collect_process_metrics`), TCP/HTTP readiness probes (`probe_readiness`), перезапуски по политике `never`/`on-failure`/`always` с exponential backoff и живой перепроверкой OAuth-доступа (`_server_auth_rechecker`), потокобезопасный `BoundedOutputBuffer` (`backend/output_stream.py`) и неблокирующее чтение живых логов `read1` + POSIX `start_new_session=True` в `backend/process_runner.py`, а также честное разделение `controlled` (остановка дерева) и `independent` (detached, без принудительного завершения).
  - Добавлены 8 OAuth-инструментов в `backend/tool_registry.py` и `backend/server.py` (`server_list`, `server_start`, `server_stop`, `server_restart`, `server_status`, `server_logs`, `server_metrics`, `server_health`) с сохранением `oauth_managed_server` и связью с `TaskManager` (`linked_task_id`, `run_pre_start_task`), изоляцией `ServiceManager.managed_servers_path()` / `MCP_SECRETS_DIR` (`app/core/service_manager.py`) и `app/selftest.py`.
  - Создана страница `app/ui/pages/servers_page.py` (`ServersPage`, `ServerProfileDialog`, `TemplateWizardDialog`), раздел «Серверы» переведён в активное меню `Ctrl+6` (`app/ui/main_window.py`, RU/EN `app/ui/i18n.py`, автозапуск `start_autostart_servers()` в `app/gui.py`), добавлена документация `docs/server-manager.md` и ссылка в `README.md`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #25](https://github.com/SolasFor/MCP-app/pull/25) после PR #20–#24.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.4`), `packaging/mcp_app.spec`, `app/core/{secret_store,service_manager}.py`, `app/{gui,selftest}.py`, `app/ui/{i18n,main_window}.py`, `app/ui/pages/{__init__,servers_page}.py`, `backend/servers/`, `backend/{managed_servers,output_stream,process_runner,tool_registry,server}.py`, `docs/server-manager.md`, `README.md`, `tests/fixtures/dev_http_server.py`, `tests/unit/{test_server_manager,test_tool_permissions}.py`, `tests/integration/{test_server_manager,test_tool_registry,test_oauth_http,test_ui_redesign_gui,test_unified_home_gui}.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend tests main.py`, `mypy` (win32 + `--platform linux`): PASS (37 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (140/140 за 9.833s — включая миграцию v1→v2, SecretStore, DAG/циклы, все шаблоны + негативные проверки, конфликт порта на живом сокете)
    - `tests/integration`: PASS (32/32 за 112.797s; всего 172/172 — включая реальный HTTP-сервер с readiness/метриками/отредактированными живыми логами/связью с `TaskStore`, crash restart + backoff и отзыв OAuth, дерево процессов и `independent` режим, порядок зависимостей, конфликт порта, совместимость `ManagedServers` и headless `ServersPage` + диалоги)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.4-portable.zip` 66.7 MB)
  - GitHub Actions CI на `f5c87b1`:
    - `Verify & Test (ubuntu-latest)`: PASS (`1m38s`) — https://github.com/SolasFor/MCP-app/actions/runs/45571994338/job/139060631225
    - `Verify & Test (windows-latest)`: PASS (`3m38s`) — https://github.com/SolasFor/MCP-app/actions/runs/45571994338/job/139060631584
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m39s`) — https://github.com/SolasFor/MCP-app/actions/runs/45571994344/job/139060631778
- Live tests отдельно от mocks: реальные локальные HTTP-серверы (`dev_http_server.py`), дочерние деревья процессов, реальные сокеты/порты, `psutil` метрики, SecretStore и headless Qt `ServersPage` — **PASS**.
- Риски / ограничения / блокеры: сборка без Authenticode-сертификата; внешние Docker/Node рантаймы проверяются при их наличии на машине владельца.
- PR / релиз: [PR #25](https://github.com/SolasFor/MCP-app/pull/25) (`feat/server-manager` → `feat/task-manager`).
- Следующий точный шаг: Этап 7 (`v0.9.5 — Workspaces`) на ветке `feat/workspaces`.

## Этап 5: v0.9.3 — Task Manager (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 5 / `v0.9.3` / `feat/task-manager` / `2ccd259`
- Реализованные задачи:
  - Реализован пакет `backend/tasks/` (`{__init__,models,store,manager}.py`): долговечный реестр `tasks.sqlite3` (WAL + `schema_migrations` v1 + пользовательские ACL) с шифрованием спецификаций команд DPAPI (Windows) / POSIX `0600` ключом, атомарной идемпотентностью `(owner_client_id, idempotency_key)`, приоритетной очередью `priority DESC, created_at ASC`, глобальными и per-client квотами параллельности (`max_global=4`, `max_per_client=2`, `max_queued_per_client=20`), восстановлением незавершённых задач при перезапуске (`recover_interrupted()` → `interrupted`, без автоповтора неидемпотентных команд), явным рестартом (`parent_task_id`) и квотами удержания/очистки спула и артефактов (`enforce_retention`), а также маппингом статусов `to_mcp_task_dict()` под схему MCP `Task` без требования клиентской поддержки `tasks/*`.
  - В `backend/process_runner.py` добавлены `run_id`, `on_started`, `cancel_run()` (завершение всего дерева процессов через Job Object на Windows или `terminate_process_tree` + POSIX `start_new_session=True`), сохранено отсечение секретов и скрытые консольные окна.
  - В `backend/tool_registry.py`, `backend/server.py` и `app/core/service_manager.py` добавлены 8 OAuth-инструментов (`task_start`, `task_status`, `task_list`, `task_output`, `task_result`, `task_cancel`, `task_restart`, `task_artifacts`) с сохранением синхронных `oauth_windows_command` и `oauth_ssh_command`, перепроверкой прав и аварийной остановки перед запуском и строгой кросс-клиентской изоляцией владельца.
  - Создана страница `app/ui/pages/tasks_page.py` (`TasksPage`: фильтры `All`/`Active`/`History` и статусов, поиск, прогресс `—` когда неизвестен без выдуманных процентов, живой redacted вывод `stdout`/`stderr`, просмотр и экспорт `result.json` артефактов, кнопки Отмена/Перезапуск) + уведомления в трее (`TrayIcon.notify_task_event` в `app/ui/tray.py`, интеграция в `app/ui/main_window.py` `Ctrl+5`, `app/gui.py`, RU/EN `app/ui/i18n.py`, `docs/task-manager.md`, `README.md`).
- Оставшиеся задачи и зависимости: последовательный merge [PR #24](https://github.com/SolasFor/MCP-app/pull/24) после PR #20–#23; задачи честно завершаются статусом `interrupted` при выключении ОС/бэкенда и не обещают продолжения после выключения компьютера.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.3`), `packaging/mcp_app.spec`, `backend/tasks/`, `backend/{process_runner,tool_registry,server}.py`, `app/core/service_manager.py`, `app/{gui,selftest}.py`, `app/ui/{i18n,main_window,tray}.py`, `app/ui/pages/{__init__,tasks_page}.py`, `tests/unit/{test_task_manager,test_tool_permissions}.py`, `tests/integration/{test_task_manager_integration,test_tool_registry,test_oauth_http,test_ui_redesign_gui,test_unified_home_gui}.py`, `docs/task-manager.md`, `README.md`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend tests`, `mypy` (win32 + `--platform linux`): PASS (30 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (135/135 за 9.591s — включая зашифрованное хранение, квоты, приоритеты, `recover_interrupted`, убийство дочернего дерева процессов при отмене, отзыв прав в очереди, кросс-клиентский отказ и ротацию)
    - `tests/integration`: PASS (25/25 за 94.214s; всего 160/160 — включая продолжение фоновой задачи после отключения клиента, пагинированный `stdout`/redacted `stderr`, `result.json`, явный рестарт и headless `TasksPage` GUI + `TrayIcon.notify_task_event`)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.3-portable.zip` 66.6 MB)
  - GitHub Actions CI на `2ccd259`:
    - `Verify & Test (ubuntu-latest)`: PASS (`1m30s`) — https://github.com/SolasFor/MCP-app/actions/runs/45567201054/job/139044801433
    - `Verify & Test (windows-latest)`: PASS (`3m20s`) — https://github.com/SolasFor/MCP-app/actions/runs/45567201054/job/139044800971
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m48s`) — https://github.com/SolasFor/MCP-app/actions/runs/45567201051/job/139044801573
- Live tests отдельно от mocks: реальные дочерние процессы и дерево процессов, SQLite WAL persistence/recovery, disk spool pagination и Qt `TasksPage` — **PASS**; реальное выключение ПК не моделируется ОС (честно зафиксирован recovery-статус `interrupted`).
- Риски / ограничения / блокеры: сборка без Authenticode-сертификата; продолжение задач после полного выключения ПК невозможно (документировано в `docs/task-manager.md`).
- PR / релиз: [PR #24](https://github.com/SolasFor/MCP-app/pull/24) (`feat/task-manager` → `feat/mcp-gateway`).
- Следующий точный шаг: Этап 6 (`v0.9.4 — Server Manager`) на ветке `feat/server-manager`.

## Этап 4: v0.9.2 — MCP Gateway (VERIFIED; live SolidWorks COM / external tunnel smoke: BLOCKED)
- Этап / версия / ветка / HEAD: Этап 4 / `v0.9.2` / `feat/mcp-gateway` / `87e7fef`
- Реализованные задачи:
  - Реализован пакет `backend/gateway/` (`{__init__,models,security,store,upstream_client,router}.py`): профили `UpstreamServerProfile`, локальный `stdio`, удалённый `Streamable HTTP` и опциональный legacy `SSE` на базе `mcp==2.3.0`; выделенная задача жизненного цикла (`_lifecycle_task`) на каждое upstream-соединение с обработкой `BaseException`/`CancelledError` при отказе на старте (`DEAD_PORT_ISOLATION_OK`), ограниченной пагинацией `tools/list`, строгими таймаутами без автоповтора неидемпотентных вызовов и обработкой `notifications/tools/list_changed` с привязкой к `client_id`.
  - Безопасность и изоляция: детерминированные namespaces `<server_id>__<tool>` (`<=64` символов с хеш-разрешением коллизий), SSRF/cloud-metadata/embedded-credentials/self-recursion валидация (`validate_upstream_url`), защита от маршрутных циклов (`X-MCP-Gateway-Id`, `X-MCP-Gateway-Hop` в `HybridAuthMiddleware` → HTTP `400 gateway_loop_detected`), отсечение downstream `Authorization`/cookie, хранение env-секретов, bearer-токенов и заголовков в DPAPI `SecretStore`, импорт стандартного `mcpServers` JSON только после подтверждения владельца с предупреждением о динамических лаунчерах (`npx`/`uvx`/скрипты), экспорт без секретов, изоляция сессий `per_client` / `shared_service`, редактирование секретов в `TextContent`, `structuredContent` и логах, ограничение `max_response_bytes`.
  - Интеграция в сервер и UI: `backend/tool_permissions.py` (`make_tool_middleware(..., gateway_router=...)`), `backend/server.py` (`GATEWAY_STORE`, `GATEWAY_ROUTER`, `REDACTOR`, закрытие при остановке), `app/core/service_manager.py` (`MCP_GATEWAY_CONFIG_PATH`, `refresh_gateway_secrets()`), новая страница `app/ui/pages/gateway_page.py` (`GatewayPage`, `GatewayServerDialog`, `GatewayImportPreviewDialog`, шаблон `solidworks_mcp_template` с `approved_by_owner=False`, инспектор схем, redacted логи), переключение в активный раздел бокового меню `Ctrl+4` (`app/ui/main_window.py`, RU/EN `app/ui/i18n.py`), `docs/mcp-gateway.md`, `README.md`, `packaging/mcp_app.spec`, `.github/workflows/transport-checks.yml` (`timeout-minutes: 15`, `QT_QPA_PLATFORM: offscreen`).
- Оставшиеся задачи и зависимости: последовательный merge [PR #23](https://github.com/SolasFor/MCP-app/pull/23) после PR #20–#22; live CAD smoke (при наличии установленного SolidWorks) и внешняя проверка MCP Inspector / ChatGPT через публичный туннель владельца.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.2`), `packaging/mcp_app.spec`, `backend/gateway/`, `backend/{server,tool_permissions}.py`, `app/core/service_manager.py`, `app/ui/{main_window,i18n}.py`, `app/ui/pages/{__init__,gateway_page}.py`, `tests/fixtures/gateway_stdio_server.py`, `tests/unit/test_gateway_security.py`, `tests/integration/{test_mcp_gateway,test_ui_redesign_gui,test_unified_home_gui}.py`, `docs/mcp-gateway.md`, `README.md`, `.github/workflows/transport-checks.yml`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend tests`, `mypy` (win32 + `--platform linux`): PASS (26 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (132/132 за 8.672s)
    - `tests/integration`: PASS (24/24 за 85.635s; всего 156/156, включая реальные `stdio`, `Streamable HTTP`, `SSE`, недоступный 4-й сервер, коллизии имён, динамические tools + `tools/list_changed`, `ImageContent` + `structured_content` + redaction, per-client isolation, fail-closed OAuth/emergency stop, ASGI HTTP `400` loop guard и headless `GatewayPage` GUI)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.2-portable.zip` 66.6 MB)
  - GitHub Actions CI на `87e7fef`:
    - `Verify & Test (ubuntu-latest)`: PASS (`1m17s`) — https://github.com/SolasFor/MCP-app/actions/runs/45563300320/job/139031944058
    - `Verify & Test (windows-latest)`: PASS (`3m16s`) — https://github.com/SolasFor/MCP-app/actions/runs/45563300320/job/139031944826
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m38s`) — https://github.com/SolasFor/MCP-app/actions/runs/45563300338/job/139031944669
- Live tests отдельно от mocks: реальные локальные процессы/серверы `stdio` + `Streamable HTTP` + `SSE` + недоступный 4-й сервер и headless Qt `GatewayPage` — **PASS**; живой SolidWorks COM smoke (`SLDWORKS.exe`, создание тестовой `SLDPRT`) и внешняя цепочка `MCP Inspector / ChatGPT -> Tunnel -> Gateway` — **BLOCKED** (на сборочной машине нет установленного SolidWorks и лицензии; нет внешней учётной записи/туннеля для удалённого публичного прогона).
- Риски / ограничения / блокеры: отсутствие `SLDWORKS.exe` для физического COM CAD smoke; внешний клиент через публичный туннель зависит от Этапа 3 (разрешение/учётные данные владельца); сборка без Authenticode-сертификата.
- PR / релиз: [PR #23](https://github.com/SolasFor/MCP-app/pull/23) (`feat/mcp-gateway` → `feat/connection-manager`).
- Следующий точный шаг: Этап 5 (`v0.9.3 — Task Manager`) на ветке `feat/task-manager`.

## Этап 3: v0.9.1 — Connection Manager (VERIFIED; external live smoke: BLOCKED)
- Этап / версия / ветка / HEAD: Этап 3 / `v0.9.1` / `feat/connection-manager` / `424481a`
- Реализованные задачи:
  - Единый `TunnelProvider` API и `ConnectionManager` (`app/core/tunnels/{__init__,base,local_only,cloudflare,ngrok,tailscale,openai_tunnel,manager}.py`): разделение `public_url` (`is_public_url`) и приватного `private_tunnel_id`/loopback-цели, `RouteOwnershipStore` (`routes.json`: PID + `create_time` и собственные маршруты), несекретный `connections.json`, политика «один внешний транспорт одновременно» и `IssuerTransitionWarning`.
  - Реализованы все 6 транспортов: `cloudflare_quick`, `cloudflare_named`, `ngrok` (`NGROK_AUTHTOKEN` в DPAPI `SecretStore` и env, `--url`, `/api/endpoints` v3 + `/api/tunnels` fallback, парсинг `ERR_NGROK_*` и free-tier interstitial), `tailscale_funnel` (`status --json`, `funnel status --json`, порты `443/8443/10000`, отказ при чужом маршруте, остановка только своего пути `off` без `reset`, различение Funnel/Serve), `openai_tunnel` (`openai/tunnel-client` `init`/`doctor`/`run`, `CONTROL_PLANE_API_KEY` в DPAPI `SecretStore` и env, `/readyz`, `is_public_url=False`, честные ограничения по тарифам и обязательная локальная OAuth/Bearer-проверка) и `local_only` (строгий loopback, без внешней публикации).
  - Интеграция в `app/config.py`, `app/core/service_manager.py`, `app/ui/provider_wizards.py`, `app/ui/pages/{connections_page,home_page}.py`, `app/ui/main_window.py`, `app/ui/i18n.py` (RU/EN), `docs/connection-manager.md`, `README.md`, `packaging/mcp_app.spec`, `pyproject.toml`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #22](https://github.com/SolasFor/MCP-app/pull/22) в `main`; live smoke внешних провайдеров при наличии учётных данных и разрешения владельца.
- Изменённые файлы / миграции: `app/config.py` (`active_provider` с двусторонней синхронизацией legacy `tunnel_mode`), `app/__init__.py` & `pyproject.toml` (`0.9.1`), `app/core/tunnels/`, `app/ui/provider_wizards.py`, `tests/unit/test_connection_manager.py`, `tests/integration/test_connection_transports.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check .`, `mypy` (win32 + `--platform linux`): PASS (20 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip_audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (127/127 за 8.647s)
    - `tests/integration`: PASS (22/22 за 76.816s; всего 149/149)
    - Живой end-to-end `local_only`: PASS (`127.0.0.1` loopback OAuth DCR + `/authorize` + `/oauth/consent` CSRF Origin + PKCE `/token` + MCP `initialize` + `tools/list` + `tools/call(server_info)` + рестарт сервера с сохранением авторизации).
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.1-portable.zip` 66.5 MB).
  - GitHub Actions CI на `424481a`:
    - `Verify & Test (ubuntu-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45522273057/job/138896844409
    - `Verify & Test (windows-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45522273057/job/138896844608
    - `RC Windows installer (no publish)` (`windows-package`): PASS — https://github.com/SolasFor/MCP-app/actions/runs/45522273017/job/138896844345
- Live tests отдельно от mocks: `local_only` — **PASS (реальный локальный сервер + OAuth/MCP round trip)**; `ngrok`, `Tailscale Funnel`, `OpenAI Secure MCP Tunnel` и публикация новых публичных маршрутов — **BLOCKED** (требуются внешние аккаунты/токены/Funnel ACL/разрешение владельца; логика, протокол, секреты и отказ при чужих маршрутах/неверном `issuer` проверены unit/mock-тестами).
- Риски / ограничения / блокеры: отсутствие установленных `ngrok` / `openai/tunnel-client` и разрешения на публикацию публичных маршрутов для live-дымовых тестов; сборка без Authenticode-сертификата.
- PR / релиз: [PR #22](https://github.com/SolasFor/MCP-app/pull/22) (`feat/connection-manager` → `feat/ui-redesign`).
- Следующий точный шаг: Этап 4 (`v0.9.2 — MCP Gateway`) на ветке `feat/mcp-gateway`.

## Этап 2: v0.9.0 — UI Redesign (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 2 / `v0.9.0` / `feat/ui-redesign` / `2ab3ddd`
- Реализованные задачи:
  - Дизайн-система Linear + Docker Desktop (`app/ui/tokens.py`, `app/ui/theme.py`, `app/ui/icons.py`): палитры Dark (`#14151A`/`#191A21`/`#272832`/`#818CF8`/`#F4F4F5`) и Light (`#F8F9FC`/`#FFFFFF`/`#E2E4E9`/`#635BDE`/`#18181B`) с проверкой контраста WCAG AA (≥ 4.5:1), режим `System` (Windows `AppsUseLightTheme` + `QStyleHints.colorSchemeChanged`), переключение без перезапуска, DWM titlebar на Windows, векторные иконки `QPainter` и `@1x/@2x` PNG-переключатели под каждую тему.
  - Живая локализация RU/EN (`app/ui/i18n.py`), HiDPI `PassThrough` и сохранение UI-настроек (`app/config.py`, `app/gui.py`): тема, язык, свёрнутость сайдбара и геометрия окна с безопасной миграцией от v0.8.5/v0.8.6.
  - Модульные компоненты и страницы (`app/ui/components/`, `app/ui/pages/`, `app/ui/main_window.py`, `app/ui/tray.py`, `app/ui/domain_guide.py`, `app/ui/proxy_page.py`, `packaging/mcp_app.spec`): сворачиваемый `Sidebar` (`Ctrl+B`), `CommandPaletteDialog` (`Ctrl+K`), `ToastManager`, `DataTable`, фильтруемый `LogViewerWidget`, 6 активных разделов (`Главная`, `Подключения`, `AI-клиенты`, `Безопасность`, `Журналы`, `Настройки`) и 7 честных карточек дорожной карты (`v0.9.2–v0.9.9`).
  - Документация и скриншоты: `docs/ui-design-system.md`, `README.md`, `tools/capture_ui_screenshots.py`, `docs/screenshots/{home-dark,home-light,connections-dark,logs-light}.png`.
- Оставшиеся задачи и зависимости: merge [PR #21](https://github.com/SolasFor/MCP-app/pull/21) в `main` после одобрения и слияния PR #20.
- Изменённые файлы / миграции: `app/config.py` (новые UI-поля с дефолтами и санитайзером для v0.8.5), `app/__init__.py` & `pyproject.toml` (`0.9.0`), модули `app/ui/`, `tests/unit/test_ui_theme_and_i18n.py`, `tests/integration/test_ui_redesign_gui.py`, `tests/integration/test_unified_home_gui.py`, `.github/workflows/{transport-checks,rc-windows}.yml`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check .`, `mypy` (win32 + `--platform linux`): PASS (12 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip_audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (121/121 за 7.605s)
    - `tests/integration`: PASS (20/20 за 29.597s; всего 141/141)
    - `tools/capture_ui_screenshots.py`: PASS (DPI `1.0`, `1.25`, `1.5`, `2.0`; 860×600 / 1120×760 / 1440×900; визуальный осмотр исправил 4 дефекта вёрстки и синхронизацию метки темы)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.0-portable.zip` 66.5 MB)
  - GitHub Actions CI на `2ab3ddd`:
    - `Verify & Test (ubuntu-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45518398422/job/138883708050
    - `Verify & Test (windows-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45518398422/job/138883708431
    - `RC Windows installer (no publish)` (`windows-package`): PASS — https://github.com/SolasFor/MCP-app/actions/runs/45518398349/job/138883707970
- Live tests отдельно от mocks: реальный рендеринг GUI, DWM titlebar, переключение Dark/Light/RU/EN, DPI `1.0–2.0` и EXE selftest выполнены на Windows 11.
- Риски / ограничения / блокеры: будущие модули (`Gateway`–`Automation`) показаны честно как `v0.9.2–v0.9.9` без фиктивного функционала; сборка без Authenticode-сертификата.
- PR / релиз: [PR #21](https://github.com/SolasFor/MCP-app/pull/21) (`feat/ui-redesign` → `feat/stability-security`, затем `main`).
- Следующий точный шаг: Этап 3 (`v0.9.1 — Connection Manager`) на ветке `feat/connection-manager`.

## Этап 1: v0.8.6 — Stability & Security (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 1 / `v0.8.6` / `feat/stability-security` / `f6c0dd7`
- Реализованные задачи:
  - Платформенный слой без зависимости от Qt (`app/platform/{__init__,base,windows,posix}.py`, `app/core/winjob.py`): Windows Job Objects (`KILL_ON_JOB_CLOSE`, опционально `BREAKAWAY_OK`), проверка идентичности процесса (`pid` + `create_time`), DPAPI (`CryptProtectData`/`CryptUnprotectData`), Credential Manager, `icacls` ACLs и fallback для POSIX.
  - Единый `ProcessRunner` (`backend/process_runner.py`, интеграция в `backend/server.py`, `backend/managed_servers.py`): разделение контролируемого и явно независимого жизненного цикла (`independent` с безопасным fallback при отсутствии `CREATE_BREAKAWAY_FROM_JOB` во вложенном Job Runner), ограничение параллельности, повторная проверка прав после очереди, неблокирующая отмена SSH через выделенный executor и `cancel_event`, скрытые консольные окна на Windows, `EmergencyStopReport`.
  - Потоковое чтение вывода (`backend/output_stream.py`): параллельный дренаж `stdout`/`stderr`, кольцевой буфер `64 KiB` (head+tail), дисковый спулинг с квотами (`2 MiB`/run, `20 MiB` всего, 100 файлов, TTL 1 ч), постраничная выдача, декодирование UTF-8/OEM/ANSI и очистка.
  - Защита секретов (`app/core/secret_store.py`, `app/core/redaction.py`, `app/core/token_store.py`, `app/core/domain_state.py`, `app/core/proxy.py`): DPAPI/Credential Manager, прозрачная миграция legacy JSON, фильтрация секретов из окружения (`sanitize_child_env`), логов (`RedactingLogFilter`) и диагностик.
  - Реестр инструментов и SQLite OAuth (`backend/tool_registry.py`, `backend/tool_permissions.py`, `backend/oauth_store.py`, `backend/oauth_execution.py`): `SCHEMA_VERSION = 2`, атомарные миграции, индивидуальные белые списки, временные разрешения, флаг аварийной остановки и `export_redacted_backup`.
  - Устойчивость соединения и диагностика (`app/core/reconnect.py`, `app/core/network_watch.py`, `app/core/tunnel_log.py`, `app/core/diagnostics.py`, `app/core/service_manager.py`, `app/ui/connection_diagnostics_dialog.py`, `app/ui/main_window.py`): backoff/jitter, health-check и восстановление при сне/смене сети, классификация ошибок туннеля, кнопка «Аварийная остановка» и экспорт redacted-отчётов.
  - Supply chain и CI: `requirements.lock`, `requirements-build.txt`, `requirements-dev.txt`, `packaging/cloudflared.json` (`2026.11.2`, SHA-256 `555b46c85582461d189cac30d14ad05480d612613801be9f110b8ce08c5b2113`), `tools/check_licenses.py`, `tools/generate_sbom.py`, `.github/workflows/{transport-checks,rc-windows,build}.yml`, `app/selftest.py`, `README.md`, `docs/{security-profiles,oauth-fixed-windows-ssh,oauth-persistence,third-party-licenses,stability-security}.md`.
- Оставшиеся задачи и зависимости: только merge [PR #20](https://github.com/SolasFor/MCP-app/pull/20) в `main` после одобрения владельцем и подписание доверенным Authenticode-сертификатом при его наличии.
- Изменённые файлы / миграции: `backend/oauth_store.py` (миграция SQLite v1→v2), `app/core/{token_store,domain_state,proxy}.py` (прозрачная миграция в `SecretStore` с безопасной совместимостью), `app/__init__.py` (`0.8.6`), новые и обновлённые модули в `app/`, `backend/`, `packaging/`, `tools/`, `docs/`, `tests/`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15, коммит `f6c0dd7`):
    - `compileall -q app backend tests tools`: PASS
    - `ruff check .`: PASS
    - `mypy` (win32) и `mypy --platform linux`: PASS (10 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38 компонентов)
    - `tools/generate_sbom.py`: PASS (38 компонентов CycloneDX)
    - `pip_audit -r requirements.lock --no-deps --disable-pip`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (117/117 за 12.542s)
    - `tests/integration`: PASS (14/14 за 9.339s; всего 131/131)
    - Замер 21.2 MiB флуда (`output_stream`): `stdout_bytes=11141460`, `stderr_bytes=11141460`, `returned_stdout=8050`, `returned_stderr=8050`, `peak_traced_bytes=730350`, `spool_disk_bytes=4194304`, `duration_ms=328`.
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.8.6-portable.zip` 66.4 MB, `SBOM.cdx.json`, `SHA256SUMS.txt`).
  - GitHub Actions CI на `f6c0dd7`:
    - `Verify & Test (ubuntu-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45514910047/job/138871733553
    - `Verify & Test (windows-latest)`: PASS — https://github.com/SolasFor/MCP-app/actions/runs/45514910047/job/138871733325
    - `RC Windows installer (no publish)` (`windows-package` с Inno Setup 6 `Setup.exe`): PASS — https://github.com/SolasFor/MCP-app/actions/runs/45514910385/job/138871735265
- Live tests отдельно от mocks: Windows Job/DPAPI/CredMan, локальный EXE selftest и 21.2 MiB flood протестированы реально на Windows 11; реальные публичные туннели/AI-клиенты не входили в объём Этапа 1.
- Риски / ограничения / блокеры:
  - Режим `full` запускает процессы с правами текущей учётной записи Windows и не является OS-песочницей.
  - Явно `independent` GUI-приложения могут продолжать работу после `EmergencyStop` (отчёт честно перечисляет их PID).
  - Отсутствует доверенный Authenticode-сертификат владельца (сборка остаётся неподписанной, автоустановка обновлений отключена).
- PR / релиз: [PR #20](https://github.com/SolasFor/MCP-app/pull/20) (`feat/stability-security` → `main`), ожидает согласия владельца на merge.
- Следующий точный шаг: Этап 2 (`v0.9.0 — UI Redesign`) на ветке `feat/ui-redesign`.

## Блокеры и ручные действия
Потенциальные, требующие участия владельца (проверяются по мере прохождения этапов):
- Сертификат Authenticode для подписания Windows EXE/Setup.exe (локально и в CI отсутствует — требуется сертификат владельца; неподписанная сборка остаётся с отключённым автообновлением).
- Внешние сервисы следующих этапов: ngrok account/authtoken, Tailscale tailnet/Funnel grants, OpenAI Platform/tunnel entitlement, SolidWorks и COM API, live-тесты внешних AI-клиентов.

## Шаблон записи об этапе
- Этап / версия / ветка / HEAD:
- Реализованные задачи:
- Оставшиеся задачи и зависимости:
- Изменённые файлы / миграции:
- Проверки: команда, окружение, результат, ссылка на CI/лог:
- Live tests отдельно от mocks:
- Риски / ограничения / блокеры:
- PR / релиз:
- Следующий точный шаг:
