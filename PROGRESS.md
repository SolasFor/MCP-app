# MCP-app — журнал выполнения

База плана: `v0.8.5` (`89deaa4`). Аудит репозитория и запуск baseline-тестов проведены.

| Этап | Целевая версия | Статус | PR / CI / доказательства |
|---|---|---|---|
| 1. Stability & Security | v0.8.6 | VERIFIED | [PR #20](https://github.com/SolasFor/MCP-app/pull/20), коммит `f6c0dd7`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45514910047), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45514910385) |
| 2. UI Redesign | v0.9.0 | VERIFIED | [PR #21](https://github.com/SolasFor/MCP-app/pull/21), коммит `2ab3ddd`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45518398422), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45518398349) |
| 3. Connection Manager | v0.9.1 | VERIFIED | [PR #22](https://github.com/SolasFor/MCP-app/pull/22), коммит `424481a`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45522273057), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45522273017) |
| 4. MCP Gateway | v0.9.2 | TODO | — |
| 5. Task Manager | v0.9.3 | TODO | — |
| 6. Server Manager | v0.9.4 | TODO | — |
| 7. Workspaces | v0.9.5 | TODO | — |
| 8. Computer Use | v0.9.6 | TODO | — |
| 9. Extensions | v0.9.7 | TODO | — |
| 10. Remote Management | v0.9.8 | TODO | — |
| 11. Automation & Monitoring | v0.9.9 | TODO | — |
| 12. Stable Release | v1.0.0 | TODO | — |

Статусы: TODO / IN_PROGRESS / BLOCKED / VERIFIED / MERGED / RELEASED. Отдельные проверки: PASS / FAIL / NOT_RUN / BLOCKED / N/A. Не менять TODO на VERIFIED без доказательств приёмки.

## Последняя рабочая сессия
- Дата, ветка, HEAD: 2026-11-25, ветка `feat/connection-manager`, `424481a` (stacked на `feat/ui-redesign` / PR #21).
- Статус Этапа 3 (`v0.9.1 — Connection Manager`): `VERIFIED` (ожидает одобрения владельца для последовательного merge [PR #22](https://github.com/SolasFor/MCP-app/pull/22); внешние публичные live-проверки Cloudflare/ngrok/Tailscale/OpenAI отмечены как `BLOCKED` без разрешения/учётных данных владельца).
- Окружение: Windows 11 Pro 25H2 (x86_64), Python 3.13.15 (`.venv`), `cloudflared 2026.11.2`, `tailscale 1.104.2`, `ngrok` и `openai/tunnel-client` локально не установлены, `gh` авторизован (`SolasFor`), `iscc` в GitHub Actions `windows-latest`.
- Следующее действие: отвести ветку `feat/mcp-gateway` от `feat/connection-manager` и реализовать Этап 4 (`v0.9.2 — MCP Gateway`).

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
