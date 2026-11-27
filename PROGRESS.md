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
| 8. Computer Use | v0.9.6 | VERIFIED | [PR #27](https://github.com/SolasFor/MCP-app/pull/27), коммит `e5837ef`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45580710966), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45580711115) |
| 9. Extensions | v0.9.7 | VERIFIED | [PR #28](https://github.com/SolasFor/MCP-app/pull/28), коммит `62c6708`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45588509164), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45588509142) |
| 10. Remote Management | v0.9.8 | VERIFIED | [PR #29](https://github.com/SolasFor/MCP-app/pull/29), коммит `72f98de`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45595306144), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45595303716) |
| 11. Automation & Monitoring | v0.9.9 | VERIFIED | [PR #30](https://github.com/SolasFor/MCP-app/pull/30), коммит `3b325f3`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45612560560), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45612560580) |
| 12. Stable Release | v1.0.0 | BLOCKED (engineering/CI VERIFIED; owner release blockers remain) | [PR #31](https://github.com/SolasFor/MCP-app/pull/31), коммит `e6bc844`, [Transport CI](https://github.com/SolasFor/MCP-app/actions/runs/45616799590), [RC Windows](https://github.com/SolasFor/MCP-app/actions/runs/45616799698) |

Статусы: TODO / IN_PROGRESS / BLOCKED / VERIFIED / MERGED / RELEASED. Отдельные проверки: PASS / FAIL / NOT_RUN / BLOCKED / N/A. Не менять TODO на VERIFIED без доказательств приёмки.

## Комплексный технический аудит после v1.0.1 (2026-11-26)
- Статус: **VERIFIED** локально (ветка `fix_cursor_and_context_menus`, версия `v1.0.1`; внешние гейты владельца — `BLOCKED`/`NOT_RUN` ниже).
- **P0-1 — Windows ACL, атомарный I/O, упаковка `pywin32` и восстановление при запуске**:
  - `app/platform/windows.py`: добавлена `is_reparse_point()` (`GetFileAttributesW` / `FILE_ATTRIBUTE_REPARSE_POINT`), нормализация путей и жёсткий отказ применять DACL к symlink/junction; сохранён расчёт DACL строго по SID `TokenUser` без короткого `USERNAME`, без `Everyone` и без снятия наследования до создания валидного дескриптора безопасности.
  - `app/core/atomic_io.py`: единая потокобезопасная атомарная запись (`.name.pid.tid.tmp`, `fsync`, повтор `os.replace` при кратковременных Win32 `ERROR_ACCESS_DENIED`/`ERROR_SHARING_VIOLATION`, гарантированное удаление `.tmp` при `ENOSPC`/ошибках) и безопасная инициализация каталогов (`try_init_private_dir`) во всех хранилищах (`secret_store`, `config`, `domain_state`, `proxy`, `token_store`, `tunnels`, `extensions`, `gateway`, `servers`, `workspaces`, `desktop`, `remote`).
  - `app/core/acl_recovery.py`, `main.py`, `app/gui.py`, `app/selftest.py`, `packaging/{mcp_app.spec,build.ps1}`: неразрушающая диагностика `diagnose_data_acls` и подтверждаемое владельцем восстановление `repair_data_acls` / `--repair-acl` (только для объектов с `OWNER == TokenUser` SID, с пропуском reparse-точек и сохранностью `secrets.key`, `secrets.vault.enc`, `token.json` и SQLite-баз); проверка ACL и DPAPI `SecretStore` в `--selftest`; явные `hiddenimports` `pywin32` в `mcp_app.spec`; корректная обработка путей к Python с пробелами в `packaging/build.ps1`.
- **P0-2 — Сохранность `MCP Owner Token` и гранулярные права AI-клиентов**:
  - `app/core/token_store.py`, `app/core/service_manager.py`, `app/backend_entry.py`, `backend/{oauth_provider,server}.py`: разделены состояния первого запуска и ошибки чтения/DPAPI/ACL (`TokenLoadStatus`, `TokenStorageError`), исключена тихая перегенерация/перезапись существующего `MCP Owner Token` при недоступном хранилище или в режиме `--headless`, добавлена блокировка `preflight()` с подсказкой `--repair-acl` и защита `OAuthStore` от сброса при прямом импорте `backend/server.py` без `MCP_SECRET_TOKEN` (`bind_owner=TOKEN_FROM_ENV`).
  - `backend/{oauth_store,oauth_execution,tool_registry}.py`, `backend/desktop/{models,manager}.py`, `app/ui/{oauth_execution_dialogs,main_window,pages/clients_page}.py`: сохранена схема `OAuthStore.SCHEMA_VERSION == 3`, расширен `CLIENT_ID_RE` для RFC 6749 / CIMD URL `client_id`, добавлены пер-клиентские политики инструментов (`exec_client_policies`: `denied_tools`, `allowed_tools_only`) и индивидуальные переопределения Computer Use (`DesktopPolicy.client_overrides`: `inherit`/`disabled`/`view`/`control`), синхронизация профиля и шаблона белого списка по умолчанию между `__default__` и существующими issuers без затирания клиентских правил, выбор актуального `latest_persistent_resource_url` и диалог `ClientPermissionsDialog` в контекстном меню `ClientsPage`.
- **P1 / P2 — Безопасность путей, Gateway SSRF redirect guard, утечки ресурсов, производительность и UI**:
  - `backend/security_policy.py`: исправлена проверка реального NUL-байта (`"\x00"` вместо литерала `"\\x00"`), добавлена блокировка NTFS ADS (`:`) и зарезервированных имён устройств Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
  - `backend/gateway/{upstream_client,router}.py`: добавлен перехватчик HTTP `3xx` редиректов с повторной проверкой `validate_upstream_url` (защита от обхода SSRF на loopback/link-local/metadata IP) и блокировкой cross-origin редиректов при наличии секретных заголовков/токенов.
  - `backend/extensions/runtime.py`: устранена утечка pipe/фоновых потоков при перезапуске упавшего воркера расширения и при ошибке/таймауте RPC `initialize`.
  - `app/core/tunnels/tailscale.py`: добавлено кэширование `tailscale status --json` (`30s` TTL) и быстрый возврат принадлежащего маршрута без блокировки GUI-потока частыми запусками CLI.
  - `app/ui/components/silent_dialog.py`, `app/ui/i18n.py`: локализованы кнопки `SilentMessageBox` (`RU`/`EN`), добавлена передача `detailed_text`, синхронизированы `728` ключей локализации.
  - `tests/integration/test_{desktop_computer_use,extensions,remote_management,ui_redesign_gui,unified_home_gui}.py`: полностью изолированы `APPDATA`, `LOCALAPPDATA` и тестовые `OAuthStore`.
- **Результаты проверок (Windows 11 Pro 25H2 x64, Python 3.13.15)**:
  - `compileall`, `ruff check app backend tests tools main.py`: **PASS** (0 замечаний).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 74 source files`).
  - `i18n` RU/EN parity: **PASS** (`728` ключей); `tools/check_licenses.py`: **PASS** (`38/38`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (0 уязвимостей).
  - `tests/unit`: **PASS** (**206/206** за `13.367s`, включая новые `test_windows_acl.py`, `test_client_and_token_persistence.py`, `test_security_and_resource_hardening.py`).
  - `tests/integration`: **PASS** (**76/76** за `43.8s`).
  - `tests/e2e` (Playwright): **PASS** (**2/2** за `11.666s` — Chromium, Firefox, Google Chrome, Microsoft Edge).
  - `tools/capture_ui_screenshots.py`: **PASS** (`DPI check` `1.0`, `1.25`, `1.5`, `1.75`, `2.0` — OK; 13 скриншотов Dark/Light RU/EN).
  - `packaging\build.ps1`: **PASS**:
    - `dist\MCPApp\MCPApp.exe` (`8,417,419` Б, SHA-256 `6c3ca62594722d9c7bcaaa5f5b86dc5ec0a3a7f87e2120a51e46eed9d70c907a`); `_internal`: `167` файлов (`137,437,868` Б).
    - `dist\MCPApp\MCPApp.exe --selftest`: **PASS** (`Qt 6.12.1`, `WindowsPlatformAdapter`, `cloudflared 2026.11.2`, `Starlette`, `RESULT OK`).
    - Живой запуск `MCPApp.exe` на одноразовом неадминистративном профиле: GUI `--minimized` (**PASS**, процесс активен, `crash.log` пуст, созданы `token.json` и `secrets.key`), `--headless` (**PASS**, `/health` HTTP `200`, `/mcp` без токена HTTP `401`, `token.json` неизменен), `--repair-acl` (**PASS**, `ok=true`, повреждённый DACL восстановлен с сохранением `token.json` и `secrets.key`).
    - `dist\MCPApp-1.0.1-portable.zip`: `58,302,631` Б, SHA-256 `a233b5e9fa9cb77f1c573f1e91f18d0e092032c5a4fd950799a21c74da3ee268`; `dist\SBOM.cdx.json`: `12,195` Б (`38` компонентов), SHA-256 `62be61e19f16dc6458d11572594e0b311e134f823ba8137faf012c56e6dde401`.
- **BLOCKED / NOT_RUN (без имитации прохождения)**:
  - Доверенный сертификат Authenticode (`.pfx`): **BLOCKED** (не настроен; EXE и Setup собираются неподписанными, `StagedUpdater.auto_install_enabled = False`).
  - Авторизация локального `sonar` CLI (`1.13.1`) и `sonarqube-cloud` MCP в Antigravity: **BLOCKED** (публичный read-only Quality Gate в PR #35 проверен через SonarCloud, локальный CLI/MCP не авторизованы).
  - Внешние live SaaS AI-клиенты, платные/доменные туннели и восстановление реального профиля на ПК `SOLAS`: **BLOCKED / NOT_RUN** (реальный профиль `%APPDATA%\MCPApp` и облачные DNS/туннели не затрагивались по правилам безопасности; локальный запуск `Setup.exe` в текущей сессии не выполнялся из-за активного экземпляра `D:\Coding\MCP App\dist\MCPApp\MCPApp.exe` с `AppMutex=MCPApp-Running`).

## Проверка GitHub Actions (PR #35) и тестирование `MCPApp-Setup-1.0.1.exe` в чистой Windows VM (2026-11-27)
- **PR #35** (`fix_cursor_and_context_menus` → `main`, статус: **OPEN**, merge не выполнялся без решения владельца): https://github.com/SolasFor/MCP-app/pull/35
- **Выявленные и исправленные по результатам первого CI-прогона дефекты (`26e04f6`)**:
  - `app/core/acl_recovery.py`: поддержан `TokenOwner` (для файлов, созданных повышенным токеном с `Owner = BUILTIN\Administrators`), вынесен CLI `--repair-acl` в `run_repair_acl_cli()` с жёсткой санацией выходного пути отчёта `_resolve_report_output_path()`.
  - `app/core/atomic_io.py`: добавлена внутрипроцессная блокировка по каноническому пути `_path_lock()` и расширенные Win32 retry-задержки `_REPLACE_DELAYS_S` при многопоточной записи.
  - `.github/workflows/{rc-windows,build}.yml`: добавлен автоматический e2e-шаг `Test MCPApp-Setup installer, upgrade, and uninstall in clean environment` на свежей VM `windows-latest`.
- **Прогоны GitHub Actions на коммите `26e04f6`**:
  - `MCP transport checks` (`#45897725422`): **PASS** — `Verify & Test (ubuntu-latest)` (`1m16s`: https://github.com/SolasFor/MCP-app/actions/runs/45897725422/job/140175672144), `Verify & Test (windows-latest)` (`2m59s`: https://github.com/SolasFor/MCP-app/actions/runs/45897725422/job/140175672604).
  - `RC Windows installer (no publish)` (`#45897725432`): **PASS** (`3m12s`: https://github.com/SolasFor/MCP-app/actions/runs/45897725432/job/140175672859).
  - `SonarCloud Code Analysis`: **PASS** (`39s`, Quality Gate `OK`, `new_security_rating=1`, `new_reliability_rating=1`, `new_maintainability_rating=1`, `duplications=0.1%`): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=35
- **Проверка артефакта `MCPApp-Setup-1.0.1.exe` в чистой VM `windows-latest` + проверка скачанного пакета (`MCPApp-RC-Windows-67`)**:
  - **Свежая тихая установка (`/VERYSILENT /CURRENTUSER`) без прав администратора**: **PASS** (`%LOCALAPPDATA%\Programs\MCP app\MCPApp.exe`, `_internal\bin\cloudflared.exe`, `unins000.exe`, ярлык в меню «Пуск», ключ `HKCU\...\Uninstall\{8F3C2A71-4D5E-4B9A-9C61-2E7A1D0B5F43}_is1`, `DisplayVersion=1.0.1`).
  - **Работа установленного `MCPApp.exe` в изолированном профиле**: `--selftest` (`RESULT OK`, `WindowsPlatformAdapter`), `--headless` (`/health` HTTP `200`, неавторизованный `/mcp` HTTP `401`, созданы `token.json` и `secrets\secrets.key`), `--repair-acl` на искусственно заблокированном подкаталоге `extensions\installed` (`ok=true`, DACL восстановлен с сохранением SHA-256 `token.json`).
  - **Обновление поверх существующей установки (in-place upgrade)**: **PASS** (устаревший маркер `_internal\stale_old_version.marker` удалён секцией `[InstallDelete]`; `token.json` с неизменным SHA-256, `secrets\secrets.key` и `settings.json` сохранены; повторные `--selftest` и `--headless` пройдены).
  - **Чистое удаление (`unins000.exe /VERYSILENT`)**: **PASS** (`MCPApp.exe`, ярлык и запись реестра удалены, данные пользователя в `%APPDATA%\MCPApp` сохранены).
  - **Контрольные суммы и метаданные скачанного артефакта (`#45897725432`)**:
    - `MCPApp-Setup-1.0.1.exe`: `46,270,766` Б, SHA-256 `1f270144a0222607e1253cfc3deec9dc17e9280e693c4d4233cb6322d023cb58` (`ProductName=MCP app`, `ProductVersion=1.0.1`, `AuthenticodeStatus=NotSigned`).
    - `MCPApp-1.0.1-portable.zip`: `62,577,287` Б, SHA-256 `fb21aac93dbf0acc15c78430031888b86fc0fb9055280542eabad3c9eef048f7`.
    - `SBOM.cdx.json`: `12,195` Б (`38` компонентов), SHA-256 `b97ca7ce5fa9a1275e16260eb91ce9af86131115ec8bc19043b0131c8c7053ab`.
    - `SHA256SUMS.txt` и `build/selftest.txt` (`RESULT OK`): сверены байт-в-байт, 0 расхождений.

## Аудит после v1.0.0 — исправление Windows ACL (2026-11-26)
- Статус: IN_PROGRESS. Подтверждено использование короткого USERNAME в icacls, создающее риск блокировки данных при совпадении имени ПК и пользователя.
- DACL устанавливается через Windows API по SID токена процесса; добавлены два регрессионных теста. ACL реального профиля и существующие секреты не изменялись.
- PASS: 189 unit-тестов, Ruff, mypy (72 файла), smoke записи во временный защищённый каталог; моделируемый отказ API сохраняет исходный DACL.
- NOT_RUN/BLOCKED: integration suite после исправления, сборка и запуск нового EXE, восстановление профиля SOLAS (текущий хост другой), installer upgrade и внешний live smoke.
- AGENTS.md актуализирован для сопровождения; план аудита — docs/maintenance-audit.md. Не считать релиз принятым до закрытия P0 и обязательных проверок.

## Последняя рабочая сессия
- Дата, ветка, версия: 2026-11-26, ветка `fix_cursor_and_context_menus` (поверх `main` / `v1.0.0` `542989a` с PR #32/#33/#34), релиз-обновление `v1.0.1` (`VERIFIED` локально).
- **UI/UX, Gateway Onboarding, OAuth & Task Manager (`v1.0.1`)**:
  - Курсор и hover: аудит `app/ui/**`, удаление `PointingHandCursor` со стандартных контролов (оставлен только на `#Link`/`#SubtleLink`), удаление ложного hover на `#CopyField`/`#Log`/read-only полях, `SafeSpinBox`/`SafeDoubleSpinBox` во всех диалогах и страницах.
  - Таблица «AI-клиенты»: `TableCellCombo` с вертикальным/горизонтальным центрированием, адаптивной высотой строк и шириной столбца без обрезания при `100%–200%` DPI и RU/EN (`clients_page.py`, `oauth_clients_dialog.py`, `table.py`, `theme.py`), с очисткой виджетов ячеек при перезагрузке.
  - Единые контекстные меню `AppContextMenu` + кнопки `⋯` и ПКМ для конкретной строки + глобальное меню `⋯` в `ClientsPage` (убрана кнопка отзыва с панели, подтверждение отзыва сохранено), `TasksPage`, `GatewayPage`, `ServersPage`, `WorkspacesPage`, `DevicesPage`, `ExtensionsPage`, `AutomationPage`.
  - Полноценное удаление неактивных задач (`succeeded`/`failed`/`cancelled`/`interrupted`) и пакетная очистка (`>7/30/90 дней`, все неактивные) в `TaskStore`/`TaskManager`/`TasksPage` с запретом удаления `queued`/`running`/cancelling/живых процессов и строгой проверкой путей `spool`/`artifacts`.
  - Автоматизированное подключение MCP-серверов в Gateway: `AddMcpServerWizard` (URL Streamable HTTP/SSE + OAuth PKCE, JSON, файл, автопоиск конфигов AI-клиентов включая Codex TOML, 7-категорный каталог шаблонов, ручной STDIO без автозапуска), с исправлением `mcp==2.3.0` извлечения `server_info`/`protocol_version`.
  - Свободный токен владельца без искусственных ограничений (`MCP_OWNER_SECRET_B64` для точного UTF-8/пробельного пароля согласия + ASCII `MCP_SECRET_TOKEN` Bearer для прямого заголовка) и переработанная RU/EN Dark/Light OAuth-форма (`/oauth/consent`, `/authorize`) с предупреждением для `full`.
  - Исправлен `task_start` по умолчанию в `allowlist` (динамический `timeout=15s`/`12s`, `60s` в `full` с сохранением жёстких лимитов) и добавлены структурированные MCP-ошибки `CallToolResult(is_error=True, structured_content=...)` с 13 кодами `TASK_*` и редактированием секретов/путей.
- Проверки `v1.0.1` (после финальных правок, Windows 11 Pro, Python 3.13.15, `.venv`):
  - `compileall`, `ruff check`: **PASS** (0 ошибок).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 72 source files`).
  - `tools/check_licenses.py`: **PASS** (38/38); `pip_audit -r requirements.txt`: **PASS** (0 уязвимостей).
  - `tests/unit`: **PASS** (**187/187** за 20.114s, включая `test_task_errors_and_purge.py`, `test_gateway_onboarding.py`, `test_domain_and_tokens.py`).
  - `tests/integration`: **PASS** (**76/76** за 80.968s, включая `test_v1_0_1_ui_and_menus.py` и `test_acceptance_wave2_gui.py`).
  - `tests/e2e` (Playwright): **PASS** (**2/2** за 11.398s — Chromium, Firefox, Google Chrome, Microsoft Edge; RU Dark, EN Light, `full`-предупреждение, токен с пробелами и кириллицей `MCP_OWNER_SECRET_B64`).
  - `tools/capture_ui_screenshots.py`: **PASS** (`DPI check` `1.0`, `1.25`, `1.5`, `1.75`, `2.0` — OK; обновлены `docs/screenshots/*.png`, визуально проверены `clients-dark.png`, `clients-light.png`, `gateway-wizard-dark.png`, `tasks-dark.png`, `oauth-consent-dark-ru.png`, `oauth-consent-light-en.png`).
  - Сборка Windows (`packaging\build.ps1`): **PASS**:
    - Frozen smoke (`dist\MCPApp\MCPApp.exe --headless` → `/health` HTTP 200): **PASS**
    - Скопировано в `D:\Coding\MCP App\dist` (`MCPApp\`, `MCPApp-1.0.1-portable.zip`, `SBOM.cdx.json`, `SHA256SUMS.txt` с сохранением исторических архивов `0.8.6–1.0.0`)
    - `"D:\Coding\MCP App\dist\MCPApp\MCPApp.exe" --selftest`: **PASS** (`Qt 6.12.1`, `cloudflared 2026.11.2`, `Starlette`, `RESULT OK`)
    - `MCPApp-1.0.1-portable.zip`: `58,205,914` Б (`55.5 MB`), SHA-256 `9e979be735a2024692ffedf8a96a8987bb4027e6671726ab648cb2241e89bb83`; `SBOM.cdx.json` SHA-256 `20461f63e108a385f093ea8737135515b3ce0539aa72b888cff39ecda0e52a65`.
  - Локально пропущено (ожидаемо): `Setup.exe` (`ISCC.exe` / Inno Setup 6 не установлен локально; собирается в GitHub Actions CI), внешние SaaS AI-клиенты и доверенная Authenticode-подпись.

## Предыдущая сессия (v1.0.0)
- Дата, ветка, основа: 2026-11-26, ветка `feat/minimalist-compact-ui-redesign` (поверх `fix/v1.0.0-acceptance-fixes` / `release/v1.0.0`), подготовка финального релиза `v1.0.0` по одобрению владельца.
- **Minimalist Compact UI Redesign & `v1.0.0` Release Prep**:
  - Выполнена полная переработка интерфейса в стиле Linear/Raycast/Docker Desktop (`DESIGN.md`, `app/ui/**`), удалены все декоративные анимации (оставлен лишь `150 ms OutCubic` `ToggleSwitch` при включённых анимациях ОС), добавлены `FlowLayout`-панели и `tests/integration/test_minimalist_ui_redesign.py` (`break-ui`, 6 размеров окна, `1.0–2.0` DPI).
  - Обновлены `README.md`, `CHANGELOG.md`, `docs/releases/v1.0.0.md`, `docs/screenshots/*.png`, изоляция `domain_state` в `tools/capture_ui_screenshots.py` и headless Qt env в `.github/workflows/build.yml`.
- Ранее (`fix/v1.0.0-acceptance-fixes`, PR #32):
  - Реализованы и проверены Wave 1 / Wave 2 / Wave 3 исправления (`compileall`, `ruff`, `mypy` Windows + Linux, `check_licenses.py`, `pip_audit`, `tests/unit`, `tests/integration`, Playwright E2E, EXE `--selftest`, `1.0–2.0` DPI).
- Окружение: Windows 11 Pro 25H2 (x86_64), Python 3.13.15 (`.venv`), `gh` авторизован (`SolasFor`), `iscc` / Inno Setup 6 выполняется на `windows-latest` в GitHub Actions.
- Следующее действие: зелёный CI на PR в `main`, merge в `main` и публикация тега/релиза `v1.0.0` через `.github/workflows/build.yml`.

## Release Acceptance Wave 3 — дополнительные исправления UI (`fix/v1.0.0-acceptance-fixes`, `VERIFIED` локально)
1. **Вкладка «Безопасность» — Computer Use (`security_page.py`, `toggle_switch.py`, `backend/desktop/{models,manager}.py`)**:
   - Полностью удалена кнопка «Остановить Computer Use» (`desktop_stop_btn`, `stop_computer_use`, пустая строка `d_row`); внутренний механизм аварийной остановки (`DesktopPolicyStore.set_emergency_stop`, `ServiceManager.emergency_stop`, условная `desktop_clear_stop_btn`) полностью сохранён.
   - При выключении главного тумблера Computer Use зависимые тумблеры (`desktop_screen_sw`, `desktop_control_sw`, `desktop_secrets_sw`, при этом `desktop_secrets_sw` также требует `desktop_control_sw`) визуально становятся серыми и недоступными для нажатия без сброса сохранённых значений; соответствующие MCP-инструменты мгновенно отключаются (`ToolRegistry` / `DesktopManager` `effective_*`), при повторном включении права и состояния восстанавливаются без перезапуска и без шумных уведомлений.
   - Настройка «Сценарий доступа по умолчанию» (`SafeComboBox`, подсказки) перенесена в карточку «Политика выполнения команд» на вкладке «Безопасность» с полным сохранением `allowlist` по умолчанию, подтверждения для `full` и персистентности.
2. **Вкладка «Журналы» (`logs_page.py`, `log_viewer.py`, `main_window.py`)**:
   - Полностью удалены кнопка «Экспорт диагностики…» (`export_diagnostics_zip` из toolbar, внутренний модуль `app/core/diagnostics_bundle.py` сохранён) и пояснительная надпись `logs.lead` вместе с переводами и отступом; на панели оставлен обычный экспорт отредактированного текста журналов (`*.log`/`*.txt`) при сохранении всех функций фильтрации, поиска, пагинации, копирования, очистки, открытия папки и автопрокрутки.
3. **Вкладка «Главная» (`home_page.py`, `main_window.py`, `i18n.py`)**:
   - Полностью удалён блок «Доступ и AI-клиенты» (`access_card`, заголовок, комбобокс, кнопки, пояснения, отступы и эксклюзивные сигналы/слоты `access_profile_changed`, `allowlist_requested`, `diagnostics_requested`, `_open_connection_diagnostics`), оставлены только Hero Engine и Endpoint без пустых отступов.

## Release Acceptance Wave 2 (`fix/v1.0.0-acceptance-fixes`, `VERIFIED` локально)
1. **Оптимизация `_internal` (`onedir`)**: `dist/MCPApp/_internal` уменьшен с `168,162,115` байт (`160.37 MB`, `323` файла, `72` каталога) до `137,304,851` байт (`130.94 MB`, `166` файлов, `62` каталога — **-29.43 MB / -157 файлов**); `MCPApp-1.0.0-portable.zip` уменьшен с `70,316,210` байт (`67.06 MB`) до `58,066,712` байт (`55.38 MB` — **-11.68 MB**). Сохранены `onedir`, `copy_metadata("mcp", "pydantic", "paramiko", "cryptography")`, лицензии и локали Qt `ru`/`en`.
2. **Постоянная система логирования**: `%APPDATA%\MCPApp\logs\` с 15 компонентными логами + `archive/`, MP-блокировкой `.write.lock` (без `WinError 32`), зеркалированием в `errors.log` без циклов, перехватом падений в `crash.log`, сохранностью `mcp_execution_audit.jsonl` и `desktop_policy_audit.jsonl`, редактированием секретов/PKCE/кодов/скриншотов даже в `DEBUG`, настройками на `SettingsPage`, переработанным `LogsPage` (`LogViewerWidget`) и безопасным экспортом диагностического ZIP (`export_diagnostics_zip`).
3. **Убраны лишние уведомления**: удалены toast о смене темы и popup о сворачивании в трей при сохранении поведения трея, ошибок и предупреждения Full Access.
4. **Упрощён список провайдеров и убран Loopback из UI**: 4 UI-провайдера без бейджей «Не найден / Установлен / Доступен», версий и `Loopback`; безопасная миграция `local_only` / `openai_tunnel` -> `PROVIDER_NONE`; внутренний loopback сохранён для тестов/headless/Admin API.
5. **Исправление потери своего домена при переключениях (`Named -> Quick / ngrok / Tailscale -> Named` + рестарт)**: независимое хранение конфигов, двусторонняя синхронизация `domain.json` + `connections.json`, корректная остановка предыдущего транспорта и точная классификация причин (`agent_missing`, `secret_decrypt_failed`, `domain_not_configured`, `domain_invalid`, `token_missing`, `token_invalid`).
6. **Пользовательские токены и разделение ключей**: кнопка `Paste` и ручной ввод `MCP Owner Token`; второй режим в `DomainWizard` (подключение существующего Cloudflare туннеля по домену и готовому `Cloudflare Tunnel Token` без API Token и без изменения DNS); явное разграничение всех 4 типов токенов и DPAPI-хранение.
7. **Computer Use с `ToggleSwitch` и автосохранением**: 4 переключателя `ToggleSwitch`, убрана кнопка «Сохранить», атомарное `DesktopPolicyStore.update()`, мгновенное применение на сервере, откат и тихое предупреждение при ошибке записи, аудит в `desktop_policy_audit.jsonl` и `computer_use.log`.
8. **Полная переработка прокси**: отказ от `127.0.0.1:1080` по умолчанию; режимы `none` (по умолчанию), `auto` (ENV/WinINET/WinHTTP/PAC/локальные VPN-порты с реальной проверкой протокола/авторизации/TLS без тихого fallback на direct) и `manual` (`SOCKS5H`/`SOCKS5`/`HTTP CONNECT` + DPAPI); фоновая диагностика и честная обработка `ngrok` (`HTTP_PROXY` only) / `Tailscale` (напрямую).
9. **Исправление OAuth в Chromium-браузерах**: корневая причина (`CSP: form-action 'self'` блокировал 303-редирект Chromium на cross-origin callback) исправлена динамическим `consent_security_headers(redirect_uri)`, добавлены канонизация `Origin`, `Sec-Fetch-Site`, CSRF cookie+token, retry-форма и HTML-страницы ошибок `/oauth/consent` и браузерного `/authorize`. Подтверждено живыми Playwright E2E-тестами в **Chromium**, **Google Chrome**, **Microsoft Edge** и **Firefox**.

## Release Acceptance v1.0.0 — исправления по пользовательскому тестированию (`VERIFIED` локально)
- Ветка / база / версия: `fix/v1.0.0-acceptance-fixes` (от `release/v1.0.0` `3037f18`) / `v1.0.0`
- Реализованные задачи:
  1. **Белый список по умолчанию (`allowlist`)**: `Settings.default_access_profile = "allowlist"` (`app/config.py`), `ExecutionApprovals.DEFAULT_PROFILE = "allowlist"` + `default_template` / `save_default_template` (`backend/oauth_execution.py`), выбор/редактирование до запуска MCP-сервера и персистентность в `settings.json` / `exec_policy` (`app/ui/main_window.py`, `app/ui/pages/home_page.py`), сохранение индивидуальных профилей и `fail-closed` откат в `safe` при неавторизованных клиентах, повреждённых политиках, невалидных настройках и аварийной остановке.
  2. **Защита выпадающих списков от колёсика мыши**: `SafeComboBox` (`app/ui/components/safe_combo.py`), игнорирующий `QWheelEvent` в закрытом состоянии (в том числе в фокусе) с передачей прокрутки родительской странице и сохранением прокрутки в раскрытом списке/клавиатурой; применён ко всем `QComboBox` в `app/` (подтверждено AST-сканом).
  3. **Бесшумные диалоги и уведомления**: `SilentDialog`, `SilentMessageBox` (`app/ui/components/silent_dialog.py`), `SilentNotificationPopup` (`app/ui/components/toast.py`), обновление `app/ui/tray.py`, `app/gui.py` и всех страниц/диалогов без вызова `QMessageBox.*`, `QApplication.beep` и `QSystemTrayIcon.showMessage` (подтверждено AST-сканом), без отключения системной громкости Windows и с сохранением явного подтверждения для режима `full`.
  4. **Выпадающий список темы**: `SafeComboBox#ThemeCombo` в правом верхнем углу (`app/ui/main_window.py`) с вариантами «Светлая / Тёмная / Системная», иконками и двусторонней синхронизацией с `SettingsPage` + сохранением после перезапуска.
  5. **Устранение зависания смены темы (~1 с → 30–56 мс)**: кэширование PNG-переключателей/шеврона, QSS и `QPalette` (`app/ui/theme.py`), однократная инициализация стиля `Fusion` и шрифта, отказ от глобального `app.setStyleSheet()` в пользу `app.setPalette()` + точечного `apply_to_widget()` только на видимые оболочку/страницу и открытые диалоги (`_PopupThemeFilter`), ленивое обновление скрытых страниц в `show_page()` и исключение синхронных CLI-вызовов `connections.list_statuses()` из обработчика смены темы.
     - Замер на реальном Windows (`MainWindow.set_theme_mode`, не `offscreen`):
       - **До оптимизации**: `light=1007.3 ms (+processEvents=1022.3 ms)`, `dark=976.7 ms (+processEvents=1004.5 ms)`.
       - **После оптимизации**: `light1=40.0 ms (+ev=56.0 ms)`, `dark1=30.3 ms (+ev=47.3 ms)`, `light2=30.1 ms (+ev=46.0 ms)` (ускорение ~21x; существенно ниже целевого порога 100–200 мс).
  6. **Исправление OAuth при переподключении после ротации токена владельца**: `OAuthStore.bind_owner()` (`backend/oauth_store.py`, миграция схемы v2→v3 с `meta.resource_url`) при смене токена владельца отзывает все `tokens`, сбрасывает `clients.approved_at = NULL` и `exec_*` overrides, но сохраняет DCR-регистрацию `clients` (`client_id`), чтобы AI-клиент при «Переподключить» мог сразу пройти `/authorize` → `/oauth/consent` с новым токеном владельца без `Invalid request` / `Client ID not found`; `ServiceManager.set_token()` перезапускает только локальный сервер, не обрывая активный туннель.
  7. **Полное удаление OpenAI Secure MCP Tunnel**: удалён `app/core/tunnels/openai_tunnel.py` и все ссылки `PROVIDER_OPENAI` в ядре/UI/тестах/документации; оставлены 5 провайдеров; добавлена безопасная миграция legacy `openai_tunnel` → `local_only` и кнопка подтверждённого владельцем удаления устаревшего ключа `tunnel/openai_tunnel_api_key` на вкладке «Подключения».
  8. **Мгновенное применение прав OAuth-клиентов**: унифицированы `canonical_oauth_urls()` и `oauth_store_path`, синхронизированы runtime URL `ngrok` и `tailscale_funnel`, очищаются `exec_temp_grants` при понижении в `safe`, `MCPServer` объявляет `capabilities.tools.listChanged = True` и рассылает `notifications/tools/list_changed` через `_ActiveSessionToolTracker`, добавлена подсказка обновления списка инструментов на `ClientsPage`.
  9. **Живое применение прав Computer Use (`desktop_*`)**: `ToolRegistry` разделён на `DESKTOP_VIEW_TOOLS` (5) и `DESKTOP_CONTROL_TOOLS` (8) (`backend/tool_registry.py`, `backend/desktop/models.py`), инструменты динамически скрываются/открываются по `DesktopPolicy` и профилю клиента (никогда в `safe`), с сохранением UIPI/UAC/password/locked-session защит и smoke-проверкой на реальном окне Windows.
  10. **`server_info`**: возвращает фактический `profile=safe|allowlist|full`, `computer_use=disabled|view|control` и `server_mode=standard|advanced` (`backend/server.py`) без утечки секретов, путей и чужих клиентов.
  11. **Очистка «Главной»**: полностью удалён нижний блок «Подключённые OAuth-клиенты» (`home_page.py`, `main_window.py`, `i18n.py`).
  12. **Очистка «Безопасности»**: полностью удалена карточка «Аварийное управление и диагностика» (`security_page.py`, `main_window.py`, `i18n.py`), с сохранением рабочих кнопок на «Главной».
- Проверки (2026-11-25, Windows 11, `.venv`, Python 3.13.15):
  - `compileall`, `ruff check app backend tests tools`, `mypy` (`win32` + `--platform linux`): **PASS** (66 файлов, 0 ошибок)
  - `tools/check_licenses.py`: **PASS** (38/38); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (0 уязвимостей)
  - `tests/unit`: **PASS** (163/163 за 11.869s); `tests/integration`: **PASS** (62/62 за 57.969s, включая `test_acceptance_gui_fixes.py`, `test_acceptance_oauth_and_desktop.py` с реальным Uvicorn reconnect E2E и реальным Win32-окном; всего **225/225**)
  - ASGI init smoke (`backend.server:build_app`): **PASS**
  - `tools/capture_ui_screenshots.py` (DPI `1.0`, `1.25`, `1.5`, `2.0` + `docs/screenshots/*.png`): **PASS**
  - `packaging/build.ps1`: **PASS** (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-1.0.0-portable.zip` 67.1 MB SHA-256 `a153a183cda186ea0f98c4c08c8bd754ee1c15db01dea85327c09919c90abe35`, `SBOM.cdx.json` SHA-256 `aeb7ab3f766925c3684c6c05938fd74bb328dee913e423ed40f29638e4cc3b7a`; Inno Setup `Setup.exe` локально пропущен из-за отсутствия `iscc`, собирается в CI).
- Оставшиеся `BLOCKED` / `NOT_RUN`: живые тесты с внешними SaaS AI-клиентами (ChatGPT/Claude/Gemini/Notion) и платными/доменными туннелями (Cloudflare Named/ngrok/Tailscale Funnel ACL), доверенная Authenticode-подпись, 72h soak-тест.

## Этап 12: v1.0.0 — Stable Release (BLOCKED: engineering/CI VERIFIED; owner gates remain)
- Этап / версия / ветка / HEAD: Этап 12 / `v1.0.0` / `release/v1.0.0` / `e6bc844`
- Реализованные задачи:
  - Обновлена версия `1.0.0` в `app/__init__.py` и `pyproject.toml`.
  - Финализирован комплект релизной документации: `docs/threat-model-v1.md`, `docs/compatibility-matrix.md` (честное разделение `VERIFIED` / `NOT_APPLICABLE` / `BLOCKED`), `docs/upgrade-guide.md`, `docs/tool-reference.md`, `CHANGELOG.md` (`v0.8.5`–`v1.0.0`), `docs/releases/v1.0.0.md` и обновлённый `README.md` (FAQ, известные ограничения и не-гарантии полной песочницы).
  - Добавлен E2E-набор `tests/integration/test_release_1_0_0.py`: миграции `v0.8.5 → v1.0.0` (принудительный сброс `allow_query_token=False`, перенос `managed_servers.json` v1→v2 с резервной копией, сохранность OAuth-клиентов), восстановление при битых конфигах (`fail-closed`) + `BackupManager` roundtrip, параллельные клиенты + отзыв OAuth в полёте с автопаузой расписаний, усечение флуда вывода (40+ KiB) и редактирование секретов, проверка версии и скан секретов по `git ls-files`.
- Оставшиеся задачи и зависимости (блокеры владельца):
  - Доверенный Authenticode-сертификат `.pfx` для подписи EXE/Setup (сборки неподписанные, `StagedUpdater.auto_install_enabled = False`).
  - Непрерывный 72-часовой soak-тест (`NOT_RUN`).
  - Внешняя live-матрица транспорт/клиент, требующая учётных данных/доменов/планов/лицензии владельца (Cloudflare Named domain, ngrok, Tailscale Funnel ACL, OpenAI Tunnel, ChatGPT/Claude/Gemini/Notion, live `SLDWORKS.exe` COM).
  - Последовательный merge PR #20–#31 в `main` и публикация официального GitHub Release `v1.0.0` (по правилам `AGENTS.md` требуют одобрения владельца).
- Изменённые файлы / миграции: `app/__init__.py`, `pyproject.toml`, `README.md`, `CHANGELOG.md`, `docs/{threat-model-v1,compatibility-matrix,upgrade-guide,tool-reference}.md`, `docs/releases/v1.0.0.md`, `tests/integration/test_release_1_0_0.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `i18n` parity: PASS (616 ключей RU/EN)
    - `compileall`, `ruff check app backend tests tools`, `mypy` (win32 + `--platform linux`): PASS (67 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (163/163); `tests/integration`: PASS (52/52; всего 215/215)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-1.0.0-portable.zip` 67.0 MB SHA-256 `502a38cf5df0b94d33229f704db16a1064fae658b7b4d43e02fbc74316d280ff`, `SBOM.cdx.json` SHA-256 `dac7d88db12c62532de4594117953b5a6abd78ca393493764dfcd0941e502c0c`, `SHA256SUMS.txt`, frozen `MCPApp.exe --headless` `/health` 200 OK, frozen `MCPApp.exe --run-extension` worker OK).
  - GitHub Actions CI на `e6bc844`:
    - `Verify & Test (ubuntu-latest)`: PASS (`2m20s`) — https://github.com/SolasFor/MCP-app/actions/runs/45616799590/job/139214170785
    - `Verify & Test (windows-latest)`: PASS (`5m35s`) — https://github.com/SolasFor/MCP-app/actions/runs/45616799590/job/139214171445
    - `windows-package` (`RC Windows installer (no publish)` с `MCPApp-Setup-1.0.0.exe`): PASS (`2m14s`) — https://github.com/SolasFor/MCP-app/actions/runs/45616799698/job/139214171074
- Live tests отдельно от mocks: `local_only`, `MCPApp.exe --selftest`, frozen `--headless`, frozen `--run-extension`, `LocalSSHServer`, `stdio`/`Streamable HTTP`/`SSE` Gateway upstreams и Win32 interactive Computer Use smoke (`v0.9.6`) — **PASS**; внешние облачные клиенты/туннели, live COM `SLDWORKS.exe` и 72h soak — **BLOCKED / NOT_RUN**.
- Риски / ограничения / блокеры: см. выше (unsigned EXE, `auto_install_enabled=False`, 72h soak `NOT_RUN`, внешняя матрица без ключей/лицензий).
- PR / релиз: [PR #31](https://github.com/SolasFor/MCP-app/pull/31) (`release/v1.0.0` → `feat/automation-monitoring`), в очереди стека PR #20–#31.
- Следующий точный шаг: владелец просматривает PR #20–#31, принимает решение по неподписанному релизу/Authenticode и при одобрении разрешает последовательный merge в `main` и публикацию `v1.0.0`.


## Этап 11: v0.9.9 — Automation & Monitoring (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 11 / `v0.9.9` / `feat/automation-monitoring` / `a7827cc`
- Реализованные задачи:
  - Пакет `backend/automation/` (`{__init__,scheduler,monitoring,admin_api,backup_updater}.py`):
    - `scheduler.py`: 5-полевой cron с поддержкой TZ/DST (`resolve_timezone`, `ZoneInfo`, корректный UTC-fallback при отсутствии `tzdata`), интервалы, `startup` и `event`-триггеры; политики пропусков (`skip` / `coalesce` / `run_once`), конкурентности (`forbid` / `allow`), идемпотентность (`idempotency_key`), запрет автоповторов при `safe_retry=False`, живая перепроверка прав с автопаузой при отзыве (`paused_revoked`), запрет мутации расписаний не-владельцу без `full`.
    - `monitoring.py`: потокобезопасный `MetricsRegistry` (счётчики, ошибки, `avg_ms` / `p95_ms`), системный срез `psutil` (`collect_system_snapshot`), фильтрация и ротация аудита (`filter_audit_entries`, `prune_audit_file`), экспорт `export_redacted_diagnostics`.
    - `admin_api.py`: строго изолированный от публичных туннелей локальный Admin REST API (`/api/v1/monitoring`, `/api/v1/schedules`, `/api/v1/schedules/{id}/run`, `/api/v1/diagnostics/export`), принимающий только loopback (`127.0.0.1` / `localhost` / `::1`), отклоняющий заголовки туннелей (`Cf-Ray`, `X-Forwarded-For`, `Ngrok-Trace-Id`, `Tailscale-User-Login`) с `403` и требующий скоупированный bearer/`X-MCP-Admin-Token` (`401`/`403`).
    - `backup_updater.py`: `BackupManager` (schema `v1`, исключение секретов/vault/OAuth по умолчанию, явное предупреждение о непереносимости DPAPI, защита от zip-slip/symlink/подмены SHA-256, атомарное восстановление + откат `.pre_restore_backup.zip`) и `StagedUpdater` (разбор GitHub Releases, проверка SHA-256 + Ed25519, откат установки и постоянно выключенный `auto_install_enabled = False`).
  - Интеграция в ядро и UI: `backend/tool_permissions.py`, `backend/server.py` (`METRICS_REGISTRY`, `AUTOMATION_SCHEDULER`, `build_local_admin_app`, `invoke_playground_tool`), `main.py --headless`, `ServiceManager.automation_dir`, `app/selftest.py`, `packaging/mcp_app.spec`, страница `app/ui/pages/automation_page.py` (4 вкладки: Расписание, Мониторинг, MCP Playground с предупреждением о LIVE-выполнении, Бэкап/Обновления), `MainWindow` (перевод `automation` в активное меню — 13/13 разделов, 0 upcoming), устранение утечки сигналов и лишней перерисовки стиля Fusion (`app/ui/{theme,main_window,tray}.py`), `i18n.py` (616 ключей RU/EN с 100% паритетом), `docs/automation-monitoring.md` (включая Session 0 separation).
- Оставшиеся задачи и зависимости: последовательный merge [PR #30](https://github.com/SolasFor/MCP-app/pull/30) в `main` после PR #20–#29; переход к Этапу 12 (`v1.0.0`).
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.9`), `main.py`, `packaging/mcp_app.spec`, `backend/automation/`, `backend/{tool_permissions,server}.py`, `app/core/service_manager.py`, `app/selftest.py`, `app/ui/{i18n,main_window,theme,tray}.py`, `app/ui/components/sidebar.py`, `app/ui/pages/{__init__,automation_page}.py`, `docs/automation-monitoring.md`, `README.md`, `tests/unit/test_automation_security.py`, `tests/integration/{test_automation_monitoring,test_ui_redesign_gui,test_unified_home_gui}.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff`, `mypy` (win32 + `--platform linux`): PASS (67 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей); `i18n` parity: PASS (616 ключей)
    - `tests/unit`: PASS (163/163 — cron/DST, misfire/concurrency/idempotency/safe-retry/revoke, отрицательные проверки Admin REST API, redacted diagnostics, zip-slip/tamper backup, неподписанные/битые обновления)
    - `tests/integration`: PASS (47/47 за 147.475s; всего 210/210 — живой `build_local_admin_app` + `invoke_playground_tool`, `BackupManager` + `StagedUpdater` Ed25519 rollback, живой `main.py --headless` `/health` 200, headless `AutomationPage` RU/EN)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.9-portable.zip` 67.0 MB, живой frozen `MCPApp.exe --headless` `/health` 200 `FROZEN_HEADLESS_OK`)
  - GitHub Actions CI на `a7827cc`:
    - `Verify & Test (ubuntu-latest)`: PASS (`1m54s`) — https://github.com/SolasFor/MCP-app/actions/runs/45612560560/job/139199584143
    - `Verify & Test (windows-latest)`: PASS (`5m3s`) — https://github.com/SolasFor/MCP-app/actions/runs/45612560560/job/139199583547
    - `windows-package` (`RC Windows installer (no publish)`): PASS (`2m39s`) — https://github.com/SolasFor/MCP-app/actions/runs/45612560580/job/139199584501
- Live tests отдельно от mocks: реальный локальный `--headless` (source и frozen `MCPApp.exe`), реальный HTTP `/api/v1/*`, Playground и Ed25519 stage/apply/rollback — **PASS**; проверка реальных GitHub Releases по сети и Windows Service Session 0 вручную не разворачивались (чтобы не менять службы ОС владельца).
- Риски / ограничения / блокеры: автоустановка обновлений остаётся отключённой до появления доверенного Authenticode-сертификата; DPAPI-секреты непереносимы между учётными записями/ПК и не включаются в резервные копии.
- PR / релиз: [PR #30](https://github.com/SolasFor/MCP-app/pull/30) (`feat/automation-monitoring` → `feat/remote-management`).
- Следующий точный шаг: Этап 12 (`v1.0.0 — Stable Release`) на ветке `release/v1.0.0`.


## Этап 10: v0.9.8 — Remote Management (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 10 / `v0.9.8` / `feat/remote-management` / `72f98de`
- Реализованные задачи:
  - Реализован пакет `backend/remote/` (`{__init__,models,store,ssh_client,manager}.py`):
    - Реестр устройств `devices.json` с атомарной записью и ACL, пароли и парольные фразы только в `SecretStore("ssh")` (`secret://ssh/<device>__password` / `passphrase`), безопасный экспорт без секретов и импорт `~/.ssh/config` (`import_ssh_config` с пропуском wildcard `Host *` / `Match` и игнорированием `ProxyCommand`, дефолтными правами `False`).
    - Жёсткая проверка ключей хостов в `SSHConnectionManager` (`paramiko.RejectPolicy()`, неизменяемый `strict_host_key=True`, обязательная проверка по `known_hosts` с немедленным отказом `PermissionError` при неизвестном или изменившемся ключе), честная обработка обрыва соединения (`exit_code < 0` → `SSHConnectionError` / статус задачи `disconnected` с `disconnect_note` без блокировки Engine и без ложного обещания остановки/возобновления удалённого процесса).
    - Защищённый SFTP (`sftp_list`, `sftp_download`, `sftp_upload`): канонические POSIX-пути, проверка корней `allowed_sftp_roots`, серверный `sftp.normalize(...)` против symlink-побегов, отказ при symlink на чтение/перезапись и квота `sftp_max_bytes`.
    - Гранулярные права устройства (`execute`, `sftp_read`, `sftp_write`, `service_control`, `metrics`, `docker_read`), раздельный режим `allowlist` (запрет shell-метасимволов, точные `allowed_commands` и `allowed_services`) и `full`, отсутствие автоматического `sudo`.
  - Добавлены 12 OAuth-инструментов в `backend/tool_registry.py` и `backend/server.py` (`device_list`, `device_info`, `device_health`, `ssh_execute`, `ssh_task_start`, `sftp_list`, `sftp_download`, `sftp_upload`, `remote_service_list`, `remote_service_start`, `remote_service_stop`, `remote_metrics`) при полном сохранении совместимого `oauth_ssh_command`; добавлена изоляция `MCP_DEVICES_CONFIG_PATH` в `ServiceManager` и `app/selftest.py`.
  - Создана страница `app/ui/pages/devices_page.py` (`DevicesPage`, `DeviceProfileDialog`, импорт `~/.ssh/config`, health/metrics, журналы), раздел «Устройства» переведён в активное меню (`app/ui/main_window.py`, RU/EN `app/ui/i18n.py`), добавлена документация `docs/remote-management.md` и ссылка в `README.md`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #29](https://github.com/SolasFor/MCP-app/pull/29) после PR #20–#28.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.8`), `packaging/mcp_app.spec`, `app/core/service_manager.py`, `app/selftest.py`, `app/ui/{i18n,main_window}.py`, `app/ui/pages/{__init__,devices_page}.py`, `backend/remote/`, `backend/{tool_registry,server}.py`, `docs/remote-management.md`, `README.md`, `tests/fixtures/local_ssh_server.py`, `tests/unit/{test_remote_security,test_tool_permissions}.py`, `tests/integration/{test_remote_management,test_tool_registry,test_oauth_http,test_ui_redesign_gui,test_unified_home_gui}.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend extensions_official tests tools main.py`, `mypy` (win32 + `--platform linux`): PASS (62 файла, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (156/156 за 13.156s — запрет отключения `strict_host_key`, фильтрация `~/.ssh/config`, SFTP path/service валидаторы, редактирование секретов, кросс-клиентская изоляция)
    - `tests/integration`: PASS (43/43; всего 199/199 — локальный Paramiko `LocalSSHServer` SSH+SFTP, проверка `known_hosts` и отказ при ротации ключа хоста, SFTP upload/list/download/квота/symlink/canonical escape, метрики/сервисы, async job и обрыв соединения `disconnected`, OAuth cross-client deny и headless `DevicesPage` GUI)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.8-portable.zip` 70.2 MB / 70,230,362 байт)
  - GitHub Actions CI на `72f98de`:
    - `Verify & Test (ubuntu-latest)`: PASS (`2m49s`) — https://github.com/SolasFor/MCP-app/actions/runs/45595306144/job/139139683666
    - `Verify & Test (windows-latest)`: PASS (`4m13s`) — https://github.com/SolasFor/MCP-app/actions/runs/45595306144/job/139139683237
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m10s`) — https://github.com/SolasFor/MCP-app/actions/runs/45595303716/job/139139677684
- Live tests отдельно от mocks: реальные локальные SSH/SFTP соединения и ротация ключей против localhost `LocalSSHServer` — **PASS**; внешний физический/облачный SSH-сервер за пределами localhost не подключался; `DevicesPage` проверялся через `QT_QPA_PLATFORM=offscreen`.
- Риски / ограничения / блокеры: без подтверждённого удалённого агента при потере SSH-соединения невозможно гарантировать остановку или возобновление запущенного процесса на удалённой машине (задача честно переходит в `disconnected`). Сборка без Authenticode-сертификата.
- PR / релиз: [PR #29](https://github.com/SolasFor/MCP-app/pull/29) (`feat/remote-management` → `feat/extensions`).
- Следующий точный шаг: Этап 11 (`v0.9.9 — Automation & Monitoring`) на ветке `feat/automation-monitoring`.


## Этап 9: v0.9.7 — Extensions (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 9 / `v0.9.7` / `feat/extensions` / `62c6708`
- Реализованные задачи:
  - Реализован пакет `backend/extensions/` (`{__init__,models,sdk,packaging,store,runtime,manager}.py`):
    - Версионируемый SDK (`ExtensionApp`, `SDK_API_VERSION="1.0"`, совместимость `1.0..1.2`, JSON-RPC 2.0 по newline-delimited stdio без импортов GUI/OAuth ядра).
    - Безопасная проверка и распаковка ZIP (`verify_and_extract_zip`): отклонение path traversal (`..`), абсолютных путей, symlink-записей, дубликатов и лимитов размера/файлов; fail-closed доверие только по **Ed25519-подписи** (`CHECKSUMS.sha256` + `SIGNATURE.ed25519` против `trusted_keys.json`) либо явному владельческому **SHA-256 пину** + подтверждению владельца.
    - Отдельный дочерний процесс `ExtensionProcessHost` с очищенным окружением (`MCPApp.exe --run-extension <entrypoint>` в frozen-сборке и `python -u` в dev), `CREATE_NO_WINDOW`, изолированным каталогом `data/<id>` (сохраняемым при отключении/обновлении/откате), резервной копией и откатом (`backups/<id>/<version>`), детектированием сбоя и автоматическим перезапуском воркера без падения ядра, секретами только для объявленных `secret_keys` (`SecretStore("extensions")`) и редактированием логов.
  - Создан локальный официальный каталог `extensions_official/`: `system_monitor` (`psutil`), `git_manager` (подавление hooks `core.hooksPath=`), `docker_manager` (честная проверка Docker CLI/daemon), `browser_automation` (валидация `http`/`https` и изолированные профили) и `starter_template`.
  - Добавлены 6 OAuth-инструментов `extension_*` в `backend/tool_registry.py` и `backend/server.py` (`extension_list`, `extension_info`, `extension_call_tool`, `extension_logs` — `allowlist`; `extension_enable`, `extension_disable` — `full`), интеграция с `ServiceManager.extensions_dir()` / `MCP_EXTENSIONS_DIR` и `app/selftest.py`.
  - Создана страница `app/ui/pages/extensions_page.py` (`ExtensionsPage`, диалоги ZIP/SHA-256 и прав), раздел «Расширения» переведён в активное меню (`app/ui/main_window.py`, RU/EN `app/ui/i18n.py`), добавлена документация `docs/extensions.md` и ссылка в `README.md`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #28](https://github.com/SolasFor/MCP-app/pull/28) после PR #20–#27.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.7`), `main.py`, `packaging/mcp_app.spec`, `app/core/{secret_store,service_manager}.py`, `app/selftest.py`, `app/ui/{i18n,main_window}.py`, `app/ui/pages/{__init__,extensions_page}.py`, `backend/extensions/`, `extensions_official/`, `backend/{tool_registry,server}.py`, `docs/extensions.md`, `README.md`, `tests/unit/{test_extensions_security,test_tool_permissions}.py`, `tests/integration/{test_extensions,test_tool_registry,test_oauth_http,test_ui_redesign_gui,test_unified_home_gui}.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend extensions_official tests tools main.py`, `mypy` (win32 + `--platform linux`): PASS (57 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (152/152 за 12.006s — валидация manifest/api_version, traversal/symlink/подмена/недоверенный ключ Ed25519, отказ без SHA-256 пина, изоляция секретов и кросс-клиентских/инструментальных прав)
    - `tests/integration`: PASS (39/39; всего 191/191 — реальная установка подписанного ZIP без пересборки ядра, JSON-RPC IPC, сохранение `data/<id>` при disable/update/rollback, восстановление после падения воркера, `system_monitor`, `git_manager`, OAuth `extension_*` и headless `ExtensionsPage` GUI)
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.7-portable.zip` 66.9 MB; живой тест frozen `MCPApp.exe --run-extension ...system_monitor/main.py` → `FROZEN_WORKER_OK 12`)
  - GitHub Actions CI на `62c6708`:
    - `Verify & Test (ubuntu-latest)`: PASS (`2m24s`) — https://github.com/SolasFor/MCP-app/actions/runs/45588509164/job/139116198545
    - `Verify & Test (windows-latest)`: PASS (`6m4s`) — https://github.com/SolasFor/MCP-app/actions/runs/45588509164/job/139116197776
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m26s`) — https://github.com/SolasFor/MCP-app/actions/runs/45588509142/job/139116199040
- Live tests отдельно от mocks: реальные дочерние процессы Python и собранный `MCPApp.exe --run-extension` (`system_monitor` / `git_manager`), реальная генерация/проверка Ed25519 ZIP — **PASS**; `ExtensionsPage` проверялся через `QT_QPA_PLATFORM=offscreen`.
- Риски / ограничения / блокеры: отдельный OS-процесс изолирует падения и секреты/env ядра, но НЕ является песочницей ОС (явно зафиксировано в UI и `docs/extensions.md`). Опциональные CAD (`SolidWorks`, `КОМПАС-3D`, `Mathcad`) и `Database Manager` не входят в базовые расширения (`BLOCKED`/опционально; SolidWorks поддерживается через Gateway). Сборка без Authenticode-сертификата.
- PR / релиз: [PR #28](https://github.com/SolasFor/MCP-app/pull/28) (`feat/extensions` → `feat/computer-use`).
- Следующий точный шаг: Этап 10 (`v0.9.8 — Remote Management`) на ветке `feat/remote-management`.


## Этап 8: v0.9.6 — Computer Use (VERIFIED)
- Этап / версия / ветка / HEAD: Этап 8 / `v0.9.6` / `feat/computer-use` / `e5837ef`
- Реализованные задачи:
  - Реализован пакет `backend/desktop/` (`{__init__,models,backend_base,png_codec,win32_backend,manager}.py`):
    - Нативный интерактивный бэкенд `Win32DesktopBackend` (изолированные 64-битные прототипы `WinDLL`, `SetProcessDpiAwarenessContext`, `EnumDisplayMonitors`/`GetDpiForMonitor` DPI, `EnumWindows`/`IsWindowElevated` через `OpenProcessToken`, проверка состояния сеанса `OpenInputDesktop`, захват окна/экрана `PrintWindow`/`GetWindowDC`/`BitBlt` → pure-Python BGRA→PNG `encode_bgra_to_png` в памяти с ограничением ширины/байт без записи на диск, нативный COM `UIAutomationCore.dll` через vtable-вызовы для UI-дерева, `InvokePattern` и `ValuePattern`, `SendInput` с UTF-16LE Unicode и виртуальными координатами нескольких мониторов, жёсткий отказ для `Ctrl+Alt+Del` и `Win+L`).
    - Сериализованный fail-closed менеджер `DesktopManager` и `DesktopPolicyStore` (+ маяк активности `activity.json` для индикатора GUI): отдельные явные opt-in разрешения владельца (`enabled`, `allow_screen_capture`, `allow_input_control`, `allow_secret_typing`, `allowed_clients`), локальный `emergency_stop`, отказ при заблокированной сессии/UAC/secure desktop, отказ по UIPI повышенным окнам и полям пароля (`is_password=True`).
  - Добавлены 13 OAuth-инструментов `desktop_*` в `backend/tool_registry.py` и `backend/server.py` (`desktop_screenshot` с возвратом `CallToolResult` — метаданные JSON + `ImageContent`, `list_windows`, `list_monitors`, `open_app`, `close_window`, `focus_window`, `get_ui_tree`, `click`, `type`, `keypress`, `scroll`, `drag`, `wait_for_element`), интеграция аварийной остановки в `ServiceManager.emergency_stop()`, изоляция `MCP_DESKTOP_POLICY_PATH` в `app/core/service_manager.py` и `app/selftest.py`.
  - Обновлён GUI (`app/ui/pages/security_page.py`, `app/ui/main_window.py`, `app/ui/i18n.py`): переключатели политик Computer Use, список разрешённых клиентов, видимый индикатор состояния в верхней панели (`Просмотр` / `Контроль`) и кнопка экстренной остановки `Stop Computer Use` (полная RU/EN-локализация).
  - Добавлена документация `docs/computer-use.md` и ссылка в `README.md`.
- Оставшиеся задачи и зависимости: последовательный merge [PR #27](https://github.com/SolasFor/MCP-app/pull/27) после PR #20–#26.
- Изменённые файлы / миграции: `app/__init__.py` & `pyproject.toml` (`0.9.6`), `packaging/mcp_app.spec`, `app/core/service_manager.py`, `app/selftest.py`, `app/ui/{i18n,main_window}.py`, `app/ui/pages/security_page.py`, `backend/desktop/`, `backend/{tool_registry,server}.py`, `docs/computer-use.md`, `README.md`, `tests/unit/{test_desktop_security,test_tool_permissions}.py`, `tests/integration/{test_desktop_computer_use,test_tool_registry,test_oauth_http}.py`, `tools/live_desktop_smoke.py`.
- Проверки:
  - Локально (Windows 11, `.venv`, Python 3.13.15):
    - `compileall`, `ruff check app backend tests tools main.py`, `mypy` (win32 + `--platform linux`): PASS (50 файлов, 0 ошибок)
    - `tools/check_licenses.py`: PASS (38/38); `tools/generate_sbom.py`: PASS (38 компонентов); `pip-audit`: PASS (0 уязвимостей)
    - `tests/unit`: PASS (148/148 за 11.032s — fail-closed политики, lock/UAC/elevated/password/SAS защиты, cross-client allowlist, encoder PNG, нормализация координат нескольких мониторов)
    - `tests/integration`: PASS (36/36 за 203.502s; всего 184/184 — mock `DesktopBackend` в headless CI для `desktop_*` инструментов и `ImageContent`, а также `SecurityPage` opt-in, видимого индикатора и `Stop Computer Use`)
    - Live interactive Windows 11 smoke (`tools/live_desktop_smoke.py` с рабочим потоком и активным циклом Qt): **PASS** (`monitors=2`, `dpi_primary=100`, `screenshot_bytes=4158` `[440x280]`, `ui_nodes=11`, `click_method=uia_invoke`, ввод текста `hello-live-123`, отказ по полю пароля `password_blocked=True`, чистое закрытие окна).
    - `packaging/build.ps1 -Python "py -3.13" -SkipInstaller`: PASS (`MCPApp.exe --selftest` → `RESULT OK`, `MCPApp-0.9.6-portable.zip` 66.8 MB)
  - GitHub Actions CI на `e5837ef`:
    - `Verify & Test (ubuntu-latest)`: PASS (`2m17s`) — https://github.com/SolasFor/MCP-app/actions/runs/45580710966/job/139089748783
    - `Verify & Test (windows-latest)`: PASS (`5m33s`) — https://github.com/SolasFor/MCP-app/actions/runs/45580710966/job/139089748313
    - `RC Windows installer (no publish)` (`windows-package`): PASS (`2m10s`) — https://github.com/SolasFor/MCP-app/actions/runs/45580711115/job/139089749566
- Live tests отдельно от mocks: реальный интерактивный тест Windows 11 desktop (`tools/live_desktop_smoke.py`) — **PASS** (захват окна через `PrintWindow` при изолированном thread desktop `exebox-*` и `WinSta0\Default`, UIA COM + SendInput). В headless CI используются `_FakeBackend` и `QT_QPA_PLATFORM=offscreen`; они не подменяют живой тест. Опциональные сторонние CAD/Office-приложения (`SolidWorks`, `КОМПАС-3D`, `Mathcad`, `Office`, `VS Code`) в автотесты Computer Use не включались (`BLOCKED` / не проверялись вживую).
- Риски / ограничения / блокеры: полноэкранный `BitBlt(GetDC(None))` между разными Win32 desktops (например, при запуске из изолированной среды `exebox-*` вместо `WinSta0\Default`) отклоняется ОС с `err=6`, тогда как `PrintWindow` для целевого `HWND` и обычный интерактивный запуск на `Default` desktop работают; сборка без Authenticode-сертификата.
- PR / релиз: [PR #27](https://github.com/SolasFor/MCP-app/pull/27) (`feat/computer-use` → `feat/workspaces`).
- Следующий точный шаг: Этап 9 (`v0.9.7 — Extensions`) на ветке `feat/extensions`.


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

## Справка и контекстные меню транспортов (2026-11-27)
- Ветка: `feat/provider-guide-menus`. Отдельные инструкции для четырёх транспортов; меню Настроить / Проверить / Инструкция; ссылка «Как это работает» закреплена за Named Tunnel.
- Локальные проверки: Ruff PASS, штатный mypy PASS (74 файла), GUI Wave 2 PASS (6 тестов), transport GUI PASS (2), acceptance GUI PASS (7). Добавлен тест маршрутизации меню и переключения справки.
- Визуальная приёмка на экране, реальные ngrok/Funnel, сборка EXE и CI: NOT_RUN. Действующие настройки, токены и запущенный сервер не менялись.

## Компактные панели подключения и журналов (2026-11-27)
- Удалены дублирующая справка Named Tunnel и два подзаголовка подключения; выровнены кнопки выбора, статусы и меню провайдеров.
- Журналы: единая панель с подписанными фильтрами, очисткой поля поиска, действиями и счётчиками; экспорт из вкладки удалён. Внутренняя диагностика и защищённый аудит сохранены.
- Ruff, штатный mypy (74 файла), GUI Wave 2 (6), transport GUI (2), acceptance GUI (7): PASS. Визуальная приёмка: NOT_RUN.

### Reference layout polish — Connections and Logs
- Matched the supplied visual references with compact provider rows, token icon actions, aligned log filters and a compact action/count area.
- Preserved token generation/paste in the token context menu and existing log filtering/actions.
- Validation: Ruff, mypy (74 files), 16 targeted GUI tests (offscreen); visual acceptance pending.

### Unified management UI redesign
- Integrated the provider guide, compact connection/log layout, and management redesign branches.
- Servers, Workspaces, Extensions, Tasks, and Gateway share compact action panels, resizable list/inspector areas and translated full-width detail tabs.
- Fixed duplicate inspector headings after language change and provider menu cursor regression.
- Validation: 45 targeted integration tests, Ruff and mypy; offscreen geometry and RU/EN checks. Manual visual acceptance pending.

### Compact Devices and Extensions UI
- Devices now uses the shared management toolbar and resizable registry/diagnostics panels.
- Devices and Extensions use compact 28px action buttons and separate localized instruction dialogs instead of page lead text; original security notices are preserved in the guides.
- Validation: Ruff, mypy (74 files), 31 targeted integration tests including RU/EN guide content, remote management and extension workflows. Manual visual acceptance pending.

## N00 — подготовка следующего цикла
- Статус: **VERIFIED** (`2026-11-27`).
- База: `main` / `v1.0.2` (`f8ba86f`, релиз опубликован). Ветка `chore/next-cycle-prep` закоммичена (`abeaecf`, 18 файлов) и отправлена в `origin/chore/next-cycle-prep`; активный worktree переключён на `feat/n01-baseline-audit` поверх `abeaecf`.
- Подготовлены `ROADMAP.md` (N00–N13), `docs/roadmap-v1.0.0.md`, `AGENTS.md`, `DESIGN.md`, `docs/acceptance-criteria.md`, `docs/auto-update.md`, `docs/antigravity-workflow.md`, `.agents/rules/*`, `.agents/workflows/*`, `ANTIGRAVITY_PROMPT.md` и `.graphifyignore`; пользовательские файлы и история сохранены.
- Инструменты, плагины и MCP в Antigravity:
  - `context7_context7`, `cloudflare_cloudflare`, `gh 2.105.0` (`SolasFor`), локальный `Playwright` и локальный AST-индекс `graphify` (без LLM/cloud sync, 0 reparse points): **PASS**.
  - `UI/UX Pro Max` безопасно зарегистрирован на уровне workspace через `.agents/skills.json` (`include_only: ["ui-ux-pro-max"]`, ссылка на `~/.agents/skills`) без изменения глобальных разрешений/настроек AG.
  - `Swarm`, `Boost`, `Teamwork` и `Vercel` не включались.
  - `sonarqube-cloud` MCP и `sonar` CLI (`1.13.1`): **BLOCKED** до ручной OAuth-авторизации владельцем (`Plugins Manager -> SonarQube -> Sign in / OAuth` либо `sonar auth login`). Аудит не заблокирован: используется проверка через GitHub PR Checks и публичный read-only API SonarCloud (`Quality Gate = OK` на `f8ba86f`).

## N01 — Baseline-аудит после v1.0.2 и точечные исправления P0/P1 (2026-11-27)
- Этап / версия / ветка: **N01** (`IN_PROGRESS` — ожидает независимого ревью и приёмки владельца) | версия `1.0.2` (без изменений) | ветка `feat/n01-baseline-audit` (от `abeaecf`).
- Сравнение тегов `v1.0.1..v1.0.2`: `15` коммитов, `22` изменённых файла (`+936 / -309` строк: унифицированный `management_layout.py`, рефакторинг `log_viewer.py`, `domain_guide.py`, `i18n.py`, `main_window.py`, `theme.py` и 7 страниц управления).
- Покрытие модулей аудита (`docs/maintenance-audit.md`): `P0-1` (`app/platform/windows.py`, `app/core/{atomic_io,acl_recovery,token_store,secret_store}.py`), `P0-2` (`backend/{oauth_store,oauth_provider,oauth_execution,tool_permissions,tool_registry,security_policy}.py`), `P1-1..P1-4` (`backend/{server,process_runner}.py`, `backend/{gateway,tasks,servers,workspaces,desktop,extensions,remote,automation}/*`, `app/core/tunnels/*`), `P2` (`app/ui/*`, `i18n`, `theme`), `P0-release` (`main.py`, `app/{gui,backend_entry,selftest}.py`, `packaging/*`, `.github/workflows/*`).
- Воспроизведённые и исправленные подтверждённые дефекты (с регрессионными/негативными тестами в `tests/unit/test_n01_audit_regressions.py` и `tests/unit/test_client_and_token_persistence.py`):
  - **F-N01-01 (P1, UI / i18n, регрессия `v1.0.1..v1.0.2`)**: в `app/ui/i18n.py` отсутствовали ключи `gateway.menu.enable` и `gateway.menu.disable`, вызываемые в `app/ui/pages/gateway_page.py:479` (в меню отображался сырой ключ). Добавлены переводы RU/EN и AST-тест покрытия всех `tr(...)` ключей в `app/`.
  - **F-N01-02 (P1, Security / Авторизация)**: `_scheduler_permission_check` в `backend/server.py` не проверял команды/хосты белого списка для `EXEC_WINDOWS`/`EXEC_SSH` через `oauth_execution.can_request(...)` и не учитывал `GATEWAY_ROUTER.list_authorized_tools(...)`. Исправлено с fail-closed проверкой.
  - **F-N01-03 (P1, Security / Remote SFTP)**: `SSHConnectionManager._verify_sftp_canonical` в `backend/remote/ssh_client.py` при отсутствии родительской директории (`for_write=True`) делал лексический fallback без обхода существующих предков через `sftp.normalize` (риск побега через symlink-предка за `allowed_sftp_roots`), а `_open_client` не загружал системные `known_hosts` при пустом `device.known_hosts_path`. Исправлено с сохранением `paramiko.RejectPolicy()`.
  - **F-N01-04 (P1, Storage / Atomic I/O & Windows ACL)**: переведены на `app.core.atomic_io` (потокобезопасные `.pid.tid.tmp`, `fsync`, ретраи Win32, очистка `.tmp` при `ENOSPC`, `restrict_path_acl`) вызовы в `backend/automation/backup_updater.py` (включая `.pre_restore_backup.zip` и блок отката без расширения функциональности бэкапа), `backend/automation/scheduler.py`, `backend/workspaces/history.py`, `backend/tasks/manager.py`, `backend/automation/monitoring.py`, `app/core/diagnostics.py`, `backend/oauth_store.py`.
  - **F-N01-05 (P1, Windows Process Lifecycle)**: `ExtensionProcessHost` в `backend/extensions/runtime.py` теперь привязывает процесс воркера расширения к `ProcessJobHandle(kill_on_close=True)` и закрывает/завершает его при остановке и ошибке запуска.
  - **F-N01-06 (P1/P2, UI sync, `--selftest` и изоляция unit-теста)**: в `app/ui/main_window.py` (`show_page`) добавлен автообновляющий вызов `refresh_all()` при переходе на `extensions` и `devices`; в `app/selftest.py` добавлена проверка импортов `ManagementPanel`, `ManagementTabs`, `management_guide_button`, `ConnectionsPage`, `GatewayPage`, `TasksPage` (плюс unit-тест `_check_qt()`); в `tests/unit/test_client_and_token_persistence.py` изолирован `_port_owner` для корректного прохождения при активном сервере.
- Подтверждённые проверки после финальных правок (`Windows 11 Pro`, Python `3.13.15`, `.venv`, `QT_QPA_PLATFORM=offscreen`):
  - `compileall`, `ruff check app backend tests tools main.py`: **PASS** (0 ошибок).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 74 source files`).
  - `tools/check_licenses.py`: **PASS** (`38/38` компонентов); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (0 известных уязвимостей).
  - `tests/unit`: **PASS** (**219/219** за `14.392s`); `tests/integration`: **PASS** (**80/80** за `46+s`); `tests/e2e` (Playwright): **PASS** (**2/2**).
  - Локальный AST Graphify (`graphify update .`): **PASS** (`5194 nodes, 16447 edges, 203 communities`, 0 reparse points).
  - Изолированная сборка PyInstaller на диске `D:` (`D:\Coding\.mcpapp-n01-tmp\build_verify`, живой процесс владельца `PID 3044`/`8428` и реальный `%APPDATA%\MCPApp` не затронуты, временные файлы на `D:` очищены после проверки):
    - `MCPApp.exe`: `11,443,933` Б, SHA-256 `4fb6a299540c8e7eb17d38fe7082d77cb1842037376c3d34d7ae95ffa258c7ee`; `SBOM.cdx.json`: `12,195` Б (`38` компонентов), SHA-256 `aebc15106adbe012aa2c143b7606dd4d0bd66215ff12178de643c84256038cb1`.
    - `--selftest`: **PASS** (`Qt 6.12.1`, `WindowsPlatformAdapter`, `cloudflared 2026.11.2`, `Starlette`, `RESULT OK`).
    - `--headless` (порт `18981`, одноразовый профиль на `D:`): **PASS** (`/health` HTTP `200`, неавторизованный `POST /mcp` HTTP `401`, созданы `token.json` и `secrets\secrets.key`).
    - `--repair-acl` (одноразовый повреждённый профиль на `D:`): **PASS** (`exit=0`, `detected_issues=1`, `ok=true`, SHA-256 `token.json` сохранён).
- **PR #37 и облачный CI** ([PR #37](https://github.com/SolasFor/MCP-app/pull/37), `feat/n01-baseline-audit` → `main`, статус: **OPEN**, merge и релиз не выполнялись; PR #32 не изменялся):
  - `MCP transport checks`: `Verify & Test (ubuntu-latest)` **PASS** (`1m19s`: https://github.com/SolasFor/MCP-app/actions/runs/45992282940/job/140482862810), `Verify & Test (windows-latest)` **PASS** (`3m19s`: https://github.com/SolasFor/MCP-app/actions/runs/45992282940/job/140482862442).
  - `RC Windows installer (no publish)`: PR `windows-package` **PASS** (`2m40s`: https://github.com/SolasFor/MCP-app/actions/runs/45992282908/job/140482862878), ручной dispatch **PASS** (https://github.com/SolasFor/MCP-app/actions/runs/45992281011).
  - `SonarCloud Code Analysis`: **PASS** (`39s`, Quality Gate `OK`, `new_security_rating=1`, `new_reliability_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=0.0%`): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=37.
- Незавершённые проверки (`BLOCKED` / `NOT_RUN`, без имитации `PASS`):
  - Подписание Authenticode (`.pfx`): **BLOCKED** (сертификат владельца отсутствует).
  - Локальный `Inno Setup` (`iscc.exe`): **NOT_RUN** локально (отсутствует на хосте; проверяется через GitHub Actions `rc-windows.yml`).
  - Живой GUI-тест второго окна (`tray`/`single-instance`): **NOT_RUN** локально (чтобы не останавливать работающий экземпляр владельца с мьютексом `MCPApp-Running`).
  - Live-проверки внешних платных/доменных туннелей (`Cloudflare Named`, `ngrok`, `Tailscale Funnel`), живых SaaS AI-клиентов и реального SSH-хоста: **NOT_RUN** (без выделенного тестового окружения и разрешения владельца).
  - Прямой вызов MCP `sonarqube-cloud` из Antigravity: **BLOCKED** до ручной OAuth-авторизации.
- Ограничения / риски и следующий шаг: регрессии по `v1.0.1..v1.0.2` и подтверждённые P1-дефекты закрыты; минорные замечания (`P2`, в частности захардкоженные русские строки диалога/подсказок вне `gateway_page` и расширенные live tunnel тесты) оставлены в рамках `N02–N08` без масштабного рефакторинга. PR #32 не изменялся; merge в `main` и публикация релиза не выполнялись. Следующий шаг: независимое ревью PR и приёмка N01 владельцем перед началом N02.

## Дополнительная приёмка N01 по результатам независимого ревью ChatGPT (2026-11-27)
- **Ветка / PR / база / версия**: `feat/n01-baseline-audit` | [PR #37](https://github.com/SolasFor/MCP-app/pull/37) (исходно проверенный коммит `b3e5101`; PR #32 не затрагивался) | версия приложения `1.0.2` (не менялась) | `ROADMAP.md` синхронизирован (`N00` -> `VERIFIED` с остаточным ограничением `sonarqube-cloud` MCP OAuth; `N01` -> `IN_PROGRESS`, готов к независимой приёмке в PR #37, без `MERGED`).
- **TDD-воспроизведение на `b3e5101` (`tests/unit/test_n01_review_followup.py`)**: из 12 новых тестов до исправлений воспроизводимо упали **10** (подтверждены дефекты SFTP symlink/dangling/`EACCES`/TOCTOU, утечки/исключения `ExtensionProcessHost`, пробелы principal-binding/fail-closed/`task_start`/исполнителя автоматизации и неатомарный `export_diagnostics`); 2 теста конкурентной атомарной записи и сохранения защищённого `TokenUser` DACL при перезаписи прошли исходно.
- **Подтверждённые и исправленные замечания**:
  1. **Security — SFTP (`backend/remote/ssh_client.py`, `tests/fixtures/local_ssh_server.py`)**:
     - В `sftp_upload` `except IOError: pass` перехватывал собственный `PermissionError` (так как в Python `PermissionError` — подкласс `OSError`/`IOError`), позволяя перезапись существующих и dangling symlink-файлов; устранено выделением `_inspect_regular_target` и `_is_sftp_enoent` без широкого `except IOError`.
     - В `_verify_sftp_canonical` ошибки `PermissionError` (`EACCES`) и прочие `OSError`/`SSHException` при `sftp.normalize` отделены от `ENOENT` (fail closed), добавлена проверка `lstat` при `ENOENT` для блокировки dangling symlink в родительском каталоге и целевом пути, а также проверка `lstat` в `sftp_list`.
     - Усилена защита от TOCTOU: эксклюзивное создание `"wxb"` для новых файлов (отказ при конкурентном появлении цели), staging через `"wxb"` во временный sibling-файл + `posix_rename` для перезаписи с `remove` при ошибке и fallback на `wb` + `fh.stat()` (`S_ISREG` и совпадение `st_ino`/`st_dev`) при `EOPNOTSUPP`, плюс `fh.stat()`/`st_ino` проверка в `sftp_download`. `paramiko.RejectPolicy()` и загрузка `known_hosts` не ослаблялись.
     - *Остаточные ограничения протокола SFTP v3* (документированы в docstring `SSHConnectionManager` и `docs/maintenance-audit.md`): `SSH_FXP_OPEN` не поддерживает клиентские флаги `O_NOFOLLOW`/`openat2(RESOLVE_NO_SYMLINKS)`, поэтому от гонки локального злоумышленника на самой удалённой машине дополнительно защищают серверные настройки (`ChrootDirectory` и выделенная УЗ ОС).
  2. **Extension Process Lifecycle (`backend/extensions/runtime.py`)**:
     - В `ExtensionProcessHost.start()` создание `self._job` перенесено до `assign_process_to_job`, явный возврат `assign_process_to_job(...) == False` переведён в fail-closed `RuntimeError`, захвачен `ProcessIdentity`, и весь цикл после `subprocess.Popen` обёрнут в `try/except BaseException` с гарантированной очисткой через `_cleanup_proc_locked` (`_terminate_worker_processes` + `_close_worker_io_and_job`).
     - Исключения в `terminate_job`, `terminate_process_tree` и `close_job` изолированы независимо друг от друга в `start()` и `stop()`, исключая утечки Job Handle, висячих pipe и дочерних/внучатых процессов и гарантируя чистый повторный `start()`.
  3. **Automation Security (`backend/automation/scheduler.py`, `backend/server.py`, `app/core/redaction.py`, `app/ui/pages/automation_page.py`, `backend/automation/backup_updater.py`)**:
     - В `ScheduleSpec` добавлена валидация `client_id` (запрет пустых строк, управляющих символов и зарезервированного `"mcp-app-user"`; `from_dict` больше не подменяет пустой `client_id` на `"owner"`). В `upsert_schedule` и `remove_schedule` для `actor_id != "owner"` запрещены подмена `client_id`, перезапись/удаление чужих или `owner`-расписаний и сохранение неавторизованных расписаний; `permission_checker` обёрнут в fail-closed `_safe_check_permission`.
     - В `backend/server.py` `_scheduler_permission_check` разбит на декомпозированные хелперы, перехватывает любые сбои fail-closed, валидирует `EXEC_WINDOWS`, `EXEC_SSH` и `TASK_START` (`kind`, `command`, `shell`, `timeout`, `host`, `user`, `port`), политики `DESKTOP_TOOLS` (с безусловным запретом `DESKTOP_CONTROL_TOOLS` в unattended-расписаниях), `GATEWAY_ROUTER` (в т.ч. для `owner`-политики) и ограничивает `owner`-расписания глобальным профилем. Подключён реальный `_execute_scheduled_tool` на `AUTOMATION_SCHEDULER._executor` со строгой привязкой `auth_context_var` к `spec.client_id` (без эскалации до `owner`, без ослабления `Full Access`), записью метрик и распознаванием ошибок инструмента; в `app/core/redaction.py` исключено ложное редактирование `"Exit code: "` внутри сериализованного JSON.
  4. **Atomic I/O и Windows ACL (`app/core/atomic_io.py`, `app/ui/pages/automation_page.py`, `backend/automation/backup_updater.py`)**:
     - Удалена мёртвая ветка `not target.exists()` в `app/core/atomic_io.py` (теперь пост-replace ACL вызывается при `not acl_applied`); на `atomic_write_text(..., restrict_acl=True)` и `atomic_write_bytes(..., restrict_acl=True)` переведены `AutomationPage.export_diagnostics` и `StagedUpdater.stage_bytes` без добавления новых функций бэкапа.
     - Проверено на NTFS (`test_windows_overwrite_enforces_protected_user_only_dacl`), при многопоточной записи и инъекции `ENOSPC`/`PermissionError` с сохранением `MCP Owner Token` и OAuth `clients`.
- **Опровергнутые / уточнённые пункты ревью**:
  - На NTFS `atomic_write_text(..., restrict_acl=True)` при перезаписи файла с унаследованным DACL уже переносил `SE_DACL_PROTECTED` + 1 ACE `TokenUser` (подтверждено на `b3e5101`), однако ветка `if restrict_acl and not target.exists():` в `atomic_io.py` действительно была недостижимой и заменена на `if restrict_acl and not acl_applied:`.
  - `_TestSFTPServer` в `tests/fixtures/local_ssh_server.py` не поддерживал `O_EXCL`/`posix_rename`/`remove` (добавлены для честного интеграционного тестирования наравне с проверкой fallback `EOPNOTSUPP`).
- **Локальные проверки после финальных правок (`Windows 11 Pro`, Python `3.13.15`, `.venv`, `QT_QPA_PLATFORM=offscreen`)**:
  - `compileall -q app backend main.py tools tests`: **PASS**.
  - `ruff check .`: **PASS** (`All checks passed!`).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 74 source files`).
  - `tools/check_licenses.py`: **PASS** (`All 38 components passed license check`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (`No known vulnerabilities found`).
  - `tests/unit`: **PASS** (**232/232** за `18.320s`, включая 12 новых тестов `tests/unit/test_n01_review_followup.py`); `tests/integration`: **PASS** (**80/80** за `47.290s`); `tests/e2e` (Playwright): **PASS** (**2/2** за `10.109s`).
  - `graphify update .`: **PASS** (`5282 nodes, 16789 edges, 215 communities`, локальный AST-режим).
  - Изолированная сборка PyInstaller на `D:\Coding\.mcpapp-n01-tmp\build_verify` (владельческий `MCPApp.exe` PID `3044`/`8428` и реальный `%APPDATA%\MCPApp` не затронуты, временные файлы на `D:` и в worktree удалены):
    - `MCPApp.exe`: `8,450,649` Б, SHA-256 `b0c3cd54f4125dc6031dda914a57967e4d786712dc9e925421630bd3a43c985c`.
    - `--selftest`: **PASS** (`exit=0`, `Qt 6.12.1`, `WindowsPlatformAdapter`, `cloudflared 2026.11.2`, `Starlette`, `RESULT OK`).
    - `--headless` (порт `18981`): **PASS** (`/health` HTTP `200`, неавторизованный `POST /mcp` HTTP `401`).
    - `--repair-acl`: **PASS** (`exit=0`, `ok=true` в временном профиле на `D:`).
- **PR #37 / CI / незавершённые проверки (`BLOCKED` / `NOT_RUN`)**:
  - Обновлён [PR #37](https://github.com/SolasFor/MCP-app/pull/37) (`feat/n01-baseline-audit` → `main`, статус: **OPEN**; PR #32 не затрагивался, merge в `main` и публикация релиза не выполнялись).
  - Облачный CI и SonarCloud Quality Gate на финальном кодовом коммите `497789e` (исправление `python:S6418` в `backend/server.py`):
    - `Verify & Test (ubuntu-latest)`: **PASS** (`2m15s`: https://github.com/SolasFor/MCP-app/actions/runs/46000862980/job/140511841054).
    - `Verify & Test (windows-latest)`: **PASS** (`2m58s`: https://github.com/SolasFor/MCP-app/actions/runs/46000862980/job/140511840609).
    - `windows-package` (`RC Windows installer`): **PASS** (`2m50s`: https://github.com/SolasFor/MCP-app/actions/runs/46000862929/job/140511840499).
    - `SonarCloud Code Analysis`: **PASS** (`37s`, Quality Gate `OK`, `new_security_rating=1`, `new_reliability_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=1.1%`, `new_security_hotspots_reviewed=100.0%`): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=37.
  - `BLOCKED`/`NOT_RUN`: Authenticode `.pfx`, локальный `ISCC.exe` (`Setup.exe` проверен в `windows-package`), второй live GUI при запущенном `MCPApp-Running`, live облачные туннели/SaaS AI-клиенты/внешний SSH, ручной OAuth для `sonarqube-cloud` MCP.
  - **Вывод**: этап N01 готов к независимой приёмке и одобрению merge владельцем перед переходом к N02.

## Заключительное исправление `N01-FINAL-01 — Automation Scheduler` по второму ревью ChatGPT (2026-11-27)
- **Ветка / PR / база / версия**: `feat/n01-baseline-audit` | [PR #37](https://github.com/SolasFor/MCP-app/pull/37) (исходно проверенный HEAD `7da4ef64c8e1fedc291185a853babe54fecc06ff`; PR #32 не затрагивался) | версия `1.0.2` сохранена.
- **TDD-воспроизведение до правок (`tests/integration/test_n01_scheduler_lifecycle.py`)**: на `7da4ef6` воспроизведены отсутствующий `app.core.admin_client`/`admin_client_provider`, ложный `succeeded` при `executor=None`, отсутствие `start_background_loop`/`is_running` в жизненном цикле сервера, потеря расписания (`extra-0`) при конкурентной записи между двумя экземплярами `AutomationScheduler` и автоактивация исторических `version: 1` расписаний без явного одобрения.
- **Внесённые минимальные архитектурные изменения**:
  - `backend/automation/scheduler.py`: удалён симулированный `{"executed": ...}` fallback (`executor=None` и `async_executor=None` теперь fail-closed как `status="failed"`); добавлена схема `SCHEDULES_SCHEMA_VERSION = 2` и флаг `live_execution_approved` (унаследованные расписания `version < 2` с `enabled=True` автоматически переводятся в паузу на загрузке до явного одобрения владельцем via `set_schedule_enabled(..., True)` / `upsert_schedule`); добавлена реентерабельная кросс-процессная блокировка `.automation.lock` (`msvcrt.locking` / `fcntl.flock`) + per-path `RLock`; реализованы `trigger_now_async`, `tick_async`, `run_startup_triggers_async`, `emit_event_async`, `start_background_loop`, `stop_background_loop` с проверкой прав перед каждой попыткой (включая `safe_retry`), атомарным резервированием слота `_active_ids`, таймаутом `asyncio.wait_for` и записью `status="cancelled"` при отмене.
  - `backend/oauth_store.py`: добавлен метод `purge_ephemeral_clients()` для очистки `sched-owner-*` и `playground-ephemeral-*`.
  - `backend/automation/admin_api.py`: сохранены loopback-only проверки, отклонение туннельных заголовков и `hmac.compare_digest` scoped auth; добавлена поддержка awaitable `scheduler_trigger_fn`, CRUD/enable/history/event маршрутов (`/api/v1/schedules`, `/api/v1/schedules/history`, `/api/v1/schedules/{id}`, `/enabled`, `/api/v1/events`) через компактный `_AdminEndpoints`.
  - `backend/server.py`: полностью удалён `_run_coro_sync` с `thread.join()` и вторым event loop; `_execute_scheduled_tool_async` привязан к `AUTOMATION_SCHEDULER._async_executor` и выполняется в основном event loop сервера (`GATEWAY_ROUTER`, `mcp`); `save_client`/`mark_approved`/`set_client_profile` для `sched-owner-*` и `playground-ephemeral-*` перенесены внутрь `try ... finally: revoke_client(...)`, а `_purge_stale_ephemeral_oauth_clients()` вызывается при старте и завершении сервера; `build_app()` lifespan запускает и корректно останавливает `AUTOMATION_SCHEDULER.start_background_loop`/`stop_background_loop`; `main()` при `MCP_ADMIN_PORT > 0` запускает `build_local_admin_app()` на `127.0.0.1:ADMIN_PORT` в том же event loop.
  - `app/core/admin_client.py` (включён в `[tool.mypy]` и `packaging/mcp_app.spec`): добавлен `LocalAdminClient` со строгой проверкой loopback host.
  - `app/core/service_manager.py`, `app/ui/main_window.py`, `app/ui/pages/automation_page.py`, `app/ui/i18n.py`: `ServiceManager` генерирует `MCP_ADMIN_TOKEN`, выделяет локальный `MCP_ADMIN_PORT`, предоставляет `admin_client()` и пересылает существующие события `tunnel.started` / `tunnel.ready`; `AutomationPage` больше не выполняет задачи локально (при отсутствии backend отображает ошибку без `succeeded`), запускает ручной триггер неблокирующе в фоновом потоке с сигналом в Qt и поддерживает действия «Включить / одобрить» / «Приостановить» на RU и EN.
  - Обновлены `tests/integration/test_automation_monitoring.py` (проверка ошибки при недоступном backend без ложного `succeeded`), `tests/integration/test_release_1_0_0.py` (явный `executor` в тесте) и `docs/automation-monitoring.md`.
- **Локальные доказательства после финальных правок (`Windows 11 Pro`, Python `3.13.15`, `.venv`, `QT_QPA_PLATFORM=offscreen`)**:
  - `compileall -q backend app tests tools`: **PASS**.
  - `ruff check app backend tests tools`: **PASS** (`All checks passed!`).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 75 source files`).
  - `tools/check_licenses.py`: **PASS** (`All 38 components passed license check`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS**.
  - `tests/unit`: **PASS** (**232/232**); `tests/integration`: **PASS** (**90/90** в `50.009s`, включая все 10 тестов `tests/integration/test_n01_scheduler_lifecycle.py` и live `--headless` subprocess Admin API тест); `tests/e2e` (Playwright): **PASS** (**2/2** в `11.940s`).
  - `graphify update .`: **PASS** (`5409 nodes, 17226 edges, 204 communities`).
  - Изолированная сборка PyInstaller на `D:\Coding\.mcpapp-n01-tmp\build_n01_final` (живой `MCPApp.exe` PID `3044`/`8428` и реальный `%APPDATA%\MCPApp` не затронуты, временные файлы на `D:` удалены):
    - `MCPApp.exe`: `8,479,332` Б, SHA-256 `b5148710134f66097db0d1769f827b6e0a6b95ffb4b92708c799d67f3e0f3099`.
    - `--selftest`: **PASS** (`RESULT OK`).
    - `--headless` с `MCP_ADMIN_PORT` и `MCP_ADMIN_TOKEN`: **PASS** (`POST /api/v1/schedules` + `POST /api/v1/schedules/exe-live-check/run` -> `succeeded`).
- **PR #37 / CI / незавершённые проверки**:
  - Обновлён [PR #37](https://github.com/SolasFor/MCP-app/pull/37) (`feat/n01-baseline-audit` → `main`, статус: **OPEN**; PR #32 не затрагивался, merge в `main` и публикация релиза не выполнялись, N02 не начинался).
  - Облачный CI и SonarCloud Quality Gate на кодовом коммите `c66baafa50a347e7dfe6a8fcfb5cc56a733d2766` (после `bebce09`):
    - `Verify & Test (ubuntu-latest)`: **PASS** (`1m52s`: https://github.com/SolasFor/MCP-app/actions/runs/46039215493/job/140642339045).
    - `Verify & Test (windows-latest)`: **PASS** (`2m28s`: https://github.com/SolasFor/MCP-app/actions/runs/46039215493/job/140642339348).
    - `windows-package` (`RC Windows installer`): **PASS** (`3m32s`: https://github.com/SolasFor/MCP-app/actions/runs/46039215291/job/140642338799).
    - `SonarCloud Code Analysis`: **PASS** (`44s`, Quality Gate `OK`, `new_reliability_rating=1`, `new_security_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=0.8%`, `new_security_hotspots_reviewed=100.0%`): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=37.
  - `BLOCKED`/`NOT_RUN`: Authenticode `.pfx`, локальный `ISCC.exe` (`Setup.exe` проверен в `windows-package`), второй live GUI при запущенном `MCPApp-Running`, live облачные туннели/SaaS AI-клиенты/внешний SSH, ручной OAuth для `sonarqube-cloud` MCP.
  - **Вывод**: этап N01 (включая `N01-FINAL-01`) полностью закрыт и готов к финальной приёмке и одобрению merge [PR #37](https://github.com/SolasFor/MCP-app/pull/37) владельцем перед переходом к N02.

## N01 — MERGED / N02 — подготовка (2026-11-27)

- PR #37 объединён по разрешению владельца: 32086cced4451d4c9ff31f80327f4dea7e9e91b5; HEAD f9b776a, 4 PR checks SUCCESS.
- Независимая приёмка: 10/10 lifecycle tests, 4.813s, exit 0, изолированный профиль. Полные 324 теста и сборка — по отчёту Antigravity, не повторены ChatGPT.
- P2: ResourceWarning незакрытого mcp_audit.log при тестовой переинициализации backend/server.py:352. Остаточные BLOCKED/NOT_RUN N01 сохранены.
- N02: feat/n02-secure-updater, ANTIGRAVITY_PROMPT.md. Код не начат; auto-install запрещён без доверенного signing. Версия 1.0.2, релиз не опубликован. PR #32 не изменять.

## N02 — Безопасное автообновление (2026-11-27)
- **Ветка / база / версия**: `feat/n02-secure-updater` (подготовка `12948ac`, база `main` `32086cc`, PR #32 не затрагивался) | версия приложения сохранена (`1.0.2`).
- **Реализованные модули и изменения**:
  - Пакет `app/updater/`:
    - `models.py` — строгий SemVer, канонический JSON-манифест `schema_version=1` (`stable` only, отказ при `public_key`/`trusted_keys`/`url`/`download_url`/лишних полях), состояния транзакции `UpdateTransaction` и `UpdaterPersistentState` (`highest_seen_version` против downgrade/replay).
    - `trust.py` — политика доверия `TrustPolicy` (`PRODUCTION_TRUST_ROOTS = ()` без тестовых ключей, ротация `not_before`/`not_after`, отзыв `revoked_key_ids`, отсоединённая проверка Ed25519 над каноническим UTF-8 JSON, нативная Win32 проверка Authenticode через `wintrust!WinVerifyTrust` + `crypt32!CryptQueryObject`). Автоустановка в релизе строго заблокирована (`MISSING_TRUST_ROOTS`), пока не будут внесены продакшн-ключи доверия и отпечатки.
    - `network.py` — строго HTTPS, pinned-хосты GitHub (`api.github.com`, `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`), не более 3 редиректов со сбросом `Authorization`, запрет URL из release body и prerelease/draft, потоковая загрузка с отменой и контролем размера/SHA-256.
    - `staging.py` — проверка квоты диска, защита от zip-slip/UNC/drive/NUL/POSIX-symlink/DOS-reparse (`0x400`)/NTFS case-collision/zip-bomb/защищённых пользовательских файлов (`token.json`, `settings.json`, `schedules.json`, `oauth/`, `secrets/`), private ACL и предзапусковая проверка TOCTOU `reverify_staged_bundle`.
    - `detector.py` — детектор `dev` / `installed` (Inno Setup, проверка прав записи и кэша отката) / `portable` (проверка прав на каталог/родителя и отсутствия посторонних файлов).
    - `helper.py` — внедеревый запуск `--apply-update` из `updates/helper_run/<tx_id>` (`__COMPAT_LAYER=RunAsInvoker`, `hmac.compare_digest` + TTL handoff token, `.updater.lock`, ожидание `ProcessIdentity`, проверка активных `TaskStore` задач), атомарная замена portable-пакета с `.MCPApp-old-<tx_id>`, пост-проверка `--version`/`--selftest`/`--headless /health=200`, автооткат при сбое и аварийное восстановление при старте (`recover_interrupted_update_on_boot`) без затрагивания `%APPDATA%\MCPApp`.
    - `manager.py` — `UpdateManager` (троттлинг авто-проверки 24 ч, opt-in download/stage, cancel, явная передача установки на `Quit`).
  - Интеграция: `main.py` (`--version [file]`, `--apply-update`), `app/config.py` (`update_auto_check`, `update_auto_download`, `update_auto_install`, `update_channel`), `app/ui/pages/automation_page.py`, `app/ui/main_window.py`, `app/gui.py`, `app/ui/theme.py`, `app/ui/i18n.py` (RU/EN паритет), `app/selftest.py`, `packaging/mcp_app.spec`, `pyproject.toml`, `tools/release_manifest.py`, `packaging/build.ps1`, `.github/workflows/rc-windows.yml`, `.github/workflows/build.yml`.
  - Существующий `backend/automation/backup_updater.py` (`BackupManager`, `StagedUpdater`) и N01-расписания в паузе сохранены без изменений поведения.
- **TDD-тесты и локальные доказательства (после финальных правок, Python `3.13.15`, `QT_QPA_PLATFORM=offscreen`)**:
  - Новые тесты: `tests/unit/test_n02_updater_security.py` (`9` security/trust/network/ZIP/TOCTOU тестов) и `tests/integration/test_n02_updater_lifecycle.py` (`7` lifecycle/installed/portable/rollback/crash-recovery/UI/release-manifest тестов) — предварительно зафиксированы RED, затем GREEN.
  - `compileall -q backend app tests tools`: **PASS**.
  - `ruff check app backend tests tools`: **PASS** (`All checks passed!`).
  - `mypy` (`win32`) и `mypy --platform linux`: **PASS** (`Success: no issues found in 83 source files`).
  - `tools/check_licenses.py`: **PASS** (`All 38 components passed license check`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (`No known vulnerabilities found`).
  - Полный прогон тестов: `tests/unit` **241/241 PASS**, `tests/integration` **97/97 PASS**, `tests/e2e` (Playwright) **2/2 PASS** (итого **340/340 PASS**).
  - `graphify update .`: **PASS** (`5661 nodes, 18181 edges, 213 communities`, `graphify-out` не отслеживается Git).
  - Изолированная frozen-сборка PyInstaller на `D:\Coding\.mcpapp-n02-tmp` (живой `D:\Coding\MCP App\dist\MCPApp\MCPApp.exe` PID `3044`/`8428` и реальный `%APPDATA%\MCPApp` не затронуты, каталог удалён):
    - Собраны `1.0.2` и стендовая `1.0.3` (`MCPApp.exe`: `8,547,934` Б, SHA-256 `24839ec7970beed35a1ef9af129a5143e02b98029b75eef6e2564631c3d2d30a`), подтверждены откат `1.0.2 -> ROLLED_BACK -> MCP app 1.0.2` и реальный апгрейд `1.0.2 -> COMMITTED -> MCP app 1.0.3` (реальные `--version`, `--selftest` `RESULT OK`, `--headless` `/health=200`) с побайтным сохранением DPAPI v2 `token.json`/`SecretStore` и N01 `schedules.json`.
- **Незавершённые / `BLOCKED` / `NOT_RUN` проверки**:
  - Локальный `ISCC.exe` отсутствует (**NOT_RUN** локально — Inno Setup установка/апгрейд/откат и `update-manifest.json` проверяются в CI job `windows-package`);
  - Продакшн-ключи Ed25519 (`PRODUCTION_TRUST_ROOTS`) и сертификат Windows Authenticode (`.pfx` / `PRODUCTION_PUBLISHER_THUMBPRINTS`) не передавались агентом — в релизе автоустановка остаётся **BLOCKED (`MISSING_TRUST_ROOTS`)**;
  - Ручной OAuth для `sonarqube-cloud` MCP не выполнялся (проверка качества через SonarCloud CI).
- **Статус**: `IN_PROGRESS` — ожидает прохождения PR checks / SonarCloud CI и независимой приёмки (без merge, без смены версии, без публикации релиза, N03 не начат).
- **PR #38 и облачный CI на кодовом коммите `780a865`** ([PR #38](https://github.com/SolasFor/MCP-app/pull/38), `feat/n02-secure-updater` → `main`, статус: **OPEN**; PR #32 не затрагивался):
  - Исправление после первой проверки CI/Sonar: в `helper.py`/`models.py`/`trust.py`/`main.py`/`tools/release_manifest.py` добавлено строгое каноническое ограничение путей (`os.path.realpath` + prefix confinement), в `.github/workflows/rc-windows.yml` и `build.yml` проверка схемы `dist/update-manifest.json` переведена на `./.venv-build/Scripts/python.exe`, добавлен негативный тест `run_apply_update_cli` для отклонения path-traversal планов (`tests/unit` **241**, `tests/integration` **97**, `tests/e2e` **2**, когнитивная сложность всех функций N02 `< 15`).
  - `Verify & Test (ubuntu-latest)`: **PASS** (`1m37s`, после перезапуска из-за совпадения прошлого запуска `cron-due` в N01-тесте с границей минуты `1795803899.92 → 1795803900.02`: https://github.com/SolasFor/MCP-app/actions/runs/46049076884/job/140677314585).
  - `Verify & Test (windows-latest)`: **PASS** (`3m19s`: https://github.com/SolasFor/MCP-app/actions/runs/46049076884/job/140677317191).
  - `windows-package` (`RC Windows installer`, clean-VM Inno Setup install/upgrade/uninstall + `dist/update-manifest.json` + `--selftest`): **PASS** (`3m10s`: https://github.com/SolasFor/MCP-app/actions/runs/46049076658/job/140675596051).
  - `SonarCloud Code Analysis`: **PASS** (`48s`, Quality Gate `OK`, `new_reliability_rating=1`, `new_security_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=0.0%`, `new_security_hotspots_reviewed=100.0%`): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=38.
  - Итог: этап N02 реализован и готов к независимой приёмке (merge, публикация релиза и N03 не выполняются).

### Дополнительная приёмка и исправления N02 по ревью ChatGPT (2026-11-27)
- **Базовый проверенный коммит PR #38**: `d66d39a90b6333650b6aeba57e6429821a65a4fe` (`feat/n02-secure-updater`, версия `1.0.2`).
- **TDD воспроизведение (RED → GREEN)**: созданы регрессионные тесты [`tests/unit/test_n02_review_regressions.py`](tests/unit/test_n02_review_regressions.py), которые на исходном `d66d39a` упали на всех 5 классах замечаний (`FAILED (failures=4, errors=1)`), а после исправлений перешли в `GREEN`.
- **Исправленные архитектурные дефекты**:
  - **`N02-01` (Независимая граница доверия helper)**: `run_apply_update_cli` в `app/updater/helper.py` проверяет `TrustPolicy` (при пустых `PRODUCTION_TRUST_ROOTS` немедленный выход `7`), подписанный `update-manifest.json` + `.sig`, отзыв/срок ключа, anti-downgrade по `highest_seen_version` и фактической версии `MCPApp.exe --version`, привязку к `parent_identity` (обязателен и завершён), одноразовость `tx_id` в `UpdaterPersistentState.consumed_handoff_ids` + удаление `plan.json` под `.updater.lock`, а также запрет UNC/системных/корневых/home/data/reparse путей при сохранении поддержки произвольного portable-каталога, совпадающего с `parent_identity.executable`. `UpdateManager.launch_staged_install_handoff` не записывает доверенные поля (`expected_hashes`, `require_authenticode`, `allowed_thumbprints`) в `plan.json`.
  - **`N02-02` (Полная биекция staging)**: `verify_portable_zip_and_compute_map` и `reverify_staged_bundle` в `app/updater/staging.py` отклоняют `None`/`{}` карты хешей, отсутствующие или лишние файлы и reparse/symlink-точки; `candidate_dir` повторно проверяется после `copytree` перед подменой.
  - **`N02-03` (Криптографический контракт отката `installed`)**: `detect_install_environment` в `app/updater/detector.py` вызывает `verify_cached_rollback_bundle` (подписанный манифест + размер/SHA-256 + Authenticode-отпечаток), иначе режим `installed` остаётся `BLOCKED` (`NO_ROLLBACK_CONTRACT`); `apply_installed_transaction` и `_recover_installed_tx` проверяют хеш/Authenticode установщика отката до запуска и целевую `source_version` после отката (`FAILED` при сбое).
  - **`N02-04` (Единый путь `TaskStore` и fail-closed проверки)**: в `app/paths.py` введены общие функции `tasks_data_dir`, `tasks_db_path` (`tasks/tasks.sqlite3`), `automation_dir_path` (использованы `ServiceManager`, `UpdateManager`, `helper`); `has_active_tasks` завершается fail-closed (`True`) при повреждённой/пустой/symlink БД или осиротевших `-wal`/`-shm`/`.key`; `check_active_operations` проверяет `TaskStore`, `.automation.lock`, running/повреждённый `history.json`, мьютекс `MCPApp-Running` (для `installed`) и процессы внутри `install_dir`.
  - **`N02-05` (Транзакционность и восстановление при старте)**: `apply_portable_transaction` финализирует `COMMITTED` до удаления `.MCPApp-old-<tx_id>`; `acquire_updater_lock` не проглатывает `OSError` тела блокировки; `recover_interrupted_update_on_boot` работает под `.updater.lock` (`ACTIVE_EXTERNAL` безопасно завершает запуск `app/gui.py` без порчи живого обновления). Физическое ограничение момента переименования `install_dir` документировано в [`docs/auto-update.md`](docs/auto-update.md).
  - **`N01-P2-CRON-BOUNDARY`**: в `tests/integration/test_n01_scheduler_lifecycle.py` добавлена защита от попадания setup на последнюю 2.5 с окна минуты при проверке due cron без ослабления утверждений.
- **Локальные проверки после финальных правок (Python `3.13.15`, `QT_QPA_PLATFORM=offscreen`)**:
  - `compileall -q app backend tests tools`: **PASS**.
  - `ruff check app backend tests tools`: **PASS**.
  - `mypy` (`win32`) и `mypy --platform linux` (`83` файла): **PASS**.
  - AST-проверка когнитивной сложности (`< 15` для `app/updater/*.py`, `app/paths.py`, `app/gui.py`): **PASS** (`HIGH_COG: []`).
  - `tools/check_licenses.py`: **PASS** (`38/38`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (`No known vulnerabilities found`).
  - Полный прогон тестов: `tests/unit` **248/248 PASS** (включая **7/7** новых тестов `test_n02_review_regressions.py`), `tests/integration` **97/97 PASS**, `tests/e2e` **2/2 PASS** (**347/347 PASS**).
  - `graphify update .`: **PASS** (`5729 nodes, 18600 edges, 211 communities`).
  - Изолированная frozen-сборка PyInstaller (`D:\Coding\.mcpapp-n02-tmp`, живой `MCPApp.exe` PID `3044`/`8428` и `%APPDATA%\MCPApp` не затронуты, временный каталог удалён `CLEANUP_OK`):
    - Собраны `1.0.2` (`8,564,351` Б, SHA-256 `3500b6644a5e28c9dad8e0168eaf3145e5b3826ea75dcdb35ba93f4cd1d53543`) и стендовая `1.0.3` (`8,564,351` Б, SHA-256 `32151926432a2929545309d366679cd318e96c105f78e3e8560b39d20f4f1fed`);
    - Реальный frozen `MCPApp.exe --apply-update` с поддельным планом: `rc=7`, версия осталась `'MCP app 1.0.2'`;
    - Модельный `installed` без подписанного/Authenticode отката: `NO_ROLLBACK_CONTRACT`;
    - Внедрение лишнего файла в staged bundle: `HASH_MISMATCH`;
    - Сбой пост-проверки portable: `ROLLED_BACK` → `'MCP app 1.0.2'`;
    - Подписанный CLI upgrade portable: `rc=0` → `'MCP app 1.0.3'` (`--version`, `--selftest` `RESULT OK`, `.MCPApp-old-*` удалён после commit, DPAPI v2 `token.json`/`secrets.vault.enc` и paused N01 `schedules.json` сохранены побайтно).
- **Облачный CI и SonarCloud на кодовом коммите `bb65c5ae3d8e0177907ef497cc51f78df1234e52`** ([PR #38](https://github.com/SolasFor/MCP-app/pull/38), `feat/n02-secure-updater` → `main`, статус: **OPEN**; PR #32 оставлен **OPEN** на `cf77f74`; merge/релиз/N03 не выполнялись):
  - После исправления SonarCloud `python:S3516` в [`app/updater/trust.py`](app/updater/trust.py) (`_extract_pe_signer_thumbprint` / `_first_store_cert_thumbprint`, после `55f90e3`):
  - `Verify & Test (ubuntu-latest)`: **PASS** (`1m42s`: https://github.com/SolasFor/MCP-app/actions/runs/46056247924/job/140699329432).
  - `Verify & Test (windows-latest)`: **PASS** (`3m24s`: https://github.com/SolasFor/MCP-app/actions/runs/46056247924/job/140699329134).
  - `windows-package` (`RC Windows installer`): **PASS** (`3m02s`: https://github.com/SolasFor/MCP-app/actions/runs/46056248021/job/140699328823).
  - `SonarCloud Code Analysis`: **PASS** (`41s`, Quality Gate `OK`, `new_reliability_rating=1`, `new_security_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=0.0%`, `new_security_hotspots_reviewed=100.0%`, неразрешённых issues: **0**): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=38.
- **Остающиеся `BLOCKED` / `NOT_RUN`**: локальный `ISCC.exe` (**NOT_RUN** — проверяется в CI `windows-package`), `PRODUCTION_TRUST_ROOTS` и Windows Authenticode `.pfx` (автоустановка в релизе **BLOCKED** с кодом `MISSING_TRUST_ROOTS`), режим `installed` без подписанного кэша отката **BLOCKED** (`NO_ROLLBACK_CONTRACT`), ручной OAuth `sonarqube-cloud` MCP (**NOT_RUN**, используется SonarCloud CI/API).

### Заключительное точечное исправление N02 (`N02-FINAL-01`, `N02-FINAL-02`) (2026-11-27)
- **Базовый проверенный коммит**: `fb1ec7e2141b8110a11e5318ed10e6ce3c74a092` (`feat/n02-secure-updater`, PR #38, версия `1.0.2`).
- **TDD воспроизведение (RED → GREEN)**:
  - До правок в [`tests/unit/test_n02_final_regressions.py`](tests/unit/test_n02_final_regressions.py) зафиксированы воспроизводимые сбои: `HISTORY_REAL_SCHEMA_RESULT=ok`, `HISTORY_INVALID_SCHEMA_RESULT=ok`, а также отсутствие проверки доверия, привязки `install_dir`/имени backup, `active_runs` и постпроверки boot-recovery (`FAILED (failures=1, errors=3)` из `4`).
  - После исправлений: `HISTORY_REAL_SCHEMA_RESULT=scheduler_active`, `HISTORY_INVALID_SCHEMA_RESULT=scheduler_active`, `4/4` регрессионных тестов `test_n02_final_regressions.py` перешли в `GREEN`.
- **Исправления**:
  - **`N02-FINAL-01` (История и живые запуски планировщика)**:
    - В `backend/automation/scheduler.py` добавлен учёт активных выполнений `automation/active_runs.json` (`ACTIVE_RUNS_SCHEMA_VERSION = 1`, `pid` + `create_time` в `_claim_execution_slot`/`_release_slot`, прунинг мёртвых PID и `has_active_runs()`).
    - В `app/updater/helper.py` (`check_active_operations`) добавлена строгая валидация схемы `{"version": 1, "runs": [...]}` и допустимых финальных статусов (`_has_unsafe_or_running_history`) + проверка живых выполнений (`_has_active_scheduler_runs`), symlink/reparse на `automation/`, `.automation.lock`, `active_runs.json` и `history.json` (fail-closed `SCHEDULER_ACTIVE`).
  - **`N02-FINAL-02` (Безопасный boot-recovery)**:
    - В `app/updater/helper.py` (`recover_interrupted_update_on_boot`, `_recover_under_lock`, `_restore_portable_backup`) введены: раздельная обработка блокировки `.updater.lock` (`ACTIVE_EXTERNAL`) без маскировки ошибок recovery; строгая загрузка `state.json` без перезаписи повреждённого файла (`BLOCKED`); проверка `TrustPolicy` (отказ при пустых `PRODUCTION_TRUST_ROOTS`) и подписанного `update-manifest.json` + `.sig`; строгая привязка к реальной `install_dir` и точному имени `.MCPApp-old-<tx_id>` без произвольных sibling-каталогов; запрет symlink/reparse внутри `install_dir`/`backup_dir`; безопасная перестановка через `.MCPApp-displaced-<tx_id>` с реальной проверкой восстановленной версии/selftest/health до присвоения `ROLLED_BACK` и откатом к исходной рабочей копии при провале без удаления backup.
    - В `app/gui.py` (`_run_boot_update_recovery`): в dev-режиме (`not frozen`) пропуск, в frozen-режиме явная передача `Path(os.path.realpath(sys.executable)).parent` и корректная обработка `BLOCKED` без удаления данных.
- **Проверки после финальных правок (Python `3.13.15`, `QT_QPA_PLATFORM=offscreen`)**:
  - `compileall -q app backend tests tools`: **PASS**.
  - `ruff check app backend tests tools`: **PASS**.
  - `mypy` (`win32`) и `mypy --platform linux` (`83` файла): **PASS**.
  - AST-проверка когнитивной сложности (`< 15` для `app/updater/*.py`, `app/paths.py`, `app/gui.py` и новых методов `scheduler.py`): **PASS** (`HIGH_COG: []`).
  - `tools/check_licenses.py`: **PASS** (`38/38`); `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (`No known vulnerabilities found`).
  - Полный прогон тестов: `tests/unit` **252/252 PASS** (`20.561s`), `tests/integration` **97/97 PASS** (`52.135s`), `tests/e2e` **2/2 PASS** (`8.316s`) — итого **351/351 PASS**.
  - `graphify update .`: **PASS** (`5764 nodes, 18782 edges, 210 communities`).
  - Изолированная frozen smoke-проверка `boot-recovery` (`D:\Coding\.mcpapp-n02-tmp`, живой `MCPApp.exe` PID `3044`/`8428` и `%APPDATA%\MCPApp` не затронуты, удалено `CLEANUP_OK`):
    - `BOOT_SMOKE_PROD_BLOCK`: при пустом `PRODUCTION_TRUST_ROOTS` `recover_interrupted_update_on_boot` вернул `BLOCKED`, `MCPApp.exe --version` остался `'MCP app 1.0.2'`.
    - `BOOT_SMOKE_FAIL_PRESERVED`: при повреждённой резервной копии постпроверка отклонена (`BLOCKED`), рабочая копия `'MCP app 1.0.2'` и backup сохранены.
    - `BOOT_SMOKE_RECOVERED_OK`: реальная прерванная portable-замена (`'MCP app 1.0.3'` → frozen `'MCP app 1.0.2'`) с реальными `--version`, `--selftest` `RESULT OK`, `--headless /health == 200` завершилась `ROLLED_BACK`, `.MCPApp-displaced-*` удалён, DPAPI v2 `token.json`/`secrets.vault.enc` и N01 `schedules.json` сохранены побайтно.
- **Облачный CI и SonarCloud на кодовом коммите `fce59dc4395f89fd0c5e87aaecdfb0d397ba206a`** ([PR #38](https://github.com/SolasFor/MCP-app/pull/38), `feat/n02-secure-updater` → `main`, статус: **OPEN**; PR #32 оставлен **OPEN** на `cf77f74`; merge/релиз/N03 не выполнялись):
  - `Verify & Test (ubuntu-latest)`: **PASS** (`2m01s`: https://github.com/SolasFor/MCP-app/actions/runs/46063053041/job/140721683871).
  - `Verify & Test (windows-latest)`: **PASS** (`3m28s`: https://github.com/SolasFor/MCP-app/actions/runs/46063053041/job/140721684203).
  - `windows-package` (`RC Windows installer`): **PASS** (`2m49s`: https://github.com/SolasFor/MCP-app/actions/runs/46063053292/job/140721684836).
  - `SonarCloud Code Analysis`: **PASS** (`37s`, Quality Gate `OK`, `new_reliability_rating=1`, `new_security_rating=1`, `new_maintainability_rating=1`, `new_duplicated_lines_density=0.0%`, `new_security_hotspots_reviewed=100.0%`, неразрешённых issues: **0**): https://sonarcloud.io/dashboard?id=SolasFor_MCP-app&pullRequest=38.
- **Остающиеся `BLOCKED` / `NOT_RUN`**: локальный `ISCC.exe` (**NOT_RUN** — проверяется в CI `windows-package`), `PRODUCTION_TRUST_ROOTS` и Windows Authenticode `.pfx` (автоустановка и автоматический boot-recovery в релизе **BLOCKED** с кодом `MISSING_TRUST_ROOTS`), режим `installed` без подписанного кэша отката **BLOCKED** (`NO_ROLLBACK_CONTRACT`), ручной OAuth `sonarqube-cloud` MCP (**NOT_RUN**, используется SonarCloud CI/API).

## N02 — MERGED / N03 — подготовка (2026-11-27)
- PR #38 объединён по разрешению владельца: 4b9bedb0ba20848230ab133fab447e428571991b; проверенный HEAD 431d84d, 4 CI checks SUCCESS.
- Независимая приёмка ChatGPT: N02 20 unit + 7 integration, N01 10 integration, 37/37 PASS, exit 0, временный профиль. Полный набор 351 и frozen smoke — по отчёту Antigravity, не повторены ChatGPT.
- Production auto-install/boot-recovery BLOCKED; installed без доверенного rollback BLOCKED. Отдельная приёмка signing, криптографической проверки восстанавливаемого portable-пакета и power-loss recovery обязательна до включения. См. docs/auto-update.md.
- P2 ResourceWarning mcp_audit.log остаётся. Другие NOT_RUN не переименованы в PASS.
- N03: feat/n03-workspace-servers; текущий промт ANTIGRAVITY_PROMPT.md; реализация не начата. Версия 1.0.2, PR #32 без изменений, релиз не опубликован.

## N03 — Интеграция Server Manager в Workspaces (`VERIFIED`, ожидает независимой приёмки ChatGPT / merge PR, 2026-11-28)
- **Базовый коммит**: подготовительный `9c4363e` на ветке `feat/n03-workspace-servers` (базовый merge-коммит `main`: `4b9bedb`, PR #38). Версия `1.0.2` не менялась, `app/updater/trust.py` и N02 production gates (`PRODUCTION_TRUST_ROOTS = ()`, `PRODUCTION_PUBLISHER_THUMBPRINTS = ()`, auto-install/boot-recovery `BLOCKED`) не ослаблены и не затронуты.
- **Архитектура и единый источник истины**:
  - Сохранены единый `ServerConfigStore` (`%APPDATA%\MCPApp\servers\managed_servers.json`), `ServerManager` (`backend/servers/manager.py`), стабильные ID профилей серверов, `cwd`, `argv`, `env`, DPAPI `SecretStore`-ссылки (`secret://servers/...`), ACL, `min_profile`, `allowed_clients`, `depends_on`, readiness probes, `controlled`/`independent` семантика и OAuth-инструменты.
  - Создан координатор [`backend/workspaces/server_links.py`](backend/workspaces/server_links.py) (`WorkspaceServerCoordinator`, `WorkspaceServersSnapshot`), использующий существующее поле `WorkspaceProfile.linked_servers` (схема v2, дедупликация, `SERVER_LINK_RE`) без создания параллельного реестра или копирования секретов. Поддержаны связи `1:N` (один проект → несколько серверов) и `N:1` (один сервер в нескольких проектах).
  - В [`app/core/atomic_io.py`](app/core/atomic_io.py) добавлена межпроцессная и реентерабельная межпоточная блокировка `cross_process_lock`, применённая во всех мутациях [`backend/workspaces/store.py`](backend/workspaces/store.py) и [`backend/servers/store.py`](backend/servers/store.py) (`load_profiles(strict=True)` перед `upsert_profile`/`delete_profile`).
- **Миграция v1→v2 и сохранность данных**:
  - `WorkspaceServerCoordinator.ensure_migrated()` идемпотентно мигрирует legacy v1-конфиги серверов и v1-реестр Workspaces в v2 с сохранением `.json.v1.bak` и user-private ACL, **никогда не угадывает** привязки по `cwd` или имени, не создаёт фиктивный общий workspace и не запускает/не останавливает процессы при миграции.
  - Повреждённый JSON вызывает `ValueError` fail-closed без перезаписи файлов на диске; в GUI выводится предупреждающий баннер `corrupt_banner`.
  - Отвязка сервера (`unlink_server`) и удаление workspace (`delete_workspace_preserving_servers`) не останавливают и не удаляют серверы; переименование ID сервера (`rename_server` / `RenameServerDialog`) разрешено только для остановленного сервера и синхронно переносит `SecretStore`-ключи, `depends_on` и `WorkspaceProfile.linked_servers`.
- **Матрица прав (`Global OAuth ∩ Workspace ∩ Server ∩ Task`) и задачи**:
  - При `workspace_authorizer` на `ServerManager` и `_server_auth_rechecker` на `backend/server.py` вызов к привязанному серверу проверяет пересечение прав клиента во всех задействованных слоях:
    - Явный `workspace_id` на `server_list`/`server_start`/`server_stop`/`server_restart`/`server_status`/`server_logs`/`server_metrics`/`server_health`: сервер обязан входить в `linked_servers` этого проекта, а клиент — иметь `read` (для чтения) или `read + execute` (для `start`/`stop`/`restart`), помимо `min_profile`/`allowed_clients` сервера.
    - Прямой вызов без `workspace_id` (`""`): для непривязанного сервера работают глобальный OAuth + права `ServerProfile`; для привязанного сервера требуется допуск хотя бы в одном привязанном `WorkspaceProfile`.
    - Confused-deputy защита при запуске `depends_on`: перед запуском любого процесса `ServerManager.start_server` (`_authorize_start_order`) проверяет права вызывающего клиента на все зависимости и их привязанные проекты.
  - [`backend/tasks/store.py`](backend/tasks/store.py) дополнен `create_running_task()` (исключает гонку с асинхронной очередью `TaskManager._dispatch_loop`), а [`backend/workspaces/manager.py`](backend/workspaces/manager.py) записывает реальные `TaskRecord`, артефакты `result.json`, `WorkspaceProfile.linked_tasks` и возвращает `task_id` в `workspace_run_task` + `linked_servers_status`/`missing_linked_servers` в `workspace_info`.
- **Консолидация UI и удаление вкладки «Серверы»**:
  - [`app/ui/pages/workspaces_page.py`](app/ui/pages/workspaces_page.py) объединяет `collection_tabs` (**Проекты** + **Непривязанные серверы**) и 5 вкладок деталей (**Файлы проекта**, **Статус Git, поиск и вывод задач**, **Серверы**, **Логи сервера**, **Метрики и здоровье**), неблокирующие фоновые операции (`start`/`stop`/`restart`/`health`/задачи проекта + `wait_for_pending_ops()`), отметку отсутствующих ссылок (`missing in registry`) с безопасной отвязкой и переименование профиля сервера.
  - Общие диалоги и рендер-таблицы вынесены без дублирования в [`app/ui/pages/servers_page.py`](app/ui/pages/servers_page.py) (`ServerProfileDialog`, `TemplateWizardDialog` с `default_cwd`, `RenameServerDialog`, `LinkServerDialog`, `populate_server_rows`, `format_server_details`, `fetch_server_logs_text`).
  - В [`app/ui/main_window.py`](app/ui/main_window.py), [`app/ui/components/sidebar.py`](app/ui/components/sidebar.py), [`app/ui/pages/__init__.py`](app/ui/pages/__init__.py), [`app/gui.py`](app/gui.py) и [`app/selftest.py`](app/selftest.py) удалён отдельный пункт навигации `"servers"` (12 разделов, горячие клавиши `Ctrl+1..Ctrl+9`), добавлены редиректы `_LEGACY_PAGE_REDIRECTS` (`"servers"`/`"server_manager"`/`"managed_servers"` → `"workspaces"`) и маршрутизация Command Palette.
  - Обновлены локализации RU/EN (`813` ключей с полным паритетом в [`app/ui/i18n.py`](app/ui/i18n.py)), документация (`docs/workspaces.md`, `docs/server-manager.md`, `docs/tool-reference.md`, `docs/ui-design-system.md`, `README.md`, `ROADMAP.md`) и скриншоты (`docs/screenshots/workspaces-dark.png`, `workspaces-light.png` при `1366×768`).
- **Локальные проверки N03 (Python `3.13.15`, `QT_QPA_PLATFORM=offscreen`)**:
  - TDD: backend [`tests/unit/test_n03_workspace_servers_migration_and_permissions.py`](tests/unit/test_n03_workspace_servers_migration_and_permissions.py) (`RED` → `GREEN`: **5/5 PASS**), E2E/GUI [`tests/integration/test_n03_workspace_servers_e2e.py`](tests/integration/test_n03_workspace_servers_e2e.py) (`RED` → `GREEN`: **3/3 PASS**, `3.979s`).
  - `compileall -q app backend tests tools`: **PASS**.
  - `ruff check app backend tests tools`: **PASS** (`0` ошибок).
  - `mypy` (`win32`, 84 файла) и `mypy --platform linux` (`84` файла): **PASS** (`0` ошибок).
  - `tools/check_licenses.py`: **PASS** (`38/38` зависимостей).
  - `pip_audit -r requirements.lock --no-deps --disable-pip`: **PASS** (`No known vulnerabilities found`).
  - Полный прогон тестов: `tests/unit` **257/257 PASS** (`20.506s`), `tests/integration` **100/100 PASS** (`57.055s`), `tests/e2e` **2/2 PASS** (`8.332s`) — итого **359/359 PASS**.
  - `tools/capture_ui_screenshots.py`: **PASS** (`DPI check scale=1.0..2.0: OK`, 15 скриншотов переснято).
  - Изолированная сборка PyInstaller (`D:\Coding\.mcpapp-n03-tmp`, живой `MCPApp.exe` и `%APPDATA%\MCPApp` не затронуты, `CLEANUP_OK=True`): `MCPApp.exe` (`11,629,229` Б, SHA-256 `970bcba61baa9de62cc61b9161f6bca6e107687cc33b432cee22981922e00518`), `--version` → `'MCP app 1.0.2'`, `--selftest` → `'RESULT OK'`, `--headless` (`127.0.0.1` + ephemeral `MCP_PORT`) `/health` → `200 {"status":"ok"}`.
- **Остающиеся `BLOCKED` / `NOT_RUN`**: локальный `ISCC.exe` (**NOT_RUN** — проверяется в CI `windows-package`); живой внешний туннельный smoke-тест **NOT_RUN** в рамках N03; N02 production gates (`PRODUCTION_TRUST_ROOTS = ()`, `PRODUCTION_PUBLISHER_THUMBPRINTS = ()`, auto-install/boot-recovery **BLOCKED** `MISSING_TRUST_ROOTS` / `NO_ROLLBACK_CONTRACT`) сохранены без изменений.
