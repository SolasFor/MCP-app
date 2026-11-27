# Полный аудит MCP App после v1.0.0

Рабочая инструкция для обычной модели или встроенного Antigravity Orchestrator. Применяется к N01/N13 текущего ROADMAP; не повторять исторические этапы из docs/roadmap-v1.0.0.md. Приоритет — подтверждённые дефекты, минимальные исправления, независимая проверка. Сохранять существующие данные и совместимость. Не выполнять релиз, merge, изменение реального DNS или восстановление ACL пользовательских данных без отдельного разрешения.

## Этапы и критерии

| Этап | Область | Критерии |
|---|---|---|
| P0-1 | Windows, запуск, ACL | SID из токена, корректный DACL для файлов/папок, совпадающие имена ПК/пользователя, ошибки API, обычная учётная запись, обновление с повреждённым ACL без потери DPAPI/SQLite, GUI startup и EXE selftest |
| P0-2 | OAuth и безопасность | safe/allowlist/full, индивидуальные права, revoke, токены, CSP, origin, issuer/resource, redirect, отсутствие утечек секретов; fail-closed в ограниченных режимах |
| P1-1 | MCP и gateway | initialize, tools/list, tools/call, схемы, structured errors, совместимость клиентов, отмена/таймаут, параллельные сессии, безопасные границы gateway |
| P1-2 | Хранилища и процессы | атомарные записи, миграции, ошибки диска/ACL, SQLite, DPAPI, задачи, spool, subprocess, shutdown, tray, логи и редактирование секретов |
| P1-3 | Транспорты | четыре UI-провайдера, сохранение настроек, reconnect, прокси, OAuth Named/Quick, ошибки сети; внешние live smoke только с разрешением |
| P1-4 | Дополнительные модули | Computer Use, workspaces, extensions, remote management, automation: авторизация каждого вызова, отказ, изоляция и обработка исключений |
| P2 | UI/UX | DESIGN.md, PyQt6, темы, RU/EN, 100–200% DPI, длинные данные, клавиатура, контекстные меню, отсутствие лишних анимаций и блокировки UI |
| P0-release | Сборка и обновление | lint/types/audit, unit/integration, CI, реальная Windows-сборка, EXE startup/selftest, installer upgrade, SHA-256, SBOM, подпись если доступна, release notes |

## Инструменты и квота

- Обычная модель или встроенный Orchestrator по выбору владельца; Ponytail для минимальных изменений. Superpowers — systematic-debugging, TDD или verification-before-completion по необходимости, без автоматического подключения всего набора.
- Context7 — только для незнакомого API; Chrome DevTools — OAuth/браузер; Cloudflare — транспорт и документация, не менять инфраструктуру.
- Impeccable — UX, Emil Design Eng — взаимодействия, Break UI — крайние данные, Remove Animations — при необходимости. DESIGN.md и Qt-компоненты важнее веб-шаблонов. Не загружать все дизайн-Skills одновременно.
- SonarQube — дополнительный контроль качества и безопасности, не замена Ruff, mypy, pip-audit, unittest и ручному security review. CLI доступен отдельно от MCP. Перед использованием проверять sonar --version и sonar auth status. Не отправлять исходники/секреты внешнему сервису без согласия. Vercel и Swarm не нужны для основного прохода.
- Swarm допускается по отдельному запросу на независимый read-only аудит нескольких областей; не совмещать с параллельной правкой одних файлов.
- Не выполнять глобальную переустановку зависимостей. Использовать Python проекта, реальные команды CI, ограничивать лог-вывод.

## SonarQube: дополнительная проверка

- Сначала выполнить локальные проверки CI. Использовать SonarQube для поиска дефектов, security hotspots, дублирования и технического долга, которые не покрыты линтерами; не исправлять автоматически все замечания и не ослаблять правила безопасности.
- Предварительные условия: sonar --version, sonar auth status; для локального sonar run mcp требуется работающий Docker/Podman/Nerdctl (или соответствующий runtime в WSL); для hosted MCP — OAuth в AG, без локального контейнера. Не устанавливать контейнерный runtime, не запускать облачную интеграцию, не создавать токены, hooks, платные проекты или CI-интеграцию автоматически.
- На момент подготовки: CLI 1.13.1 установлен; авторизация CLI отсутствует. В AG включён плагин SonarQube и настроен официальный удалённый MCP SonarQube Cloud EU (https://api.sonarcloud.io/mcp), запрошены read-only и ограниченный набор инструментов. Endpoint доступен, возвращает OAuth challenge HTTP 401. Требуется завершить OAuth в AG и проверить tools/list, включая отсутствие инструментов изменения данных. Для hosted MCP Docker не требуется; CLI и его авторизация проверяются отдельно. Если подключения нет, отметить BLOCKED и продолжить локальные проверки.
- После отдельного подключения и согласования передачи исходников: проверить наличие связанного проекта и доступных функций, выбрать целевые файлы или изменения, при необходимости изучить findings/quality gate. Не выводить секреты и не передавать каталоги APPDATA, .env, логи и токены. Не считать инструмент прошедшим проверку без результата.
- Повторять анализ только после существенных исправлений или для финальной приёмки; не запускать дорогостоящий глубокий анализ после каждого изменения. Сохранять идентификаторы правил, важность, файл/строку, подтверждение или мотивированное отклонение ложного срабатывания.

## Проверки

Сверить команды с .github/workflows:
- python -m ruff check app backend tests tools
- python -m mypy
- python -m unittest discover -s tests/unit -p "test_*.py" -v
- python -m unittest discover -s tests/integration -p "test_*.py" -v
- python -m pip_audit -r requirements.lock --no-deps --disable-pip
- Windows build, EXE selftest и отдельный запуск GUI с временным профилем.

Для P0 ACL дополнительно тестировать восстановление существующих папок с ошибочным DACL (только disposable VM/профиль), запуск без администратора, сохранение ключей и данных, отсутствие лишних ACE. Не обещать восстановление уже повреждённого профиля до проверки. Не исправлять ACL настоящего профиля экспериментальными командами.


## Старт и контроль покрытия

- Рабочая версия на момент подготовки: v1.0.1, ветка fix_cursor_and_context_menus; актуальный HEAD сверять перед работой. Не считать 189 ранее пройденных unit-тестов новой приёмкой.
- P0: проследить все вызовы restrict_path_acl, поведение при False/PermissionError, создание временных файлов, защищённые DACL и доступ владельца. Проверить упаковку pywin32 в EXE; реальный одноимённый ПК/пользователь и повреждённый профиль требуют отдельной тестовой среды. Не менять профиль рабочего компьютера.
- Контроль покрытия: app/platform, app/core, app/ui, backend/server.py, backend/oauth*, backend/tool_permissions.py, backend/gateway, backend/tasks, backend/servers, backend/workspaces, backend/desktop, backend/extensions, backend/remote, backend/automation, packaging, CI и документация. Отметить каждый модуль как проверенный, не требующий исправления, исправленный либо заблокированный.
- До интеграционных тестов проверить fixtures и изоляцию APPDATA/LOCALAPPDATA, сетевых портов, дочерних процессов и внешних сервисов. Не запускать реальные пользовательские команды, туннели или Computer Use в основном профиле ради теста.
- Если лимит заканчивается: сохранить краткий checkpoint в PROGRESS.md и продолжить с первого незакрытого критерия, не повторяя весь анализ.
- Финальный независимый review: новая независимая беседа выбранной модели или ChatGPT с зафиксированным diff. Swarm только по отдельному запросу, преимущественно read-only, максимум 2–3 независимых области плюс верификация; все изменения интегрирует один агент.

## Отчёт

Для каждого этапа: findings (P0/P1/P2, файл/строка, воспроизведение), минимальный diff, проверки PASS/FAIL/NOT_RUN/BLOCKED, остаточный риск. Сначала исправить P0; не выпускать обновление при незакрытом P0. В PROGRESS.md записывать только подтверждённые результаты, сохраняя историю.

## Результаты выполненного комплексного аудита (2026-11-26, `v1.0.1`)

| Этап | Статус | Подтверждённые исправления и проверки |
|---|---|---|
| P0-1 | PASS (локально + EXE) | Защита от symlink/junction (`is_reparse_point`), DACL по SID `TokenUser` без `Everyone`, атомарный I/O (`atomic_io.py` с очисткой при `ENOSPC`), неразрушающая диагностика и восстановление `acl_recovery.py` / `--repair-acl` / ранний GUI-диалог без удаления DPAPI/SQLite/токенов, `pywin32` `hiddenimports`, расширенный `--selftest`, исправление пробелов в `packaging/build.ps1`. Проверено `test_windows_acl.py` и живыми запусками `MCPApp.exe` (`--selftest`, `--minimized`, `--repair-acl`) в одноразовом неадминистративном профиле. |
| P0-2 | PASS | Исключена перезапись/перегенерация `MCP Owner Token` при ошибках чтения/ACL/DPAPI и в `--headless` (`TokenLoadStatus`, `TokenStorageError`, `_hydrate_headless_env`, `bind_owner=TOKEN_FROM_ENV`); сохранены индивидуальные профили `safe`/`allowlist`/`full`, добавлены пер-клиентские политики инструментов (`exec_client_policies`), пер-клиентские переопределения Computer Use (`DesktopPolicy.client_overrides`), поддержка URL `client_id` (CIMD) и `ClientPermissionsDialog`. Проверено `test_client_and_token_persistence.py`, `test_oauth_*` и Playwright E2E (Chromium, Firefox, Chrome, Edge). |
| P1-1 | PASS | Проверены `initialize`, `tools/list`, `tools/call`, структурированные ошибки `TASK_*` и редактируемые ошибки модулей (`tool_permissions.py`), добавлена защита HTTP `3xx` редиректов `UpstreamClient` от обхода `validate_upstream_url` (SSRF) и утечки секретных заголовков на cross-origin при редиректе. |
| P1-2 | PASS | Все JSON/секретные хранилища переведены на `atomic_io` и `try_init_private_dir`; закрыты утечки pipe/потоков воркера расширений при рестарте/таймауте (`extensions/runtime.py`); проверены Job Objects, `output_stream` со спулингом, SQLite `busy_timeout`, `SecretRedactor` и `LoggingManager`. |
| P1-3 | PASS (локально) / BLOCKED (live cloud) | Проверены 4 публичных UI-провайдера, сохранность конфигурации кастомного домена при переключениях, режимы прокси (`none`/`auto`/`manual`), добавлено `30s`-кэширование `tailscale status --json` без блокировки GUI. Внешние облачные/платные туннели не изменялись (`BLOCKED` без отдельного разрешения). |
| P1-4 | PASS | Исправлен литеральный NUL (`"\x00"`), NTFS ADS (`:`) и имена устройств Windows в `security_policy.py`; проверены fail-closed ограничения `workspaces`, `servers`, `desktop` (UIPI/UAC/locked desktop + пер-клиентские overrides), `extensions` (Ed25519/SHA-256), `remote` (`RejectPolicy`, SFTP root/symlink) и `automation` (loopback-only Admin API, `paused_revoked`, `auto_install_enabled=False`). |
| P2 | PASS | Проверены `DESIGN.md`, `SafeComboBox`, `SafeSpinBox`, `AppContextMenu`, `ClientPermissionsDialog`, локализованы стандартные кнопки `SilentMessageBox` (`RU`/`EN`), синхронизированы `728` ключей `i18n`, проверен рендеринг при `100%–200%` DPI (`tools/capture_ui_screenshots.py`). |
| P0-release | PASS (portable + EXE) / NOT_RUN (`Setup.exe` локально) / BLOCKED (Authenticode, SonarQube) | `ruff`, `mypy` (`win32` + `linux`, 74 файла), `check_licenses.py` (`38/38`), `pip-audit` (0 CVE), `206` unit + `76` integration + `2` Playwright E2E, реальная сборка `dist/MCPApp/MCPApp.exe`, `MCPApp-1.0.1-portable.zip`, `SBOM.cdx.json`, `SHA256SUMS.txt` и живые smoke-тесты EXE. Локальный `ISCC.exe` не установлен (`Setup.exe` собирается в GitHub Actions CI); сертификат `.pfx` и авторизация SonarQube отсутствуют (`BLOCKED`). |
