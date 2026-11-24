# MCP-app — техническое задание v0.8.5 → v1.0.0

Репозиторий: https://github.com/SolasFor/MCP-app. Версии ниже — целевые; если репозиторий уже продвинулся, сверить актуальные теги, не понижать версию, задокументировать корректировку. Соблюдать AGENTS.md. Все этапы включают код, GUI по мере готовности, тесты, миграции, документацию и проверку совместимости. Публичные маршруты, коммерческие аккаунты и сертификаты требуют участия владельца. Существующая база: OAuth, CMD/PowerShell/SSH, три профиля доступа, Cloudflare Quick/Named, managed_servers.json, аудит, Windows CI. Проверить фактическую реализацию до работы.

## 1. v0.8.6 — Stability & Security
Ветка: feat/stability-security.

- Общий ProcessRunner: CMD/PowerShell, managed processes; управляемые деревья Windows Job Objects, корректное завершение при timeout/cancel, проверка принадлежности процессов, раздельный жизненный цикл обычных команд и явно независимых приложений. Не показывать терминал; не завершать чужие процессы.
- Потоковое параллельное чтение stdout/stderr с ограниченными буферами, квотами диска, безопасным постраничным выводом, корректной обработкой UTF-8/Windows, ротацией и очисткой. Ограничить число запросов и управляемых задач; отмена SSH не должна блокировать другие вызовы.
- SecretStore: DPAPI/Credential Manager для токена владельца, credentials туннелей, внешних OAuth/API/SSH секретов. Сохранить зашифрованную OAuth SQLite БД; атомарные миграции, ACL, резервная копия без утечек; исключение внутренних секретов из окружения, логов и диагностик. Не заявлять изоляцию полного shell.
- Единый реестр инструментов, проверка прав в discovery и вызове, проверка актуальности прав в очереди, сохранение профилей; индивидуальные белые списки, временные разрешения и отзыв доступа. Аварийная остановка новых запросов и контролируемых процессов, отчёт о тех, которые остановить нельзя. Не добавлять per-call prompts.
- Восстановление соединения с backoff/jitter, health-check, обработка сна и смены сети; различать сетевые ошибки и отмены SSE; защищённые диагностические отчёты.
- Фиксированные Python/build dependencies и версия cloudflared, проверка хэшей/подписей и лицензий, Ruff/mypy поэтапно, pip-audit, SBOM, минимальные права CI, единый gated release workflow. Подготовить Authenticode без выдуманного сертификата; актуализировать README и устаревшие security docs.
- Вынести общую инфраструктуру, не переписывая проект целиком. Платформенные интерфейсы предусмотреть с этого этапа.

Приёмка: baseline regression suite; большой вывод не вызывает неконтролируемого роста памяти/диска; тесты timeout, cancellation, process tree, revoke, environment redaction; OAuth persistence на прежнем адресе; Windows/Linux CI, Windows EXE selftest. Реальные ограничения и замеры зафиксировать.

## 2. v0.9.0 — UI Redesign
Ветка: feat/ui-redesign.

- Визуальные референсы: https://linear.app/ и https://docs.docker.com/ai/mcp-catalog-and-toolkit/. Linear — компактная навигация, типографика, ненавязчивые акценты; Docker Desktop — функциональные таблицы, статусы сервисов, журналы и инструменты. Не копировать товарные знаки и чужие ассеты.
- Dark: фон #14151A, панели #191A21, границы #272832, акцент #818CF8, текст #F4F4F5. Light: #F8F9FC, #FFFFFF, #E2E4E9, #635BDE, #18181B. Это предложенные базовые токены; скорректировать контраст после тестирования. Dark/Light/System, Segoe UI, векторные иконки, скругления 6–10 px, единые состояния hover/focus/disabled/error, минимальные анимации.
- Разделить MainWindow на страницы/компоненты; дизайн-токены, ThemeManager, навигация, таблицы, диалоги, уведомления, пустые/ошибочные состояния, лог-вьюер, поиск, Ctrl+K, сворачиваемая боковая панель, системный трей. Поддержать DPI, клавиатурную навигацию, RU/EN, сохранение настроек.
- Главная объединяет состояние Engine, старт/стоп, текущий адрес, копирование, профиль доступа, основных клиентов, диагностику. Расширенные параметры — в Connections. Навигация по мере готовности модулей: Главная, Подключения, AI-клиенты, Gateway, Задачи, Серверы, Workspaces, Устройства, Расширения, Автоматизация, Безопасность, Журналы, Настройки. Будущие функции не выдавать за работающие.
- Сохранить существующий функционал domain wizard, proxy, OAuth clients, диагностики, settings и tray. Добавить скриншоты обеих тем.

Приёмка: все существующие действия работают; переключение тем без перезапуска; UI smoke/regression tests, Windows 10/11, DPI 100/125/150/200%, размеры окна, навигация, сохранение настроек. Проверка визуальных дефектов на реальном Windows.

## 3. v0.9.1 — Connection Manager
Ветка: feat/connection-manager; разбить на PR: core+Cloudflare/Local, ngrok, Tailscale, OpenAI, end-to-end.

- TunnelProvider API: detect/version/configure/start/stop/status/diagnose/connection_identity; модель public HTTPS URL отдельно от private tunnel ID; единый manager, lifecycle, таймауты, backoff, ownership маршрутов, защищённые настройки, переходы состояний, логирование, мастер настройки каждого провайдера. По умолчанию один внешний провайдер одновременно; local loopback сохраняется. Не останавливать чужие агенты/маршруты.
- Cloudflare Quick: сохранить временный режим, показывать изменчивость URL и ограничения SSE. Named: переиспользовать существующий туннель, DNS, credentials и мастер; не пересоздавать при каждом запуске. Предложенный домен mcp.souron.space — только пример до настройки владельцем. Local only: никаких внешних публикаций, loopback bind, авторизация по выбранному контексту.
- ngrok: официальный агент, проверка версии, мастер входа/authtoken, защищённое хранение, закреплённый аккаунтом домен, явное повторное использование, получение фактического endpoint через поддерживаемый API, health-check, диагностика квот/предупреждений и OAuth browser flow. Проверить текущий синтаксис CLI и тарифы. Документация https://ngrok.com/docs/.
- Tailscale Funnel: официальный CLI; состояние tailnet, MagicDNS/HTTPS, ACL/grants Funnel, проверка доступных портов, авторизация через штатный клиент, публикация выбранного MCP endpoint, статус и восстановление маршрута; не путать Funnel (публичный) с Serve (приватный); не сбрасывать чужие маршруты. Адрес зависит от стабильности имени устройства/tailnet. Документация https://tailscale.com/docs/features/tailscale-funnel.
- OpenAI Secure MCP Tunnel: официальный https://github.com/openai/tunnel-client и https://developers.openai.com/api/docs/guides/secure-mcp-tunnels. Проверить актуальную доступность Windows-сборки, CLI, способ создания/повторного использования tunnel ID, требования к runtime credentials и доступу организации/workspace. GUI ввода/настройки ID и ключа через SecretStore, локальный HTTP target, lifecycle, диагностика, инструкция подключения поддерживаемых продуктов. Если Windows-агент недоступен, оценить официальный вариант сборки или поддерживаемое окружение и явно обозначить ограничение. Не обещать, что обычный ChatGPT на любом тарифе поддерживает этот режим. Не подменять идентификацию клиента фактом подключения через туннель; проверить реальный end-to-end auth и scopes. При отсутствии идентичности/проверенного auth — не выставлять привилегированные tools.
- OAuth: постоянный issuer/resource URL для конкретного профиля, привязка токенов к ресурсу, сохранение БД и ключей, безопасный переход между провайдерами, явное предупреждение при смене адреса. Не переносить токены между issuer. Не обещать отсутствие повторного входа при смене провайдера, истечении/отзыве токена. Раздельно хранить идентификаторы подключения и параметры OAuth.

Приёмка: перезапуск приложения и Windows, отключение сети, восстановление адреса у постоянных провайдеров, сохранение авторизации при неизменном issuer/credentials, негативные проверки auth, отсутствие утечки ключей, отсутствие публикации в Local only. Проверить фактический initialize/tools/list/tools/call и OAuth round trip через каждый доступный транспорт. При отсутствии аккаунта/entitlement — мок-тесты и отдельный BLOCKED live test, не выдавать за подтверждённую поддержку.

## 4. v0.9.2 — MCP Gateway
Ветка: feat/mcp-gateway.

- MCP-app одновременно upstream MCP client и downstream MCP server. Реестр локальных stdio, удалённых Streamable HTTP, опционального legacy SSE. Хранить профили: id/name, транспорт, exe/argv/cwd/env secret refs или URL, autostart, health, разрешения. Импорт распространённых JSON-конфигураций только после локального одобрения владельцем; экспорт без секретов.
- Lifecycle: initialize, capability negotiation, discovery/pagination, tools/list_changed, sessions, cancellation, deadlines, retry без повторения неидемпотентных операций, reconnect и health-check. Изоляция сессий и upstream credentials по клиенту/владельцу; совместное использование только явно разрешённых сервисных учётных записей.
- Router: стабильные безопасные namespaces (`solidworks__...`), уникальные имена в рамках ограничений клиентов, корректная передача schema, content blocks (text/image/resource/structuredContent), errors, resources/prompts по capabilities, ограничения объёма. Не объявлять неподдерживаемые capabilities, не пробрасывать downstream bearer upstream; реализовать безопасную внешнюю OAuth-авторизацию по спецификации.
- Разрешения на сервер и инструмент проверять при каждом вызове; ограниченные клиенты видят только явно разрешённые возможности. Запрет циклов шлюзов, проверка URL/redirect/SSRF согласно политике (разрешённые владельцем локальные endpoints возможны), контроль неизвестных серверов, недоверенных tool descriptions и секретов. Не запускать произвольные скачанные MCP-пакеты автоматически.
- GUI: список серверов, создание/импорт, редактирование, старт/стоп, статус, инструменты/схемы, logs, health, permissions, проверка соединения, обновление списка инструментов.
- CAD smoke: выбрать совместимый SolidWorks MCP, проверить версию/лицензию и COM API, запуск в пользовательском сеансе, обнаружение tools, информация об открытом документе, создать тестовую деталь в отдельной папке, проверить размеры, сохранить SLDPRT. Не менять реальные документы. При наличии доступа проверить цепочку ChatGPT → туннель → Gateway → SolidWorks MCP → локальный SolidWorks. Поддержка записи зависит от AI-клиента, MCP сервера и аккаунта; не обходить его правила. Отдельный CAD-адаптер не обязателен.

Приёмка: минимум 3 тестовых MCP-сервера разных типов, discovery/call, динамические tools, конфликт имён, access denied на list/call, credentials/session separation, отказ одного сервера без падения остальных, мультимодальный ответ, внешний клиент MCP Inspector. Реальный CAD/ChatGPT test — отдельное доказательство или явный блокер.

## 5. v0.9.3 — Task Manager
Ветка: feat/task-manager.

- Durable SQLite job registry: queued/running/succeeded/failed/cancelled/interrupted, timestamps, owner, profile, exit code, artifact refs. Очередь с приоритетами, concurrency quotas, idempotency keys, дедлайны, отмена, повтор только явно, recheck permissions при старте. Независимость от HTTP-запроса; восстановление истории после рестарта, не повторять автоматически неидемпотентные команды. Большой вывод на диск с квотами, offsets, pagination/retention, исключение секретов из метаданных и логов.
- Tools: task_start/status/list/output/result/cancel/restart/artifacts. Сохранить синхронные oauth_windows_command и oauth_ssh_command. Если поддерживаемая версия MCP имеет стандарт Tasks, оценить совместимость, не требовать неподдерживаемую клиентом функцию.
- GUI: активные/очередь/история, фильтры, владелец, elapsed, отмена/повтор, live logs, artifacts, уведомления в трее; показывать процент только если известен.

Приёмка: длинная задача продолжается при disconnect, повторное получение результата; параллельность/квоты, cancel tree, revoke, cross-client deny, retention, reboot/interrupted recovery, duplicate request. Не обещать продолжение задачи после выключения компьютера.

## 6. v0.9.4 — Server Manager
Ветка: feat/server-manager.

- Миграция managed_servers.json; GUI реестра профилей, exe/argv/cwd, env secret refs, health, запуск/остановка/restart, зависимость серверов с проверкой циклов, restart policy/backoff, автозапуск. Владение процессами/портами, метрики CPU/RAM, HTTP/TCP readiness, bounded live logs, выбор контролируемого или явно независимого режима. Не завершать чужие PID, не запускать непроверенные команды из шаблона.
- Шаблоны Python/FastAPI/Flask, Node/Express, Vite/Next, Docker Compose, static HTTP, custom. Параметры проверять, не устанавливать зависимости без разрешения, не открывать порты наружу автоматически.
- Tools server_list/start/stop/restart/status/logs/metrics/health с совместимостью oauth_managed_server; per-client access, конфигурация владельцем, связь с Task Manager.

Приёмка: импорт без потерь, создание профиля из GUI, тестовый локальный сервер с readiness и логами, restart/backoff, дерево процессов, независимый режим, конфликт порта, отказ доступа.

## 7. v0.9.5 — Workspaces
Ветка: feat/workspaces.

- Workspace registry: локальный каталог, имя, язык, git root, Python venv/Node, команды, env secret refs, связанные задачи/серверы/расширения; GUI выбора, дерево, поиск, статус Git, быстрые действия, import/export без секретов.
- Tools workspace_list/info/tree/read_file/write_file/search/apply_patch/move_file/delete_file/diff/history/run_task; git_status/diff/log/branches/checkout/commit. Разрешения на проект, read/write/delete/execute/git отдельно. Атомарная запись, hash/version precondition, bounded output/size, локальная история/откат; не затирать пользовательские изменения. .gitignore и пользовательские исключения, защищать секретные и служебные файлы.
- Windows path security: canonical paths, junction/reparse/symlink/UNC/ADS, race conditions; проверка доступа к фактически открываемому объекту, deny или безопасная обработка; не заявлять sandbox для полного CMD/PowerShell. Для Git не выполнять недоверенные hooks/filters вне явно настроенного доверенного окружения.

Приёмка: тестовый проект, поиск/patch/diff, запуск тестов в venv, Git branch/commit при разрешении, конфликт версии файла, traversal/junction негативные тесты, cross-client isolation для специализированных инструментов.

## 8. v0.9.6 — Computer Use
Ветка: feat/computer-use.

- Агент интерактивного сеанса Windows; UI Automation/pywinauto/Win32/MSS/SendInput (проверить версии и лицензии). Список окон/мониторов, DPI, скриншоты и UI tree, открытие/закрытие/фокус/размер, click/type/keypress/scroll/drag/wait. Структурированные UIA элементы предпочитать координатам. MCP content image с ограничением размера.
- Tools desktop_screenshot/list_windows/list_monitors/open_app/close_window/focus_window/get_ui_tree/click/type/keypress/scroll/drag/wait_for_element. Отдельное явное разрешение владельца на доступ к экрану и управление, видимый индикатор, локальная аварийная остановка, сериализация операций, fail closed при locked session, UAC/secure desktop и elevated windows не обходить. Не сохранять скриншоты без необходимости, не автоматизировать ввод секретов без разрешения, не передавать чувствительное содержимое неразрешённым клиентам.
- Тесты стандартного GUI, несколько мониторов/DPI, опционально SolidWorks, КОМПАС-3D, Mathcad, Office, VS Code. Для CAD точные операции через специализированный API предпочтительнее кликов.

Приёмка: реальный тест в интерактивном Windows-сеансе, открытие тестового приложения, получение скриншота/дерева и управление, отказ неавторизованному клиенту, stop, locked session, DPI. В headless CI использовать моки, но не подменять ими ручной тест.

## 9. v0.9.7 — Extensions
Ветка: feat/extensions.

- Версионируемый SDK, manifest (id/name/version/api_version/entrypoint/permissions/tools), registry, отдельный процесс + IPC, lifecycle, события, декларативные UI-компоненты, compatibility checks, per-extension secret refs, разрешения на tool registry. Не загружать произвольный сторонний код в процесс ядра. Отдельный процесс не равен sandbox; недоверенный код — только в доказуемо изолированной среде либо запрещён.
- Локальный менеджер и каталог: поиск, установка ZIP/доверенный репозиторий, целостность/подпись, безопасная распаковка, разрешения владельца, enable/disable, update/rollback/uninstall, логи и статус. Никаких автоматических установок с неподтверждённого источника. SDK docs, starter template, тестовые fixtures.
- Официальные расширения первого релиза: System Monitor, Git Manager, Docker Manager, Browser Automation (в рамках выданных прав, отдельные браузерные профили при необходимости). Дополнительные CAD (SolidWorks, КОМПАС-3D, Mathcad) и Database Manager — опциональные, только если доступен API/лицензия; SolidWorks можно подключить ранее через Gateway.

Приёмка: установить проверенное тестовое расширение без rebuild ядра, discovery/call с permissions, отключить, обновить/откатить, пережить crash, отказ невалидному manifest/архиву/несовместимой версии, сохранение данных. Документировать реальные ограничения изоляции.

## 10. v0.9.8 — Remote Management
Ветка: feat/remote-management.

- Реестр устройств/групп, SSH profiles, импорт ~/.ssh/config, SSH Agent/ключи, безопасная проверка host keys (не AutoAddPolicy), GUI подключения/проверки, status/logs/metrics.
- SFTP list/upload/download с квотами, разрешёнными корнями, защитой путей; remote Workspaces, jobs, health, CPU/RAM/disks, system services, Docker, управление с правами конкретного профиля. Не повышать привилегии автоматически. Разделять user/host/port и команды в ограниченном режиме. При disconnect не обещать остановку/возобновление удалённого процесса без подтверждённого механизма.
- Tools device_list/info/health, ssh_execute, ssh_task_start, sftp_list/download/upload, remote_service_list/start/stop, remote_metrics. Сохранить oauth_ssh_command. Индивидуальные разрешения и аудит, reconnect/backoff.

Приёмка: тестовый SSH/SFTP-сервер, known host verification, отказ изменившемуся host key, загрузка/скачивание тестового файла, remote job/status, отключение сети без блокирования локального Engine, cross-client deny.

## 11. v0.9.9 — Automation & Monitoring
Ветка: feat/automation-monitoring.

- Scheduler: время/старт/события, TZ и DST, concurrency/misfire policies, retries для безопасных операций, idempotency, владелец и recheck permissions, история, локальные уведомления. Изменение расписаний владельцем/явно уполномоченным профилем. Остановка при отзыве прав; не повторять опасные действия автоматически.
- Monitoring: CPU/RAM/disk, MCP request counts/latency/errors, клиенты, tunnel/gateway status, audit viewer, фильтры, retention, экспорт redacted diagnostics. Локальный защищённый REST API с auth и отдельными правами, не публиковать административные endpoints наружу.
- MCP Playground: фактический вызов инструментов в контексте выбранного тестового профиля, schema-based form, results/error/image/structured content, явная маркировка настоящего запуска; тестовые действия не должны случайно менять рабочие документы. Проверять deny и allowed cases.
- Backup/restore настроек: schema version, атомарная миграция, безопасная обработка архивов, без секретов по умолчанию; DPAPI не считать переносимым между пользователями/ПК. Updater: проверка GitHub releases, changelog, staged download, проверка доверенной подписи, rollback, резервная копия; автоустановка отключена до реального доверенного подписания.
- Опциональный headless режим и Windows Service: минимальные привилегии, отдельный пользовательский агент для Computer Use (Session 0 separation). Никаких автоматических изменений системных служб владельца без разрешения.

Приёмка: расписание с событиями/revoke/DST, корректные метрики, реальный Playground call, отрицательные auth checks REST, redacted export, backup/restore, тест неподписанного/повреждённого обновления и rollback, headless startup.

## 12. v1.0.0 — Stable Release
Ветка: release/v1.0.0.

- Финальное архитектурное и security review, threat model (публичные туннели, OAuth, полный shell, сторонние серверы/расширения, UI, SSH, supply chain), исправление замечаний. Dependency/secret scans, SBOM, подпись и checksums. Не заявлять безопасность полноценной песочницы при full access.
- Unit/integration/security/performance/e2e; Windows 10/11, portable/setup, clean install, update from v0.8.5, uninstall, rollback, migrations. 72-часовой soak test или явное отсутствие фактического результата; network/sleep/reboot, concurrent clients, output floods, disk full, broken config, crash/revoke, cross-client auth. Проверять контрольные сценарии всех предыдущих этапов.
- Реальная матрица transport/client: Cloudflare Quick/Named, ngrok, Tailscale, OpenAI Secure, Local; MCP Inspector, ChatGPT, Codex, OpenAI API, Claude, Gemini, Notion, VS Code только при поддерживаемом способе подключения и наличии аккаунта. Для OpenAI Secure проверять только официально поддерживаемые продукты. Отмечать not applicable / blocked / verified с доказательствами, не обещать совместимость без теста.
- README, документация пользователя и разработчика, все провайдеры, tool reference, SDK, FAQ, безопасность и известные ограничения, upgrade guide, CHANGELOG. RC v1.0.0-rc.1, исправления, финальный релиз только после обязательных проверок и согласования владельцем (либо его явного разрешения на автоматический релиз).
- Артефакты: MCPApp-Setup-1.0.0.exe, MCPApp-1.0.0-portable.zip, SHA256SUMS.txt, SBOM.cdx.json, CHANGELOG.md/release notes. Authenticode доверенным сертификатом при наличии; отсутствие сертификата — явный блокер подписанного релиза, не маскировать. Если владелец принимает исключение для неподписанного релиза, документировать и оставить автоустановку выключенной.

Приёмка: все обязательные функции проверены, блокеры/исключения приняты владельцем, CI зелёный, релизные файлы проверены и соответствуют коммиту. Нереализованные функции нельзя маркировать готовыми.

## После v1.0 (не входит в обязательные 12 этапов)
Собственный MCP Relay, Multi-device, Linux/macOS, Docker/headless distribution, публичный Web Dashboard, marketplace. Платформенные адаптеры и модульная архитектура должны облегчить дальнейшее развитие, но не задерживать Windows v1.0.
