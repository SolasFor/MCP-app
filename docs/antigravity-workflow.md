# Antigravity — профиль разработки MCP App

Рабочий каталог D:/Coding/MCP App, репозиторий SolasFor/MCP-app. Настройки проекта не требуют конкретной модели: владелец выбирает обычную модель или встроенный Orchestrator. Не назначать одновременно два оркестратора, не менять модель/глобальные permission grants автоматически. Использовать локальный Git и тесты прежде дополнительных инструментов.

## Проверенная локальная инвентаризация N00
На момент подготовки обнаружены:
- config.json: chrome-devtools-plugin, cloudflare, context7, sonarqube, superpowers — enabled=true; swarm, vercel-plugin — enabled=false.
- mcp_config.json: sonarqube-cloud; кэш MCP definitions также Cloudflare, Context7, Vercel. Кэш не доказывает live connection; Vercel отключён.
- .gemini/config/skills: ponytail, graphify, impeccable, break-ui, apple-design, emil-design-eng и другие; .agents/skills: UI/UX Pro Max в пользовательском каталоге; проектный mcp-app-audit.
- Git, gh, Python 3.13 local venv, Graphify CLI, OpenSSH доступны; sonar-scanner в PATH не найден. CI использует Python 3.12. SonarCloud Quality Gate последнего PR проверять через gh. Не требовать локальный scanner/JDK для работы с Cloud MCP.
- Не читать/выводить headers, tokens, OAuth cache, глобальные разрешения. Наличие конфигов и флагов — не подтверждение успешного вызова инструмента из AG. Live checks выполнять из AG безопасными read-only запросами; при ошибке BLOCKED, не менять токены самовольно.

## Маршрутизация
| Инструмент | Когда | Ограничения |
|---|---|---|
| Superpowers | архитектура, TDD, систематическая отладка | один подход, не дублировать оркестрацию |
| Ponytail | небольшие правки | не урезать проверки/обработку ошибок |
| Graphify | связи и blast radius | локальный AST, игнорируемый индекс, перепроверка кодом; не hooks/watchers/cloud |
| UI/UX Pro Max или Impeccable | N03–N05, N08–N12 UI | DESIGN.md/Qt приоритет; не менять стек |
| Break UI | граничные состояния UI | проверять реальные результаты |
| mcp-app-audit | N01/N13 | docs/maintenance-audit.md |
| Context7 | неизвестные API | read-only документация, без секретов |
| SonarQube Cloud | PR/review | проверять Quality Gate, исправлять root cause, без ослабления |
| Chrome DevTools | OAuth и браузерная часть | тестовый browser, не реальные cookies |
| Cloudflare | N07 и туннели | только read-only диагностика, DNS/маршруты по отдельному разрешению |
| GitHub/gh | git/PR/CI | scopes/branch gates, никаких force push |
| Swarm | только отдельно разрешённые независимые задачи | сейчас disabled |
| Vercel | не требуется | сейчас disabled |
| Local MCP | независимая проверка ChatGPT | не вызывать рекурсивно AG через AG |

## Первый запуск агента
Проверить git status, branch, HEAD, worktree, Python, gh auth status (не выводить токены), graphify help; AG Customizations → Installed проверить listed tools. Для Context7 получить документацию PyQt6, для SonarCloud — статус project/PR, для Chrome DevTools — тестовую страницу, для Cloudflare — только read-only при необходимости. Если UI/UX Pro Max не виден, проверить доступность SKILL.md, не переустанавливать неизвестные источники. Не запускать live SSH/туннели или сканирование без согласия. Не пытаться включить Swarm/Vercel.

## N02
Claude Opus high reasoning либо Carbon (при доступности). Superpowers/TDD, Ponytail, Graphify AST, Context7, SonarCloud CI; UI Skills только для Qt. Проверить AG Installed; ручной OAuth SonarCloud остаётся BLOCKED, PR-check допустим. Не менять глобальные разрешения. Текущий промт ANTIGRAVITY_PROMPT.md.

## N03 — профиль запуска
Claude Opus high reasoning либо Carbon как единственный оркестратор (при доступности). Superpowers/TDD, Ponytail, Graphify AST, один из UI/UX Pro Max или Impeccable, Break UI, Context7, SonarCloud CI и GitHub. Проверить AG Installed при старте, не менять глобальные настройки. Sonar MCP OAuth остаётся NOT_RUN, PR-check допустим. Текущий план ANTIGRAVITY_PROMPT.md.

## N04 — профиль запуска
Claude Opus high reasoning либо Carbon как единственный оркестратор (при доступности). Superpowers/TDD, Ponytail, Graphify AST, один основной UI/UX Pro Max или Impeccable, Break UI, Context7, SonarCloud CI и GitHub. Проверить AG Installed; Sonar MCP OAuth остаётся NOT_RUN, PR-check допустим. Не менять глобальные настройки. Discovery только read-only, не исполнять анализируемые проекты. План ANTIGRAVITY_PROMPT.md.

## N05 — профиль запуска
Claude Opus high reasoning либо Carbon как единственный оркестратор (при доступности). Superpowers/TDD, Ponytail, Graphify AST, один основной UI/UX Pro Max или Impeccable, Break UI, Context7/официальная документация Paramiko/OpenSSH/Tailscale, SonarCloud CI и GitHub. Проверить AG Installed; Sonar MCP OAuth NOT_RUN, PR-check допустим. Не менять глобальные настройки. Сетевые тесты по умолчанию loopback fixtures; живые устройства только в отдельно согласованном scope. План ANTIGRAVITY_PROMPT.md.
