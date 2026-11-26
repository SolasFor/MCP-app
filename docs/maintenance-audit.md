# Полный аудит MCP App после v1.0.0

Рабочая инструкция для Antigravity Orchestrator. Не повторять исторические этапы ROADMAP. Приоритет — подтверждённые дефекты, минимальные исправления, независимая проверка. Сохранять существующие данные и совместимость. Не выполнять релиз, merge, изменение реального DNS или восстановление ACL пользовательских данных без отдельного разрешения.

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

- Встроенный Orchestrator по умолчанию; Ponytail Lite для минимальных изменений. Superpowers — systematic-debugging, TDD или verification-before-completion по необходимости, без автоматического подключения всего набора.
- Context7 — только для незнакомого API; Chrome DevTools — OAuth/браузер; Cloudflare — транспорт и документация, не менять инфраструктуру.
- Impeccable — UX, Emil Design Eng — взаимодействия, Break UI — крайние данные, Remove Animations — при необходимости. DESIGN.md и Qt-компоненты важнее веб-шаблонов. Не загружать все дизайн-Skills одновременно.
- SonarQube — только после проверки CLI и подключения; не отправлять исходники/секреты внешнему сервису без согласия. Vercel и Swarm не нужны для основного прохода.
- Swarm допускается по отдельному запросу на независимый read-only аудит нескольких областей; не совмещать с параллельной правкой одних файлов.
- Не выполнять глобальную переустановку зависимостей. Использовать Python проекта, реальные команды CI, ограничивать лог-вывод.

## Проверки

Сверить команды с .github/workflows:
- python -m ruff check app backend tests tools
- python -m mypy
- python -m unittest discover -s tests/unit -p "test_*.py" -v
- python -m unittest discover -s tests/integration -p "test_*.py" -v
- python -m pip_audit -r requirements.lock --no-deps --disable-pip
- Windows build, EXE selftest и отдельный запуск GUI с временным профилем.

Для P0 ACL дополнительно тестировать восстановление существующих папок с ошибочным DACL (только disposable VM/профиль), запуск без администратора, сохранение ключей и данных, отсутствие лишних ACE. Не обещать восстановление уже повреждённого профиля до проверки. Не исправлять ACL настоящего профиля экспериментальными командами.

## Отчёт

Для каждого этапа: findings (P0/P1/P2, файл/строка, воспроизведение), минимальный diff, проверки PASS/FAIL/NOT_RUN/BLOCKED, остаточный риск. Сначала исправить P0; не выпускать обновление при незакрытом P0. В PROGRESS.md записывать только подтверждённые результаты, сохраняя историю.