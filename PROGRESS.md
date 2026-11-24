# MCP-app — журнал выполнения

База плана: `v0.8.5` (`89deaa4`). Аудит репозитория и запуск baseline-тестов проведены.

| Этап | Целевая версия | Статус | PR / CI / доказательства |
|---|---|---|---|
| 1. Stability & Security | v0.8.6 | IN_PROGRESS | Ветка `feat/stability-security` |
| 2. UI Redesign | v0.9.0 | TODO | — |
| 3. Connection Manager | v0.9.1 | TODO | — |
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
- Дата, ветка, HEAD: 2026-11-25, ветка `feat/stability-security`, база `v0.8.5` (`89deaa4`).
- Baseline тесты: PASS (`compileall` OK; `tests/unit`: 95 tests OK; `tests/integration`: 14 tests OK — итого 109/109 PASS на Python 3.13.15).
- Окружение: Windows 11 Pro 25H2 (x86_64), Python 3.13.15 (`.venv`), `cloudflared 2026.10.7`, `tailscale 1.104.2`, `gh` авторизован (`SolasFor`), `ngrok` / `docker` / `iscc` локально не установлены (Inno Setup 6 есть в GitHub Actions `windows-latest`).
- Изменения: инициализирован локальный Git-репозиторий от `origin/main` (`v0.8.5`), создана ветка `feat/stability-security`.
- Следующее действие: реализация Этапа 1 (`v0.8.6 — Stability & Security`).

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
