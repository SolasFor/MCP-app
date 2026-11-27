# Критерии приёмки N00–N13

Все критерии дополняют AGENTS.md, docs/maintenance-audit.md и ROADMAP.md. Для каждого этапа: baseline SHA, изменённые файлы, команды/exit codes, negative tests, реальные результаты, остаточный риск, статус TODO/IN_PROGRESS/BLOCKED/VERIFIED/MERGED/RELEASED. Непроведённое = NOT_RUN. Не изменять тесты ради зелёного статуса.

| Этап | Минимальное доказательство |
|---|---|
| N00 | main синхронизирован, локальные правки сохранены, фактический список инструментов и блокеров, инструкция/план готовы; код продукта не изменён |
| N01 | воспроизводимый аудит, приоритеты, локальный baseline, исправления только подтверждённых P0/P1, независимое ревью |
| N02 | полный контракт docs/auto-update.md, независимая граница доверия helper, полная биекция staging, signed/Authenticode rollback contract (иначе `installed` `BLOCKED`), bad signature fail-closed, production block без доверенных корней/Authenticode |
| N03 | миграция v1.0.2→новый формат и повторный запуск, no loss of IDs/permissions/env refs; unlinked profiles доступны; tools совместимы; sidebar/shortcuts/palette/README согласованы |
| N04 | Next.js/Python/Docker/monorepo/unknown, дубликаты, path traversal, no execution/secrets on discovery, cancel без записи |
| N05 | verified host key, wrong/changed key rejects, failed auth, no secrets in logs, scopes, Windows/Linux smoke, импорт deny-by-default, cancel/no unwanted network scan |
| N06 | effective permission matrix, live revoke, access denied after revoke, redaction, no privilege widening |
| N07 | bounded retries, manual stop wins, sleep/network change, Quick URL change/OAuth, no process leaks, live transports where owner authorizes |
| N08 | bounded metrics, unavailable shown honestly, UI responsive, no secret collection, RU/EN/DPI |
| N09 | import validation, duplicate detection, tool/schema compatibility, denied tool/scope tests, untrusted STDIO no auto-exec |
| N10 | real Windows/Linux probes, unknown OS safe, SFTP path/symlink/quota, service permission checks, no automatic sudo |
| N11 | signed/pinned packages, invalid archive/signature rejected, update/rollback, permissions unchanged, process isolation honestly described |
| N12 | cycle detection, type validation, cancellation, bounded retries/concurrency, auth each step, no arbitrary unapproved command |
| N13 | full CI Linux/Windows, Sonar Quality Gate, test installer & upgrade, EXE selftest, SHA256/SBOM, docs, real UI/external smoke or explicit BLOCKED |

CI-equivalent: python -m compileall -q backend app tests tools; python -m ruff check app backend tests tools; python -m mypy; python tools/check_licenses.py; python -m pip_audit -r requirements.lock --no-deps --disable-pip; QT_QPA_PLATFORM=offscreen unit/integration unittest discover; official packaging/build.ps1 in disposable environment, not over running dist. GitHub PR checks and gated Build workflow required before release. Offscreen tests do not replace actual Windows visuals or device/network tests.
