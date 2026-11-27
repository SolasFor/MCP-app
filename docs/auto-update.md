# Безопасное автообновление — проект N02 (TODO)

Baseline: backend/automation/backup_updater.py StagedUpdater проверяет SHA-256 + Ed25519, но auto_install_enabled=False; текущая страница Automation проверяет GitHub metadata. Текущий release workflow создаёт Inno Setup, portable ZIP, SHA256SUMS, SBOM; отсутствие доверенного Authenticode не устраняется контрольной суммой. Не включать существующий флаг без нового безопасного installer lifecycle.

## Модель доверия
- Официальный GitHub SolasFor/MCP-app, stable channel; строгие версии, no downgrade, ignore drafts/prereleases по умолчанию. HTTPS с проверкой сертификата, лимиты размера/таймаутов/redirect, allowlist release asset hosts и names. Никаких arbitrary URLs из release body.
- Предпочтение: detached Ed25519 signature над каноническим manifest (schema/channel/version/commit/asset name/size/SHA256/platform/format/key_id). Встроенный trusted public key; секретный ключ только protected release signing environment. Никакой генерации или передачи реального закрытого ключа агентом. Настроить ротацию с overlap, отзыв/компрометацию и отказ без доверенного ключа. SHA из того же источника без подписи недостаточен. Authenticode при доступном доверенном сертификате как дополнительный слой; не обещать SmartScreen без него.
- Подписывать окончательные assets после сборки, проверять signature на CI, минимальные permissions и review release job. Отсутствующий secret означает блокировку автоустановки, не silent downgrade. Первый переход с 1.0.2 — вручную в доверенную версию; не bootstrap доверие из скачанного манифеста.

## Жизненный цикл
- Фоновый check (по умолчанию разрешён с настройкой), throttling/timeout/cancel, уведомление без звука. Auto-download opt-in; auto-install opt-in только после доверенного signing, при явном Quit или согласованном restart; не при сворачивании в трей.
- Immutable staging в защищённом каталоге, атомарная запись, проверка ZIP traversal, symlink/reparse, bomb/quota, manifest mismatch, повторная проверка непосредственно перед исполнением. Никакой перезаписи running EXE или _internal.
- Установленный режим: отделённый updater/helper ждёт подтверждённого завершения GUI/controlled processes и проверяет отсутствие активных задач; использует штатный Inno Setup с проверенными аргументами и exit code. Portable: staged directory swap, old directory сохраняется до health confirmation, не смешивать _internal. Helper находится вне заменяемого каталога. Не трогать независимые сервисы или чужие PID. Обеспечить mutex/race protection и отмену.
- При отказе/прерывании, нехватке диска, ошибке startup/selftest/timeout — безопасный rollback файлов и понятный отчёт; журнал без секретов. Самопроверка не заменяет реальный startup; подтвердить запуск/версию/миграцию до удаления старого пакета. Не удалять %APPDATA% MCPApp, DPAPI vault, OAuth SQLite, profiles и настройки; миграции отдельно и обратно совместимо. Для installer rollback определить надёжный контракт с предыдущим проверенным пакетом, иначе блокировать автоустановку.
- В интерфейсе показать версию, время последней проверки, статус подписи, changelog, действия и причину отказа. Не запускать скачанный код без подписи. Существующий backup не расширять.

## Приёмка
Disposable installed/portable profiles, подлинный/поддельный/неподписанный manifest, неправильная версия/asset/hash/key, invalid ZIP/redirect, повреждение staging между проверкой и запуском, active tasks, mutex, kill/power loss, no disk, installer failure, failed startup, rollback, сохранение OAuth/DPAPI/config и no admin. Реальные Windows upgrade/uninstall и проверка подписанного артефакта на CI. Без signing infrastructure статус BLOCKED для включения auto-install; не выпускать функцию как полностью готовую.

## Граница после N01
Baseline 32086cc. Старые расписания N01 остаются в паузе до одобрения. Auto-install без доверенного signing заблокирован независимо от настройки. Тестовые ключи не production trust roots. Если нет безопасного контракта rollback, формат BLOCKED. Реализация по ANTIGRAVITY_PROMPT.md только после разрешения владельца.
