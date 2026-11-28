# Удалённое управление устройствами по SSH / SFTP (`N05` — Onboarding Wizard & Security)

## Мастер подключения SSH-устройств (`SSHDeviceWizardDialog`)

Пошаговый мастер на вкладке **«Устройства (SSH / SFTP)»** автоматизирует безопасную настройку удалённых Windows- и Linux-устройств поверх существующих `DeviceStore`, `DeviceProfile`, `SSHConnectionManager` и `RemoteManager` (без параллельного реестра или второго SSH-исполнителя):

1. **Шаг 1 — Источник и адрес (`Source`)**:
   - **Ручной ввод**: `device_id`, имя, группа, `host`, `port`, `username` (строгая валидация против option/URL/shell injection).
   - **Импорт OpenSSH Config (`inspect_ssh_config`)**: read-only разбор явных `Host`-блоков (отключены wildcard/negation-шаблоны, `Match`, `ProxyCommand`, `ProxyJump`, `LocalCommand`, `RemoteCommand`, `Include` и прочие директивы выполнения), показ диагностик и дедупликация по ID и каноническому endpoint `(host, port, username)`.
   - **Ограниченное обнаружение в локальной сети (opt-in)**: только после явного подтверждения владельца (`owner_consent=True`), строго в приватных/CGNAT/ULA/loopback диапазонах (`IPv4 >= /24`, `IPv6 >= /120`, не более `256` адресов, без DNS и публичного интернета). Найденные хосты имеют статус `Not trusted / Not auth`.
   - **Tailscale peers (opt-in)**: read-only чтение `tailscale status --json` при наличии локального CLI и явного согласия владельца (никогда не вызывает `tailscale up/login` и не меняет маршруты/ACL).
2. **Шаг 2 — Проверка SSH Host Key ДО аутентификации**:
   - Отдельное pre-auth рукопожатие (`probe_ssh_host_key`) выполняет **0 пакетов аутентификации**.
   - **Запрещён слепой TOFU и `AutoAddPolicy` (`RejectPolicy` всегда)**. Для продолжения обязательна независимая out-of-band сверка пользователем: ввод `SHA256:...` отпечатка или OpenSSH публичного ключа `<algorithm> <base64>` + явная отметка подтверждения (`verify_independent_host_key`).
   - При несовпадении ключа в `known_hosts` или profile pin (`host_key_changed`) мастер **жёстко блокирует** подключение. Смена скомпрометированного/обновлённого ключа выполняется только через отдельный диалог ротации (`HostKeyRotationDialog` → `rotate_device_host_key`).
3. **Шаг 3 — Строгая аутентификация и диагностика (`agent` / `key` / `password_ref`)**:
   - Строго изолированный выбранный метод без неявного fallback Paramiko (`allow_agent=False, look_for_keys=False` для `key` и `password_ref`; `allow_agent=True, look_for_keys=False` для `agent`).
   - Явная генерация новой пары **Ed25519** (`GenerateSSHKeyDialog` → `generate_ssh_ed25519_keypair`): атомарное создание `O_CREAT | O_EXCL` (без перезаписи существующих ключей), ограничение Windows ACL, показ и копирование только публичного ключа `ssh-ed25519 ...` (приватный ключ не передаётся в MCP/логи).
   - Контекстные инструкции настройки OpenSSH для Windows 10/11 и Linux (`SSHSetupGuideDialog`): `sshd`, брандмауэр, `authorized_keys` / `administrators_authorized_keys` и получение SHA-256 fingerprint — **без автоматического включения `sshd`, правил firewall, `sudo` или UAC на удалённом устройстве**.
4. **Шаг 4 — Read-only определение ОС и возможностей**:
   - На уже аутентифицированной и pinned-сессии запускается bounded-зонд (`uname -s -m` / `cmd.exe /d /c ver`) и безопасная read-only проверка SFTP (`sftp.normalize(".")`). Поддерживаются `linux`, `windows` и fail-closed `unknown`.
5. **Шаг 5 — Разрешения, deny-by-default, предпросмотр и атомарный WAL-коммит**:
   - **Новые и импортированные устройства создаются deny-by-default**: `allow_oauth_clients=False` и все флаги `DevicePermissions` выключены (`False`). Существующие legacy-профили v1 (без поля `allow_oauth_clients`) сохраняют совместимое поведение при обновлении.
   - Перед записью формируется полный редактируемый предпросмотр с привязкой к точному криптографическому снимку (`SSHDevicePlanSnapshot` / `WizardStalePlanError`).
   - Коммит (`commit_device_wizard_plan`) защищён WAL-журналом `.n05_device_tx.json`: атомарно обновляются `devices.json`, app-managed `<data_dir>/remote/known_hosts` и ссылки `SecretStore("ssh")` (`set_secret` с уникальным суффиксом), с автоматическим откатом при сбое или аварийном перезапуске. Кнопка **«Отмена»** очищает временные поля и не записывает ни одного файла/секрета.

## Границы доверия: app-managed `known_hosts`, `~/.ssh/known_hosts` и anti-downgrade pin

- Профили, добавленные через мастер N05 (или прошедшие явную ротацию ключа через `HostKeyRotationDialog`), сохраняют доверенный ключ в изолированный файл приложения `<data_dir>/remote/known_hosts` и фиксируют тройной pin в `DeviceProfile`:
  `pinned_host_key_algorithm`, `pinned_host_key_sha256`, `pinned_host_key_base64`.
- Пользовательский `~/.ssh/known_hosts` используется read-only для диагностики конфликтов и совместимости с legacy-профилями без `known_hosts_path` / pin — MCP App никогда не перезаписывает пользовательский `~/.ssh/known_hosts`.
- Во время runtime-подключений `SSHConnectionManager` передаёт pinned `transport_factory` с приоритетом алгоритма ключа (anti-downgrade защита) и перепроверяет байты предъявленного ключа после рукопожатия до отправки учётных данных.
- Логи, предпросмотр, `device_list` и `device_info` никогда не содержат `password`, `passphrase`, `password_ref` или `passphrase_ref` для OAuth-клиентов.

## Матрица доступа OAuth и live revoke

| Сценарий OAuth | Доступ к удалённым устройствам | Дополнительные проверки `RemoteManager` |
|---|---|---|
| **`safe`** *(безопасный)* | **Заблокирован** (`PermissionError`) | Полный отказ на `device_list` и всех инструментах |
| **`allowlist`** *(по умолчанию)* | Только если `allow_oauth_clients=True`, `min_profile != "full"`, клиент не запрещён `allowed_clients` и включён флаг `DevicePermissions.*` | Точное совпадение `allowed_commands` (без метасимволов shell), `allowed_services`, канонические пути `allowed_sftp_roots`, живой `live_client_authorizer` |
| **`full`** *(полный доступ)* | Только при `allow_oauth_clients=True`, разрешении клиента и включённом `DevicePermissions.*` | Произвольные SSH-команды от имени SSH-пользователя **без подтверждения каждого вызова**; поддельный OAuth `client_id="owner"` заблокирован; живой отзыв клиента останавливает даже ещё не стартовавший `ssh_task_start` worker |

- Внутренний режим владельца GUI (`from_oauth=False, client_id="owner"`) проверяет `DevicePermissions` на действиях, не требуя `allow_oauth_clients=True`.
- Legacy-инструмент `oauth_ssh_command` (в `server.py`) сохранён совместимым, дополнительно валидирует `host`/`port`/`user` через модели `backend/remote/models.py`, читает `~/.ssh/config` безопасно через `inspect_ssh_config` и использует `RejectPolicy()`.

## Прочие инварианты

- **Секреты в `SecretStore("ssh")`**: пароли и парольные фразы хранятся по ссылкам `secret://ssh/<device>__password[__<suffix>]` (DPAPI на Windows / ACL на POSIX) и не попадают в `devices.json`, экспорт или логи.
- **SFTP-границы и квоты**: все пути нормализуются в каноническом POSIX-виде, проверяются против `allowed_sftp_roots`, включая `sftp.normalize(...)` на сервере (защита от symlink-выхода), и ограничены квотой `sftp_max_bytes` (по умолчанию 10 МБ).
- **Честная семантика обрыва сети**: при разрыве SSH во время `ssh_task_start` соединение закрывается без блокировки локального Engine, задача получает статус `disconnected`, а в `disconnect_note` честно фиксируется, что остановку или возобновление удалённого процесса нельзя подтвердить без подтверждённого агента на целевом хосте.

## OAuth-инструменты (12 инструментов + совместимый `oauth_ssh_command`)

- Устройства и диагностика: `device_list`, `device_info`, `device_health`, `remote_metrics`
- Команды и фоновые задачи: `ssh_execute`, `ssh_task_start` (при сохранении legacy `oauth_ssh_command`)
- SFTP: `sftp_list`, `sftp_download`, `sftp_upload`
- Службы ОС: `remote_service_list`, `remote_service_start`, `remote_service_stop`
