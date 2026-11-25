# Удалённое управление устройствами по SSH / SFTP (v0.9.8 — Remote Management)

## Принципы безопасности

- **Жёсткая проверка ключей хостов (`RejectPolicy`)**: параметр `strict_host_key=True` нельзя отключить. MCP-app никогда не использует `AutoAddPolicy`. Неизвестный хост или изменившийся ключ (`BadHostKeyException`) немедленно отклоняются с `PermissionError`.
- **Импорт `~/.ssh/config`**: импортирует только явные `Host`-записи (`HostName`, `User`, `Port`, `IdentityFile`), пропуская маски (`*`, `?`) и игнорируя `ProxyCommand`. У импортированных профилей все привилегированные права (`execute`, `sftp_read`, `sftp_write`, `service_control`, `metrics`) выключены до явного включения владельцем.
- **Секреты в `SecretStore("ssh")`**: пароли и парольные фразы хранятся по ссылкам `secret://ssh/<device>__password` (DPAPI на Windows / ACL на POSIX) и не попадают в `devices.json`, экспорт или логи.
- **SFTP-границы и квоты**: все пути нормализуются в каноническом POSIX-виде, проверяются против `allowed_sftp_roots`, включая `sftp.normalize(...)` на сервере (защита от symlink-выхода), и ограничены квотой `sftp_max_bytes` (по умолчанию 10 МБ).
- **Разделение прав**: режим `safe` полностью блокирует удалённые устройства; `allowlist` требует точного совпадения команды в `allowed_commands` (без `;`, `&&`, `|`, `` ` ``, `$()`, перенаправлений) и сервиса в `allowed_services`. Автоматическое `sudo` не используется.
- **Честная семантика обрыва сети**: при разрыве SSH во время `ssh_task_start` соединение закрывается без блокировки локального Engine, задача получает статус `disconnected`, а в `disconnect_note` честно фиксируется, что остановку или возобновление удалённого процесса нельзя подтвердить без подтверждённого агента на целевом хосте.

## OAuth-инструменты (12 инструментов + совместимый `oauth_ssh_command`)

- Устройства и диагностика: `device_list`, `device_info`, `device_health`, `remote_metrics`
- Команды и фоновые задачи: `ssh_execute`, `ssh_task_start` (при сохранении legacy `oauth_ssh_command`)
- SFTP: `sftp_list`, `sftp_download`, `sftp_upload`
- Службы ОС: `remote_service_list`, `remote_service_start`, `remote_service_stop`
