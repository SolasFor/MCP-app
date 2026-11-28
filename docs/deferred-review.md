# Реестр отложенных замечаний до N13
Решение владельца: N06–N12 feature-first, затем комплексная доработка N13. Не откладывать подтверждённые блокирующие P0/P1 безопасности, потери данных/секретов, разрешений и базовой работоспособности. Не обходить CI. Некритичные P2/P3 записывать с воспроизведением и влиянием.
| ID | Замечание | Статус |
|---|---|---|
| D01 | ResourceWarning mcp_audit.log (исторический тест N01) | OPEN P2; N13 |
| D02 | Реальные внешние SSH Windows/Linux, Tailscale и туннели | NOT_RUN; только разрешённые хосты/аккаунты |
| D03 | IPv6 loopback WinError 10013 | SKIPPED; N13 |
| D04 | SonarQube MCP ручная OAuth | NOT_RUN; SonarCloud CI используется |
| D05 | Signing, криптографическая целостность portable rollback, power-loss recovery | BLOCKED; отдельный production gate |
N13 не означает автоматическое включение production updater. Новые функции бэкапа вне scope.
