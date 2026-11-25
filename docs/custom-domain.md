# Как подключить свой домен (`Cloudflare Named Tunnel`)

Постоянный HTTPS-адрес вида `https://mcp.example.com/mcp` вместо временного `*.trycloudflare.com`. Поддерживается SSE и постоянное хранение OAuth-клиентов между перезапусками.

В мастере **«Свой домен»** доступны два режима настройки (токены Cloudflare **отделены** от `MCP Owner Token` приложения):

## Режим 1. Автонастройка через Cloudflare API Token
1. Создайте одноразовый API Token на [dash.cloudflare.com](https://dash.cloudflare.com/profile/api-tokens) с правами создания туннеля и DNS CNAME.
2. Введите домен (`mcp.example.com`) и одноразовый API Token (с переключателем «Показать / Скрыть»).
3. Приложение само создаст туннель и CNAME-запись, сохранит полученный **Cloudflare Tunnel Token** в DPAPI `SecretStore` и **не сохранит** одноразовый API Token.

## Режим 2. Существующий туннель (домен + Cloudflare Tunnel Token)
1. Если туннель и DNS CNAME уже созданы в Cloudflare Zero Trust вручную, выберите режим **«Существующий туннель: домен + Cloudflare Tunnel Token»**.
2. Введите домен и готовый **Cloudflare Tunnel Token** (`DPAPI SecretStore`) — API Token и изменение DNS не требуются.
3. При необходимости нажмите **«Проверить доступность домена и Cloudflare»** (фоновая проверка Cloudflare Edge и домена).

## Режим 3. Локальный `%USERPROFILE%\.cloudflared\config.yml`
Если присутствует `config.yml` с нужным `hostname`, приложение использует его автоматически без пересоздания туннеля и DNS.

## Сохранность настроек и точная диагностика ошибок
- Настройки домена и зашифрованный `Tunnel Token` сохраняются в `domain.json`, `tunnels/connections.json` и `secrets/` и **не сбрасываются** при временном переключении на `Cloudflare Quick`, `ngrok` или `Tailscale Funnel` или после перезапуска приложения.
- Диагностика провайдера различает точные причины сбоев (`agent_missing`, `secret_decrypt_failed`, `domain_not_configured`, `domain_invalid`, `token_missing`, `token_invalid`) и записывает их в `%APPDATA%\MCPApp\logs\tunnel.log` и `errors.log`.
