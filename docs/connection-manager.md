# MCP-app Connection Manager (`v1.0.0`)

Единый слой управления транспортами (`app/core/tunnels/`) с разделением публичного HTTPS-адреса и loopback-цели, единым жизненным циклом, защитой секретов в `SecretStore` и изоляцией OAuth по `issuer` / `resource_url`.

## Поддерживаемые провайдеры (все 5)

| Провайдер | Идентификатор | Публичный HTTPS URL | Особенности и ограничения |
| --- | --- | --- | --- |
| **Cloudflare Quick** | `cloudflare_quick` | Да (`*.trycloudflare.com`) | Временный URL при каждом запуске; без SSE (`MCP_JSON_RESPONSE=1`); клиенты переавторизуются при смене адреса. |
| **Cloudflare Named** | `cloudflare_named` | Да (свой домен) | Переиспользует существующий туннель (`domain.json` или `~/.cloudflared/config.yml`), не пересоздавая его при запуске. |
| **ngrok Agent v3** | `ngrok` | Да (`*.ngrok-free.*` / reserved) | `NGROK_AUTHTOKEN` хранится в DPAPI `SecretStore` и передаётся только через окружение. Читает реальный endpoint из `http://127.0.0.1:4040/api/endpoints` (`/api/tunnels` fallback) и синхронизирует `issuer`/`resource_url` с сервером и GUI. Бесплатные домены могут показывать browser warning interstitial. |
| **Tailscale Funnel** | `tailscale_funnel` | Да (`*.ts.net` HTTPS) | Использует `tailscale status --json`, `funnel status --json`; разрешены только порты `443`, `8443`, `10000`. Проверяет чужие маршруты, синхронизирует `issuer`/`resource_url` с сервером и GUI, при остановке снимает только свой путь (`off`). Отличает публичный Funnel от приватного Serve. |
| **Local Only** | `local_only` | **Нет** | Строгий loopback (`127.0.0.1`, `localhost`, `::1`), внешние маршруты не открываются, авторизация OAuth/Bearer остаётся включённой. |

> **Миграция удалённого `openai_tunnel`:** OpenAI Secure MCP Tunnel полностью исключён из v1.0.0. Если в сохранённой конфигурации обнаруживается `openai_tunnel`, приложение безопасно переводит активный провайдер в `local_only` (без автопубликации) и предлагает владельцу на вкладке «Подключения» удалить устаревший ключ `tunnel/openai_tunnel_api_key` из `SecretStore`.

## Изоляция OAuth и владелец маршрутов

- Одновременно активен один внешний провайдер; локальный loopback доступен всегда.
- При смене провайдера или `issuer` выводится явное предупреждение (`IssuerTransitionWarning`): токены OAuth привязаны к конкретному `issuer` и никогда не переносятся автоматически.
- `RouteOwnershipStore` (`%APPDATA%\MCPApp\tunnels\routes.json`) записывает принадлежащие MCP-app PID + `create_time` и маршруты Tailscale Funnel, чтобы остановка не завершала чужие процессы и не удаляла посторонние маршруты.
- Все несекретные настройки лежат в `%APPDATA%\MCPApp\tunnels\connections.json`, а токены/ключи — исключительно в `SecretStore` (`DPAPI` / `POSIX`).

## Статус live-проверок vs mocks

- **`local_only`**: проверен реальный end-to-end MCP/OAuth round trip (`tests/integration/test_connection_transports.py`).
- **`ngrok` / `Tailscale Funnel` / публичный `Cloudflare Named`**: полностью покрыты unit- и интеграционными тестами с локальными mock HTTP API и mock CLI; реальные публичные маршруты и коммерческие аккаунты не публикуются без отдельного согласия владельца (помечены как `BLOCKED` в `PROGRESS.md`).
