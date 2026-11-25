# MCP-app Connection Manager (`v0.9.1`)

Единый слой управления транспортами (`app/core/tunnels/`) с разделением публичного HTTPS-адреса и приватного `Tunnel ID` / loopback-цели, единым жизненным циклом, защитой секретов в `SecretStore` и изоляцией OAuth по `issuer`.

## Поддерживаемые провайдеры (все 6)

| Провайдер | Идентификатор | Публичный HTTPS URL | Особенности и ограничения |
| --- | --- | --- | --- |
| **Cloudflare Quick** | `cloudflare_quick` | Да (`*.trycloudflare.com`) | Временный URL при каждом запуске; без SSE (`MCP_JSON_RESPONSE=1`); клиенты переавторизуются при смене адреса. |
| **Cloudflare Named** | `cloudflare_named` | Да (свой домен) | Переиспользует существующий туннель (`domain.json` или `~/.cloudflared/config.yml`), не пересоздавая его при запуске. |
| **ngrok Agent v3** | `ngrok` | Да (`*.ngrok-free.*` / reserved) | `NGROK_AUTHTOKEN` хранится в DPAPI `SecretStore` и передаётся только через окружение. Читает реальный endpoint из `http://127.0.0.1:4040/api/endpoints` (`/api/tunnels` fallback). Бесплатные домены могут показывать browser warning interstitial. |
| **Tailscale Funnel** | `tailscale_funnel` | Да (`*.ts.net` HTTPS) | Использует `tailscale status --json`, `funnel status --json`; разрешены только порты `443`, `8443`, `10000`. Проверяет чужие маршруты и при остановке снимает только свой путь (`off`), не вызывая `tailscale funnel reset`. Отличает публичный Funnel от приватного Serve. |
| **OpenAI Secure MCP Tunnel** | `openai_tunnel` | **Нет** (`is_public_url=False`) | Официальный `openai/tunnel-client` (`init`, `doctor`, `run`). `CONTROL_PLANE_API_KEY` хранится в DPAPI `SecretStore`. Передаёт только приватный `tunnel_id` в поддерживаемые workspace OpenAI (не любой тариф ChatGPT). НЕ отключает OAuth/Bearer-проверку. |
| **Local Only** | `local_only` | **Нет** | Строгий loopback (`127.0.0.1`, `localhost`, `::1`), внешние маршруты не открываются, авторизация OAuth/Bearer остаётся включённой. |

## Изоляция OAuth и владелец маршрутов

- Одновременно активен один внешний провайдер; локальный loopback доступен всегда.
- При смене провайдера или `issuer` выводится явное предупреждение (`IssuerTransitionWarning`): токены OAuth привязаны к конкретному `issuer` и никогда не переносятся автоматически.
- `RouteOwnershipStore` (`%APPDATA%\MCPApp\tunnels\routes.json`) записывает принадлежащие MCP-app PID + `create_time` и маршруты Tailscale Funnel, чтобы остановка не завершала чужие процессы и не удаляла посторонние маршруты.
- Все несекретные настройки лежат в `%APPDATA%\MCPApp\tunnels\connections.json`, а токены/ключи — исключительно в `SecretStore` (`DPAPI` / `POSIX`).

## Статус live-проверок vs mocks

- **`local_only`**: проверен реальный end-to-end MCP/OAuth round trip (`tests/integration/test_connection_transports.py`).
- **`ngrok` / `Tailscale Funnel` / `OpenAI Secure MCP Tunnel` / публичный `Cloudflare`**: полностью покрыты unit- и интеграционными тестами с локальными mock HTTP API и mock CLI; реальные публичные маршруты и коммерческие аккаунты не публикуются без отдельного согласия владельца (помечены как `BLOCKED` в `PROGRESS.md`).
