# Как подключить свой домен

По умолчанию MCP app работает в режиме **«Временный адрес»**: Cloudflare выдаёт случайный адрес `*.trycloudflare.com`, без домена и аккаунта. Он меняется при каждом запуске, не поддерживает SSE и не гарантирует доступность.

Свой домен даёт постоянный адрес вида `https://mcp.example.com/mcp`. Настраивается один раз, примерно за 10 минут. Понадобятся домен и бесплатный аккаунт Cloudflare.

Та же инструкция есть в приложении: **«Подключение» → «Как подключить свой домен»**. Там команды уже содержат полный путь к встроенному `cloudflared.exe`. Ниже он обозначен как `cloudflared`. Если cloudflared нет в PATH, подставьте путь, например `& "C:\MCP app\_internal\bin\cloudflared.exe"`.

## 1. Добавьте домен в Cloudflare

На [dash.cloudflare.com](https://dash.cloudflare.com/sign-up) нажмите **Add a domain** и выберите тариф Free. У регистратора домена замените NS-серверы на те, что покажет Cloudflare. Дождитесь статуса **Active**: обычно это занимает от пары минут до нескольких часов.

## 2. Войдите в Cloudflare из cloudflared

```powershell
cloudflared tunnel login
```

В открывшемся браузере выберите домен и нажмите **Authorize**. В `%USERPROFILE%\.cloudflared` появится файл `cert.pem`.

## 3. Создайте туннель

```powershell
cloudflared tunnel create mcp-app
```

Команда напечатает UUID туннеля и создаст файл `%USERPROFILE%\.cloudflared\<UUID>.json`. Это ключ туннеля, никому его не передавайте.

## 4. Привяжите адрес к туннелю

```powershell
cloudflared tunnel route dns mcp-app mcp.example.com
```

Cloudflare сам создаст CNAME-запись.

## 5. Создайте config.yml

Приложение ищет его здесь: `%USERPROFILE%\.cloudflared\config.yml`.

```yaml
tunnel: <UUID>
credentials-file: C:\Users\<вы>\.cloudflared\<UUID>.json

ingress:
  - hostname: mcp.example.com
    service: http://127.0.0.1:8000
  - service: http_status:404
```

В Блокноте при сохранении выберите «Тип файла: все файлы», иначе получится `config.yml.txt`.

## 6. Включите свой домен в приложении

Откройте **«Подключение» → «Свой домен»**, введите `mcp.example.com` и нажмите «Сохранить», затем «Запустить». Клиентам дайте адрес `https://mcp.example.com/mcp`, токен прежний.

## Если не заработало

| Сообщение | Что сделать |
|---|---|
| «Свой домен ещё не настроен: нет конфига туннеля» | Файл лежит не в той папке или сохранён как `config.yml.txt`. |
| «… нет в ingress config.yml» | Адрес в приложении и `hostname` в config.yml должны совпадать. |
| Туннель не подключается | Нужен исходящий доступ к Cloudflare на порт 7844 (брандмауэр, роутер, VPN). |
| Клиент получает ошибку 1033 или 530 | Туннель не запущен, или DNS-запись из шага 4 ещё не создана. |

Подробнее: [документация Cloudflare про локальные туннели](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/).
