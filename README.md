# MCP app

Десктопное приложение для Windows 10/11: одной кнопкой поднимает **MCP-сервер** (`backend/server.py`) и открывает к нему доступ из интернета через **Cloudflare Tunnel**. Работает из трея, сам перезапускает упавшие части и не оставляет процессов-сирот.

- **Временный адрес** `*.trycloudflare.com`: без домена и без аккаунта Cloudflare, работает сразу после установки.
- **Свой домен**: постоянный адрес через именованный туннель (`~/.cloudflared/config.yml`).
- **Токен доступа**: задаётся вручную или генерируется; клиенты передают его в `Authorization: Bearer …` (или `?token=…`).

## Установка (для пользователя)

1. Скачайте `MCPApp-Setup-<версия>.exe` (или `MCPApp-<версия>-portable.zip`).
2. Установите. Права администратора не нужны, приложение ставится в `%LOCALAPPDATA%\Programs\MCP app`.
3. Запустите **MCP app** → **Запустить**. На чистой машине сразу выбран режим «Временный адрес».
4. На странице «Обзор» скопируйте адрес и токен и добавьте MCP-сервер (коннектор) в клиенте.

Python и cloudflared ставить не нужно: оба внутри сборки.

**SmartScreen.** Сборка не подписана сертификатом, поэтому при первом запуске Windows покажет «Windows защитила ваш компьютер». Нажмите «Подробнее» → «Выполнить в любом случае».

## Безопасность публичных MCP-подключений

Начиная с PR-03, по умолчанию сервер публикует только безопасный MCP-инструмент
`server_info`. Операции с файлами, Windows-командами и SSH требуют **явного
включения расширенного профиля** и, для исполнения команд, точных разрешённых
списков. У всех клиентов со старым общим Bearer-токеном пока одинаковые права —
не включайте расширенный профиль для непроверенных внешних клиентов.

Для новых установок токен в ссылке (`?token=`) выключен по умолчанию; существующее
значение настройки сохраняется при обновлении. Используйте заголовок
`Authorization: Bearer ...` и не публикуйте токен в переписке.

Подробнее: [профили доступа и ограничения](docs/security-profiles.md).

## Данные

| Что | Где |
|---|---|
| Настройки | `%APPDATA%\MCPApp\settings.json` |
| Токен (доступ только у вашего пользователя) | `%APPDATA%\MCPApp\token.json` |
| Рабочая папка и журнал аудита сервера | `%APPDATA%\MCPApp\server\mcp_audit.log` |
| Отчёт о сбое | `%APPDATA%\MCPApp\crash.log` |

При удалении эти данные остаются. Данные прежней версии (`%APPDATA%\SouronMCP`) копируются при первом запуске, поэтому токен и клиенты сохраняются.

## Запуск из исходников

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Здесь нужен установленный cloudflared: `winget install --id Cloudflare.cloudflared`.

## Сборка .exe и установщика

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

Скрипт сам:
1. создаёт окружение `.venv-build` и ставит зависимости (из `requirements.lock`, если он есть);
2. скачивает последний `cloudflared.exe` и проверяет подпись Cloudflare;
3. рисует иконку и ресурс версии;
4. собирает `dist\MCPApp\MCPApp.exe` через PyInstaller (onedir, без консоли);
5. запускает самопроверку собранного exe (`MCPApp.exe --selftest`);
6. упаковывает portable zip и, если установлен Inno Setup 6, `MCPApp-Setup-<версия>.exe`.

Для установщика нужен Inno Setup: `winget install --id JRSoftware.InnoSetup`. Другой Python для сборки выбирается так: `-Python "py -3.13"`.

**Зафиксируйте версии** из рабочего окружения, чтобы сборка совпадала с тем, что у вас работает:

```powershell
pip freeze > requirements.lock
```

**CI.** Workflow лежит в `packaging/ci/build.yml`. Чтобы включить, перенесите его в `.github/workflows/`.

## Структура

```
main.py                 точка входа: GUI / --backend / --selftest
app/gui.py              QApplication, трей, один экземпляр, перенос данных
app/core/               ServiceManager, процессы, health-check, токен, автозапуск
app/ui/                 окно в стиле Claude Desktop, тема, эффекты, иконки
backend/server.py       MCP-сервер (uvicorn + MCP SDK)
packaging/              PyInstaller spec, build.ps1, installer.iss, CI
```
