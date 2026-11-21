# SouronMCP

Десктопная утилита для Windows (трей), которая одной кнопкой запускает и останавливает:

- **MCP-сервер** (`backend/server.py`, streamable-http, `127.0.0.1:8000`);
- **Cloudflare Named Tunnel** (`cloudflared tunnel --config ... run`) → `https://mcp.souron.space/mcp`.

## Структура

```
MCP-app/
├─ main.py                  # единая точка входа: GUI по умолчанию, --backend = MCP-сервер
├─ requirements.txt
├─ backend/
│  ├─ __init__.py
│  └─ server.py             # ваш существующий сервер (+ функция main())
├─ app/
│  ├─ __init__.py           # APP_NAME, версия
│  ├─ paths.py              # пути dev / .exe, поиск cloudflared.exe
│  ├─ config.py             # настройки → %APPDATA%\SouronMCP\settings.json
│  ├─ backend_entry.py      # запуск бэкенда в дочернем процессе
│  ├─ gui.py                # ВРЕМЕННО: консольный прогон ядра (шаг 3 заменит на окно)
│  ├─ core/                 # без зависимости от виджетов
│  │  ├─ process.py         # ManagedProcess: асинхронная обёртка QProcess
│  │  ├─ health.py          # HealthMonitor: TCP :8000 и cloudflared /ready
│  │  ├─ service_manager.py # оркестратор: порядок старта, перезапуски, статус
│  │  ├─ winjob.py          # Job Object: дочерние процессы не переживут GUI
│  │  └─ autostart.py       # автозапуск через HKCU\...\Run
│  └─ ui/                   # шаг 3: main_window.py, tray.py, widgets.py, style.qss
├─ assets/                  # шаг 3: иконки (app.ico, tray_on/off/warn.png)
├─ bin/                     # (опц.) cloudflared.exe для включения в сборку — в .gitignore
└─ packaging/               # шаг 4: SouronMCP.spec, build.ps1
```

## Архитектура: почему GUI не зависает

```
┌──────────────────── SouronMCP.exe (GUI-процесс, один поток Qt) ────────────────────┐
│  MainWindow / Tray ── start_all() / stop_all() ──▶ ServiceManager                     │
│        ▲                                             │                                │
│        └─── сигналы: overall_state_changed,          ├─▶ ManagedProcess("server")──┐   │
│             service_state_changed, log_line         ├─▶ ManagedProcess("tunnel")──┤   │
│                                                     └─▶ HealthMonitor (таймер 2 с) │   │
└─────────────────────────────────────────────────────────────────────────────────────┬──┘
                       Job Object (KILL_ON_JOB_CLOSE)                                 │
          ┌─────────────────────────────────────────────────────────────────────────┴────────┐
          │  SouronMCP.exe --backend  (uvicorn :8000)     cloudflared tunnel ... run       │
          │         stdout+stderr ──pipe──▶ QProcess    stdout+stderr ──pipe──▶ QProcess │
          └─────────────────────────────────────────────────────────────────────────────────┘
```

1. **Никаких потоков и блокирующих вызовов.** `QProcess` асинхронен: старт возвращается мгновенно, вывод приходит событием `readyReadStandardOutput`. Health-check'и — через `QTcpSocket` и `QNetworkAccessManager`, тоже асинхронно.
2. **Сервер — отдельный процесс, а не поток.** Изоляция: если MCP-команда повесит сервер или он упадёт, GUI жив и перезапустит его. В .exe один бинарник: GUI запускает сам себя с `--backend`.
3. **Порядок.** Старт: preflight → server → ждём порт 8000 → tunnel → ждём `/ready`. Стоп: tunnel → server.
4. **Честный статус.** «Сервер: Запущен» = порт принимает соединения. «Туннель: Активен» = `cloudflared` отвечает 200 на `http://127.0.0.1:20241/ready` (есть соединение с Cloudflare).
5. **Автоперезапуск** с экспоненциальной задержкой 2/4/8/16/30 с, максимум 5 попыток подряд.
6. **Никаких сирот.** Дочерние процессы в Job Object: если GUI убит из Диспетчера задач — Windows сам завершит сервер и туннель, порт 8000 не останется занят.

## Запуск (шаг 2 — без окна)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# скопируйте свой server.py в backend\server.py и добавьте в него main()
python main.py          # логи server + tunnel в одной консоли, Ctrl+C — остановка
```

Перед запуском закройте старые окна терминала с `python server.py` и `cloudflared tunnel run`, иначе preflight сообщит, что порт 8000 занят.

## Безопасность

Репозиторий публичный. Токены, `.env`, SSH-ключи, `cert.pem` и credentials-файлы туннеля исключены в `.gitignore` — проверьте `git status` перед коммитом `backend/server.py`.
