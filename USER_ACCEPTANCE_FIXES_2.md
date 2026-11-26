# MCP-app v1.0.0 — Отчёт о втором этапе исправлений (Wave 2 Release Acceptance)

Ветка: `fix/v1.0.0-acceptance-fixes` (PR #32, база `release/v1.0.0`)
Дата: `2026-11-25`

---

## 1. Общее резюме Wave 2

Выполнен полный цикл диагностики, разработки, тестирования и пересборки Windows-дистрибутива по результатам второго этапа пользовательского тестирования `MCP-app v1.0.0`:
- Исправлена критическая блокировка OAuth 2.1 в Chromium-браузерах (Chrome / Edge), вызванная строгим `CSP: form-action 'self'` на 303-редиректе после POST формы согласия.
- Реализована централизованная многопроцессно-безопасная система постоянного логирования в `%APPDATA%\MCPApp\logs\` с 15 компонентными журналами, ротацией `.gz`, редактированием секретов (включая `DEBUG`) и защищённым экспортом диагностического ZIP.
- Убраны навязчивые уведомления (смена темы, сворачивание в трей), упрощён список транспортных провайдеров (4 UI-провайдера без ложных бейджей и Loopback в UI).
- Исправлено затирание адреса и настроек своего домена (`Cloudflare Named Tunnel`) при переключении провайдеров и перезапусках, добавлен режим подключения существующего туннеля по **Cloudflare Tunnel Token**, а также явный ввод/вставка **MCP Owner Token**.
- Переключатели Computer Use переведены на анимированные `ToggleSwitch` с мгновенным атомарным автосохранением без кнопки «Сохранить».
- Полностью переработана система прокси (`none` по умолчанию вместо фейкового `127.0.0.1:1080`, `auto` с реальной проверкой протокола/авторизации/TLS без тихого fallback и `manual` `SOCKS5H`/`SOCKS5`/`HTTP CONNECT`).
- Оптимизирован PyInstaller `onedir`-дистрибутив Windows (`-29.43 MB` и `-157` файлов в `_internal`).

---

## 2. Корневая причина OAuth-сбоя в Chromium (`Invalid request`) и исправление

### 2.1. Эмпирическое воспроизведение и первопричина
При реальном тестировании через Chrome и Edge CDP наблюдалась блокировка:
```text
Sending form data to 'http://127.0.0.1:.../oauth/consent' violates the following Content Security Policy directive: "form-action 'self'". The request has been blocked.
```
По спецификации CSP3 браузеры семейства Chromium проверяют директиву `form-action` **не только на URL самой формы (`POST /oauth/consent`), но и на целевом URL HTTP 303 redirect** после отправки формы. Поскольку OAuth callback всегда ведёт на другой origin/схему (`https://claude.ai/...`, `http://localhost:<cb_port>/oauth/callback`, `vscode://...`), `form-action 'self'` блокировал редирект на стороне клиента **уже после того**, как одноразовый pending-тикет был удалён на сервере, что приводило к сбою авторизации и повторным ошибкам `Invalid request`.

Дополнительные причины:
- Ненормализованное сравнение заголовка `Origin` и `params.resource` (чувствительность к регистру/портам по умолчанию).
- Отсутствие проверки `Sec-Fetch-Site` и double-submit CSRF-токена.
- Минимальные текстовые ответы `403`/`410` на `/oauth/consent` без формы повторного ввода и сырой JSON на `/authorize` при ошибках браузерной навигации (например, после перезапуска с утерянным `client_id`).

### 2.2. Реализация (`backend/oauth_provider.py`, `backend/server.py`)
- **`consent_security_headers(redirect_uri)`**: для каждого `GET /oauth/consent` и ответа `303 RedirectResponse` динамически формируется `form-action 'self' <origin/scheme>`, включающий **только одного** валидированного клиента (`redirect_uri` из `PendingConsent`), с блокировкой опасных схем (`javascript`, `data`, `vbscript`, `blob`, `file`, `about`) и без подстановочного `*`.
- Канонизация `Origin` и `params.resource`, проверка `Sec-Fetch-Site in ("same-origin", "none")` и double-submit `csrf_token` (HttpOnly cookie `mcp_oauth_csrf` + скрытое поле формы).
- Понятные HTML-страницы ошибок (`_render_error_html`) при истечении ссылки (`410`), несовпадении безопасности (`403`), отзыве клиента (`403`), неверном токене владельца (inline retry-форма для попыток 1–4 из 5), а также перехват `400 JSON` на браузерном `GET /authorize` (`Accept: text/html`) в `HybridAuthMiddleware` с рендерингом понятной HTML-страницы («Reconnect in your AI client»).

### 2.3. Матрица живых браузерных E2E-тестов Playwright (`tests/e2e/test_oauth_browsers_playwright.py`)
| Браузер | Результат | Проверено |
|---|---|---|
| Playwright Chromium | **PASS** | DCR, `/authorize`, `/oauth/consent`, неверный токен (403 retry), верный токен -> cross-origin 303 callback (0 ошибок CSP), PKCE `/token`, MCP `initialize` + `tools/list`, Deny (`access_denied`), 410 expired, 400 HTML `/authorize`, 403 CSRF, отсутствие секретов в `oauth.log`/`errors.log` |
| Google Chrome (`channel="chrome"`) | **PASS** | Полный сценарий выше на установленном Chrome Windows 11 |
| Microsoft Edge (`channel="msedge"`) | **PASS** | Полный сценарий выше на установленном Edge Windows 11 |
| Playwright Firefox | **PASS** | Полный сценарий выше |

---

## 3. Оптимизация папки `_internal` и Windows-дистрибутива (`onedir`)

### 3.1. Сравнение ДО и ПОСЛЕ (`packaging/mcp_app.spec`)
| Метрика | ДО (Wave 1 `620fd21`) | ПОСЛЕ (Wave 2) | Изменение |
|---|---|---|---|
| `dist/MCPApp` (размер) | `177,618,802` B (`169.39 MB`) | `145,540,073` B (`138.80 MB`) | **-30.59 MB (-18.06%)** |
| `dist/MCPApp` (файлы / папки) | `324` файлов / `73` папки | `167` файлов / `63` папки | **-157 файлов / -10 папок** |
| `dist/MCPApp/_internal` (размер) | `168,162,115` B (`160.37 MB`) | `137,304,851` B (`130.94 MB`) | **-29.43 MB (-18.35%)** |
| `dist/MCPApp/_internal` (файлы / папки) | `323` файла / `72` папки | `166` файлов / `62` папки | **-157 файлов / -10 папок** |
| `MCPApp-1.0.0-portable.zip` | `70,316,210` B (`67.06 MB`) | `58,066,712` B (`55.38 MB`) | **-11.68 MB (-17.42%)** |

### 3.2. Что исключено и почему (без потери функциональности)
- `PyQt6/Qt6/bin/opengl32sw.dll` (`~20.6 MB`): программный OpenGL-рендерер, не используемый QWidgets-интерфейсом.
- Неиспользуемые локализации Qt (97 `.qm` файлов, оставлены только `qtbase_ru.qm` и `qtbase_en.qm`).
- Неиспользуемые плагины Qt: `qtuiotouchplugin.dll`, `qnetworklistmanager.dll`, `platforms/qminimal.dll`, `tls/qopensslbackend.dll`, `tls/qcertonlybackend.dll`, лишние `imageformats` (`qgif`, `qicns`, `qjpeg`, `qtga`, `qtiff`, `qwbmp`, `qwebp`). Сохранены `platforms/qwindows.dll`, `platforms/qoffscreen.dll`, `styles/qmodernwindowsstyle.dll`, `iconengines/qsvgicon.dll`, `imageformats/{qico,qsvg}.dll`, `tls/qschannelbackend.dll`.
- Дубликаты MSVC CRT DLL в `PyQt6/Qt6/bin/`, идентичные корневым файлам в `_internal`.
- Сборочные артефакты `*.dist-info/{INSTALLER,RECORD,REQUESTED,WHEEL,sboms/*}` при сохранении `METADATA`, `entry_points.txt`, `top_level.txt` и `licenses/`. Дополнительно добавлены явные `copy_metadata("mcp", "pydantic", "paramiko", "cryptography")` (что сразу закрыло обнаруженный новым `--selftest` пробел с отсутствием `mcp-*.dist-info`).
- Расширены `excludes` (`tkinter`, `unittest`, `pydoc_data`, `doctest`, `pdb`, `idlelib`, `setuptools`, `pkg_resources`, `pip`, `wheel`, `pytest`, `playwright`, неиспользуемые модули PyQt6) и фильтрация подмодулей `tests` в `uvicorn`/`mcp`.

### 3.3. Проверка собранного `dist\MCPApp\MCPApp.exe`
- `MCPApp.exe --selftest`: `RESULT OK` (`Qt 6.12.1`, `cloudflared 2026.11.2`, `Starlette`, `importlib.metadata`, динамический CSP, редактирование секрета в `LoggingManager`).
- `MCPApp.exe --run-extension`: динамический запуск официального расширения без ошибок импорта.
- `MCPApp.exe --headless`: `/health` = `200`, `/.well-known/oauth-authorization-server` = `200`, созданы все 15 файлов в `%MCP_LOGS_DIR%`.
- Запуск реального GUI (`MCPApp.exe` на живом дисплее Windows с изолированным `%APPDATA%`): процесс стабильно работает без ошибок OpenGL/DLL, создаёт все 15 файлов в `%APPDATA%\MCPApp\logs\`, токен в `app.log` замаскирован.

---

## 4. Централизованная система постоянного логирования (`app/core/logging_manager.py`, `app/core/diagnostics_bundle.py`)

- Каталог по умолчанию: `%APPDATA%\MCPApp\logs\` (`$MCP_LOGS_DIR` для изоляции в тестах/дочерних процессах).
- Все 15 компонентных журналов (`app`, `backend`, `tunnel`, `oauth`, `proxy`, `computer_use`, `gateway`, `tasks`, `servers`, `workspaces`, `extensions`, `ssh`, `automation`, `errors`, `crash`) + `archive/`.
- Межпроцессная файловая блокировка (`.write.lock`) с закрытием файловых дескрипторов до снятия блокировки (отсутствие `WinError 32` на Windows при параллельной записи из GUI и `--backend`).
- Автоматическая gzip-ротация (порог по умолчанию `10 МБ`, архив `archive/`, срок хранения `30 дней`, лимит каталога `200 МБ`, уровень по умолчанию `INFO`).
- Зеркалирование `ERROR`/`CRITICAL` в `errors.log` без бесконечного цикла, перехват `sys.excepthook` / `threading.excepthook` в `crash.log`.
- Неразрушающая миграция legacy `crash.log` и `server/mcp_audit.log` в `archive/` и сохранение защищённых `mcp_execution_audit.jsonl` и `desktop_policy_audit.jsonl` вне обычной ротации и очистки UI.
- Полное редактирование секретов (`SecretRedactor` — Bearer, Basic, `Proxy-Authorization`, `MCP_SECRET_TOKEN`, `TUNNEL_TOKEN`, `CLOUDFLARE_API_TOKEN`, `NGROK_AUTHTOKEN`, `code`, `code_verifier`, cookies, пароли в URL, base64-скриншоты) **до** записи на диск даже в режиме `DEBUG`.
- Переработанная вкладка **«Журналы»** (`LogViewerWidget` / `LogsPage`) и карточка настроек логирования в **«Настройках»** (`SettingsPage`), включая постраничную дозагрузку больших файлов (`read_tail_page`), счётчик ошибок, «Открыть папку логов», «Очистить» (без удаления security audit) и «Экспорт диагностики…» (ZIP без секретов, OAuth SQLite БД, скриншотов и документов).

---

## 5. Убраны лишние уведомления, 4 UI-провайдера и Loopback

- Полностью удалены toast о смене темы (`main_window.py`, `i18n.py`) и системное/popup уведомление при сворачивании в трей (`hidden_to_tray` удалён). Скрытие в трей, отчёт об ошибках и подтверждение Full Access полностью сохранены.
- На вкладке «Подключения» остались только 4 UI-провайдера (`Cloudflare Quick`, `Cloudflare Named`, `ngrok Agent`, `Tailscale Funnel`), без бейджей «Не найден / Установлен / Доступен», версий агентов и `Loopback` (отображается только минимальный бейдж `Активен` у выбранного провайдера).
- Внутренний loopback сохранён в backend (`LocalOnlyProvider` для Admin/headless/автотестов); legacy `local_only` и `openai_tunnel` безопасно мигрируют в `PROVIDER_NONE` («Транспорт не выбран») без автопубликации туннеля и с баннером на «Подключениях».

---

## 6. Свой домен (`Cloudflare Named Tunnel`), пользовательские токены и переключения провайдеров

- **Независимое хранение конфигов провайдеров**: исправлен сброс `public_url` и адреса домена при переключениях `Cloudflare Named -> Cloudflare Quick / ngrok / Tailscale -> Cloudflare Named` и после перезапуска (`ServiceManager._sync_named_provider_config()`, `Settings.sanitize()`, `domain_state.py`, `cloudflare.py`).
- **Два режима `DomainWizard`**:
  1. Автоматическая настройка по одноразовому Cloudflare API Token (токен не сохраняется; сохраняется полученный Tunnel Token в DPAPI).
  2. Подключение к существующему туннелю по **домену + Cloudflare Tunnel Token** (без API Token и без пересоздания DNS/туннеля, с фоновой проверкой доступности Cloudflare Edge и домена).
- **MCP Owner Token**: добавлена кнопка `Вставить` (`Paste`), ручной ввод/редактирование/показ-скрытие/копирование/генерация и явное текстовое разграничение `MCP Owner Token`, `Cloudflare API Token`, `Cloudflare Tunnel Token` и `ngrok Authtoken`.
- **Точная диагностика домена**: разделение `agent_missing`, `secret_decrypt_failed`, `domain_not_configured`, `domain_invalid`, `token_missing`, `token_invalid`.

---

## 7. Computer Use — `ToggleSwitch` и автосохранение

- 4 `QCheckBox` на `SecurityPage` заменены на анимированные `ToggleSwitch` (`app/ui/components/toggle_switch.py`), синхронизированные с Dark/Light темами.
- Удалена кнопка «Сохранить»; переключения тумблеров и завершение редактирования `allowed_clients` / `allowed_apps` немедленно и атомарно сохраняются через `DesktopPolicyStore.update()` (сохраняя `min_profile` и другие поля), применяются в live-режиме на сервере без перезапуска/переавторизации OAuth-клиентов и фиксируются в защищённом `desktop_policy_audit.jsonl` + `computer_use.log` без шумных toast-уведомлений. При ошибке записи интерфейс откатывается и показывает тихое предупреждение `SilentMessageBox.warning`.

---

## 8. Переработка системы прокси (`app/core/proxy.py`, `app/core/edge_relay.py`, `app/ui/proxy_page.py`)

- Удалено фейковое значение по умолчанию `socks5://127.0.0.1:1080`: по умолчанию активен режим `none` (прямое соединение), legacy-конфиги с выключенным `127.0.0.1:1080` мигрируют в `none`.
- **3 режима**: `none`, `auto` (проверка `ENV` с `NO_PROXY`, `WinINET`, `WinHTTP`, `PAC` и локальных VPN-портов с обязательным реальным handshake + подключением к цели + TLS вместо одной проверки открытого порта и **без тихого сброса на direct** при ошибке) и `manual` (`SOCKS5H`, `SOCKS5`, `HTTP CONNECT`, хост/порт/логин/пароль в DPAPI `SecretStore`).
- Честная обработка `ngrok` (поддерживает только `HTTP_PROXY`/`HTTPS_PROXY`, явное предупреждение при выборе SOCKS5) и `Tailscale` (использует системный демон без локального прокси-моста).

---

## 9. Артефакты сборки и контрольные суммы (локальная Windows 11 сборка)

- `dist/MCPApp/MCPApp.exe` + `dist/MCPApp/_internal/` (`onedir`)
- `dist/MCPApp-1.0.0-portable.zip`: `58,066,712` байт (`55.38 MB`), SHA-256 `e0179c034bbc614b30e4e56fa2176f73c3afc82a4c8e37db1b4295977c8d574e`
- `dist/SBOM.cdx.json`: `38` компонентов, SHA-256 `d8df93757538ce243c7311cbeca656601de525af0f831faa89f74401dc4931d6`
- `MCPApp-Setup-1.0.0.exe`: локально `iscc` не установлен, собирается и проверяется в GitHub Actions `windows-package`.

---

## 10. Оставшиеся `NOT_RUN` / `BLOCKED` проверки

- Внешние облачные/доменные живые прогоны, требующие ключей/аккаунтов/тарифов владельца (`Cloudflare Named` live API, `ngrok` аккаунт, `Tailscale Funnel` ACL, внешние клиенты ChatGPT/Claude/Gemini/Notion, `SLDWORKS.exe` COM).
- Доверенная подпись Authenticode (`.pfx`) и 72-часовой непрерывный soak-тест (`NOT_RUN`).
- Автоматический merge PR в `main` и публикация релиза не выполнялись без явного одобрения владельца (`AGENTS.md`).
