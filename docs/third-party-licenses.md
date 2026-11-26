# Сторонние компоненты и лицензии (MCP-app v0.8.6)

Проверка совместимости лицензий выполняется автоматически скриптом `tools/check_licenses.py`
по зафиксированному списку зависимостей `requirements.lock` и манифесту `packaging/cloudflared.json`.
Полный машиночитаемый перечень компонентов с версиями, PURL и лицензиями генерируется в `SBOM.cdx.json`
(`tools/generate_sbom.py`).

## Ключевые лицензионные обязательства

| Компонент | Версия | Лицензия | Примечание |
|---|---|---|---|
| `PyQt6` | `6.12.1` | `GPL-3.0-only` | GUI-оболочка; распространение собранного бинарника требует соблюдения условий GPLv3 |
| `PyQt6-Qt6` | `6.12.1` | `LGPL v3` | Qt6 runtime-библиотеки |
| `PyQt6_sip` | `13.13.1` | `BSD-2-Clause` | Связующий слой SIP |
| `paramiko` | `5.1.0` | `LGPL-2.1` | SSH-клиент |
| `cryptography` | `50.0.2` | `Apache-2.0 OR BSD-3-Clause` | Шифрование Fernet |
| `mcp`, `mcp-types` | `2.3.0` | `MIT` | Официальный MCP Python SDK |
| `uvicorn`, `starlette`, `httpx2`, `httpcore2`, `sse-starlette`, `psutil` | см. `requirements.lock` | `BSD-3-Clause` | HTTP-стек и системные метрики |
| `pydantic`, `anyio`, `PyJWT`, `jsonschema` | см. `requirements.lock` | `MIT` | Модели, async, JWT |
| `pywin32` (Windows) | `312` | `PSF` | Интеграция Win32 |
| `cloudflared` (`cloudflared-windows-amd64.exe`) | `2026.11.2` | `Apache-2.0` | Проверяется по SHA-256 и подписи Cloudflare |
