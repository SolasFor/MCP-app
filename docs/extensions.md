# Расширения и SDK (v0.9.7 — Extensions)

## Архитектура и границы изоляции

- Каждое расширение запускается в **отдельном дочернем процессе ОС** с минимально очищенным окружением (`PYTHONPATH`, `MCP_EXTENSION_ID`, `MCP_EXTENSION_DATA_DIR`), собственным рабочим каталогом `data/<id>` и обменом по **newline-delimited JSON-RPC 2.0 (stdio)**.
- В собранном Windows-приложении `MCPApp.exe` запуск идёт через `MCPApp.exe --run-extension <entrypoint.py>` (без окна консоли `CREATE_NO_WINDOW`).
- **Честная граница изоляции:** отдельный процесс защищает ядро MCP-app от падений расширения, утечки токенов OAuth ядра и несанкционированных секретов других расширений, но **не является OS-песочницей** против вредоносного кода, запущенного под тем же пользователем Windows/POSIX. Поэтому автоустановки из недоверенных источников запрещены.

## Проверка пакетов (Ed25519 / SHA-256)

1. При установке/обновлении из `.zip` проверяются:
   - запрет path traversal (`..`), абсолютных путей, UNC/дисковых префиксов и symlink-записей;
   - лимиты на число файлов (`<= 200`) и распакованный размер (`<= 25 MB`);
   - валидность `manifest.json` и совместимость `api_version` с SDK (`1.0 .. 1.2`);
   - доверие (fail-closed): либо **Ed25519-подпись** (`CHECKSUMS.sha256` + `SIGNATURE.ed25519`) от ключа из `trusted_keys.json`, либо явный **SHA-256 пин** + подтверждение владельца.
2. Перед обновлением (`update_zip`) текущая версия копируется в `backups/<id>/<version>`, а каталог `data/<id>` сохраняется при отключении, обновлении и откате (`rollback`).

## Минимальный пример SDK (`extensions_official/starter_template`)

```python
from backend.extensions.sdk import ExtensionApp

app = ExtensionApp("my_extension", "1.0.0")

@app.tool("hello", description="Simple health check")
def hello(name: str = "world") -> dict:
    return {"greeting": f"Hello, {name}", "data_dir": str(app.data_dir)}

if __name__ == "__main__":
    raise SystemExit(app.run_stdio())
```

## Официальные расширения

- `system_monitor` (`extensions_official/system_monitor`): метрики CPU/RAM/диска и топ процессов через `psutil`.
- `git_manager` (`extensions_official/git_manager`): безопасный read-only статус и журнал Git с подавлением hooks (`core.hooksPath=`, `core.fsmonitor=false`).
- `docker_manager` (`extensions_official/docker_manager`): честная проверка наличия Docker CLI/daemon и список контейнеров.
- `browser_automation` (`extensions_official/browser_automation`): проверка `http`/`https` URL, отдельные профили браузера внутри `data/browser_automation/profiles/`.
- CAD (`SolidWorks`, `КОМПАС-3D`, `Mathcad`) и `Database Manager` в базовую поставку не входят (опциональны при наличии локального API/лицензии; SolidWorks поддерживается через Gateway preset).

## OAuth-инструменты

- `allowlist`: `extension_list`, `extension_info`, `extension_call_tool` (для read-only инструментов или явно одобренных `approved_tools`), `extension_logs`.
- `full`: дополнительно `extension_enable`, `extension_disable`.
- `safe`: доступ к инструментам расширений запрещён.
