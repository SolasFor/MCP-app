# Computer Use (`v0.9.6`)

MCP-app Computer Use enables AI clients to inspect and interact with the local interactive Windows 10/11 desktop session under strict owner opt-in controls (`%APPDATA%\MCPApp\desktop\policy.json`).

## Implementation & Zero Added Runtime Dependencies
- Uses native Windows APIs (`User32`, `GDI32`, `SendInput`, `Shcore.GetDpiForMonitor`, `OpenInputDesktop`, `UIAutomationCore.dll` COM `IUIAutomation` / `InvokePattern` / `ValuePattern`), `pywin32`, `psutil`, and a pure-Python stdlib PNG encoder (`backend/desktop/png_codec.py`).
- No unreviewed screen-scraping packages or external binaries are required (`requirements.lock` stays at 38 license-audited components).

## Security & Privacy Boundaries (Fail-Closed)
- **Disabled by Default**: Master `enabled`, screen/UI capture (`allow_screen_capture`), window/input control (`allow_input_control`), and secret/password typing (`allow_secret_typing`) all default to `False`.
- **Visible Indicator & Local Stop**: Whenever Computer Use is enabled (`VIEW` / `CONTROL`) or actively running a call, a visible indicator appears in the `MainWindow` top bar. The owner can halt Computer Use locally from **Security -> Stop Computer Use** or via **Emergency Stop**.
- **Locked Session & UAC/Secure Desktop**: Before every operation, `check_session_state()` queries `OpenInputDesktop` + `GetUserObjectInformationW`. If the session is locked or on a non-`Default` desktop (such as UAC / Secure Desktop), every Computer Use call fails closed.
- **Elevated Windows (UIPI)**: Non-elevated MCP-app refuses to inspect screenshots/UI trees of, focus, or close elevated windows (`OpenProcessToken` / `TokenElevation`, or fail closed when `OpenProcess` returns `ERROR_ACCESS_DENIED`).
- **Secrets & Memory-Only Screenshots**: Screenshots are encoded to bounded PNG bytes (`<=1280px` width / `<=1.5 MB` by default) in RAM and returned via MCP `ImageContent`, never saved to disk. Password fields (`is_password=True`) are redacted in `desktop_get_ui_tree`, and typing registered secrets or into password fields is blocked unless `allow_secret_typing` is explicitly enabled.
- **Serialized Operations & CAD Preference**: All desktop actions execute under a serialization lock. For CAD tools (SolidWorks, КОМПАС-3D, Mathcad), specialized API/Gateway MCP tools remain preferred over UI clicks.
