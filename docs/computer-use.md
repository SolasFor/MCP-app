# Computer Use (`v1.0.0` Wave 2)

MCP-app Computer Use enables AI clients to inspect and interact with the local interactive Windows 10/11 desktop session under strict owner opt-in controls (`%APPDATA%\MCPApp\desktop\policy.json`).

## Implementation & Zero Added Runtime Dependencies
- Uses native Windows APIs (`User32`, `GDI32`, `SendInput`, `Shcore.GetDpiForMonitor`, `OpenInputDesktop`, `UIAutomationCore.dll`), `pywin32`, `psutil`, and a pure-Python stdlib PNG encoder (`backend/desktop/png_codec.py`).
- Controlled in **Security** using animated theme-aware `ToggleSwitch` controls with **immediate atomic auto-save** (`DesktopPolicyStore.update()`, no manual Save button, no Stop Computer Use button, no noisy save toasts) and immediate live tool propagation via `notifications/tools/list_changed` without restarting the server or re-authorizing OAuth clients. When the master switch (`enabled`) is OFF, dependent toggles turn grey and disabled while preserving saved preferences across restarts and strictly blocking view/control/secret MCP tools; `allow_secret_typing` additionally requires `allow_input_control`. Save failures roll back UI state cleanly and show a silent warning.
- Every toggle and filter change is recorded in the tamper-resistant `desktop_policy_audit.jsonl` and `%APPDATA%\MCPApp\logs\computer_use.log`.

## Security & Privacy Boundaries (Fail-Closed)
- **Disabled by Default**: Master `enabled`, screen/UI capture (`allow_screen_capture`), window/input control (`allow_input_control`), and secret/password typing (`allow_secret_typing`) all default to `False`.
- **Visible Indicator & Internal Emergency Stop**: Whenever Computer Use is enabled (`VIEW` / `CONTROL`) or actively running a call, a visible indicator appears in the `MainWindow` top bar. Turning off the master Computer Use switch immediately disables all Computer Use MCP tools, while the internal emergency stop (`ServiceManager.emergency_stop` / `DesktopPolicyStore.set_emergency_stop`, plus **Emergency Stop** on Home and conditional **Clear Emergency Stop** on Security) remains preserved.
- **Locked Session, UAC & UIPI**: Fails closed on locked sessions, UAC/secure desktops (`OpenInputDesktop`), and elevated target windows; screenshots stay memory-only (never written to disk; redacted if logged).
