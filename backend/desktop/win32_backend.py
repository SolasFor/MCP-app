"""Windows interactive desktop backend: Win32 GDI/User32, SendInput, DPI, and native UIA COM."""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any

import psutil

from backend.desktop.backend_base import DesktopBackend
from backend.desktop.models import (
    MAX_SCREENSHOT_BYTES,
    MAX_UI_TREE_DEPTH,
    MAX_UI_TREE_NODES,
    MonitorInfo,
    ScreenshotResult,
    SessionState,
    UIElementNode,
    WindowInfo,
)
from backend.desktop.png_codec import encode_bgra_to_png

_CLSID_CUIAUTOMATION = "{ff48dba4-60ef-4201-aa87-54103eef594e}"
_IID_IUIAUTOMATION = "{30cbe57d-d9d0-452a-ab13-7ac5ac4825ee}"
_IID_INVOKE_PATTERN = "{fb377fbe-8ea6-46d5-9c73-6499642d3059}"
_IID_VALUE_PATTERN = "{a94cd8b1-0844-4cd6-9d2d-640537ab39e9}"

_UIA_INVOKE_PATTERN_ID = 10000
_UIA_VALUE_PATTERN_ID = 10002

_CONTROL_TYPE_NAMES: dict[int, str] = {
    50000: "Button",
    50001: "Calendar",
    50002: "CheckBox",
    50003: "ComboBox",
    50004: "Edit",
    50005: "Hyperlink",
    50006: "Image",
    50007: "ListItem",
    50008: "List",
    50009: "Menu",
    50010: "MenuBar",
    50011: "MenuItem",
    50012: "ProgressBar",
    50013: "RadioButton",
    50014: "ScrollBar",
    50015: "Slider",
    50016: "Spinner",
    50017: "StatusBar",
    50018: "Tab",
    50019: "TabItem",
    50020: "Text",
    50021: "ToolBar",
    50022: "ToolTip",
    50023: "Tree",
    50024: "TreeItem",
    50025: "Custom",
    50026: "Group",
    50027: "Thumb",
    50028: "DataGrid",
    50029: "DataItem",
    50030: "Document",
    50031: "SplitButton",
    50032: "Window",
    50033: "Pane",
    50034: "Header",
    50035: "HeaderItem",
    50036: "Table",
    50037: "TitleBar",
    50038: "Separator",
}

_VK_MAP: dict[str, int] = {
    "BACKSPACE": 0x08,
    "TAB": 0x09,
    "ENTER": 0x0D,
    "RETURN": 0x0D,
    "SHIFT": 0x10,
    "CTRL": 0x11,
    "CONTROL": 0x11,
    "ALT": 0x12,
    "MENU": 0x12,
    "PAUSE": 0x13,
    "CAPSLOCK": 0x14,
    "ESC": 0x1B,
    "ESCAPE": 0x1B,
    "SPACE": 0x20,
    "PAGEUP": 0x21,
    "PGUP": 0x21,
    "PAGEDOWN": 0x22,
    "PGDN": 0x22,
    "END": 0x23,
    "HOME": 0x24,
    "LEFT": 0x25,
    "UP": 0x26,
    "RIGHT": 0x27,
    "DOWN": 0x28,
    "INSERT": 0x2D,
    "DEL": 0x2E,
    "DELETE": 0x2E,
    "WIN": 0x5B,
    "LWIN": 0x5B,
    **{f"F{i}": 0x6F + i for i in range(1, 13)},
}


def normalize_virtual_coords(x: int, y: int, vx: int, vy: int, vw: int, vh: int) -> tuple[int, int]:
    """Normalize screen coordinates `(x, y)` onto Windows SendInput `[0..65535]` virtual desktop range."""
    safe_w = max(2, int(vw))
    safe_h = max(2, int(vh))
    nx = int(round(((int(x) - int(vx)) * 65535) / (safe_w - 1)))
    ny = int(round(((int(y) - int(vy)) * 65535) / (safe_h - 1)))
    return max(0, min(65535, nx)), max(0, min(65535, ny))


def _vtable_fn(ptr: int, slot: int, restype: Any, *argtypes: Any) -> Any:
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
    fn_ptr = ctypes.cast(vtbl, ctypes.POINTER(ctypes.c_void_p))[slot]
    proto = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(restype, ctypes.c_void_p, *argtypes)
    return proto(fn_ptr)


def _release_com(ptr: ctypes.c_void_p | int | None) -> None:
    addr = ptr.value if isinstance(ptr, ctypes.c_void_p) else ptr
    if not addr:
        return
    try:
        rel = _vtable_fn(int(addr), 2, ctypes.c_ulong)
        rel(int(addr))
    except Exception:  # noqa: BLE001
        pass


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("union", _INPUT_UNION)]


class _MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
        ("szDevice", wintypes.WCHAR * 32),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


class Win32DesktopBackend(DesktopBackend):
    """Native Windows desktop automation backend (User32/GDI32/SendInput/UIAutomation COM)."""

    def __init__(self) -> None:
        win_dll_cls = getattr(ctypes, "WinDLL", None)
        windll = getattr(ctypes, "windll", None)
        if sys.platform != "win32" or (win_dll_cls is None and windll is None):
            raise RuntimeError("Win32DesktopBackend is only supported on Windows")
        if win_dll_cls is not None:
            self._u32: Any = win_dll_cls("user32", use_last_error=True)
            self._gdi32: Any = win_dll_cls("gdi32", use_last_error=True)
            self._k32: Any = win_dll_cls("kernel32", use_last_error=True)
            self._adv: Any = win_dll_cls("advapi32", use_last_error=True)
            self._ole32: Any = win_dll_cls("ole32")
            self._oleaut32: Any = win_dll_cls("oleaut32")
            try:
                self._shcore: Any = win_dll_cls("shcore")
            except OSError:
                self._shcore = None
        else:
            assert windll is not None
            self._u32 = windll.user32
            self._gdi32 = windll.gdi32
            self._k32 = windll.kernel32
            self._adv = windll.advapi32
            self._ole32 = windll.ole32
            self._oleaut32 = windll.oleaut32
            self._shcore = getattr(windll, "shcore", None)
        self._configure_prototypes()
        self._ensure_dpi_awareness()

    def _configure_prototypes(self) -> None:
        p = ctypes.c_void_p
        cb = ctypes.POINTER
        self._u32.SetProcessDpiAwarenessContext.argtypes = [p]
        self._u32.SetProcessDpiAwarenessContext.restype = ctypes.c_int
        self._u32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._u32.OpenInputDesktop.restype = p
        self._u32.CloseDesktop.argtypes = [p]
        self._u32.CloseDesktop.restype = wintypes.BOOL
        self._u32.GetUserObjectInformationW.argtypes = [p, ctypes.c_int, p, wintypes.DWORD, cb(wintypes.DWORD)]
        self._u32.GetUserObjectInformationW.restype = wintypes.BOOL
        self._u32.GetWindowThreadProcessId.argtypes = [p, cb(wintypes.DWORD)]
        self._u32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self._u32.GetMonitorInfoW.argtypes = [p, p]
        self._u32.GetMonitorInfoW.restype = wintypes.BOOL
        self._u32.EnumDisplayMonitors.argtypes = [p, p, p, wintypes.LPARAM]
        self._u32.EnumDisplayMonitors.restype = wintypes.BOOL
        self._u32.GetForegroundWindow.argtypes = []
        self._u32.GetForegroundWindow.restype = p
        self._u32.IsWindowVisible.argtypes = [p]
        self._u32.IsWindowVisible.restype = wintypes.BOOL
        self._u32.IsIconic.argtypes = [p]
        self._u32.IsIconic.restype = wintypes.BOOL
        self._u32.GetWindowTextLengthW.argtypes = [p]
        self._u32.GetWindowTextLengthW.restype = ctypes.c_int
        self._u32.GetWindowTextW.argtypes = [p, ctypes.c_wchar_p, ctypes.c_int]
        self._u32.GetWindowTextW.restype = ctypes.c_int
        self._u32.GetClassNameW.argtypes = [p, ctypes.c_wchar_p, ctypes.c_int]
        self._u32.GetClassNameW.restype = ctypes.c_int
        self._u32.GetWindowRect.argtypes = [p, cb(wintypes.RECT)]
        self._u32.GetWindowRect.restype = wintypes.BOOL
        self._u32.EnumWindows.argtypes = [p, wintypes.LPARAM]
        self._u32.EnumWindows.restype = wintypes.BOOL
        self._u32.GetSystemMetrics.argtypes = [ctypes.c_int]
        self._u32.GetSystemMetrics.restype = ctypes.c_int
        self._u32.GetDC.argtypes = [p]
        self._u32.GetDC.restype = p
        self._u32.GetWindowDC.argtypes = [p]
        self._u32.GetWindowDC.restype = p
        self._u32.ReleaseDC.argtypes = [p, p]
        self._u32.ReleaseDC.restype = ctypes.c_int
        self._u32.PrintWindow.argtypes = [p, p, wintypes.UINT]
        self._u32.PrintWindow.restype = wintypes.BOOL
        self._u32.IsWindow.argtypes = [p]
        self._u32.IsWindow.restype = wintypes.BOOL
        self._u32.PostMessageW.argtypes = [p, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        self._u32.PostMessageW.restype = wintypes.BOOL
        self._u32.ShowWindow.argtypes = [p, ctypes.c_int]
        self._u32.ShowWindow.restype = wintypes.BOOL
        self._u32.SetForegroundWindow.argtypes = [p]
        self._u32.SetForegroundWindow.restype = wintypes.BOOL
        self._u32.MoveWindow.argtypes = [p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.BOOL]
        self._u32.MoveWindow.restype = wintypes.BOOL
        self._u32.SendInput.argtypes = [wintypes.UINT, p, ctypes.c_int]
        self._u32.SendInput.restype = wintypes.UINT

        self._gdi32.CreateCompatibleDC.argtypes = [p]
        self._gdi32.CreateCompatibleDC.restype = p
        self._gdi32.CreateCompatibleBitmap.argtypes = [p, ctypes.c_int, ctypes.c_int]
        self._gdi32.CreateCompatibleBitmap.restype = p
        self._gdi32.SelectObject.argtypes = [p, p]
        self._gdi32.SelectObject.restype = p
        self._gdi32.BitBlt.argtypes = [
            p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, p, ctypes.c_int, ctypes.c_int, wintypes.DWORD
        ]
        self._gdi32.BitBlt.restype = wintypes.BOOL
        self._gdi32.GetDIBits.argtypes = [p, p, wintypes.UINT, wintypes.UINT, p, p, wintypes.UINT]
        self._gdi32.GetDIBits.restype = ctypes.c_int
        self._gdi32.DeleteObject.argtypes = [p]
        self._gdi32.DeleteObject.restype = wintypes.BOOL
        self._gdi32.DeleteDC.argtypes = [p]
        self._gdi32.DeleteDC.restype = wintypes.BOOL

        self._k32.GetCurrentProcess.argtypes = []
        self._k32.GetCurrentProcess.restype = p
        self._k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._k32.OpenProcess.restype = p
        self._k32.CloseHandle.argtypes = [p]
        self._k32.CloseHandle.restype = wintypes.BOOL

        self._adv.OpenProcessToken.argtypes = [p, wintypes.DWORD, cb(p)]
        self._adv.OpenProcessToken.restype = wintypes.BOOL
        self._adv.GetTokenInformation.argtypes = [p, ctypes.c_int, p, wintypes.DWORD, cb(wintypes.DWORD)]
        self._adv.GetTokenInformation.restype = wintypes.BOOL

        self._ole32.CoInitializeEx.argtypes = [p, wintypes.DWORD]
        self._ole32.CoInitializeEx.restype = ctypes.c_long
        self._ole32.CoCreateInstance.argtypes = [ctypes.c_char_p, p, wintypes.DWORD, ctypes.c_char_p, cb(p)]
        self._ole32.CoCreateInstance.restype = ctypes.c_long

        self._oleaut32.SysAllocString.argtypes = [ctypes.c_wchar_p]
        self._oleaut32.SysAllocString.restype = p
        self._oleaut32.SysFreeString.argtypes = [p]
        self._oleaut32.SysFreeString.restype = None

        if self._shcore is not None:
            self._shcore.GetDpiForMonitor.argtypes = [p, ctypes.c_int, cb(wintypes.UINT), cb(wintypes.UINT)]
            self._shcore.GetDpiForMonitor.restype = ctypes.c_long

    def _ensure_dpi_awareness(self) -> None:
        try:
            # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
            self._u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _current_process_elevated(k32: Any, adv: Any) -> bool:
        tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
            return False
        try:
            elev = wintypes.DWORD(0)
            ret = wintypes.DWORD(0)
            if adv.GetTokenInformation(tok, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret)):
                return bool(elev.value)
            return False
        finally:
            k32.CloseHandle(tok)

    def check_session_state(self) -> SessionState:
        hdesk = self._u32.OpenInputDesktop(0, False, 0x0001)
        if not hdesk:
            return SessionState(
                interactive=False,
                locked=True,
                secure_desktop=True,
                desktop_name="",
                reason="Interactive input desktop unavailable or session is locked",
            )
        try:
            buf = ctypes.create_unicode_buffer(256)
            needed = wintypes.DWORD(0)
            ok = self._u32.GetUserObjectInformationW(hdesk, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed))
            name = buf.value if ok else ""
            is_default = name.casefold() == "default"
            return SessionState(
                interactive=is_default,
                locked=not is_default,
                secure_desktop=not is_default,
                desktop_name=name,
                reason="" if is_default else f"Active desktop is {name!r} (not Default interactive session)",
            )
        finally:
            self._u32.CloseDesktop(hdesk)

    def is_window_elevated(self, hwnd: int) -> bool:
        pid = wintypes.DWORD(0)
        self._u32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid))
        if not pid.value:
            return True
        proc_handle = self._k32.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not proc_handle:
            # Fail closed when target process refuses query (e.g. elevated/PPL UIPI boundary)
            return True
        try:
            tok = wintypes.HANDLE()
            if not self._adv.OpenProcessToken(proc_handle, 0x0008, ctypes.byref(tok)):
                return True
            try:
                elev = wintypes.DWORD(0)
                ret = wintypes.DWORD(0)
                if not self._adv.GetTokenInformation(tok, 20, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(ret)):
                    return True
                target_elevated = bool(elev.value)
                self_elevated = self._current_process_elevated(self._k32, self._adv)
                return target_elevated and not self_elevated
            finally:
                self._k32.CloseHandle(tok)
        finally:
            self._k32.CloseHandle(proc_handle)

    def list_monitors(self) -> list[MonitorInfo]:
        monitors: list[MonitorInfo] = []
        cb_type = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(
            wintypes.BOOL,
            wintypes.HMONITOR,
            wintypes.HDC,
            ctypes.POINTER(wintypes.RECT),
            wintypes.LPARAM,
        )

        def callback(hmon: int, _hdc: int, _rect: Any, _data: int) -> bool:
            info = _MONITORINFOEXW()
            info.cbSize = ctypes.sizeof(_MONITORINFOEXW)
            if self._u32.GetMonitorInfoW(wintypes.HMONITOR(hmon), ctypes.byref(info)):
                dpi_x = wintypes.UINT(96)
                dpi_y = wintypes.UINT(96)
                if self._shcore is not None:
                    try:
                        self._shcore.GetDpiForMonitor(wintypes.HMONITOR(hmon), 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y))
                    except Exception:  # noqa: BLE001
                        pass
                rm = info.rcMonitor
                rw = info.rcWork
                idx = len(monitors)
                monitors.append(
                    MonitorInfo(
                        index=idx,
                        name=str(info.szDevice or f"DISPLAY{idx + 1}"),
                        primary=bool(info.dwFlags & 1),
                        x=int(rm.left),
                        y=int(rm.top),
                        width=int(rm.right - rm.left),
                        height=int(rm.bottom - rm.top),
                        work_x=int(rw.left),
                        work_y=int(rw.top),
                        work_width=int(rw.right - rw.left),
                        work_height=int(rw.bottom - rw.top),
                        dpi_x=int(dpi_x.value or 96),
                        dpi_y=int(dpi_y.value or 96),
                    )
                )
            return True

        self._u32.EnumDisplayMonitors(None, None, cb_type(callback), 0)
        return monitors

    def list_windows(self, *, include_minimized: bool = False) -> list[WindowInfo]:
        windows: list[WindowInfo] = []
        fg_hwnd = int(self._u32.GetForegroundWindow() or 0)
        cb_type = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )

        def callback(hwnd: int, _lparam: int) -> bool:
            if not self._u32.IsWindowVisible(wintypes.HWND(hwnd)):
                return True
            minimized = bool(self._u32.IsIconic(wintypes.HWND(hwnd)))
            if minimized and not include_minimized:
                return True
            length = int(self._u32.GetWindowTextLengthW(wintypes.HWND(hwnd)))
            if length <= 0:
                return True
            title_buf = ctypes.create_unicode_buffer(length + 2)
            self._u32.GetWindowTextW(wintypes.HWND(hwnd), title_buf, len(title_buf))
            title = title_buf.value.strip()
            if not title:
                return True
            cls_buf = ctypes.create_unicode_buffer(256)
            self._u32.GetClassNameW(wintypes.HWND(hwnd), cls_buf, 256)
            rect = wintypes.RECT()
            self._u32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect))
            w = int(rect.right - rect.left)
            h = int(rect.bottom - rect.top)
            if not minimized and (w <= 0 or h <= 0):
                return True
            pid = wintypes.DWORD(0)
            self._u32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(pid))
            proc_name = ""
            if pid.value:
                try:
                    proc_name = psutil.Process(int(pid.value)).name()
                except psutil.Error:
                    proc_name = ""
            windows.append(
                WindowInfo(
                    hwnd=int(hwnd),
                    title=title,
                    class_name=cls_buf.value,
                    pid=int(pid.value),
                    process_name=proc_name,
                    x=int(rect.left),
                    y=int(rect.top),
                    width=w,
                    height=h,
                    minimized=minimized,
                    active=(int(hwnd) == fg_hwnd),
                    elevated=self.is_window_elevated(int(hwnd)),
                )
            )
            return True

        self._u32.EnumWindows(cb_type(callback), 0)
        return windows

    def capture_screenshot(
        self,
        *,
        monitor_index: int | None = None,
        hwnd: int | None = None,
        max_width: int = 1280,
        max_bytes: int = MAX_SCREENSHOT_BYTES,
    ) -> ScreenshotResult:
        monitors = self.list_monitors()
        scale_pct = monitors[0].scale_percent if monitors else 100
        source = "virtual_desktop"
        if hwnd is not None:
            rect = wintypes.RECT()
            if not self._u32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect)):
                raise ValueError(f"Unknown window handle: {hwnd}")
            vx, vy = int(rect.left), int(rect.top)
            vw, vh = int(rect.right - rect.left), int(rect.bottom - rect.top)
            source = "window"
        elif monitor_index is not None:
            if not (0 <= monitor_index < len(monitors)):
                raise ValueError(f"Invalid monitor_index: {monitor_index}")
            m = monitors[monitor_index]
            vx, vy, vw, vh = m.x, m.y, m.width, m.height
            scale_pct = m.scale_percent
            source = f"monitor:{monitor_index}"
        else:
            vx = int(self._u32.GetSystemMetrics(76))
            vy = int(self._u32.GetSystemMetrics(77))
            vw = int(self._u32.GetSystemMetrics(78))
            vh = int(self._u32.GetSystemMetrics(79))

        if vw <= 0 or vh <= 0:
            raise RuntimeError("Target capture region has zero area")

        hdc_target = self._u32.GetWindowDC(wintypes.HWND(hwnd)) if hwnd is not None else 0
        hdc_screen = hdc_target or self._u32.GetDC(None)
        if not hdc_screen:
            raise RuntimeError("GetDC failed")
        hdc_mem = self._gdi32.CreateCompatibleDC(hdc_screen)
        hbmp = self._gdi32.CreateCompatibleBitmap(hdc_screen, vw, vh)
        old_obj = None
        try:
            old_obj = self._gdi32.SelectObject(hdc_mem, hbmp)
            captured = False
            if hwnd is not None:
                # PW_RENDERFULLCONTENT = 2 captures hardware-accelerated / DWM / off-thread windows cleanly.
                captured = bool(self._u32.PrintWindow(wintypes.HWND(hwnd), hdc_mem, 2))
                if not captured:
                    captured = bool(self._u32.PrintWindow(wintypes.HWND(hwnd), hdc_mem, 0))
                if not captured and hdc_target:
                    captured = bool(self._gdi32.BitBlt(hdc_mem, 0, 0, vw, vh, hdc_target, 0, 0, 0x00CC0020))
            if not captured:
                src_dc = hdc_screen if hwnd is None else self._u32.GetDC(None)
                if not src_dc:
                    raise RuntimeError("GetDC failed")
                try:
                    if not self._gdi32.BitBlt(hdc_mem, 0, 0, vw, vh, src_dc, vx, vy, 0x00CC0020):
                        err = getattr(ctypes, "get_last_error", lambda: 0)()
                        raise RuntimeError(f"BitBlt screen capture failed (err={err})")
                finally:
                    if hwnd is not None and src_dc != hdc_screen:
                        self._u32.ReleaseDC(None, src_dc)
            bmi = _BITMAPINFO()
            bmi.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = vw
            bmi.bmiHeader.biHeight = -vh  # top-down DIB
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0  # BI_RGB
            buf = ctypes.create_string_buffer(vw * vh * 4)
            lines = self._gdi32.GetDIBits(hdc_mem, hbmp, 0, vh, buf, ctypes.byref(bmi), 0)
            if not lines:
                raise RuntimeError("GetDIBits failed")
            png_bytes, out_w, out_h = encode_bgra_to_png(
                buf.raw, vw, vh, max_width=max_width, max_bytes=max_bytes
            )
            return ScreenshotResult(
                png_bytes=png_bytes,
                width=out_w,
                height=out_h,
                scale_percent=scale_pct,
                source=source,
                monitor_index=monitor_index,
                hwnd=hwnd,
            )
        finally:
            if old_obj:
                self._gdi32.SelectObject(hdc_mem, old_obj)
            if hbmp:
                self._gdi32.DeleteObject(hbmp)
            if hdc_mem:
                self._gdi32.DeleteDC(hdc_mem)
            self._u32.ReleaseDC(wintypes.HWND(hwnd) if hdc_target else None, hdc_screen)

    def open_app(
        self,
        executable: str,
        args: tuple[str, ...] = (),
        cwd: str = "",
    ) -> dict[str, Any]:
        exe_path = Path(executable)
        if not exe_path.is_absolute() or not exe_path.is_file():
            raise ValueError("Use an existing absolute executable path")
        if exe_path.suffix.lower() != ".exe":
            raise ValueError("Use a direct .exe executable")
        work_dir = Path(cwd) if cwd else exe_path.parent
        if not work_dir.is_dir():
            raise ValueError("Working directory does not exist")
        proc = subprocess.Popen(
            [str(exe_path), *args],
            cwd=str(work_dir),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
        )
        return {"pid": proc.pid, "executable": str(exe_path)}

    def close_window(self, hwnd: int) -> bool:
        if not self._u32.IsWindow(wintypes.HWND(hwnd)):
            raise ValueError(f"Window {hwnd} does not exist")
        # WM_CLOSE = 0x0010
        return bool(self._u32.PostMessageW(wintypes.HWND(hwnd), 0x0010, 0, 0))

    def focus_window(
        self,
        hwnd: int,
        *,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> WindowInfo:
        if not self._u32.IsWindow(wintypes.HWND(hwnd)):
            raise ValueError(f"Window {hwnd} does not exist")
        if self._u32.IsIconic(wintypes.HWND(hwnd)):
            self._u32.ShowWindow(wintypes.HWND(hwnd), 9)  # SW_RESTORE
        self._u32.SetForegroundWindow(wintypes.HWND(hwnd))
        if any(v is not None for v in (x, y, width, height)):
            cur = wintypes.RECT()
            self._u32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(cur))
            nx = int(cur.left if x is None else x)
            ny = int(cur.top if y is None else y)
            nw = int((cur.right - cur.left) if width is None else width)
            nh = int((cur.bottom - cur.top) if height is None else height)
            self._u32.MoveWindow(wintypes.HWND(hwnd), nx, ny, max(60, nw), max(40, nh), True)
        for win in self.list_windows(include_minimized=True):
            if win.hwnd == hwnd:
                return win
        raise ValueError(f"Window {hwnd} is no longer available")

    # ------------------------------ Native UIAutomation COM helpers ------------------------------
    def _create_uia(self) -> int:
        # COINIT_APARTMENTTHREADED = 2
        self._ole32.CoInitializeEx(None, 2)
        clsid = uuid.UUID(_CLSID_CUIAUTOMATION).bytes_le
        iid = uuid.UUID(_IID_IUIAUTOMATION).bytes_le
        ptr = ctypes.c_void_p()
        hr = int(self._ole32.CoCreateInstance(clsid, None, 1, iid, ctypes.byref(ptr)))
        if hr < 0 or not ptr.value:
            raise RuntimeError(f"Failed to instantiate IUIAutomation COM (hr={hr:#x})")
        return int(ptr.value)

    def _bstr_to_str(self, bstr_ptr: ctypes.c_void_p) -> str:
        if not bstr_ptr.value:
            return ""
        try:
            return ctypes.wstring_at(bstr_ptr.value)
        finally:
            self._oleaut32.SysFreeString(bstr_ptr)

    def _read_element_node(
        self,
        elem_ptr: int,
        walker_ptr: int,
        *,
        depth: int,
        max_depth: int,
        budget: list[int],
    ) -> UIElementNode:
        budget[0] -= 1

        def get_int(slot: int, default: int = 0) -> int:
            out = ctypes.c_int(default)
            fn = _vtable_fn(elem_ptr, slot, ctypes.c_long, ctypes.POINTER(ctypes.c_int))
            hr = fn(elem_ptr, ctypes.byref(out))
            return int(out.value) if hr == 0 else default

        def get_bstr(slot: int) -> str:
            out = ctypes.c_void_p()
            fn = _vtable_fn(elem_ptr, slot, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
            hr = fn(elem_ptr, ctypes.byref(out))
            return self._bstr_to_str(out) if hr == 0 else ""

        pid = get_int(20, 0)
        ctype_id = get_int(21, 0)
        ctype_name = _CONTROL_TYPE_NAMES.get(ctype_id, f"Control({ctype_id})")
        name = get_bstr(23)
        enabled = bool(get_int(28, 1))
        auto_id = get_bstr(29)
        cls_name = get_bstr(30)
        is_pwd = bool(get_int(35, 0))
        native_hwnd = 0
        out_hwnd = ctypes.c_void_p()
        try:
            fn_h = _vtable_fn(elem_ptr, 36, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
            if fn_h(elem_ptr, ctypes.byref(out_hwnd)) == 0 and out_hwnd.value:
                native_hwnd = int(out_hwnd.value)
        except Exception:  # noqa: BLE001
            pass
        offscreen = bool(get_int(38, 0))
        rect = wintypes.RECT()
        fn_r = _vtable_fn(elem_ptr, 43, ctypes.c_long, ctypes.POINTER(wintypes.RECT))
        bounds = {"x": 0, "y": 0, "width": 0, "height": 0}
        if fn_r(elem_ptr, ctypes.byref(rect)) == 0:
            bounds = {
                "x": int(rect.left),
                "y": int(rect.top),
                "width": max(0, int(rect.right - rect.left)),
                "height": max(0, int(rect.bottom - rect.top)),
            }

        children: list[UIElementNode] = []
        if depth < max_depth and budget[0] > 0:
            get_first = _vtable_fn(walker_ptr, 4, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
            get_next = _vtable_fn(walker_ptr, 6, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
            child_ptr = ctypes.c_void_p()
            if get_first(walker_ptr, elem_ptr, ctypes.byref(child_ptr)) == 0 and child_ptr.value:
                cur_child: int | None = int(child_ptr.value)
                while cur_child and budget[0] > 0:
                    children.append(
                        self._read_element_node(
                            cur_child,
                            walker_ptr,
                            depth=depth + 1,
                            max_depth=max_depth,
                            budget=budget,
                        )
                    )
                    nxt_ptr = ctypes.c_void_p()
                    hr_n = get_next(walker_ptr, cur_child, ctypes.byref(nxt_ptr))
                    _release_com(cur_child)
                    cur_child = int(nxt_ptr.value) if (hr_n == 0 and nxt_ptr.value) else None
                if cur_child:
                    _release_com(cur_child)

        return UIElementNode(
            control_type=ctype_name,
            name="" if is_pwd else name,
            automation_id=auto_id,
            class_name=cls_name,
            bounds=bounds,
            enabled=enabled,
            offscreen=offscreen,
            is_password=is_pwd,
            hwnd=native_hwnd,
            pid=pid,
            children=tuple(children),
        )

    def _find_raw_element(
        self,
        elem_ptr: int,
        walker_ptr: int,
        *,
        name: str,
        automation_id: str,
        control_type: str,
        budget: list[int],
    ) -> tuple[int | None, dict[str, Any] | None]:
        """Search subtree returning AddRef'd matched COM pointer (caller must release) + metadata."""
        if budget[0] <= 0:
            return None, None
        budget[0] -= 1

        def get_int(slot: int, default: int = 0) -> int:
            out = ctypes.c_int(default)
            fn = _vtable_fn(elem_ptr, slot, ctypes.c_long, ctypes.POINTER(ctypes.c_int))
            return int(out.value) if fn(elem_ptr, ctypes.byref(out)) == 0 else default

        def get_bstr(slot: int) -> str:
            out = ctypes.c_void_p()
            fn = _vtable_fn(elem_ptr, slot, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
            return self._bstr_to_str(out) if fn(elem_ptr, ctypes.byref(out)) == 0 else ""

        ctype_name = _CONTROL_TYPE_NAMES.get(get_int(21, 0), "")
        cur_name = get_bstr(23)
        cur_auto = get_bstr(29)
        is_pwd = bool(get_int(35, 0))
        enabled = bool(get_int(28, 1))
        rect = wintypes.RECT()
        fn_r = _vtable_fn(elem_ptr, 43, ctypes.c_long, ctypes.POINTER(wintypes.RECT))
        bounds = {"x": 0, "y": 0, "width": 0, "height": 0}
        if fn_r(elem_ptr, ctypes.byref(rect)) == 0:
            bounds = {
                "x": int(rect.left),
                "y": int(rect.top),
                "width": max(0, int(rect.right - rect.left)),
                "height": max(0, int(rect.bottom - rect.top)),
            }

        matches = True
        if automation_id and cur_auto.casefold() != automation_id.casefold():
            matches = False
        if name and cur_name.casefold() != name.casefold():
            matches = False
        if control_type and ctype_name.casefold() != control_type.casefold():
            matches = False

        if matches and (automation_id or name or control_type):
            addref = _vtable_fn(elem_ptr, 1, ctypes.c_ulong)
            addref(elem_ptr)
            return elem_ptr, {
                "control_type": ctype_name,
                "name": "[REDACTED PASSWORD FIELD]" if is_pwd else cur_name,
                "automation_id": cur_auto,
                "bounds": bounds,
                "enabled": enabled,
                "is_password": is_pwd,
            }

        get_first = _vtable_fn(walker_ptr, 4, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
        get_next = _vtable_fn(walker_ptr, 6, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
        child_ptr = ctypes.c_void_p()
        if get_first(walker_ptr, elem_ptr, ctypes.byref(child_ptr)) == 0 and child_ptr.value:
            cur_child: int | None = int(child_ptr.value)
            while cur_child and budget[0] > 0:
                found_ptr, meta = self._find_raw_element(
                    cur_child,
                    walker_ptr,
                    name=name,
                    automation_id=automation_id,
                    control_type=control_type,
                    budget=budget,
                )
                if found_ptr:
                    _release_com(cur_child)
                    return found_ptr, meta
                nxt_ptr = ctypes.c_void_p()
                hr_n = get_next(walker_ptr, cur_child, ctypes.byref(nxt_ptr))
                _release_com(cur_child)
                cur_child = int(nxt_ptr.value) if (hr_n == 0 and nxt_ptr.value) else None
            if cur_child:
                _release_com(cur_child)
        return None, None

    def get_ui_tree(
        self,
        *,
        hwnd: int | None = None,
        max_depth: int = 4,
        max_nodes: int = 200,
    ) -> dict[str, Any]:
        depth_cap = max(1, min(int(max_depth), MAX_UI_TREE_DEPTH))
        node_cap = max(1, min(int(max_nodes), MAX_UI_TREE_NODES))
        uia = self._create_uia()
        walker = ctypes.c_void_p()
        root = ctypes.c_void_p()
        try:
            get_walker = _vtable_fn(uia, 14, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
            if get_walker(uia, ctypes.byref(walker)) != 0 or not walker.value:
                raise RuntimeError("Failed to obtain ControlViewWalker")
            if hwnd is not None:
                from_hwnd = _vtable_fn(uia, 6, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
                if from_hwnd(uia, ctypes.c_void_p(hwnd), ctypes.byref(root)) != 0 or not root.value:
                    raise ValueError(f"Could not resolve UIA element for hwnd={hwnd}")
            else:
                get_root = _vtable_fn(uia, 5, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
                if get_root(uia, ctypes.byref(root)) != 0 or not root.value:
                    raise RuntimeError("Failed to obtain UIA root element")
            budget = [node_cap]
            tree = self._read_element_node(
                int(root.value),
                int(walker.value),
                depth=0,
                max_depth=depth_cap,
                budget=budget,
            )
            return {
                "hwnd": hwnd,
                "nodes_captured": node_cap - budget[0],
                "truncated": budget[0] <= 0,
                "root": tree.to_dict(),
            }
        finally:
            _release_com(root)
            _release_com(walker)
            _release_com(uia)

    def _locate(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> tuple[int, dict[str, Any] | None]:
        uia = self._create_uia()
        walker = ctypes.c_void_p()
        root = ctypes.c_void_p()
        try:
            get_walker = _vtable_fn(uia, 14, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
            if get_walker(uia, ctypes.byref(walker)) != 0 or not walker.value:
                return 0, None
            if hwnd is not None:
                from_hwnd = _vtable_fn(uia, 6, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
                if from_hwnd(uia, ctypes.c_void_p(hwnd), ctypes.byref(root)) != 0 or not root.value:
                    return 0, None
            else:
                get_root = _vtable_fn(uia, 5, ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))
                if get_root(uia, ctypes.byref(root)) != 0 or not root.value:
                    return 0, None
            found_ptr, meta = self._find_raw_element(
                int(root.value),
                int(walker.value),
                name=name,
                automation_id=automation_id,
                control_type=control_type,
                budget=[MAX_UI_TREE_NODES * 2],
            )
            return (found_ptr or 0), meta
        finally:
            _release_com(root)
            _release_com(walker)
            _release_com(uia)

    def find_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> dict[str, Any] | None:
        ptr, meta = self._locate(
            hwnd=hwnd, name=name, automation_id=automation_id, control_type=control_type
        )
        _release_com(ptr)
        return meta

    def invoke_element(
        self,
        *,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
        control_type: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        ptr, meta = self._locate(
            hwnd=hwnd, name=name, automation_id=automation_id, control_type=control_type
        )
        if not ptr:
            return False, None
        raw_pat = ctypes.c_void_p()
        inv_pat = ctypes.c_void_p()
        try:
            get_pat = _vtable_fn(ptr, 16, ctypes.c_long, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
            if get_pat(ptr, _UIA_INVOKE_PATTERN_ID, ctypes.byref(raw_pat)) == 0 and raw_pat.value:
                iid_inv = uuid.UUID(_IID_INVOKE_PATTERN).bytes_le
                qi = _vtable_fn(int(raw_pat.value), 0, ctypes.c_long, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p))
                if qi(int(raw_pat.value), iid_inv, ctypes.byref(inv_pat)) == 0 and inv_pat.value:
                    invoke_fn = _vtable_fn(int(inv_pat.value), 3, ctypes.c_long)
                    if invoke_fn(int(inv_pat.value)) == 0:
                        return True, meta
            return False, meta
        finally:
            _release_com(inv_pat)
            _release_com(raw_pat)
            _release_com(ptr)

    def set_element_value(
        self,
        *,
        text: str,
        hwnd: int | None = None,
        name: str = "",
        automation_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        ptr, meta = self._locate(hwnd=hwnd, name=name, automation_id=automation_id, control_type="")
        if not ptr:
            return False, None
        raw_pat = ctypes.c_void_p()
        val_pat = ctypes.c_void_p()
        bstr = None
        try:
            try:
                focus_fn = _vtable_fn(ptr, 3, ctypes.c_long)
                focus_fn(ptr)
            except Exception:  # noqa: BLE001
                pass
            if meta and meta.get("is_password"):
                return False, meta
            get_pat = _vtable_fn(ptr, 16, ctypes.c_long, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
            if get_pat(ptr, _UIA_VALUE_PATTERN_ID, ctypes.byref(raw_pat)) == 0 and raw_pat.value:
                iid_val = uuid.UUID(_IID_VALUE_PATTERN).bytes_le
                qi = _vtable_fn(int(raw_pat.value), 0, ctypes.c_long, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p))
                if qi(int(raw_pat.value), iid_val, ctypes.byref(val_pat)) == 0 and val_pat.value:
                    bstr = self._oleaut32.SysAllocString(text)
                    set_val = _vtable_fn(int(val_pat.value), 3, ctypes.c_long, ctypes.c_void_p)
                    if set_val(int(val_pat.value), bstr) == 0:
                        return True, meta
            return False, meta
        finally:
            if bstr:
                self._oleaut32.SysFreeString(bstr)
            _release_com(val_pat)
            _release_com(raw_pat)
            _release_com(ptr)

    # ------------------------------ SendInput mouse & keyboard ------------------------------
    def _send_inputs(self, inputs: list[_INPUT]) -> None:
        arr = (_INPUT * len(inputs))(*inputs)
        sent = int(self._u32.SendInput(len(inputs), arr, ctypes.sizeof(_INPUT)))
        if sent != len(inputs):
            raise RuntimeError("SendInput blocked by Windows UIPI or desktop state")

    def _move_pointer(self, x: int, y: int) -> None:
        vx = int(self._u32.GetSystemMetrics(76))
        vy = int(self._u32.GetSystemMetrics(77))
        vw = int(self._u32.GetSystemMetrics(78))
        vh = int(self._u32.GetSystemMetrics(79))
        nx, ny = normalize_virtual_coords(x, y, vx, vy, vw, vh)
        inp = _INPUT(type=0)
        # MOUSEEVENTF_MOVE (1) | MOUSEEVENTF_ABSOLUTE (0x8000) | MOUSEEVENTF_VIRTUALDESK (0x4000)
        inp.union.mi = _MOUSEINPUT(dx=nx, dy=ny, mouseData=0, dwFlags=0x0001 | 0x8000 | 0x4000, time=0, dwExtraInfo=0)
        self._send_inputs([inp])

    def mouse_click(
        self,
        x: int,
        y: int,
        *,
        button: str = "left",
        double: bool = False,
    ) -> None:
        btn = button.lower()
        flags_map = {
            "left": (0x0002, 0x0004),
            "right": (0x0008, 0x0010),
            "middle": (0x0020, 0x0040),
        }
        if btn not in flags_map:
            raise ValueError(f"Unsupported mouse button: {button!r}")
        down_f, up_f = flags_map[btn]
        self._move_pointer(x, y)
        clicks = 2 if double else 1
        for _ in range(clicks):
            d = _INPUT(type=0)
            d.union.mi = _MOUSEINPUT(dx=0, dy=0, mouseData=0, dwFlags=down_f, time=0, dwExtraInfo=0)
            u = _INPUT(type=0)
            u.union.mi = _MOUSEINPUT(dx=0, dy=0, mouseData=0, dwFlags=up_f, time=0, dwExtraInfo=0)
            self._send_inputs([d, u])

    def type_text(self, text: str) -> None:
        if not text:
            return
        # Encode to UTF-16LE code units so KEYEVENTF_UNICODE (0x0004) handles Cyrillic/ASCII identically.
        raw = text.encode("utf-16-le")
        inputs: list[_INPUT] = []
        for idx in range(0, len(raw), 2):
            code = int.from_bytes(raw[idx : idx + 2], "little")
            down = _INPUT(type=1)
            down.union.ki = _KEYBDINPUT(wVk=0, wScan=code, dwFlags=0x0004, time=0, dwExtraInfo=0)
            up = _INPUT(type=1)
            up.union.ki = _KEYBDINPUT(wVk=0, wScan=code, dwFlags=0x0004 | 0x0002, time=0, dwExtraInfo=0)
            inputs.extend([down, up])
        self._send_inputs(inputs)

    def send_keypress(self, keys: str) -> None:
        parts = [p.strip().upper() for p in keys.split("+") if p.strip()]
        if not parts:
            raise ValueError("Empty key specification")
        if {"CTRL", "ALT", "DEL"} <= set(parts) or {"CONTROL", "ALT", "DELETE"} <= set(parts):
            raise PermissionError("Refusing protected Secure Attention Sequence (Ctrl+Alt+Del)")
        if parts in (["WIN", "L"], ["LWIN", "L"]):
            raise PermissionError("Refusing session lock shortcut (Win+L)")

        vks: list[int] = []
        for p in parts:
            if p in _VK_MAP:
                vks.append(_VK_MAP[p])
            elif len(p) == 1 and ("A" <= p <= "Z" or "0" <= p <= "9"):
                vks.append(ord(p))
            else:
                raise ValueError(f"Unsupported key token: {p!r}")

        inputs: list[_INPUT] = []
        for vk in vks:
            k_down = _INPUT(type=1)
            k_down.union.ki = _KEYBDINPUT(wVk=vk, wScan=0, dwFlags=0, time=0, dwExtraInfo=0)
            inputs.append(k_down)
        for vk in reversed(vks):
            k_up = _INPUT(type=1)
            k_up.union.ki = _KEYBDINPUT(wVk=vk, wScan=0, dwFlags=0x0002, time=0, dwExtraInfo=0)
            inputs.append(k_up)
        self._send_inputs(inputs)

    def mouse_scroll(
        self,
        delta: int,
        *,
        x: int | None = None,
        y: int | None = None,
        horizontal: bool = False,
    ) -> None:
        if x is not None and y is not None:
            self._move_pointer(x, y)
        # MOUSEEVENTF_WHEEL = 0x0800, MOUSEEVENTF_HWHEEL = 0x1000; 120 units per notch
        flag = 0x1000 if horizontal else 0x0800
        inp = _INPUT(type=0)
        inp.union.mi = _MOUSEINPUT(
            dx=0, dy=0, mouseData=wintypes.DWORD(int(delta) * 120), dwFlags=flag, time=0, dwExtraInfo=0
        )
        self._send_inputs([inp])

    def mouse_drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        button: str = "left",
        steps: int = 10,
    ) -> None:
        btn = button.lower()
        flags_map = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010)}
        if btn not in flags_map:
            raise ValueError(f"Unsupported drag button: {button!r}")
        down_f, up_f = flags_map[btn]
        self._move_pointer(start_x, start_y)
        d = _INPUT(type=0)
        d.union.mi = _MOUSEINPUT(dx=0, dy=0, mouseData=0, dwFlags=down_f, time=0, dwExtraInfo=0)
        self._send_inputs([d])
        n = max(2, min(int(steps), 50))
        for i in range(1, n + 1):
            ix = int(round(start_x + (end_x - start_x) * (i / n)))
            iy = int(round(start_y + (end_y - start_y) * (i / n)))
            self._move_pointer(ix, iy)
            time.sleep(0.01)
        u = _INPUT(type=0)
        u.union.mi = _MOUSEINPUT(dx=0, dy=0, mouseData=0, dwFlags=up_f, time=0, dwExtraInfo=0)
        self._send_inputs([u])
