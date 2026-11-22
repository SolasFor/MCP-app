"""Готовит ресурсы для сборки: build/MCPApp.ico и build/version_info.txt.

    python packaging/make_assets.py

* Иконка рисуется тем же кодом, что и в приложении (app/ui/icons.py), — один логотип
  в окне, трее, проводнике и установщике. Если есть assets/icon.ico, берётся он.
* version_info.txt — ресурс версии для PyInstaller: «Свойства → Подробно» у .exe
  показывают название, версию и описание вместо пустых полей.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # без окна и без дисплея (CI)

from app import APP_ID, APP_NAME, __version__  # noqa: E402

VERSION_TEMPLATE = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={tuple4},
    prodvers={tuple4},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', '{name}'),
        StringStruct('FileDescription', '{name} — MCP-сервер через Cloudflare Tunnel'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', '{app_id}'),
        StringStruct('OriginalFilename', '{app_id}.exe'),
        StringStruct('ProductName', '{name}'),
        StringStruct('ProductVersion', '{version}')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def _version_tuple(version: str) -> tuple[int, int, int, int]:
    parts = []
    for chunk in version.split(".")[:4]:
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits or 0))
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)

    icon_target = BUILD / f"{APP_ID}.ico"
    custom = ROOT / "assets" / "icon.ico"
    if custom.is_file():
        shutil.copyfile(custom, icon_target)
    else:
        from PyQt6.QtGui import QGuiApplication

        app = QGuiApplication(sys.argv)  # QPixmap требует экземпляр приложения
        from app.ui.icons import write_ico

        write_ico(icon_target)
        del app

    (BUILD / "version_info.txt").write_text(
        VERSION_TEMPLATE.format(
            tuple4=_version_tuple(__version__), version=__version__, name=APP_NAME, app_id=APP_ID,
        ),
        encoding="utf-8",
    )
    print(f"assets: {icon_target.name}, version_info.txt ({__version__})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
