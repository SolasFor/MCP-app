"""Иконки, нарисованные кодом: окну и трею не нужны файлы ресурсов.

Логотип MCP app: скруглённый квадрат цвета Clay и знак «соединения» — две точки
и дуга между ними (сервер ↔ клиент через туннель). Свой знак, а не логотип
Anthropic: используются только цвета палитры.

Если положить assets/icon.ico, он заменит нарисованный логотип; к иконке в трее
всё равно добавится цветная точка статуса.

write_ico() собирает многоразмерный .ico для PyInstaller и установщика
(вызывается из packaging/make_icon.py). Вызывать только после создания QApplication.
"""
from __future__ import annotations

import struct
from functools import lru_cache
from pathlib import Path

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap

from app.paths import resource_dir
from app.ui import theme

_APP_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
_TRAY_SIZES = (16, 20, 24, 32, 40, 48, 64)
_ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


@lru_cache(maxsize=1)
def _custom_base() -> QPixmap | None:
    path = resource_dir() / "assets" / "icon.ico"
    if not path.is_file():
        return None
    pixmap = QPixmap(str(path))
    return None if pixmap.isNull() else pixmap


def _draw_logo(p: QPainter, size: int) -> None:
    custom = _custom_base()
    if custom is not None:
        p.drawPixmap(0, 0, custom.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                                         Qt.TransformationMode.SmoothTransformation))
        return

    inset = size * 0.04
    rect = QRectF(inset, inset, size - 2 * inset, size - 2 * inset)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0.0, QColor(theme.ACCENT_HOVER))
    gradient.setColorAt(1.0, QColor(theme.ACCENT_STRONG))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(gradient))
    radius = size * 0.26
    p.drawRoundedRect(rect, radius, radius)

    # Знак «соединения»: две точки и дуга сверху.
    ink = QColor("#FFFFFF")
    cx, cy = size / 2, size * 0.56
    spread = size * 0.22
    node = max(1.6, size * 0.085)
    left, right = QPointF(cx - spread, cy), QPointF(cx + spread, cy)

    arc = QPainterPath(left)
    arc.cubicTo(QPointF(cx - spread, cy - size * 0.30), QPointF(cx + spread, cy - size * 0.30), right)
    pen = QPen(ink, max(1.4, size * 0.075))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(arc)

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(ink)
    p.drawEllipse(left, node, node)
    p.drawEllipse(right, node, node)


def _render(size: int, status_color: str | None) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    _draw_logo(p, size)

    if status_color:
        # Точка статуса в правом нижнем углу, с «вырезом» цвета фона.
        diameter = size * 0.46
        ring = max(1.0, size * 0.08)
        dot = QRectF(size - diameter, size - diameter, diameter, diameter)
        dot = dot.adjusted(ring / 2, ring / 2, -ring / 2, -ring / 2)
        p.setPen(QPen(QColor(theme.BG), ring))
        p.setBrush(QColor(status_color))
        p.drawEllipse(dot)

    p.end()
    return pixmap


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    """Иконка окна и панели задач (без точки статуса)."""
    icon = QIcon()
    for size in _APP_SIZES:
        icon.addPixmap(_render(size, None))
    return icon


@lru_cache(maxsize=16)
def status_icon(color: str) -> QIcon:
    """Иконка трея с цветной точкой статуса (кэшируется по цвету)."""
    icon = QIcon()
    for size in _TRAY_SIZES:
        icon.addPixmap(_render(size, color))
    return icon


def write_ico(target: Path) -> None:
    """Многоразмерный .ico с PNG-кадрами (формат, который понимает Windows Vista+)."""
    frames: list[tuple[int, bytes]] = []
    for size in _ICO_SIZES:
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        _render(size, None).toImage().save(buffer, "PNG")
        buffer.close()
        frames.append((size, bytes(data)))

    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = len(header) + 16 * len(frames)
    entries, blobs = b"", b""
    for size, png in frames:
        dim = 0 if size >= 256 else size  # 0 в заголовке = 256
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(header + entries + blobs)
