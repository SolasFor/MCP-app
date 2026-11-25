"""Vector icons and app logo drawn with QPainter (no external raster icon assets needed)."""
from __future__ import annotations

import struct
from functools import lru_cache
from pathlib import Path

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

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
        p.drawPixmap(
            0,
            0,
            custom.scaled(
                size,
                size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            ),
        )
        return

    inset = size * 0.04
    rect = QRectF(inset, inset, size - 2 * inset, size - 2 * inset)
    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0.0, QColor("#818CF8"))
    gradient.setColorAt(1.0, QColor("#5B5EE6"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(gradient))
    radius = size * 0.24
    p.drawRoundedRect(rect, radius, radius)

    ink = QColor("#FFFFFF")
    cx, cy = size / 2, size * 0.56
    spread = size * 0.22
    node = max(1.6, size * 0.085)
    left, right = QPointF(cx - spread, cy), QPointF(cx + spread, cy)

    arc = QPainterPath(left)
    arc.cubicTo(
        QPointF(cx - spread, cy - size * 0.30),
        QPointF(cx + spread, cy - size * 0.30),
        right,
    )
    pen = QPen(ink, max(1.4, size * 0.075))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(arc)

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(ink)
    p.drawEllipse(left, node, node)
    p.drawEllipse(right, node, node)


def _render(size: int, status_color: str | None, ring_bg: str | None = None) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    _draw_logo(p, size)

    if status_color:
        diameter = size * 0.46
        ring = max(1.0, size * 0.08)
        dot = QRectF(size - diameter, size - diameter, diameter, diameter)
        dot = dot.adjusted(ring / 2, ring / 2, -ring / 2, -ring / 2)
        p.setPen(QPen(QColor(ring_bg or theme.BG), ring))
        p.setBrush(QColor(status_color))
        p.drawEllipse(dot)

    p.end()
    return pixmap


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    """Application window and taskbar icon."""
    icon = QIcon()
    for size in _APP_SIZES:
        icon.addPixmap(_render(size, None))
    return icon


@lru_cache(maxsize=32)
def status_icon(color: str, ring_bg: str = "") -> QIcon:
    """Tray icon with colored status dot keyed by dot color and ring background."""
    ring = ring_bg or theme.BG
    icon = QIcon()
    for size in _TRAY_SIZES:
        icon.addPixmap(_render(size, color, ring))
    return icon


def _draw_vector_glyph(p: QPainter, name: str, s: float, pen: QPen, fill: QColor) -> None:
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    if name == "home":
        path = QPainterPath(QPointF(s * 0.16, s * 0.46))
        path.lineTo(QPointF(s * 0.50, s * 0.18))
        path.lineTo(QPointF(s * 0.84, s * 0.46))
        p.drawPath(path)
        body = QPainterPath(QPointF(s * 0.24, s * 0.44))
        body.lineTo(QPointF(s * 0.24, s * 0.82))
        body.lineTo(QPointF(s * 0.76, s * 0.82))
        body.lineTo(QPointF(s * 0.76, s * 0.44))
        p.drawPath(body)
    elif name == "connections":
        p.drawEllipse(QRectF(s * 0.14, s * 0.36, s * 0.28, s * 0.28))
        p.drawEllipse(QRectF(s * 0.58, s * 0.36, s * 0.28, s * 0.28))
        p.drawLine(QPointF(s * 0.42, s * 0.50), QPointF(s * 0.58, s * 0.50))
    elif name == "clients":
        p.drawEllipse(QRectF(s * 0.34, s * 0.18, s * 0.32, s * 0.32))
        arc = QPainterPath(QPointF(s * 0.18, s * 0.82))
        arc.cubicTo(QPointF(s * 0.22, s * 0.56), QPointF(s * 0.78, s * 0.56), QPointF(s * 0.82, s * 0.82))
        p.drawPath(arc)
    elif name == "gateway":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.22, s * 0.26, s * 0.56), 2, 2)
        p.drawRoundedRect(QRectF(s * 0.56, s * 0.22, s * 0.26, s * 0.56), 2, 2)
        p.drawLine(QPointF(s * 0.44, s * 0.40), QPointF(s * 0.56, s * 0.40))
        p.drawLine(QPointF(s * 0.44, s * 0.60), QPointF(s * 0.56, s * 0.60))
    elif name == "tasks":
        p.drawRoundedRect(QRectF(s * 0.20, s * 0.18, s * 0.60, s * 0.64), 2, 2)
        p.drawLine(QPointF(s * 0.34, s * 0.40), QPointF(s * 0.66, s * 0.40))
        p.drawLine(QPointF(s * 0.34, s * 0.58), QPointF(s * 0.58, s * 0.58))
    elif name == "servers":
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.20, s * 0.64, s * 0.24), 2, 2)
        p.drawRoundedRect(QRectF(s * 0.18, s * 0.56, s * 0.64, s * 0.24), 2, 2)
        p.drawPoint(QPointF(s * 0.30, s * 0.32))
        p.drawPoint(QPointF(s * 0.30, s * 0.68))
    elif name == "workspaces":
        path = QPainterPath(QPointF(s * 0.16, s * 0.26))
        path.lineTo(QPointF(s * 0.40, s * 0.26))
        path.lineTo(QPointF(s * 0.48, s * 0.36))
        path.lineTo(QPointF(s * 0.84, s * 0.36))
        path.lineTo(QPointF(s * 0.84, s * 0.78))
        path.lineTo(QPointF(s * 0.16, s * 0.78))
        path.closeSubpath()
        p.drawPath(path)
    elif name in ("devices", "monitor"):
        p.drawRoundedRect(QRectF(s * 0.16, s * 0.22, s * 0.68, s * 0.46), 2, 2)
        p.drawLine(QPointF(s * 0.36, s * 0.80), QPointF(s * 0.64, s * 0.80))
        p.drawLine(QPointF(s * 0.50, s * 0.68), QPointF(s * 0.50, s * 0.80))
    elif name == "extensions":
        p.drawRoundedRect(QRectF(s * 0.20, s * 0.20, s * 0.26, s * 0.26), 2, 2)
        p.drawRoundedRect(QRectF(s * 0.54, s * 0.20, s * 0.26, s * 0.26), 2, 2)
        p.drawRoundedRect(QRectF(s * 0.20, s * 0.54, s * 0.26, s * 0.26), 2, 2)
        p.drawRoundedRect(QRectF(s * 0.54, s * 0.54, s * 0.26, s * 0.26), 2, 2)
    elif name == "automation":
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
        p.drawLine(QPointF(s * 0.50, s * 0.30), QPointF(s * 0.50, s * 0.52))
        p.drawLine(QPointF(s * 0.50, s * 0.52), QPointF(s * 0.64, s * 0.60))
    elif name in ("security", "shield"):
        path = QPainterPath(QPointF(s * 0.50, s * 0.16))
        path.lineTo(QPointF(s * 0.80, s * 0.28))
        path.lineTo(QPointF(s * 0.78, s * 0.56))
        path.cubicTo(QPointF(s * 0.74, s * 0.72), QPointF(s * 0.58, s * 0.80), QPointF(s * 0.50, s * 0.84))
        path.cubicTo(QPointF(s * 0.42, s * 0.80), QPointF(s * 0.26, s * 0.72), QPointF(s * 0.22, s * 0.56))
        path.lineTo(QPointF(s * 0.20, s * 0.28))
        path.closeSubpath()
        p.drawPath(path)
    elif name in ("logs", "terminal"):
        p.drawRoundedRect(QRectF(s * 0.16, s * 0.20, s * 0.68, s * 0.60), 2, 2)
        p.drawLine(QPointF(s * 0.28, s * 0.40), QPointF(s * 0.40, s * 0.50))
        p.drawLine(QPointF(s * 0.40, s * 0.50), QPointF(s * 0.28, s * 0.60))
        p.drawLine(QPointF(s * 0.48, s * 0.60), QPointF(s * 0.68, s * 0.60))
    elif name == "settings":
        p.drawEllipse(QRectF(s * 0.34, s * 0.34, s * 0.32, s * 0.32))
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
    elif name == "search":
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.46, s * 0.46))
        p.drawLine(QPointF(s * 0.58, s * 0.58), QPointF(s * 0.82, s * 0.82))
    elif name == "sidebar":
        p.drawRoundedRect(QRectF(s * 0.16, s * 0.20, s * 0.68, s * 0.60), 2, 2)
        p.drawLine(QPointF(s * 0.38, s * 0.20), QPointF(s * 0.38, s * 0.80))
    elif name == "sun":
        p.drawEllipse(QRectF(s * 0.32, s * 0.32, s * 0.36, s * 0.36))
        for x1, y1, x2, y2 in (
            (0.50, 0.12, 0.50, 0.22),
            (0.50, 0.78, 0.50, 0.88),
            (0.12, 0.50, 0.22, 0.50),
            (0.78, 0.50, 0.88, 0.50),
        ):
            p.drawLine(QPointF(s * x1, s * y1), QPointF(s * x2, s * y2))
    elif name == "moon":
        path = QPainterPath(QPointF(s * 0.64, s * 0.22))
        path.cubicTo(QPointF(s * 0.42, s * 0.24), QPointF(s * 0.28, s * 0.46), QPointF(s * 0.38, s * 0.66))
        path.cubicTo(QPointF(s * 0.46, s * 0.80), QPointF(s * 0.68, s * 0.82), QPointF(s * 0.78, s * 0.68))
        path.cubicTo(QPointF(s * 0.60, s * 0.68), QPointF(s * 0.50, s * 0.46), QPointF(s * 0.64, s * 0.22))
        p.drawPath(path)
    elif name == "warning":
        path = QPainterPath(QPointF(s * 0.50, s * 0.18))
        path.lineTo(QPointF(s * 0.84, s * 0.80))
        path.lineTo(QPointF(s * 0.16, s * 0.80))
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.50, s * 0.42), QPointF(s * 0.50, s * 0.60))
        p.drawPoint(QPointF(s * 0.50, s * 0.70))
    elif name == "close":
        p.drawLine(QPointF(s * 0.26, s * 0.26), QPointF(s * 0.74, s * 0.74))
        p.drawLine(QPointF(s * 0.74, s * 0.26), QPointF(s * 0.26, s * 0.74))
    elif name == "check":
        p.drawLine(QPointF(s * 0.20, s * 0.54), QPointF(s * 0.42, s * 0.74))
        p.drawLine(QPointF(s * 0.42, s * 0.74), QPointF(s * 0.80, s * 0.28))
    elif name == "refresh":
        p.drawArc(QRectF(s * 0.20, s * 0.20, s * 0.60, s * 0.60), 30 * 16, 280 * 16)
        p.drawLine(QPointF(s * 0.72, s * 0.20), QPointF(s * 0.78, s * 0.38))
    else:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(fill)
        p.drawEllipse(QRectF(s * 0.34, s * 0.34, s * 0.32, s * 0.32))


@lru_cache(maxsize=256)
def vector_icon(name: str, color: str, size: int = 16) -> QIcon:
    """Create a crisp 1x/2x vector icon using QPainter."""
    icon = QIcon()
    for scale in (1, 2):
        px = size * scale
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        qcolor = QColor(color)
        pen = QPen(qcolor, 1.55 * scale)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        _draw_vector_glyph(p, name, float(px), pen, qcolor)
        p.end()
        pm.setDevicePixelRatio(float(scale))
        icon.addPixmap(pm)
    return icon


def write_ico(target: Path) -> None:
    """Write multi-resolution .ico for PyInstaller and Inno Setup."""
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
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(header + entries + blobs)
