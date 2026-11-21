"""Иконки, нарисованные кодом: окну и трею не нужны файлы ресурсов.

Если положить assets/icon.ico, он заменит нарисованную букву «S»; к иконке
в трее всё равно добавится цветная точка статуса.

Вызывать только после создания QApplication (QPixmap требует GUI).
"""
from __future__ import annotations

from functools import lru_cache

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QIcon, QLinearGradient, QPainter, QPen, QPixmap

from app.paths import resource_dir
from app.ui import theme

_APP_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
_TRAY_SIZES = (16, 20, 24, 32, 40, 48, 64)


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
    gradient.setColorAt(0.0, QColor(theme.ACCENT_LIGHT))
    gradient.setColorAt(1.0, QColor(theme.ACCENT_DARK))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(gradient))
    radius = size * 0.24
    p.drawRoundedRect(rect, radius, radius)

    font = QFont("Segoe UI")
    font.setBold(True)
    font.setPixelSize(max(8, round(size * 0.62)))
    p.setFont(font)
    p.setPen(QColor("#ffffff"))
    p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "S")


def _render(size: int, status_color: str | None) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    _draw_logo(p, size)

    if status_color:
        # Точка статуса в правом нижнем углу, с «вырезом» цвета фона панели задач.
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
