"""Theme-aware ToggleSwitch widget respecting OS reduced-motion preferences."""
from __future__ import annotations

from PyQt6.QtCore import QEasingCurve, QEvent, QRectF, QSize, Qt, QVariantAnimation
from PyQt6.QtGui import QColor, QFontMetrics, QPainter, QPaintEvent, QPen
from PyQt6.QtWidgets import QAbstractButton, QSizePolicy, QWidget

from app.ui import theme

_TRACK_W = 34
_TRACK_H = 18
_GAP = 10


class ToggleSwitch(QAbstractButton):
    """Accessible pill toggle switch synchronized with active theme tokens."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._thumb_pos = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim_value)
        self.toggled.connect(self._animate_to_state)

    def _on_anim_value(self, value: object) -> None:
        self._thumb_pos = float(value)  # type: ignore[arg-type]
        self.update()

    def _animate_to_state(self, checked: bool) -> None:
        target = 1.0 if checked else 0.0
        if not theme.animations_enabled():
            self._anim.stop()
            self._thumb_pos = target
            self.update()
            return
        self._anim.stop()
        self._anim.setStartValue(self._thumb_pos)
        self._anim.setEndValue(target)
        self._anim.start()

    def setChecked(self, checked: bool) -> None:  # noqa: N802
        was_blocked = self.signalsBlocked()
        super().setChecked(checked)
        if was_blocked or not theme.animations_enabled():
            self._anim.stop()
            self._thumb_pos = 1.0 if checked else 0.0
            self.update()

    def apply_theme(self) -> None:
        self.update()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        super().changeEvent(event)
        if event.type() == QEvent.Type.EnabledChange:
            self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        fm = QFontMetrics(self.font())
        label = self.text()
        text_w = fm.horizontalAdvance(label) + (_GAP if label else 0)
        height = max(_TRACK_H + 8, fm.height() + 8)
        return QSize(_TRACK_W + text_w + 4, height)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return self.sizeHint()

    def paintEvent(self, _event: QPaintEvent) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        enabled = self.isEnabled()
        checked = self.isChecked()
        t = self._thumb_pos if self._anim.state() == QVariantAnimation.State.Running else (1.0 if checked else 0.0)

        y = (self.height() - _TRACK_H) / 2.0
        track_rect = QRectF(0.0, y, float(_TRACK_W), float(_TRACK_H))
        radius = _TRACK_H / 2.0

        if enabled:
            off_color = QColor(theme.BORDER_STRONG)
            on_color = QColor(theme.ACCENT_STRONG)
            track_color = QColor(
                round(off_color.red() + (on_color.red() - off_color.red()) * t),
                round(off_color.green() + (on_color.green() - off_color.green()) * t),
                round(off_color.blue() + (on_color.blue() - off_color.blue()) * t),
            )
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(track_color)
            painter.drawRoundedRect(track_rect, radius, radius)
        else:
            track_color = QColor(theme.BORDER_STRONG)
            track_color.setAlphaF(0.50)
            painter.setPen(QPen(QColor(theme.BORDER), 1.0))
            painter.setBrush(track_color)
            painter.drawRoundedRect(track_rect.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)

        if enabled and self.hasFocus():
            painter.setPen(QPen(QColor(theme.ACCENT), 1.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(track_rect.adjusted(-1.0, -1.0, 1.0, 1.0), radius + 1.0, radius + 1.0)

        knob = _TRACK_H - 4.0
        knob_x = 2.0 + (_TRACK_W - knob - 4.0) * t
        knob_y = y + 2.0
        painter.setPen(Qt.PenStyle.NoPen)
        if enabled:
            knob_color = QColor("#FFFFFF" if checked else theme.ELEVATED)
        elif checked:
            knob_color = QColor(theme.TEXT_FAINT)
        else:
            knob_color = QColor(theme.ELEVATED)
            knob_color.setAlphaF(0.8)
        painter.setBrush(knob_color)
        painter.drawEllipse(QRectF(knob_x, knob_y, knob, knob))

        label = self.text()
        if label:
            painter.setPen(QColor(theme.TEXT if enabled else theme.TEXT_FAINT))
            text_rect = QRectF(_TRACK_W + _GAP, 0.0, max(0.0, self.width() - _TRACK_W - _GAP), float(self.height()))
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, label)
        painter.end()
