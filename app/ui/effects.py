"""Эффекты интерфейса: подсветка под курсором, бегущий блеск, искры по клику.

Идеи взяты из reactbits.dev (SpotlightCard, ShinyText, ClickSpark) и переписаны
на QPainter: в PyQt нет CSS-анимаций, поэтому каждый эффект — это
QVariantAnimation плюс свой paintEvent.

Движение здесь только служебное (impeccable, режим Operate): оно либо
показывает состояние (блеск = «идёт процесс»), либо подтверждает нажатие,
и длится 150–360 мс. У простоя ничего не анимируется: таймеры стоят.
"""
from __future__ import annotations

import math

from PyQt6.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPointF,
    QPropertyAnimation,
    QRectF,
    Qt,
    QVariantAnimation,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
    QTextOption,
)
from PyQt6.QtWidgets import QFrame, QLabel, QPushButton, QWidget

from app.ui import theme

CARD_RADIUS = 12
QWIDGETSIZE_MAX = 16_777_215  # «без ограничения» для setMaximumHeight
_RUNNING = QVariantAnimation.State.Running


# ====================================================================== SpotlightCard
class SpotlightFrame(QFrame):
    """Карточка с мягким светом, следующим за курсором.

    Свет появляется и гаснет за 180 мс, рисуется поверх фона из QSS (под дочерними
    виджетами) и обрезается по радиусу карточки. Движения мыши над дочерними
    виджетами ловим фильтром событий — иначе свет «залипал» бы на кнопках.
    """

    def __init__(self, radius: int = 280, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMouseTracking(True)
        self._radius = radius
        self._pos = QPointF(-1000.0, -1000.0)
        self._strength = 0.0
        self._filters_installed = False
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_strength)

    # ------------------------------------------------------------------ анимация
    def _on_strength(self, value: object) -> None:
        self._strength = float(value)  # type: ignore[arg-type]
        self.update()

    def _animate_to(self, target: float) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._strength)
        self._anim.setEndValue(target)
        self._anim.start()

    # ------------------------------------------------------------------ мышь
    def showEvent(self, event) -> None:  # noqa: ANN001
        super().showEvent(event)
        if not self._filters_installed:
            self._filters_installed = True
            for child in self.findChildren(QWidget):
                child.setMouseTracking(True)
                child.installEventFilter(self)

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.MouseMove and isinstance(obj, QWidget):
            self._pos = QPointF(obj.mapTo(self, event.position().toPoint()))
            if self._strength > 0.0:
                self.update()
        return False

    def enterEvent(self, event) -> None:  # noqa: ANN001
        self._pos = QPointF(event.position())
        self._animate_to(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: ANN001
        self._animate_to(0.0)
        super().leaveEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001
        self._pos = QPointF(event.position())
        if self._strength > 0.0:
            self.update()
        super().mouseMoveEvent(event)

    # ------------------------------------------------------------------ отрисовка
    def paintEvent(self, event) -> None:  # noqa: ANN001
        super().paintEvent(event)
        if self._strength <= 0.01:
            return
        clip = QPainterPath()
        clip.addRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), CARD_RADIUS, CARD_RADIUS)

        inner = QColor(theme.ACCENT)
        inner.setAlphaF(0.12 * self._strength)
        outer = QColor(theme.ACCENT)
        outer.setAlphaF(0.0)
        gradient = QRadialGradient(self._pos, float(self._radius))
        gradient.setColorAt(0.0, inner)
        gradient.setColorAt(1.0, outer)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setClipPath(clip)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPath(clip)
        painter.end()


# ====================================================================== ShinyText
class ShinyLabel(QLabel):
    """Текст с бегущим бликом — включается только на время процесса.

    Пока блик выключен, это обычный QLabel (и таймер не работает).
    Блик рисуется поверх штатной отрисовки тем же цветом статуса,
    только светлее, — цвет не меняет смысла.
    """

    BAND = 0.34  # ширина светлой полосы в долях ширины надписи

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._base = QColor(theme.TEXT)
        self._shine = QColor("#ffffff")
        self._offset = -self.BAND
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(2100)
        self._anim.setStartValue(-self.BAND)
        self._anim.setEndValue(1.0 + self.BAND)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._on_offset)

    # ------------------------------------------------------------------ API
    def set_base_color(self, color: str) -> None:
        self._base = QColor(color)
        self._shine = QColor(color).lighter(175)
        self.update()

    def set_shine(self, active: bool) -> None:
        running = self._anim.state() == _RUNNING
        if active and not running:
            self._anim.start()
        elif not active and running:
            self._anim.stop()
            self._offset = -self.BAND
            self.update()

    # ------------------------------------------------------------------ внутреннее
    def _on_offset(self, value: object) -> None:
        self._offset = float(value)  # type: ignore[arg-type]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        super().paintEvent(event)
        if self._anim.state() != _RUNNING or not self.text():
            return
        rect = QRectF(self.contentsRect())
        if rect.width() <= 0:
            return

        gradient = QLinearGradient(rect.left(), 0.0, rect.right(), 0.0)
        for stop, color in self._stops():
            gradient.setColorAt(stop, color)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        painter.setFont(self.font())
        painter.setPen(QPen(QBrush(gradient), 1.0))
        painter.drawText(rect, self.text(), QTextOption(self.alignment()))
        painter.end()

    def _stops(self) -> list[tuple[float, QColor]]:
        """Точки градиента: базовый цвет и светлая полоса в текущем положении."""
        half = self.BAND / 2
        raw = [
            (0.0, self._base),
            (self._offset, self._base),
            (self._offset + half, self._shine),
            (self._offset + self.BAND, self._base),
            (1.0, self._base),
        ]
        stops: list[tuple[float, QColor]] = []
        last = -1.0
        for position, color in raw:
            clamped = min(1.0, max(0.0, position))
            if clamped <= last:  # QLinearGradient требует возрастающие различные точки
                continue
            stops.append((clamped, color))
            last = clamped
        return stops


# ====================================================================== ClickSpark
class SparkButton(QPushButton):
    """Кнопка, которая на нажатие выбрасывает короткие лучи из точки клика.

    Обратная связь на главном действии: старт сервисов занимает секунды,
    и пользователь сразу видит, что нажатие засчитано.
    """

    RAYS = 8
    DURATION_MS = 360

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._center = QPointF()
        self._t = 1.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(self.DURATION_MS)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_tick)
        self._anim.finished.connect(self.update)

    def _on_tick(self, value: object) -> None:
        self._t = float(value)  # type: ignore[arg-type]
        self.update()

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() == Qt.MouseButton.LeftButton:
            self._center = QPointF(event.position())
            self._anim.stop()
            self._anim.start()
        super().mousePressEvent(event)

    def paintEvent(self, event) -> None:  # noqa: ANN001
        super().paintEvent(event)
        if self._anim.state() != _RUNNING:
            return
        t = self._t
        color = QColor("#ffffff")
        color.setAlphaF(max(0.0, 0.55 * (1.0 - t)))
        pen = QPen(color, 2.0)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(pen)
        inner = 6.0 + 26.0 * t
        length = 9.0 * (1.0 - t)
        for index in range(self.RAYS):
            angle = math.radians(360.0 / self.RAYS * index + 22.5)
            dx, dy = math.cos(angle), math.sin(angle)
            start = QPointF(self._center.x() + dx * inner, self._center.y() + dy * inner)
            end = QPointF(start.x() + dx * length, start.y() + dy * length)
            painter.drawLine(start, end)
        painter.end()


# ====================================================================== раскрытие
def reveal(widget: QWidget, show: bool, height: int, duration: int = 180) -> None:
    """Плавно раскрыть/свернуть виджет по высоте (для панели журнала).

    Ссылка на анимацию живёт на самом виджете: без неё сборщик мусора
    удалит объект раньше, чем он доиграет.
    """
    previous = getattr(widget, "_reveal_anim", None)
    if previous is not None:
        previous.stop()

    anim = QPropertyAnimation(widget, b"maximumHeight", widget)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    widget._reveal_anim = anim  # type: ignore[attr-defined]

    if show:
        widget.setMaximumHeight(0)
        widget.setVisible(True)
        anim.setStartValue(0)
        anim.setEndValue(max(1, height))
        anim.finished.connect(lambda: widget.setMaximumHeight(QWIDGETSIZE_MAX))
    else:
        anim.setStartValue(widget.height())
        anim.setEndValue(0)

        def done() -> None:
            widget.setVisible(False)
            widget.setMaximumHeight(QWIDGETSIZE_MAX)

        anim.finished.connect(done)
    anim.start()
