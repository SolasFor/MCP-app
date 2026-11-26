"""Silent custom modal dialogs replacing QMessageBox so Windows never plays system alert sounds."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui import icons, theme

StandardButton = QMessageBox.StandardButton

_BUTTON_SPECS: tuple[tuple[StandardButton, str], ...] = (
    (StandardButton.Yes, "Да"),
    (StandardButton.No, "Нет"),
    (StandardButton.Ok, "ОК"),
    (StandardButton.Cancel, "Отмена"),
    (StandardButton.Close, "Закрыть"),
)


class SilentDialog(QDialog):
    """Theme-aware QDialog base that never emits Windows MessageBeep/system sounds."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        theme.apply_to_widget(self)
        theme.apply_window_titlebar(self)


class SilentMessageBox(SilentDialog):
    """Drop-in silent replacement for QMessageBox.warning/critical/information/question."""

    StandardButton = QMessageBox.StandardButton

    def __init__(
        self,
        *,
        kind: str,
        title: str,
        text: str,
        buttons: StandardButton = StandardButton.Ok,
        default_button: StandardButton = StandardButton.NoButton,
        informative_text: str = "",
        detailed_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(400)
        self.setMaximumWidth(560)
        self.setModal(True)
        self._clicked_button: StandardButton = StandardButton.NoButton
        self._buttons_map: dict[StandardButton, QPushButton] = {}
        self._custom_buttons: list[QPushButton] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        body = QHBoxLayout()
        body.setSpacing(10)
        body.setAlignment(Qt.AlignmentFlag.AlignTop)

        icon_name, icon_color = {
            "warning": ("warning", theme.WARN),
            "critical": ("warning", theme.ERR),
            "question": ("shield", theme.ACCENT),
            "information": ("info", theme.ACCENT),
        }.get(kind, ("info", theme.ACCENT))

        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.vector_icon(icon_name, icon_color, 22).pixmap(22, 22))
        icon_lbl.setFixedSize(26, 26)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        body.addWidget(icon_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(6)
        self.message_label = QLabel(text)
        self.message_label.setObjectName("SectionTitle" if informative_text else "")
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        text_col.addWidget(self.message_label)

        if informative_text:
            self.info_label = QLabel(informative_text)
            self.info_label.setWordWrap(True)
            self.info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            text_col.addWidget(self.info_label)
        else:
            self.info_label = None

        body.addLayout(text_col, 1)
        root.addLayout(body)

        if detailed_text:
            details = QPlainTextEdit()
            details.setReadOnly(True)
            details.setPlainText(detailed_text)
            details.setMaximumHeight(160)
            root.addWidget(details)

        self._btn_row = QHBoxLayout()
        self._btn_row.setSpacing(8)
        self._btn_row.addStretch(1)

        for std_btn, label in _BUTTON_SPECS:
            if buttons & std_btn:
                btn = QPushButton(label)
                if std_btn in (StandardButton.Yes, StandardButton.Ok) and kind != "warning":
                    btn.setObjectName("Accent")
                elif std_btn == StandardButton.Yes and kind == "warning":
                    btn.setObjectName("Danger")
                btn.clicked.connect(lambda _c=False, b=std_btn: self._finish_with(b))
                self._buttons_map[std_btn] = btn
                self._btn_row.addWidget(btn)

        if default_button != StandardButton.NoButton and default_button in self._buttons_map:
            self._buttons_map[default_button].setDefault(True)
            self._buttons_map[default_button].setFocus()
        elif StandardButton.No in self._buttons_map:
            self._buttons_map[StandardButton.No].setDefault(True)
            self._buttons_map[StandardButton.No].setFocus()
        elif StandardButton.Cancel in self._buttons_map:
            self._buttons_map[StandardButton.Cancel].setDefault(True)
            self._buttons_map[StandardButton.Cancel].setFocus()
        elif self._buttons_map:
            first = next(iter(self._buttons_map.values()))
            first.setDefault(True)

        root.addLayout(self._btn_row)

    def _finish_with(self, button: StandardButton) -> None:
        self._clicked_button = button
        if button in (StandardButton.Yes, StandardButton.Ok):
            self.accept()
        else:
            self.reject()

    def result_button(self) -> StandardButton:
        if self._clicked_button != StandardButton.NoButton:
            return self._clicked_button
        if StandardButton.Cancel in self._buttons_map:
            return StandardButton.Cancel
        if StandardButton.No in self._buttons_map:
            return StandardButton.No
        if StandardButton.Close in self._buttons_map:
            return StandardButton.Close
        return StandardButton.NoButton

    def button(self, which: StandardButton) -> QPushButton | None:
        """Return the QPushButton corresponding to a StandardButton, if present."""
        return self._buttons_map.get(which)

    @classmethod
    def _show(
        cls,
        *,
        kind: str,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: StandardButton,
        default_button: StandardButton,
        informative_text: str = "",
        detailed_text: str = "",
    ) -> StandardButton:
        dlg = cls(
            kind=kind,
            title=title,
            text=text,
            buttons=buttons,
            default_button=default_button,
            informative_text=informative_text,
            detailed_text=detailed_text,
            parent=parent,
        )
        dlg.exec()
        return dlg.result_button()

    @classmethod
    def warning(
        cls,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: StandardButton = StandardButton.Ok,
        default_button: StandardButton = StandardButton.NoButton,
        *,
        informative_text: str = "",
    ) -> StandardButton:
        return cls._show(
            kind="warning",
            parent=parent,
            title=title,
            text=text,
            buttons=buttons,
            default_button=default_button,
            informative_text=informative_text,
        )

    @classmethod
    def critical(
        cls,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: StandardButton = StandardButton.Ok,
        default_button: StandardButton = StandardButton.NoButton,
        *,
        informative_text: str = "",
        detailed_text: str = "",
    ) -> StandardButton:
        return cls._show(
            kind="critical",
            parent=parent,
            title=title,
            text=text,
            buttons=buttons,
            default_button=default_button,
            informative_text=informative_text,
            detailed_text=detailed_text,
        )

    @classmethod
    def information(
        cls,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: StandardButton = StandardButton.Ok,
        default_button: StandardButton = StandardButton.NoButton,
        *,
        informative_text: str = "",
    ) -> StandardButton:
        return cls._show(
            kind="information",
            parent=parent,
            title=title,
            text=text,
            buttons=buttons,
            default_button=default_button,
            informative_text=informative_text,
        )

    @classmethod
    def question(
        cls,
        parent: QWidget | None,
        title: str,
        text: str,
        buttons: StandardButton = StandardButton.Yes | StandardButton.No,
        default_button: StandardButton = StandardButton.No,
        *,
        informative_text: str = "",
    ) -> StandardButton:
        return cls._show(
            kind="question",
            parent=parent,
            title=title,
            text=text,
            buttons=buttons,
            default_button=default_button,
            informative_text=informative_text,
        )

    @classmethod
    def confirm(
        cls,
        parent: QWidget | None,
        title: str,
        headline: str,
        body: str,
        *,
        accept_label: str = "Продолжить",
        cancel_label: str = "Отмена",
    ) -> bool:
        dlg = cls(
            kind="question",
            title=title,
            text=headline,
            buttons=StandardButton.NoButton,
            default_button=StandardButton.NoButton,
            informative_text=body,
            parent=parent,
        )
        accepted = {"ok": False}
        accept_btn = QPushButton(accept_label)
        accept_btn.setObjectName("Accent")
        cancel_btn = QPushButton(cancel_label)
        cancel_btn.setDefault(True)

        def on_accept() -> None:
            accepted["ok"] = True
            dlg.accept()

        accept_btn.clicked.connect(on_accept)
        cancel_btn.clicked.connect(dlg.reject)
        dlg._btn_row.addWidget(accept_btn)
        dlg._btn_row.addWidget(cancel_btn)
        dlg.exec()
        return accepted["ok"]
