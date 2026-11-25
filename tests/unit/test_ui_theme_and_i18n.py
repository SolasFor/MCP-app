"""Unit tests for design tokens WCAG contrast, ThemeManager, RU/EN i18n, and UI settings."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import Settings
from app.ui import theme, tokens
from app.ui.i18n import LANG_EN, LANG_RU, Translator, keys_for


class UiTokensAndI18nTests(unittest.TestCase):
    def tearDown(self) -> None:
        theme.manager().set_mode(theme.THEME_DARK)

    def test_dark_and_light_tokens_meet_wcag_aa_contrast(self) -> None:
        for palette in (tokens.DARK_TOKENS, tokens.LIGHT_TOKENS):
            for surface in (palette.bg, palette.surface, palette.elevated):
                self.assertGreaterEqual(
                    tokens.contrast_ratio(palette.text_strong, surface), 4.5, f"{palette.name} text_strong on {surface}"
                )
                self.assertGreaterEqual(
                    tokens.contrast_ratio(palette.text, surface), 4.5, f"{palette.name} text on {surface}"
                )
                self.assertGreaterEqual(
                    tokens.contrast_ratio(palette.text_muted, surface), 4.5, f"{palette.name} text_muted on {surface}"
                )
                self.assertGreaterEqual(
                    tokens.contrast_ratio(palette.text_faint, surface), 4.5, f"{palette.name} text_faint on {surface}"
                )
            for bg_btn in (palette.accent_strong, palette.accent_hover, palette.accent_pressed):
                self.assertGreaterEqual(
                    tokens.contrast_ratio(palette.accent_text, bg_btn), 4.5, f"{palette.name} btn text on {bg_btn}"
                )

    def test_i18n_ru_and_en_have_exact_key_parity_and_live_signal(self) -> None:
        ru_keys = keys_for(LANG_RU)
        en_keys = keys_for(LANG_EN)
        self.assertEqual(ru_keys, en_keys)
        self.assertGreaterEqual(len(ru_keys), 100)

        translator = Translator(LANG_RU)
        events: list[str] = []
        translator.language_changed.connect(events.append)
        self.assertEqual(translator.t("nav.home"), "Главная")
        translator.set_language(LANG_EN)
        self.assertEqual(translator.t("nav.home"), "Home")
        self.assertEqual(events, [LANG_EN])
        translator.set_language("invalid")
        self.assertEqual(translator.language, LANG_RU)

    def test_theme_manager_system_mode_and_stylesheet_tokens(self) -> None:
        mgr = theme.manager()
        with patch("app.ui.theme.detect_system_theme", return_value=theme.THEME_LIGHT):
            mgr.set_mode(theme.THEME_SYSTEM)
            self.assertEqual(mgr.resolved, theme.THEME_LIGHT)
            self.assertEqual(theme.BG, tokens.LIGHT_TOKENS.bg)
        with patch("app.ui.theme.detect_system_theme", return_value=theme.THEME_DARK):
            mgr.set_mode(theme.THEME_SYSTEM)
            self.assertEqual(mgr.resolved, theme.THEME_DARK)
            self.assertEqual(theme.BG, tokens.DARK_TOKENS.bg)

    def test_settings_preserve_legacy_and_sanitize_new_ui_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({"tunnel_mode": "quick", "server_port": 8000}), encoding="utf-8")
            with patch.object(Settings, "path", return_value=path):
                loaded = Settings.load()
                self.assertEqual(loaded.theme_mode, "dark")
                self.assertEqual(loaded.language, "ru")
                self.assertFalse(loaded.sidebar_collapsed)
                self.assertEqual(loaded.window_width, 1120)

                path.write_text(
                    json.dumps(
                        {
                            "theme_mode": "neon",
                            "language": "fr",
                            "sidebar_collapsed": "yes",
                            "window_width": 100,
                            "window_height": "bad",
                        }
                    ),
                    encoding="utf-8",
                )
                broken = Settings.load()
                self.assertEqual(broken.theme_mode, "dark")
                self.assertEqual(broken.language, "ru")
                self.assertFalse(broken.sidebar_collapsed)
                self.assertEqual(broken.window_width, 1120)
                self.assertEqual(broken.window_height, 760)


if __name__ == "__main__":
    unittest.main()
