"""Regression tests for secure settings defaults and upgrade validation."""
from __future__ import annotations

import unittest

from app.config import Settings


class SettingsSecurityTests(unittest.TestCase):
    def test_fresh_install_is_standard_profile(self) -> None:
        settings = Settings()
        self.assertFalse(settings.allow_query_token)
        self.assertFalse(settings.enable_advanced_tools)
        self.assertFalse(settings.enable_execution_tools)

    def test_old_query_token_setting_is_disabled_on_upgrade(self) -> None:
        settings = Settings(allow_query_token=True)
        settings.sanitize()
        self.assertFalse(settings.allow_query_token)

    def test_execution_cannot_be_enabled_without_advanced(self) -> None:
        settings = Settings(enable_advanced_tools=False, enable_execution_tools=True)
        settings.sanitize()
        self.assertFalse(settings.enable_execution_tools)

    def test_malformed_settings_do_not_enable_public_privileges(self) -> None:
        settings = Settings(
            allow_query_token="false",  # type: ignore[arg-type]
            enable_advanced_tools="false",  # type: ignore[arg-type]
            enable_execution_tools="true",  # type: ignore[arg-type]
        )
        settings.sanitize()
        self.assertFalse(settings.allow_query_token)
        self.assertFalse(settings.enable_advanced_tools)
        self.assertFalse(settings.enable_execution_tools)

    def test_explicit_boolean_advanced_opt_in_preserved(self) -> None:
        settings = Settings(enable_advanced_tools=True, enable_execution_tools=False)
        settings.sanitize()
        self.assertTrue(settings.enable_advanced_tools)
        self.assertFalse(settings.enable_execution_tools)


if __name__ == "__main__":
    unittest.main()
