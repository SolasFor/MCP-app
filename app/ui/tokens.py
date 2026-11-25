"""Design tokens (Minimalist Graphite + Muted Emerald Desktop UI) for Dark and Light themes."""
from __future__ import annotations

from dataclasses import dataclass

FONT_UI = '"Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif'
FONT_MONO = '"Cascadia Mono", "JetBrains Mono", "Consolas", monospace'
SANS_FAMILIES = ("Segoe UI Variable Text", "Segoe UI", "Inter")
MONO_FAMILIES = ("Cascadia Mono", "JetBrains Mono", "Consolas")

# Unified spacing & geometry scale (logical Qt pixels)
SPACE_XS = 4
SPACE_SM = 6
SPACE_MD = 8
SPACE_LG = 12
SPACE_XL = 16
SPACE_2XL = 20
SPACE_3XL = 24

RADIUS_SM = 5
RADIUS_CONTROL = 6
RADIUS_MD = 8
RADIUS_CARD = 8
RADIUS_LG = 8

WINDOW_DEFAULT_W = 960
WINDOW_DEFAULT_H = 640
WINDOW_MIN_W = 800
WINDOW_MIN_H = 540

SIDEBAR_WIDTH = 184
SIDEBAR_COLLAPSED_WIDTH = 52
NAV_ITEM_HEIGHT = 32
CONTROL_HEIGHT = 32
SETTING_ROW_HEIGHT = 38
TABLE_ROW_HEIGHT = 34
ICON_SIZE = 16


@dataclass(frozen=True)
class ThemeTokens:
    name: str
    bg: str
    sidebar: str
    surface: str
    elevated: str
    control: str
    control_hover: str
    control_pressed: str
    active: str
    input: str
    hairline: str
    border: str
    border_strong: str
    text_strong: str
    text: str
    text_muted: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_strong: str
    accent_pressed: str
    accent_text: str
    accent_soft_bg: str
    accent_soft_border: str
    btn_emphasis: str
    btn_emphasis_hover: str
    btn_emphasis_pressed: str
    btn_emphasis_border: str
    btn_emphasis_text: str
    link: str
    ok: str
    ok_soft_bg: str
    ok_soft_border: str
    warn: str
    warn_soft_bg: str
    warn_soft_border: str
    err: str
    err_soft_bg: str
    err_soft_border: str
    idle: str


DARK_TOKENS = ThemeTokens(
    name="dark",
    bg="#151617",
    sidebar="#1B1C1E",
    surface="#202124",
    elevated="#252629",
    control="#2C2E31",
    control_hover="#35373A",
    control_pressed="#3D4044",
    active="#303236",
    input="#1D1F21",
    hairline="#2B2D30",
    border="#35373B",
    border_strong="#484B50",
    text_strong="#F0F0F2",
    text="#EDEEF0",
    text_muted="#A1A4AB",
    text_faint="#8D9199",
    accent="#69B78B",
    accent_hover="#286B43",
    accent_strong="#2F7A4D",
    accent_pressed="#225C39",
    accent_text="#FFFFFF",
    accent_soft_bg="#1B2B22",
    accent_soft_border="#2D4D3B",
    btn_emphasis="#35383D",
    btn_emphasis_hover="#3F4349",
    btn_emphasis_pressed="#2C2E33",
    btn_emphasis_border="#4C5058",
    btn_emphasis_text="#F0F0F2",
    link="#69B78B",
    ok="#69B78B",
    ok_soft_bg="#1B2B22",
    ok_soft_border="#2D4D3B",
    warn="#D9A65C",
    warn_soft_bg="#2B2418",
    warn_soft_border="#4F3F24",
    err="#E57373",
    err_soft_bg="#2C1C1D",
    err_soft_border="#542F31",
    idle="#8D9199",
)

LIGHT_TOKENS = ThemeTokens(
    name="light",
    bg="#F7F8F9",
    sidebar="#EFEFF2",
    surface="#FFFFFF",
    elevated="#FFFFFF",
    control="#ECEEF0",
    control_hover="#E2E5E9",
    control_pressed="#D6DAE0",
    active="#E3E6EA",
    input="#FFFFFF",
    hairline="#E2E4E8",
    border="#D1D5DC",
    border_strong="#B4BAC4",
    text_strong="#141517",
    text="#232529",
    text_muted="#555961",
    text_faint="#636871",
    accent="#1F6E43",
    accent_hover="#1E5E3B",
    accent_strong="#267349",
    accent_pressed="#184D30",
    accent_text="#FFFFFF",
    accent_soft_bg="#E9F4EE",
    accent_soft_border="#B8DEC8",
    btn_emphasis="#232529",
    btn_emphasis_hover="#33363C",
    btn_emphasis_pressed="#18191C",
    btn_emphasis_border="#232529",
    btn_emphasis_text="#FFFFFF",
    link="#1F6E43",
    ok="#1F6E43",
    ok_soft_bg="#EAF5EE",
    ok_soft_border="#B9DFC9",
    warn="#9A6516",
    warn_soft_bg="#FDF6EA",
    warn_soft_border="#ECD3A4",
    err="#C43E3E",
    err_soft_bg="#FDF1F1",
    err_soft_border="#F2C2C2",
    idle="#636871",
)


def _linearize(channel_hex: str) -> float:
    c = int(channel_hex, 16) / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    """Compute WCAG 2.1 relative luminance for a `#RRGGBB` color."""
    cleaned = hex_color.lstrip("#")
    if len(cleaned) != 6:
        raise ValueError(f"Expected #RRGGBB hex color, got {hex_color!r}")
    r = _linearize(cleaned[0:2])
    g = _linearize(cleaned[2:4])
    b = _linearize(cleaned[4:6])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    """Compute WCAG 2.1 contrast ratio between two `#RRGGBB` colors."""
    l1 = relative_luminance(fg_hex)
    l2 = relative_luminance(bg_hex)
    hi, lo = (l1, l2) if l1 >= l2 else (l2, l1)
    return (hi + 0.05) / (lo + 0.05)
