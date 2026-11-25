"""Design tokens (Linear + Docker Desktop aesthetic) for Dark and Light themes."""
from __future__ import annotations

from dataclasses import dataclass

FONT_UI = '"Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif'
FONT_MONO = '"Cascadia Mono", "JetBrains Mono", "Consolas", monospace'
SANS_FAMILIES = ("Segoe UI Variable Text", "Segoe UI", "Inter")
MONO_FAMILIES = ("Cascadia Mono", "JetBrains Mono", "Consolas")

RADIUS_SM = 6
RADIUS_MD = 8
RADIUS_LG = 10


@dataclass(frozen=True)
class ThemeTokens:
    name: str
    bg: str
    sidebar: str
    surface: str
    elevated: str
    control: str
    control_hover: str
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
    bg="#14151A",
    sidebar="#191A21",
    surface="#191A21",
    elevated="#20222B",
    control="#232530",
    control_hover="#2C2F3D",
    active="#292C3A",
    input="#111217",
    hairline="#272832",
    border="#313340",
    border_strong="#414454",
    text_strong="#F4F4F5",
    text="#E4E4E7",
    text_muted="#A1A1AA",
    text_faint="#8E909E",
    accent="#818CF8",
    accent_hover="#5154DC",
    accent_strong="#5B5EE6",
    accent_pressed="#4648C7",
    accent_text="#FFFFFF",
    accent_soft_bg="#1E2038",
    accent_soft_border="#383B6B",
    link="#818CF8",
    ok="#34D399",
    ok_soft_bg="#122922",
    ok_soft_border="#1F4D3E",
    warn="#FBBF24",
    warn_soft_bg="#2D2512",
    warn_soft_border="#57441A",
    err="#F87171",
    err_soft_bg="#2F191C",
    err_soft_border="#5C2A30",
    idle="#8E909E",
)

LIGHT_TOKENS = ThemeTokens(
    name="light",
    bg="#F8F9FC",
    sidebar="#FFFFFF",
    surface="#FFFFFF",
    elevated="#FFFFFF",
    control="#F1F3F7",
    control_hover="#E5E8F0",
    active="#ECEEFE",
    input="#FFFFFF",
    hairline="#E2E4E9",
    border="#D4D7DF",
    border_strong="#B8BDCB",
    text_strong="#18181B",
    text="#27272A",
    text_muted="#52525B",
    text_faint="#646975",
    accent="#635BDE",
    accent_hover="#524AD1",
    accent_strong="#635BDE",
    accent_pressed="#463EC0",
    accent_text="#FFFFFF",
    accent_soft_bg="#EEF0FF",
    accent_soft_border="#C7CCF8",
    link="#554DD4",
    ok="#15803D",
    ok_soft_bg="#ECFDF3",
    ok_soft_border="#BBF7D0",
    warn="#B45309",
    warn_soft_bg="#FFFBEB",
    warn_soft_border="#FDE68A",
    err="#DC2626",
    err_soft_bg="#FEF2F2",
    err_soft_border="#FECACA",
    idle="#646975",
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
