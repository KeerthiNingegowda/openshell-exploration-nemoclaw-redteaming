"""Color theme for the TUI.

Translated from ``crates/openshell-tui/src/theme.rs``.

Rust uses ``ratatui::style::Style`` values keyed by semantic role (text, accent,
border, status_ok/warn/err ...). Since the Python TUI targets ``textual``, we
express the same palette as CSS-style hex colors plus a small dataclass of
semantic roles. The NVIDIA brand colors are preserved exactly.

Rust patterns:
- ``enum ThemeMode { Auto, Dark, Light }`` -> :class:`enum.Enum` with FromStr.
- ``struct Theme { pub text: Style, ... }`` -> :class:`Theme` dataclass of colors.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ThemeMode(Enum):
    AUTO = "auto"  # detect from terminal; fall back to dark
    DARK = "dark"
    LIGHT = "light"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, s: str) -> "ThemeMode":
        v = s.lower()
        for member in cls:
            if member.value == v:
                return member
        raise ValueError(f"unknown theme mode: {s} (expected auto, dark, or light)")


# Brand colors shared between themes (Rust ``mod brand``).
NVIDIA_GREEN = "#76b900"
NVIDIA_GREEN_DARK = "#508c00"
EVERGLADE = "#123123"
MAROON = "#800000"


@dataclass(frozen=True)
class Theme:
    """Semantic color roles used throughout the UI (as hex strings)."""

    text: str
    muted: str
    heading: str
    accent: str
    accent_bold: str
    border: str
    border_focused: str
    status_ok: str
    status_warn: str
    status_err: str
    key_hint: str
    claw: str
    title_bar: str
    badge: str

    @classmethod
    def dark(cls) -> "Theme":
        """Dark theme — NVIDIA green on a dark terminal background."""
        return cls(
            text="white",
            muted="grey62",
            heading="white",
            accent=NVIDIA_GREEN,
            accent_bold=NVIDIA_GREEN,
            border=EVERGLADE,
            border_focused=NVIDIA_GREEN,
            status_ok=NVIDIA_GREEN,
            status_warn="yellow",
            status_err="red",
            key_hint=NVIDIA_GREEN,
            claw=NVIDIA_GREEN,
            title_bar=EVERGLADE,
            badge=NVIDIA_GREEN_DARK,
        )

    @classmethod
    def light(cls) -> "Theme":
        """Light theme — darker green on a light background."""
        return cls(
            text="black",
            muted="grey37",
            heading="black",
            accent=NVIDIA_GREEN_DARK,
            accent_bold=NVIDIA_GREEN_DARK,
            border="grey70",
            border_focused=NVIDIA_GREEN_DARK,
            status_ok=NVIDIA_GREEN_DARK,
            status_warn="yellow",
            status_err="red",
            key_hint=NVIDIA_GREEN_DARK,
            claw=NVIDIA_GREEN_DARK,
            title_bar="grey85",
            badge=NVIDIA_GREEN_DARK,
        )


def detect(mode: ThemeMode) -> Theme:
    """Resolve a :class:`ThemeMode` into a concrete :class:`Theme`.

    ``AUTO`` falls back to dark (matching the Rust default when terminal
    background detection is unavailable).
    """
    if mode is ThemeMode.LIGHT:
        return Theme.light()
    return Theme.dark()
