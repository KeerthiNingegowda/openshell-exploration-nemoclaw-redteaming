"""openshell_tui — Python translation of the ``openshell-tui`` Rust crate.

Ports the ratatui-based terminal UI to the ``textual`` library.

- :mod:`openshell_tui.app` — application state model + textual App (``src/app.rs``).
- :mod:`openshell_tui.theme` — color themes (``src/theme.rs``).
"""

from . import app, theme

__all__ = ["app", "theme"]
