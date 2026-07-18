# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""openshell_tui — Python translation of the ``openshell-tui`` Rust crate.

Ports the ratatui-based terminal UI to the ``textual`` library.

- :mod:`openshell_tui.app` — application state model + textual App (``src/app.rs``).
- :mod:`openshell_tui.theme` — color themes (``src/theme.rs``).
"""

from . import app, theme

__all__ = ["app", "theme"]