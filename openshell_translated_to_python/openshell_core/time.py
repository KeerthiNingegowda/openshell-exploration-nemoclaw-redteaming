# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Time helpers.

Translated from ``crates/openshell-core/src/time.rs`` (the ``now_ms`` helper used
by the secrets/credential modules). Rust returns milliseconds since the Unix
epoch as ``i64``.
"""

from __future__ import annotations

import time


def now_ms() -> int:
    """Current Unix time in milliseconds."""
    return int(time.time() * 1000)