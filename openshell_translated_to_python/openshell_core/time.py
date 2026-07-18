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
