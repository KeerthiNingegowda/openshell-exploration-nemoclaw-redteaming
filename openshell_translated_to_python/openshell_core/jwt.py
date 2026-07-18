"""Minimal, signature-unverified JWT inspection.

Translated from ``crates/openshell-core/src/jwt.rs``.

This is used ONLY for client-side refresh scheduling (deciding when a bearer
token is near expiry). It never verifies the signature and must not be used for
any authorization decision — same warning as the Rust module.
"""

from __future__ import annotations

import base64
import json


def parse_exp_secs(token: str) -> int | None:
    """Decode the numeric ``exp`` claim (Unix seconds) without verifying.

    Returns ``None`` (Rust ``Option<i64>``) when the token is not a parseable
    JWT or has no integer ``exp`` claim. A leading ``"Bearer "`` prefix is
    tolerated so callers may pass a raw token or an ``authorization`` header.
    """
    raw = token[len("Bearer ") :] if token.startswith("Bearer ") else token
    parts = raw.split(".", 2)
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    # Rust uses URL_SAFE_NO_PAD; Python's urlsafe decoder needs padding restored.
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        value = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    exp = value.get("exp")
    if isinstance(exp, int):
        return exp
    return None
