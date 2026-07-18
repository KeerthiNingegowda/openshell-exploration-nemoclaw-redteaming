"""Shared image-name resolution for community sandbox images.

Translated from ``crates/openshell-core/src/image.rs``.

Both the CLI and TUI expand bare sandbox names (e.g. ``"base"``) into
fully-qualified container image references. Centralised so every client resolves
names identically.
"""

from __future__ import annotations

import os

# Bare sandbox names expand to ``{prefix}/{name}:latest``. Override at runtime
# with the ``OPENSHELL_COMMUNITY_REGISTRY`` env var.
DEFAULT_COMMUNITY_REGISTRY = "ghcr.io/nvidia/openshell-community/sandboxes"


def default_sandbox_image() -> str:
    """Return ``{registry}/base:latest`` — the fallback image for all drivers."""
    return f"{DEFAULT_COMMUNITY_REGISTRY}/base:latest"


def resolve_community_image(value: str) -> str:
    """Resolve a user-supplied image string into a fully-qualified reference.

    1. If the value contains ``/``, ``:`` or ``.`` it is already a complete
       reference and returned as-is.
    2. Otherwise it is a community sandbox shorthand, expanded to
       ``{registry}/{value}:latest`` where ``{registry}`` defaults to
       :data:`DEFAULT_COMMUNITY_REGISTRY` but can be overridden via the
       ``OPENSHELL_COMMUNITY_REGISTRY`` environment variable.
    """
    if "/" in value or ":" in value or "." in value:
        return value
    prefix = os.environ.get("OPENSHELL_COMMUNITY_REGISTRY") or DEFAULT_COMMUNITY_REGISTRY
    prefix = prefix.rstrip("/")
    return f"{prefix}/{value}:latest"
