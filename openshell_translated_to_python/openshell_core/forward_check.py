"""Local port-forward availability check.

Small helper corresponding to ``openshell_core::forward::check_port_available``
(``crates/openshell-core/src/forward.rs``). Used by the CLI before creating a
sandbox with a ``--forward`` spec so a busy local port fails fast instead of
orphaning a sandbox.

A forward spec is ``"local:remote"`` or ``"local:host:remote"``; we only need the
local port to test bindability.
"""

from __future__ import annotations

import socket


def _local_port(spec: str) -> int:
    first = spec.split(":", 1)[0]
    try:
        return int(first)
    except ValueError as exc:
        raise ValueError(f"invalid forward spec: {spec!r}") from exc


def check_port_available(spec: str) -> None:
    """Raise if the local port in ``spec`` cannot be bound (already in use)."""
    port = _local_port(spec)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ValueError(f"local port {port} is already in use") from exc
