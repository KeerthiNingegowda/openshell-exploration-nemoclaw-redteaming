# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Sandbox Protocol launch-correlation session identifier.

Translated from ``crates/openshell-core/src/sandbox_session.rs`` (a new upstream
module referenced by ``jwt.py``).

``SandboxSessionId`` is a random UUID that correlates the two ends of one Sandbox
Protocol launch. It is NOT carried in JWTs and is NOT an authorization identity —
it only coordinates a driver/supervisor handshake. The nil UUID is rejected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass


class SandboxSessionIdError(Exception):
    """The value is not a valid (non-nil) UUID session id."""


@dataclass(frozen=True)
class SandboxSessionId:
    _value: uuid.UUID

    @classmethod
    def new(cls) -> "SandboxSessionId":
        """Generate a fresh random (v4) session id."""
        return cls(uuid.uuid4())

    @classmethod
    def parse(cls, value: str) -> "SandboxSessionId":
        try:
            parsed = uuid.UUID(value)
        except ValueError as error:
            raise SandboxSessionIdError(str(error)) from error
        if parsed.int == 0:  # nil UUID is not a valid session id
            raise SandboxSessionIdError("nil UUID is not a valid session id")
        return cls(parsed)

    def __str__(self) -> str:
        return str(self._value)

    def __repr__(self) -> str:
        return f"SandboxSessionId({self._value})"
