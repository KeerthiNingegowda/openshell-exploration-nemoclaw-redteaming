# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Stable sandbox runtime generation identifier.

Translated from ``crates/openshell-core/src/sandbox_generation.rs`` (a new
upstream module referenced by ``jwt.py``).

``SandboxGenerationId`` identifies one requested *start* of a stable sandbox. The
gateway derives it from the durable lifecycle transition (a monotonic resource
version), so a retried driver call carries the same identity after a process
restart. Values are constrained to safe runtime-identifier characters.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class SandboxGenerationIdError(enum.Enum):
    EMPTY = "sandbox generation ID is required"
    TOO_LONG = "sandbox generation ID exceeds 64 characters"
    INVALID_CHARACTER = "sandbox generation ID contains an unsupported character"


class SandboxGenerationIdException(Exception):
    def __init__(self, kind: SandboxGenerationIdError) -> None:
        self.kind = kind
        super().__init__(kind.value)


@dataclass(frozen=True)
class SandboxGenerationId:
    _value: str

    MAX_LEN = 64

    @classmethod
    def from_start_resource_version(cls, resource_version: int) -> "SandboxGenerationId":
        """Stable generation for a gateway start transition (``g`` + 16 hex digits)."""
        return cls(f"g{resource_version:016x}")

    @classmethod
    def parse(cls, value: str) -> "SandboxGenerationId":
        if value == "":
            raise SandboxGenerationIdException(SandboxGenerationIdError.EMPTY)
        if len(value) > cls.MAX_LEN:
            raise SandboxGenerationIdException(SandboxGenerationIdError.TOO_LONG)
        if not all(("a" <= c <= "z") or c.isdigit() or c == "-" for c in value):
            raise SandboxGenerationIdException(SandboxGenerationIdError.INVALID_CHARACTER)
        return cls(value)

    def as_str(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value
