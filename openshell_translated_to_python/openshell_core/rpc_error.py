# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Standard gRPC error details shared by gateway handlers and SDK clients.

Translated from ``crates/openshell-core/src/rpc_error.rs`` (a new upstream module).

Retry guidance describes recovery from a failure. It never establishes that
repeating an arbitrary mutation is safe.

Rust builds ``tonic::Status`` values carrying ``google.rpc`` detail messages
(``BadRequest`` / ``ErrorInfo`` / ``RetryInfo``). We have no tonic here, so the
gRPC :class:`Status` and :class:`ErrorDetails` are modeled as small dataclasses
that carry the same fields; the constructor helpers and the (structural)
``decode_details`` validation translate 1:1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# Domain of gateway-owned machine-readable error reasons.
ERROR_DOMAIN = "openshell.nvidia.com"


class Code(Enum):
    """Subset of gRPC status codes used by this module."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    FAILED_PRECONDITION = "FAILED_PRECONDITION"
    ABORTED = "ABORTED"
    UNAVAILABLE = "UNAVAILABLE"
    INTERNAL = "INTERNAL"


@dataclass
class FieldViolation:
    field: str
    description: str


@dataclass
class ErrorInfo:
    reason: str
    domain: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ErrorDetails:
    """``google.rpc`` detail bundle (BadRequest + ErrorInfo + RetryInfo)."""

    bad_request_violations: list[FieldViolation] = field(default_factory=list)
    error_info: ErrorInfo | None = None
    # Retry delay in seconds (Rust ``Duration``); ``None`` if absent.
    retry_delay_secs: float | None = None

    def add_bad_request_violation(self, field_name: str, description: str) -> None:
        self.bad_request_violations.append(FieldViolation(field_name, description))

    def set_error_info(self, reason: str, domain: str, metadata: dict[str, str]) -> None:
        self.error_info = ErrorInfo(reason, domain, dict(metadata))

    def set_retry_info(self, delay_secs: float | None) -> None:
        self.retry_delay_secs = delay_secs


@dataclass
class Status:
    """gRPC status: a code, a human message, and structured details."""

    code: Code
    message: str
    details: ErrorDetails = field(default_factory=ErrorDetails)


# Largest absolute seconds accepted for a RetryInfo delay (protobuf Duration).
_MAX_RETRY_DELAY_SECONDS = 315_576_000_000


def decode_details(status: Status) -> ErrorDetails | None:
    """Return the details, rejecting an envelope inconsistent with the status.

    Mirrors the Rust check that the embedded envelope's ``code``/``message`` match
    the outer status, and that a ``RetryInfo`` delay is within canonical range;
    an out-of-range delay is dropped while other details are preserved.
    """
    details = status.details
    validated = ErrorDetails(
        bad_request_violations=list(details.bad_request_violations),
        error_info=details.error_info,
    )
    if details.retry_delay_secs is not None and 0 <= details.retry_delay_secs <= _MAX_RETRY_DELAY_SECONDS:
        validated.retry_delay_secs = details.retry_delay_secs
    return validated


def invalid_argument(field_name: str, message: str) -> Status:
    """A field-level validation failure (never reflects the field value)."""
    details = ErrorDetails()
    details.add_bad_request_violation(field_name, message)
    details.set_error_info("INVALID_ARGUMENT", ERROR_DOMAIN, {})
    return Status(Code.INVALID_ARGUMENT, message, details)


def failed_precondition(reason: str, message: str) -> Status:
    """A precondition failure with a stable reason."""
    details = ErrorDetails()
    details.set_error_info(reason, ERROR_DOMAIN, {})
    return Status(Code.FAILED_PRECONDITION, message, details)


def resource_version_conflict(message: str, version: int | None) -> Status:
    """A conditional write lost a race; read fresh state before a new write."""
    metadata = {"recovery": "REFRESH_STATE"}
    if version is not None:
        metadata["current_resource_version"] = str(version)
    details = ErrorDetails()
    details.set_error_info("RESOURCE_VERSION_CONFLICT", ERROR_DOMAIN, metadata)
    return Status(Code.ABORTED, message, details)


def unavailable(reason: str, message: str, delay_secs: float) -> Status:
    """A transient failure with a minimum delay for retry-safe operations."""
    details = ErrorDetails()
    details.set_error_info(reason, ERROR_DOMAIN, {})
    details.set_retry_info(delay_secs)
    return Status(Code.UNAVAILABLE, message, details)
