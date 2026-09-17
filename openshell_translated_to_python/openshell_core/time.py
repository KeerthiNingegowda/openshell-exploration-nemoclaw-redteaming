# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Time helpers.

Translated from ``crates/openshell-core/src/time.rs``.

Besides ``now_ms`` (used by the secrets/credential modules), upstream added a
canonical conversion + validation suite for the protobuf well-known time types
``google.protobuf.Timestamp`` and ``google.protobuf.Duration``. Rust uses
``prost_types::{Timestamp, Duration}``; here we model both as tiny dataclasses
with ``seconds``/``nanos`` (matching the WKT wire fields) so the range and
canonicalization rules translate 1:1. Conversions raise :class:`ProtoTimeError`
rather than returning ``Result``.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass

# Earliest/latest second accepted by google.protobuf.Timestamp
# (0001-01-01 .. 9999-12-31 UTC).
MIN_TIMESTAMP_SECONDS = -62_135_596_800
MAX_TIMESTAMP_SECONDS = 253_402_300_799
# Largest absolute seconds component accepted by google.protobuf.Duration.
MAX_DURATION_SECONDS = 315_576_000_000


class ProtoTimeError(enum.Enum):
    """Protobuf WKT time value is non-canonical or unrepresentable."""

    TIMESTAMP_OUT_OF_RANGE = "TimestampOutOfRange"
    INVALID_TIMESTAMP_NANOS = "InvalidTimestampNanos"
    DURATION_OUT_OF_RANGE = "DurationOutOfRange"
    INVALID_DURATION_NANOS = "InvalidDurationNanos"
    NEGATIVE_DURATION = "NegativeDuration"
    OVERFLOW = "Overflow"


class ProtoTimeException(Exception):
    """Raised by the conversion helpers, carrying a :class:`ProtoTimeError`."""

    def __init__(self, kind: ProtoTimeError) -> None:
        self.kind = kind
        super().__init__(kind.value)


@dataclass(frozen=True)
class Timestamp:
    """``google.protobuf.Timestamp`` — seconds + nanos since the Unix epoch."""

    seconds: int
    nanos: int


@dataclass(frozen=True)
class Duration:
    """``google.protobuf.Duration`` — signed seconds + nanos."""

    seconds: int
    nanos: int


def now_ms() -> int:
    """Current Unix time in milliseconds."""
    return int(time.time() * 1000)


def validate_timestamp(value: Timestamp) -> None:
    """Validate a timestamp's range and canonical nanosecond component."""
    if not (MIN_TIMESTAMP_SECONDS <= value.seconds <= MAX_TIMESTAMP_SECONDS):
        raise ProtoTimeException(ProtoTimeError.TIMESTAMP_OUT_OF_RANGE)
    if not (0 <= value.nanos < 1_000_000_000):
        raise ProtoTimeException(ProtoTimeError.INVALID_TIMESTAMP_NANOS)


def compare_timestamps(left: Timestamp, right: Timestamp) -> int:
    """Compare two canonical timestamps (-1/0/1) without reducing precision."""
    validate_timestamp(left)
    validate_timestamp(right)
    lhs = (left.seconds, left.nanos)
    rhs = (right.seconds, right.nanos)
    return (lhs > rhs) - (lhs < rhs)


def timestamp_from_millis(value: int) -> Timestamp:
    """Convert Unix epoch milliseconds to a canonical timestamp.

    Uses floor division (Rust ``div_euclid``/``rem_euclid``) so negative
    millisecond values yield a canonical non-negative nanos component.
    """
    # Python's // and % already implement Euclidean (floor) semantics for
    # positive divisors, matching Rust's div_euclid/rem_euclid here.
    timestamp = Timestamp(seconds=value // 1_000, nanos=(value % 1_000) * 1_000_000)
    validate_timestamp(timestamp)
    return timestamp


def optional_timestamp_from_legacy_millis(value: int) -> Timestamp | None:
    """Convert a legacy timestamp where zero meant "unset" to WKT presence."""
    if value == 0:
        return None
    return timestamp_from_millis(value)


def timestamp_to_millis(value: Timestamp) -> int:
    """Convert a canonical timestamp to Unix epoch milliseconds (truncating nanos)."""
    validate_timestamp(value)
    return value.seconds * 1_000 + value.nanos // 1_000_000


def timestamp_from_unix_seconds_float(value: float) -> Timestamp:
    """Convert a Python ``time.time()``-style float to a canonical timestamp.

    Python analogue of Rust's ``timestamp_from_system_time`` (which converts a
    ``SystemTime``). Handles pre-epoch (negative) values with the same
    carry/borrow of the nanos component that the Rust source performs.
    """
    seconds = int(value // 1)
    nanos = int(round((value - seconds) * 1_000_000_000))
    if nanos == 1_000_000_000:  # rounding carry
        seconds += 1
        nanos = 0
    timestamp = Timestamp(seconds=seconds, nanos=nanos)
    validate_timestamp(timestamp)
    return timestamp


def unix_seconds_float_from_timestamp(value: Timestamp) -> float:
    """Inverse of :func:`timestamp_from_unix_seconds_float`."""
    validate_timestamp(value)
    return value.seconds + value.nanos / 1_000_000_000


def validate_duration(value: Duration) -> None:
    """Validate a duration's range and sign-consistent nanosecond component."""
    if not (-MAX_DURATION_SECONDS <= value.seconds <= MAX_DURATION_SECONDS):
        raise ProtoTimeException(ProtoTimeError.DURATION_OUT_OF_RANGE)
    if (
        not (-999_999_999 <= value.nanos <= 999_999_999)
        or (value.seconds > 0 and value.nanos < 0)
        or (value.seconds < 0 and value.nanos > 0)
    ):
        raise ProtoTimeException(ProtoTimeError.INVALID_DURATION_NANOS)


def duration_from_seconds_float(value: float) -> Duration:
    """Convert a non-negative float seconds value to a canonical duration.

    Python analogue of Rust's ``duration_from_std`` (``std::time::Duration`` is
    unsigned, so the input is non-negative).
    """
    seconds = int(value // 1)
    nanos = int(round((value - seconds) * 1_000_000_000))
    duration = Duration(seconds=seconds, nanos=nanos)
    validate_duration(duration)
    return duration


def duration_to_seconds_float(value: Duration) -> float:
    """Convert a non-negative canonical duration to float seconds."""
    validate_duration(value)
    if value.seconds < 0 or value.nanos < 0:
        raise ProtoTimeException(ProtoTimeError.NEGATIVE_DURATION)
    return value.seconds + value.nanos / 1_000_000_000