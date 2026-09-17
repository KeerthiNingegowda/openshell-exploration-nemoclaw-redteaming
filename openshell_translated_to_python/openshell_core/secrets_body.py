# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Metadata-only classification for REST bodies whose credential rewrite is disabled.

Translated from ``crates/openshell-core/src/secrets_body.rs`` (upstream ``mod body``
of ``secrets.rs``; referenced by :mod:`openshell_core.secrets` and the
provider-credentials body classifier).

Where header/URL rewriting *resolves* placeholders into real secrets, request
bodies where rewrite is disabled must instead be *classified*: a complete
reserved token may be forwarded unchanged only if it is a currently-issued,
non-expired, endpoint-bound credential — and it is never resolved to its secret.
Anything else fails closed.

Two pieces:

- :class:`BodyCredentialClassifier` — an immutable snapshot that says whether a
  given token is *authorized to forward unchanged*. It holds no secret values,
  only validity/expiry status and the known/bound/allowed-revision sets.
- :class:`BodyPlaceholderGuard` — a streaming guard that withholds any complete
  reserved candidate until the classifier authorizes it, retaining a trailing
  window so a marker split across reads cannot leak. Percent-encoding is decoded
  for scanning while permitted bytes are released verbatim (never normalized).

This is a faithful translation; it is the body-scanning half of the credential
security model and so is translated in full rather than stubbed.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .secrets import (
    CREDENTIAL_MARKER_SCAN_TAIL_BYTES,
    PLACEHOLDER_PREFIX,
    PROVIDER_ALIAS_MARKER,
    SecretResolver,
    _alias_env_key,
    _is_alias_token_char,
    _is_env_key_char,
    _revisioned_placeholder_parts,
    _split_revisioned_env_key,
    _stable_placeholder_parts,
    _validate_resolved_secret,
    placeholder_env_key,
    placeholder_for_env_key,
)
from .time import now_ms

# Maximum retained candidate on the wire, including percent encoding.
MAX_BODY_TOKEN_BYTES = 4096


class BodyCredentialError(enum.Enum):
    """Why a reserved body token cannot be forwarded. Contains no request data."""

    KNOWN_UNAVAILABLE = "known_unavailable"
    CLASSIFICATION_UNAVAILABLE = "classification_unavailable"
    INVALID_TOKEN = "invalid_token"
    TOKEN_TOO_LONG = "token_too_long"
    TRAILER = "trailer"

    def reason(self) -> str:
        return self.value


class BodyCredentialException(Exception):
    """Raised by the body guard/classifier, carrying a :class:`BodyCredentialError`."""

    def __init__(self, kind: BodyCredentialError) -> None:
        self.kind = kind
        super().__init__(
            "request body credential placeholder denied because rewrite is disabled "
            f"({kind.reason()})"
        )


@dataclass(frozen=True)
class _ValueStatus:
    valid: bool
    expires_at_ms: int


class BodyCredentialClassifier:
    """Immutable classification snapshot. Deliberately holds no secret values."""

    def __init__(
        self,
        resolver: SecretResolver | None = None,
        known: set[str] | None = None,
        bound: set[str] | None = None,
        revisions: dict[str, set[int]] | None = None,
    ) -> None:
        self._values: dict[str, _ValueStatus] = {}
        self._known: set[str] = set(known or ())
        self._bound: set[str] = set(bound or ())
        self._revisions: dict[str, set[int]] = dict(revisions or {})
        if resolver is not None:
            for token, value in resolver._by_placeholder.items():
                key = placeholder_env_key(token)
                if key is not None:
                    self._known.add(key)
                self._values[token] = _ValueStatus(
                    valid=_validate_resolved_secret(value.value) is not None,
                    expires_at_ms=value.expires_at_ms,
                )

    def check(self, token: str) -> None:
        """Authorize forwarding a complete token unchanged; never resolve it.

        Raises :class:`BodyCredentialException` when the token may not be
        forwarded.
        """
        # Provider-shaped aliases use canonical-key fallback in the resolver;
        # normalize that spelling here too (including revision/handle suffixes).
        alias_key = _alias_env_key(token)
        if alias_key is not None:
            self.check(placeholder_for_env_key(alias_key))
            return

        key = placeholder_env_key(token)
        if key is None:
            raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)
        if key == "" or not all(_is_env_key_char(ch) for ch in key):
            raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)

        # Reserved identity namespaces must parse completely (incl. u64 overflow).
        if token.startswith(PLACEHOLDER_PREFIX):
            suffix = token[len(PLACEHOLDER_PREFIX) :]
            if (
                _split_revisioned_env_key(suffix) is not None
                and _revisioned_placeholder_parts(token) is None
            ):
                raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)
            ident, sep, underlying = suffix.partition("_")
            if (
                sep
                and (ident.startswith("v") or ident.startswith("s"))
                and underlying in self._known
                and _revisioned_placeholder_parts(token) is None
                and _stable_placeholder_parts(token) is None
            ):
                raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)

        if key not in self._known:
            return
        # A tombstone or a legacy unbound key is not a currently issued credential.
        # Destination membership does not matter: this never resolves body text.
        if key not in self._bound:
            raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)

        revision = _revisioned_placeholder_parts(token)
        if revision is None and _stable_placeholder_parts(token) is None:
            raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)
        if revision is not None:
            rev_num = revision[0]
            allowed = self._revisions.get(key)
            if allowed is None or rev_num not in allowed:
                raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)

        value = self._values.get(token)
        if value is None and revision is not None:
            value = self._values.get(placeholder_for_env_key(key))
        if value is None:
            raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)
        if not value.valid or (value.expires_at_ms > 0 and value.expires_at_ms <= now_ms()):
            raise BodyCredentialException(BodyCredentialError.KNOWN_UNAVAILABLE)


class BodyPlaceholderGuard:
    """Withholds complete reserved candidates while streaming unrelated body bytes.

    Use :meth:`push` for each chunk (returns bytes safe to forward now) and
    :meth:`finish` at EOF (flushes the remainder). A reserved candidate is only
    released once :meth:`BodyCredentialClassifier.check` authorizes it.
    """

    def __init__(self, classifier: BodyCredentialClassifier | None) -> None:
        self._pending = bytearray()
        self._classifier = classifier
        self._previous_decoded: int | None = None

    def push(self, data: bytes) -> bytes:
        output = bytearray()
        # Bound pending storage even if the caller supplies an entire large body.
        # Matches Rust ``bytes.chunks(..)``: empty input yields no iterations.
        for i in range(0, len(data), MAX_BODY_TOKEN_BYTES):
            self._pending.extend(data[i : i + MAX_BODY_TOKEN_BYTES])
            output.extend(self._release(eof=False))
        return bytes(output)

    def finish(self) -> bytes:
        return bytes(self._release(eof=True))

    def _release(self, eof: bool) -> bytearray:
        # Track wire offsets so permitted bytes are released without normalization.
        decoded = bytearray()
        offsets: list[int] = []
        wire = 0
        pending = self._pending
        n = len(pending)
        while wire < n:
            offsets.append(wire)
            if pending[wire] == ord("%"):
                if wire + 2 >= n and not eof:
                    offsets.pop()
                    break
                if wire + 3 <= n:
                    hi = _hex_val(pending[wire + 1])
                    lo = _hex_val(pending[wire + 2])
                    if hi is not None and lo is not None:
                        decoded.append(hi * 16 + lo)
                        wire += 3
                        continue
            decoded.append(pending[wire])
            wire += 1
        offsets.append(wire)

        safe = wire if eof else max(0, wire - CREDENTIAL_MARKER_SCAN_TAIL_BYTES)

        prefix = PLACEHOLDER_PREFIX.encode()
        marker = PROVIDER_ALIAS_MARKER.encode()
        pos = 0
        dlen = len(decoded)
        while pos < dlen:
            canonical = decoded[pos:].startswith(prefix)
            alias = decoded[pos:].startswith(marker)
            if not canonical and not alias:
                pos += 1
                continue
            start = pos
            key_start = pos + (len(prefix) if canonical else len(marker))
            end = key_start
            while end < dlen and _is_env_key_char(chr(decoded[end])):
                # Adjacent canonical references are separate tokens.
                if end > key_start and decoded[end:].startswith(prefix):
                    break
                end += 1
            if offsets[end] - offsets[start] > MAX_BODY_TOKEN_BYTES:
                raise BodyCredentialException(BodyCredentialError.TOKEN_TOO_LONG)
            if end == dlen and not eof:
                # Without metadata, preserve the prefix-only fail-closed behavior.
                if self._classifier is None:
                    raise BodyCredentialException(BodyCredentialError.CLASSIFICATION_UNAVAILABLE)
                safe = min(safe, offsets[start])
                break
            if end == key_start:
                raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)

            token = ""
            if alias:
                if end < dlen and _is_alias_token_char(chr(decoded[end])):
                    raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)
                if start >= 1:
                    previous: int | None = decoded[start - 1]
                else:
                    previous = self._previous_decoded
                if previous is None or not _is_alias_token_char(chr(previous)):
                    raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN)
                # Alias prefix spelling does not select the env key.
                token += "x"
            try:
                token += decoded[start:end].decode("utf-8")
            except UnicodeDecodeError as error:
                raise BodyCredentialException(BodyCredentialError.INVALID_TOKEN) from error
            if self._classifier is None:
                raise BodyCredentialException(BodyCredentialError.CLASSIFICATION_UNAVAILABLE)
            self._classifier.check(token)
            safe = max(safe, offsets[end])
            pos = end

        # Never split a percent triplet, which would change the next scan's view.
        index = _partition_point(offsets, safe) - 1
        if index < 0:
            index = 0
        safe = offsets[index]
        if index > 0:
            self._previous_decoded = decoded[index - 1]
        released = self._pending[:safe]
        del self._pending[:safe]
        return bytearray(released)


def _hex_val(byte: int) -> int | None:
    ch = chr(byte).lower()
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "a" <= ch <= "f":
        return 10 + ord(ch) - ord("a")
    return None


def _partition_point(offsets: list[int], safe: int) -> int:
    """Number of leading offsets ``<= safe`` (Rust ``slice::partition_point``)."""
    count = 0
    for offset in offsets:
        if offset <= safe:
            count += 1
        else:
            break
    return count
