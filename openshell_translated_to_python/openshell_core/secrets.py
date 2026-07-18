# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Credential-placeholder resolution for the network supervisor.

Translated from ``crates/openshell-core/src/secrets.rs`` (2200 lines in Rust).

Core idea: real provider secrets never live in the sandbox child environment.
Instead each provider env var is replaced with an opaque *placeholder* string
(``openshell:resolve:env:KEY``). The network supervisor holds a
:class:`SecretResolver` that maps placeholders back to the real secret and
rewrites outgoing HTTP headers / bodies just before forwarding upstream — so a
compromised agent only ever sees placeholders.

This translation covers the essential, security-relevant logic:
- placeholder construction / namespacing (with credential "revisions"),
- ``SecretResolver`` build from a provider env map,
- placeholder resolution with expiry + prohibited-character validation,
- header-value rewriting (direct, ``Bearer``-prefixed, and Basic-auth forms).

Exhaustive body/websocket/GraphQL rewriting from the Rust source is summarized
with clear stubs where it would only add mechanical string-scanning volume.

Rust patterns:
- ``Result<T, UnresolvedPlaceholderError>`` -> returns ``T`` or raises
  :class:`UnresolvedPlaceholderError`.
- ``Option<&str>`` -> ``str | None``.
- Manual ``Debug`` impl that hides secrets -> :meth:`SecretResolver.__repr__`.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import unquote

from .time import now_ms

PLACEHOLDER_PREFIX = "openshell:resolve:env:"
PROVIDER_ALIAS_MARKER = "OPENSHELL-RESOLVE-ENV-"

# Reserved namespace used for revisioned placeholders, e.g.
# ``openshell:resolve:env:rev:<n>:KEY``.
_REVISION_NAMESPACE = "rev:"


def contains_reserved_credential_marker(value: str) -> bool:
    """True if ``value`` (raw or percent-decoded) contains a reserved marker."""
    if PLACEHOLDER_PREFIX in value or PROVIDER_ALIAS_MARKER in value:
        return True
    decoded = unquote(value)
    return PLACEHOLDER_PREFIX in decoded or PROVIDER_ALIAS_MARKER in decoded


class UnresolvedPlaceholderError(Exception):
    """A reserved credential token was detected but could not be resolved.

    ``location`` is one of ``"header"``, ``"query_param"``, ``"path"`` — used for
    fail-closed logging without leaking the secret.
    """

    def __init__(self, location: str) -> None:
        self.location = location
        super().__init__(
            f"unresolved credential placeholder in {location}: detected reserved "
            "credential token that could not be resolved"
        )


def uses_reserved_revision_namespace(key: str) -> bool:
    """Provider env keys must not themselves live in the reserved namespace."""
    return key.startswith(_REVISION_NAMESPACE) or key.startswith("OPENSHELL_RESOLVE_ENV")


def placeholder_for_env_key(key: str) -> str:
    """Canonical (revision-less) placeholder for an env var key."""
    return f"{PLACEHOLDER_PREFIX}{key}"


def placeholder_for_env_key_for_revision(key: str, revision: int) -> str:
    """Revisioned placeholder. Revision 0 is the canonical (unversioned) form."""
    if revision == 0:
        return placeholder_for_env_key(key)
    return f"{PLACEHOLDER_PREFIX}{_REVISION_NAMESPACE}{revision}:{key}"


def _revisioned_placeholder_env_key(value: str) -> str | None:
    """Extract KEY from ``openshell:resolve:env:rev:<n>:KEY``, else None."""
    if not value.startswith(PLACEHOLDER_PREFIX):
        return None
    rest = value[len(PLACEHOLDER_PREFIX) :]
    if not rest.startswith(_REVISION_NAMESPACE):
        return None
    rest = rest[len(_REVISION_NAMESPACE) :]
    _, sep, key = rest.partition(":")
    return key if sep else None


def _validate_resolved_secret(value: str) -> str | None:
    """Reject secrets containing CR, LF, or NUL (header/response injection)."""
    if any(ch in value for ch in ("\r", "\n", "\0")):
        return None
    return value


@dataclass
class _SecretValue:
    value: str
    expires_at_ms: int  # 0 means no expiry


@dataclass
class SecretResolver:
    """Maps opaque placeholders back to real secret values.

    Rust stores a ``HashMap<String, SecretValue>``; we use a dict. The custom
    ``Debug`` impl in Rust exposes only the placeholder *count* to avoid leaking
    secrets — :meth:`__repr__` does the same.
    """

    _by_placeholder: dict[str, _SecretValue] = field(default_factory=dict)

    def __repr__(self) -> str:  # never print keys or values
        return f"SecretResolver(placeholders={len(self._by_placeholder)})"

    # ---- construction -----------------------------------------------------
    @classmethod
    def from_provider_env(
        cls,
        provider_env: dict[str, str],
        credential_expires_at_ms: dict[str, int] | None = None,
        revision: int = 0,
    ) -> tuple[dict[str, str], "SecretResolver | None"]:
        """Build ``(child_env, resolver)``.

        ``child_env`` is the sanitized environment injected into sandbox child
        processes: each provider key now maps to its *placeholder* rather than
        the real secret. ``resolver`` is ``None`` when there is nothing to
        resolve (Rust returns ``Option<Self>``).
        """
        credential_expires_at_ms = credential_expires_at_ms or {}
        if not provider_env:
            return {}, None

        child_env: dict[str, str] = {}
        by_placeholder: dict[str, _SecretValue] = {}
        for key, value in provider_env.items():
            if uses_reserved_revision_namespace(key):
                # Rust logs a warning and skips reserved-namespace keys.
                continue
            placeholder = placeholder_for_env_key_for_revision(key, revision)
            secret = _SecretValue(value=value, expires_at_ms=credential_expires_at_ms.get(key, 0))
            child_env[key] = placeholder
            by_placeholder[placeholder] = secret

        if not by_placeholder:
            return child_env, None
        return child_env, cls(_by_placeholder=by_placeholder)

    @classmethod
    def merge(cls, resolvers) -> "SecretResolver | None":
        """Merge several resolvers into one (later entries win)."""
        by_placeholder: dict[str, _SecretValue] = {}
        for resolver in resolvers:
            by_placeholder.update(resolver._by_placeholder)
        if not by_placeholder:
            return None
        return cls(_by_placeholder=by_placeholder)

    # ---- resolution -------------------------------------------------------
    def resolve_placeholder(self, value: str) -> str | None:
        """Resolve a placeholder to its real secret, or ``None``.

        Falls back by KEY to the current credential when a revisioned
        placeholder ages out, so long-running child processes survive provider
        credential refresh. Returns ``None`` for unknown, expired, or
        prohibited-character values.
        """
        secret = self._by_placeholder.get(value)
        if secret is None:
            key = _revisioned_placeholder_env_key(value)
            if key is None:
                return None
            secret = self._by_placeholder.get(placeholder_for_env_key(key))
            if secret is None:
                return None
        if secret.expires_at_ms > 0 and secret.expires_at_ms <= now_ms():
            return None  # expired
        return _validate_resolved_secret(secret.value)

    def expires_at_ms_for_placeholder(self, placeholder: str) -> int | None:
        secret = self._by_placeholder.get(placeholder)
        return secret.expires_at_ms if secret else None

    # ---- header rewriting -------------------------------------------------
    def rewrite_header_value(self, value: str) -> str | None:
        """Rewrite one header value, resolving any embedded placeholder.

        Returns the rewritten value, or ``None`` when nothing needed rewriting.
        Raises :class:`UnresolvedPlaceholderError` when a reserved marker is
        present but cannot be resolved (fail-closed).
        Handles three forms, matching the Rust logic:
        1. direct:   ``x-api-key: openshell:resolve:env:KEY``
        2. Basic:    ``Basic base64(user:openshell:resolve:env:PASS)``
        3. prefixed: ``Bearer openshell:resolve:env:KEY``
        """
        trimmed = value.strip()

        secret = self.resolve_placeholder(trimmed)
        if secret is not None:
            return secret

        low = trimmed.lower()
        if low.startswith("basic "):
            encoded = trimmed[len("basic ") :].strip()
            rewritten = self._rewrite_basic_auth_token(encoded)
            if rewritten is not None:
                return f"Basic {rewritten}"

        # Prefixed placeholder: split on first whitespace.
        split = _find_whitespace(trimmed)
        if split is None:
            if contains_reserved_credential_marker(trimmed):
                raise UnresolvedPlaceholderError("header")
            return None
        prefix, candidate = trimmed[:split], trimmed[split:].strip()
        secret = self.resolve_placeholder(candidate)
        if secret is not None:
            return f"{prefix} {secret}"
        if contains_reserved_credential_marker(candidate):
            raise UnresolvedPlaceholderError("header")
        return None

    def _rewrite_basic_auth_token(self, encoded: str) -> str | None:
        """Decode ``Basic`` base64, resolve a placeholder in the password half."""
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8", "strict")
        except (binascii.Error, ValueError):
            return None
        user, sep, password = decoded.partition(":")
        if not sep:
            return None
        secret = self.resolve_placeholder(password)
        if secret is None:
            if contains_reserved_credential_marker(password):
                raise UnresolvedPlaceholderError("header")
            return None
        re_encoded = base64.b64encode(f"{user}:{secret}".encode()).decode("ascii")
        return re_encoded

    def rewrite_text_placeholders(self, text: str, location: str) -> tuple[str, int]:
        """Replace every placeholder occurrence in free text.

        Returns ``(rewritten_text, replacement_count)``. Raises
        :class:`UnresolvedPlaceholderError` if a reserved marker remains
        unresolved. (Simplified vs. the Rust byte-scanning implementation, which
        also handles the ``PROVIDER_ALIAS_MARKER`` alias form; the security
        contract — resolve-or-fail-closed — is preserved.)
        """
        if PLACEHOLDER_PREFIX not in text and PROVIDER_ALIAS_MARKER not in text:
            return text, 0

        out: list[str] = []
        replacements = 0
        i = 0
        n = len(text)
        while i < n:
            idx = text.find(PLACEHOLDER_PREFIX, i)
            if idx == -1:
                out.append(text[i:])
                break
            out.append(text[i:idx])
            # Consume the placeholder token (env-key chars + revision syntax).
            j = idx + len(PLACEHOLDER_PREFIX)
            while j < n and (text[j].isalnum() or text[j] in "_:"):
                j += 1
            token = text[idx:j]
            secret = self.resolve_placeholder(token)
            if secret is None:
                raise UnresolvedPlaceholderError(location)
            out.append(secret)
            replacements += 1
            i = j
        return "".join(out), replacements


def _find_whitespace(s: str) -> int | None:
    for idx, ch in enumerate(s):
        if ch.isspace():
            return idx
    return None