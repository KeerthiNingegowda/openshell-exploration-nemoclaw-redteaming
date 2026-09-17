# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Credential-placeholder resolution for the network supervisor.

Translated from ``crates/openshell-core/src/secrets.rs`` (~2600 lines in Rust,
most of the tail being tests which are not translated here).

Core idea: real provider secrets never live in the sandbox child environment.
Instead each provider env var is replaced with an opaque *placeholder* string
(``openshell:resolve:env:KEY``). The network supervisor holds a
:class:`SecretResolver` that maps placeholders back to the real secret and
rewrites outgoing HTTP request lines, header values and bodies just before
forwarding upstream — so a compromised agent only ever sees placeholders.

Placeholder grammar (matches the Rust ``PLACEHOLDER_PREFIX``):

- canonical:      ``openshell:resolve:env:KEY``
- revisioned:     ``openshell:resolve:env:v<revision>_KEY``  (revision > 0)
- stable-handle:  ``openshell:resolve:env:s<64-hex-handle>_KEY``
- provider alias: ``...OPENSHELL-RESOLVE-ENV-KEY`` (a provider-shaped form that
  survives systems which mangle ``:`` into ``-`` and uppercase env names)

Changes reflected from upstream since the previous translation:
- The revisioned placeholder format changed from ``rev:<n>:KEY`` to
  ``v<revision>_KEY`` and a new stable-handle form ``s<handle>_KEY`` was added.
- Endpoint scoping: :class:`SecretResolver` now tracks ``denied_env_keys`` and
  ``identity_bound_env_keys`` so an endpoint-scoped view resolves only the
  credentials authorized for that endpoint; a denial is reported as a typed
  *endpoint mismatch* rather than a plain "unavailable".
- Byte / header marker detection helpers
  (:func:`contains_reserved_credential_marker_bytes`,
  :func:`header_value_contains_reserved_credential_marker`).
- Full request-line rewriting: percent-decode-aware path and query rewriting,
  path-credential validation, and a redacted (``[CREDENTIAL]``) target for OPA
  policy evaluation and logs (:func:`rewrite_target_for_eval`,
  :func:`redact_target_for_policy`, :func:`rewrite_http_header_block`).

Rust patterns:
- ``Result<T, UnresolvedPlaceholderError>`` -> returns ``T`` or raises
  :class:`UnresolvedPlaceholderError`.
- ``Option<&str>`` -> ``str | None``.
- Manual ``Debug`` impl that hides secrets -> :meth:`SecretResolver.__repr__`.
- The streamed-body scanner (``secrets_body.rs`` / ``mod body``) is a separate
  translation unit; see ``secrets_body.py``.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import unquote

from .time import now_ms

PLACEHOLDER_PREFIX = "openshell:resolve:env:"
PROVIDER_ALIAS_MARKER = "OPENSHELL-RESOLVE-ENV-"

# Public aliases (Rust exposes ``*_PUBLIC`` consts for fail-closed scanning by
# other modules such as the body scanner).
PLACEHOLDER_PREFIX_PUBLIC = PLACEHOLDER_PREFIX
PROVIDER_ALIAS_MARKER_PUBLIC = PROVIDER_ALIAS_MARKER

# Longest wire form of a reserved marker: percent-encoding expands every marker
# byte to three bytes (``%XX``), and detection decodes in a single pass.
_LONGEST_RESERVED_MARKER_WIRE_BYTES = 3 * max(len(PLACEHOLDER_PREFIX), len(PROVIDER_ALIAS_MARKER))

# Retain this many trailing bytes when scanning a streamed request body so a
# reserved marker split across reads cannot be forwarded before detection. A
# marker is only detected while all of its wire bytes sit in the scan buffer at
# once, so the retained window must hold every byte of the longest form but the
# last.
CREDENTIAL_MARKER_SCAN_TAIL_BYTES = _LONGEST_RESERVED_MARKER_WIRE_BYTES


# ---------------------------------------------------------------------------
# Character classes / raw marker detection
# ---------------------------------------------------------------------------
def _is_env_key_char(ch: str) -> bool:
    """Chars valid in an env var key name (extract placeholder boundaries)."""
    return ch.isascii() and (ch.isalnum() or ch == "_")


def _is_alias_token_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in "_-.~")


def _contains_raw_reserved_marker(value: str) -> bool:
    return PLACEHOLDER_PREFIX in value or PROVIDER_ALIAS_MARKER in value


def contains_reserved_credential_marker(value: str) -> bool:
    """True if ``value`` (raw or percent-decoded) contains a reserved marker."""
    if _contains_raw_reserved_marker(value):
        return True
    return _contains_raw_reserved_marker(_percent_decode(value))


def header_value_contains_reserved_credential_marker(value: str) -> bool:
    """True if an HTTP header value carries reserved placeholder syntax.

    Also inspects the *decoded* content of ``Basic`` authentication, since a
    placeholder can hide inside the base64-encoded ``user:password`` token.
    """
    trimmed = value.strip()
    if contains_reserved_credential_marker(trimmed):
        return True
    decoded = _decode_basic_auth_value(trimmed)
    if decoded is None:
        return False
    return _contains_raw_reserved_marker(decoded)


def _basic_auth_token(value: str) -> str | None:
    for prefix in ("Basic ", "basic "):
        if value.startswith(prefix):
            return value[len(prefix) :].strip()
    return None


def _decode_basic_auth_value(value: str) -> str | None:
    token = _basic_auth_token(value)
    if token is None:
        return None
    return _decode_basic_auth_token(token)


def _decode_basic_auth_token(encoded: str) -> str | None:
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-8", "strict")
    except (binascii.Error, ValueError):
        return None


def contains_reserved_credential_marker_bytes(value: bytes) -> bool:
    """Byte-oriented marker detection (raw, percent-encoded, or binary input).

    Splits on NUL and scans each lossily-decoded segment, mirroring the Rust
    ``String::from_utf8_lossy(..).split('\\0')`` scan.
    """
    if not value:
        return False
    text = value.decode("utf-8", "replace")
    return any(contains_reserved_credential_marker(segment) for segment in text.split("\0"))


# ---------------------------------------------------------------------------
# Error and result types
# ---------------------------------------------------------------------------
class UnresolvedPlaceholderError(Exception):
    """A reserved credential token was detected but could not be resolved.

    ``location`` is one of ``"header"``, ``"query_param"``, ``"path"``,
    ``"websocket"``, ``"request_target"`` — used for fail-closed logging without
    leaking the secret. ``endpoint_mismatch`` distinguishes a credential that is
    genuinely unavailable from one denied for the request endpoint.
    """

    def __init__(self, location: str, *, endpoint_mismatch: bool = False) -> None:
        self.location = location
        self.endpoint_mismatch = endpoint_mismatch
        reason = (
            "credential is not authorized for the request endpoint"
            if endpoint_mismatch
            else "credential placeholder could not be resolved"
        )
        super().__init__(f"{reason} in {location}")

    @classmethod
    def unavailable(cls, location: str) -> "UnresolvedPlaceholderError":
        return cls(location, endpoint_mismatch=False)

    def is_endpoint_mismatch(self) -> bool:
        return self.endpoint_mismatch


@dataclass
class RewriteResult:
    """Result of rewriting an HTTP header block with credential resolution.

    ``redacted_target`` is a log-safe request target with ``[CREDENTIAL]`` in
    place of resolved secrets, or ``None`` when the target was not modified.
    """

    rewritten: bytes
    redacted_target: str | None


@dataclass
class RewriteTargetResult:
    """Result of rewriting a request target for OPA evaluation."""

    resolved: str  # real secrets — for upstream forwarding only
    redacted: str  # ``[CREDENTIAL]`` in place of secrets — for OPA + logs


@dataclass
class _SecretValue:
    value: str
    expires_at_ms: int  # 0 means no expiry


# ---------------------------------------------------------------------------
# SecretResolver
# ---------------------------------------------------------------------------
@dataclass
class SecretResolver:
    """Maps opaque placeholders back to real secret values.

    Rust stores a ``HashMap<String, SecretValue>`` plus endpoint-scoping sets; we
    use dicts / sets. The custom ``Debug`` impl in Rust exposes only the
    placeholder *count* to avoid leaking secrets — :meth:`__repr__` does the same.

    - ``denied_env_keys``: env keys denied for the current (endpoint-scoped) view.
    - ``identity_bound_env_keys``: keys whose credential carries endpoint
      identity; canonical/alias placeholders for these never resolve, forcing
      request input to use the revision-scoped placeholder issued to the workload.
    - ``revision_fallback_allowed_revisions``: for identity-bound keys, the set of
      opaque revisions permitted to fall back to the current credential.
    """

    _by_placeholder: dict[str, _SecretValue] = field(default_factory=dict)
    _denied_env_keys: set[str] = field(default_factory=set)
    _identity_bound_env_keys: set[str] = field(default_factory=set)
    _revision_fallback_allowed_revisions: dict[str, set[int]] = field(default_factory=dict)

    def __repr__(self) -> str:  # never print keys or values
        return f"SecretResolver(placeholders={len(self._by_placeholder)})"

    # ---- construction -----------------------------------------------------
    @classmethod
    def from_provider_env(
        cls, provider_env: dict[str, str]
    ) -> tuple[dict[str, str], "SecretResolver | None"]:
        """Build ``(child_env, resolver)`` at the canonical (revision 0) form."""
        return cls.from_provider_env_for_revision(provider_env, {}, 0)

    @classmethod
    def from_provider_env_for_revision(
        cls,
        provider_env: dict[str, str],
        credential_expires_at_ms: dict[str, int],
        revision: int,
    ) -> tuple[dict[str, str], "SecretResolver | None"]:
        return cls._from_provider_env_for_revision_with_current_aliases(
            provider_env, credential_expires_at_ms, revision, include_current_aliases=False
        )

    @classmethod
    def from_provider_env_for_current_revision(
        cls,
        provider_env: dict[str, str],
        credential_expires_at_ms: dict[str, int],
        revision: int,
    ) -> tuple[dict[str, str], "SecretResolver | None", "SecretResolver | None"]:
        return cls._from_provider_env_for_current_revision_with_stable_handles(
            provider_env, credential_expires_at_ms, revision, {}
        )

    @classmethod
    def _from_provider_env_for_current_revision_with_stable_handles(
        cls,
        provider_env: dict[str, str],
        credential_expires_at_ms: dict[str, int],
        revision: int,
        stable_handles: dict[str, str],
    ) -> tuple[dict[str, str], "SecretResolver | None", "SecretResolver | None"]:
        """Build workload env + (generation, current) resolver snapshots.

        Stable credentials are registered only in the *current* resolver. Their
        previous values never enter the bounded revision-generation queue, so a
        revoked or replaced handle cannot resolve an older access token.
        """
        child_env: dict[str, str] = {}
        generation_values: dict[str, _SecretValue] = {}
        current_values: dict[str, _SecretValue] = {}

        for key, value in provider_env.items():
            if uses_reserved_revision_namespace(key):
                # Rust logs a warning and skips reserved-namespace keys.
                continue
            secret = _SecretValue(value=value, expires_at_ms=credential_expires_at_ms.get(key, 0))
            handle = stable_handles.get(key)
            if handle is not None:
                placeholder = placeholder_for_env_key_for_stable_handle(key, handle)
            else:
                placeholder = placeholder_for_env_key_for_revision(key, revision)
                if revision != 0:
                    generation_values[placeholder] = secret
            child_env[key] = placeholder
            current_values[placeholder] = secret
            current_values[placeholder_for_env_key(key)] = secret

        def _resolver(by_placeholder: dict[str, _SecretValue]) -> "SecretResolver | None":
            return cls(_by_placeholder=by_placeholder) if by_placeholder else None

        return child_env, _resolver(generation_values), _resolver(current_values)

    @classmethod
    def _from_provider_env_for_revision_with_current_aliases(
        cls,
        provider_env: dict[str, str],
        credential_expires_at_ms: dict[str, int],
        revision: int,
        include_current_aliases: bool,
    ) -> tuple[dict[str, str], "SecretResolver | None"]:
        if not provider_env:
            return {}, None

        child_env: dict[str, str] = {}
        by_placeholder: dict[str, _SecretValue] = {}
        for key, value in provider_env.items():
            if uses_reserved_revision_namespace(key):
                continue
            placeholder = placeholder_for_env_key_for_revision(key, revision)
            secret = _SecretValue(value=value, expires_at_ms=credential_expires_at_ms.get(key, 0))
            child_env[key] = placeholder
            by_placeholder[placeholder] = secret
            if include_current_aliases and revision != 0:
                by_placeholder[placeholder_for_env_key(key)] = secret

        if not by_placeholder:
            return child_env, None
        return child_env, cls(_by_placeholder=by_placeholder)

    @classmethod
    def merge(cls, resolvers) -> "SecretResolver | None":
        """Merge several resolvers into one (later entries win)."""
        by_placeholder: dict[str, _SecretValue] = {}
        denied: set[str] = set()
        identity_bound: set[str] = set()
        revision_fallback: dict[str, set[int]] = {}
        for resolver in resolvers:
            by_placeholder.update(resolver._by_placeholder)
            denied.update(resolver._denied_env_keys)
            identity_bound.update(resolver._identity_bound_env_keys)
            revision_fallback.update(resolver._revision_fallback_allowed_revisions)
        if not by_placeholder:
            return None
        return cls(
            _by_placeholder=by_placeholder,
            _denied_env_keys=denied,
            _identity_bound_env_keys=identity_bound,
            _revision_fallback_allowed_revisions=revision_fallback,
        )

    def scoped_to_env_keys(
        self,
        bound_keys: set[str],
        allowed_bound_keys: set[str],
        revision_fallback_allowed_revisions: dict[str, set[int]],
    ) -> "SecretResolver":
        """Return an endpoint-scoped resolver view.

        Credential keys listed in ``bound_keys`` resolve only when also present
        in ``allowed_bound_keys``; unbound provider configuration remains
        available. Secret strings are shared through the copied entries.
        """
        denied_env_keys = bound_keys - allowed_bound_keys
        by_placeholder = {
            placeholder: secret
            for placeholder, secret in self._by_placeholder.items()
            if (key := placeholder_env_key(placeholder)) is None or key not in denied_env_keys
        }
        return SecretResolver(
            _by_placeholder=by_placeholder,
            _denied_env_keys=denied_env_keys,
            _identity_bound_env_keys=set(bound_keys),
            _revision_fallback_allowed_revisions=revision_fallback_allowed_revisions,
        )

    def _unresolved_for(self, location: str, placeholder: str) -> UnresolvedPlaceholderError:
        key = placeholder_env_key(placeholder)
        mismatch = key is not None and key in self._denied_env_keys
        return UnresolvedPlaceholderError(location, endpoint_mismatch=mismatch)

    # ---- resolution -------------------------------------------------------
    def resolve_placeholder(self, value: str) -> str | None:
        """Resolve a placeholder to its real secret, or ``None``.

        Endpoint-bound keys reject identityless (canonical / alias) placeholders
        so a stale process cannot resolve a replacement provider's credential.
        Falls back by KEY to the current credential when a revisioned placeholder
        ages out, subject to the identity-bound revision allow-list. Returns
        ``None`` for unknown, expired, or prohibited-character values.
        """
        key_of = placeholder_env_key(value)
        if (
            key_of is not None
            and key_of in self._identity_bound_env_keys
            and _revisioned_placeholder_parts(value) is None
            and _stable_placeholder_parts(value) is None
        ):
            return None

        secret = self._by_placeholder.get(value)
        if secret is None:
            key = _revisioned_placeholder_env_key(value)
            if key is None:
                key = _alias_env_key(value)
            if key is None:
                return None
            parts = _revisioned_placeholder_parts(value)
            if parts is not None:
                revision, rev_key = parts
                if rev_key in self._identity_bound_env_keys:
                    allowed = self._revision_fallback_allowed_revisions.get(rev_key)
                    if allowed is None or revision not in allowed:
                        return None
            secret = self._by_placeholder.get(placeholder_for_env_key(key))
            if secret is None:
                return None
        return _resolve_secret_value(secret)

    def resolve_current_env_key_checked(self, key: str, location: str) -> str | None:
        """Resolve the current value for an env key selected by trusted code.

        Unlike :meth:`resolve_placeholder_checked`, this accepts an env key rather
        than a user-provided placeholder token — so internal transforms (e.g.
        SigV4) can select the endpoint-bound current credential without exposing
        identityless placeholder aliases to sandbox request input. Raises on an
        endpoint-denied key.
        """
        if key in self._denied_env_keys:
            raise UnresolvedPlaceholderError(location, endpoint_mismatch=True)
        secret = self._by_placeholder.get(placeholder_for_env_key(key))
        return _resolve_secret_value(secret) if secret is not None else None

    def resolve_placeholder_checked(self, value: str, location: str) -> str | None:
        """Resolve a placeholder while preserving endpoint-denial information.

        ``None`` means genuinely unavailable. An endpoint-bound key denied by the
        scoped resolver raises a typed mismatch so callers can emit the security
        denial instead of treating it as missing config.
        """
        key = placeholder_env_key(value)
        if key is not None and key in self._denied_env_keys:
            raise UnresolvedPlaceholderError(location, endpoint_mismatch=True)
        return self.resolve_placeholder(value)

    def expires_at_ms_for_placeholder(self, placeholder: str) -> int | None:
        secret = self._by_placeholder.get(placeholder)
        return secret.expires_at_ms if secret else None

    # ---- header rewriting -------------------------------------------------
    def rewrite_header_value(self, value: str) -> str | None:
        """Rewrite one header value, resolving any embedded placeholder.

        Returns the rewritten value, or ``None`` when nothing needed rewriting.
        Raises :class:`UnresolvedPlaceholderError` when a reserved marker is
        present but cannot be resolved (fail-closed). Handles three forms:
        1. direct:   ``x-api-key: openshell:resolve:env:KEY``
        2. Basic:    ``Basic base64(user:openshell:resolve:env:PASS)``
        3. prefixed: ``Bearer openshell:resolve:env:KEY``
        """
        trimmed = value.strip()

        secret = self.resolve_placeholder(trimmed)
        if secret is not None:
            return secret

        encoded = _basic_auth_token(trimmed)
        if encoded is not None:
            rewritten = self._rewrite_basic_auth_token(encoded)
            if rewritten is not None:
                return f"Basic {rewritten}"

        split = _find_whitespace(trimmed)
        if split is None:
            if contains_reserved_credential_marker(trimmed):
                raise self._unresolved_for("header", trimmed)
            return None
        prefix, candidate = trimmed[:split], trimmed[split:].strip()
        secret = self.resolve_placeholder(candidate)
        if secret is not None:
            return f"{prefix} {secret}"
        if contains_reserved_credential_marker(candidate):
            raise self._unresolved_for("header", candidate)
        return None

    def _rewrite_basic_auth_token(self, encoded: str) -> str | None:
        """Decode ``Basic`` base64, resolve placeholders, re-encode.

        Returns ``None`` if decoding fails or no placeholders are found.
        """
        decoded = _decode_basic_auth_token(encoded.strip())
        if decoded is None:
            return None
        if not _contains_raw_reserved_marker(decoded):
            return None
        rewritten, replacements = self.rewrite_text_placeholders(decoded, "header")
        if replacements == 0:
            return None
        return base64.b64encode(rewritten.encode()).decode("ascii")

    def rewrite_text_placeholders(self, text: str, location: str) -> tuple[str, int]:
        """Replace every canonical or alias placeholder occurrence in free text.

        Returns ``(rewritten_text, replacement_count)``. The text is only
        accepted if it contains no reserved markers afterwards; otherwise raises
        :class:`UnresolvedPlaceholderError` (fail-closed).
        """
        if not _contains_raw_reserved_marker(text):
            return text, 0

        out: list[str] = []
        replacements = 0
        pos = 0
        n = len(text)
        while pos < n:
            next_canonical = _find(text, PLACEHOLDER_PREFIX, pos)
            next_alias = _find(text, PROVIDER_ALIAS_MARKER, pos)
            if next_alias is not None:
                next_alias = _alias_start_for_marker(text, next_alias)
            candidates = [c for c in (next_canonical, next_alias) if c is not None]
            if not candidates:
                out.append(text[pos:])
                break
            abs_start = min(candidates)
            out.append(text[pos:abs_start])

            if text[abs_start:].startswith(PLACEHOLDER_PREFIX):
                match = self._credential_token_at(text, abs_start)
                if match is None:
                    raise UnresolvedPlaceholderError(location)
                token_end, token = match
                secret = self.resolve_placeholder(token)
                if secret is None:
                    raise self._unresolved_for(location, token)
                out.append(secret)
                replacements += 1
                pos = token_end
                continue

            alias = _alias_token_at(text, abs_start)
            if alias is not None:
                token_end, token = alias
                secret = self.resolve_placeholder(token)
                if secret is None:
                    raise self._unresolved_for(location, token)
                out.append(secret)
                replacements += 1
                pos = token_end
                continue

            raise UnresolvedPlaceholderError(location)

        rewritten = "".join(out)
        if _contains_raw_reserved_marker(rewritten):
            raise UnresolvedPlaceholderError(location)
        return rewritten, replacements

    def rewrite_websocket_text_placeholders(self, text: str) -> tuple[str, int]:
        """Rewrite placeholders inside a WebSocket text message (fail-closed)."""
        return self.rewrite_text_placeholders(text, "websocket")

    def _credential_token_at(self, text: str, abs_start: int) -> tuple[int, str] | None:
        return (
            self._longest_known_token_match(text, abs_start)
            or _canonical_token_at(text, abs_start)
            or _alias_token_at(text, abs_start)
        )

    def _longest_known_token_match(self, text: str, abs_start: int) -> tuple[int, str] | None:
        suffix = text[abs_start:]
        best: tuple[int, str] | None = None
        for placeholder in self._by_placeholder:
            if not suffix.startswith(placeholder):
                continue
            key_end = abs_start + len(placeholder)
            if not _token_boundary_ok(text, abs_start, key_end, placeholder):
                continue
            if best is None or len(placeholder) > len(best[1]):
                best = (key_end, placeholder)
        return best


def _resolve_secret_value(secret: _SecretValue) -> str | None:
    if secret.expires_at_ms > 0 and secret.expires_at_ms <= now_ms():
        return None  # expired
    return _validate_resolved_secret(secret.value)


# ---------------------------------------------------------------------------
# Placeholder token parsing
# ---------------------------------------------------------------------------
def _alias_start_for_marker(text: str, marker_abs: int) -> int:
    start = marker_abs
    while start > 0 and _is_alias_token_char(text[start - 1]):
        start -= 1
    return start


def _canonical_token_at(text: str, abs_start: int) -> tuple[int, str] | None:
    if not text[abs_start:].startswith(PLACEHOLDER_PREFIX):
        return None
    key_start = abs_start + len(PLACEHOLDER_PREFIX)
    key_end = key_start
    while key_end < len(text) and _is_env_key_char(text[key_end]):
        key_end += 1
    if key_end <= key_start:
        return None
    return key_end, text[abs_start:key_end]


def _alias_token_at(text: str, abs_start: int) -> tuple[int, str] | None:
    suffix = text[abs_start:]
    marker_rel = suffix.find(PROVIDER_ALIAS_MARKER)
    if marker_rel <= 0:
        return None
    key_start = abs_start + marker_rel + len(PROVIDER_ALIAS_MARKER)
    key_end = key_start
    while key_end < len(text) and _is_env_key_char(text[key_end]):
        key_end += 1
    if key_end == key_start:
        return None
    before_ok = abs_start == 0 or not _is_alias_token_char(text[abs_start - 1])
    after_ok = key_end == len(text) or not _is_alias_token_char(text[key_end])
    if not (before_ok and after_ok):
        return None
    return key_end, text[abs_start:key_end]


def _alias_env_key(token: str) -> str | None:
    marker_start = token.find(PROVIDER_ALIAS_MARKER)
    if marker_start <= 0:
        return None
    if not all(_is_alias_token_char(ch) for ch in token[:marker_start]):
        return None
    key_start = marker_start + len(PROVIDER_ALIAS_MARKER)
    key_end = key_start
    while key_end < len(token) and _is_env_key_char(token[key_end]):
        key_end += 1
    if key_end == len(token) and key_end > key_start:
        return token[key_start:key_end]
    return None


def _revisioned_placeholder_env_key(token: str) -> str | None:
    parts = _revisioned_placeholder_parts(token)
    return parts[1] if parts else None


def _revisioned_placeholder_parts(token: str) -> tuple[int, str] | None:
    if not token.startswith(PLACEHOLDER_PREFIX):
        return None
    suffix = token[len(PLACEHOLDER_PREFIX) :]
    parts = _split_revisioned_env_key(suffix)
    if parts is None:
        return None
    revision, key = parts
    try:
        return int(revision), key
    except ValueError:
        return None


def _stable_placeholder_parts(token: str) -> tuple[str, str] | None:
    if not token.startswith(PLACEHOLDER_PREFIX):
        return None
    return _split_stable_env_key(token[len(PLACEHOLDER_PREFIX) :])


def placeholder_env_key(token: str) -> str | None:
    """Extract the underlying env KEY from any placeholder form, else None."""
    stable = _stable_placeholder_parts(token)
    if stable is not None:
        return stable[1]
    rev = _revisioned_placeholder_env_key(token)
    if rev is not None:
        return rev
    if token.startswith(PLACEHOLDER_PREFIX):
        return token[len(PLACEHOLDER_PREFIX) :]
    return _alias_env_key(token)


def uses_reserved_revision_namespace(key: str) -> bool:
    """Provider env keys must not themselves live in the reserved namespace."""
    return _split_revisioned_env_key(key) is not None or _split_stable_env_key(key) is not None


def _split_revisioned_env_key(key: str) -> tuple[str, str] | None:
    """Parse ``v<digits>_<ENV_KEY>`` -> ``(revision, env_key)``."""
    if not key.startswith("v"):
        return None
    suffix = key[1:]
    revision, sep, env_key = suffix.partition("_")
    if not sep:
        return None
    if not revision or not revision.isascii() or not revision.isdigit():
        return None
    if not env_key or not all(_is_env_key_char(ch) for ch in env_key):
        return None
    return revision, env_key


def _split_stable_env_key(key: str) -> tuple[str, str] | None:
    """Parse ``s<64-hex-handle>_<ENV_KEY>`` -> ``(handle, env_key)``."""
    if not key.startswith("s"):
        return None
    suffix = key[1:]
    handle, sep, env_key = suffix.partition("_")
    if not sep:
        return None
    if len(handle) != 64 or not all(c.isdigit() or c in "abcdef" for c in handle):
        return None
    if not env_key or not all(_is_env_key_char(ch) for ch in env_key):
        return None
    return handle, env_key


def _token_boundary_ok(text: str, abs_start: int, token_end: int, token: str) -> bool:
    if token.startswith(PLACEHOLDER_PREFIX):
        return (
            token_end == len(text)
            or not _is_env_key_char(text[token_end])
            or text[token_end:].startswith(PLACEHOLDER_PREFIX)
        )
    before_ok = abs_start == 0 or not _is_alias_token_char(text[abs_start - 1])
    after_ok = token_end == len(text) or not _is_alias_token_char(text[token_end])
    return before_ok and after_ok


def placeholder_for_env_key(key: str) -> str:
    """Canonical (revision-less) placeholder for an env var key."""
    return f"{PLACEHOLDER_PREFIX}{key}"


def placeholder_for_env_key_for_revision(key: str, revision: int) -> str:
    """Revisioned placeholder. Revision 0 is the canonical (unversioned) form."""
    if revision == 0:
        return placeholder_for_env_key(key)
    return f"{PLACEHOLDER_PREFIX}v{revision}_{key}"


def placeholder_for_env_key_for_stable_handle(key: str, handle: str) -> str:
    """Stable-handle placeholder: ``openshell:resolve:env:s<handle>_KEY``."""
    return f"{PLACEHOLDER_PREFIX}s{handle}_{key}"


# ---------------------------------------------------------------------------
# Secret / credential validation
# ---------------------------------------------------------------------------
def _validate_resolved_secret(value: str) -> str | None:
    """Reject secrets containing CR, LF, or NUL (header/response injection, CWE-113)."""
    if any(ch in value for ch in ("\r", "\n", "\0")):
        return None
    return value


def _validate_credential_for_path(value: str) -> str | None:
    """Reject path-unsafe credentials (traversal, separators, delimiters; CWE-22).

    Returns an error reason string, or ``None`` when the value is safe.
    """
    if "../" in value or "..\\" in value or value == "..":
        return "credential contains path traversal sequence"
    if any(ch in value for ch in ("\0", "\r", "\n")):
        return "credential contains control character"
    if "/" in value or "\\" in value:
        return "credential contains path separator"
    if "?" in value or "#" in value:
        return "credential contains URI delimiter"
    return None


# ---------------------------------------------------------------------------
# Percent encoding/decoding (RFC 3986)
# ---------------------------------------------------------------------------
_QUERY_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
# pchar = unreserved / sub-delims / ":" / "@"
_PATH_SAFE = _QUERY_UNRESERVED | frozenset("!$&'()*+,;=:@")


def _percent_encode(input_str: str, safe: frozenset[str]) -> str:
    out: list[str] = []
    for byte in input_str.encode("utf-8"):
        ch = chr(byte)
        if ch in safe:
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def _percent_encode_query(input_str: str) -> str:
    return _percent_encode(input_str, _QUERY_UNRESERVED)


def _percent_encode_path_segment(input_str: str) -> str:
    return _percent_encode(input_str, _PATH_SAFE)


def _percent_decode(input_str: str) -> str:
    """Percent-decode, preserving invalid ``%`` sequences verbatim (like Rust)."""
    return unquote(input_str, encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# URI rewriting
# ---------------------------------------------------------------------------
def _rewrite_request_line(line: str, resolver: "SecretResolver") -> tuple[str, str | None]:
    """Rewrite placeholders in the request line's URL.

    Given ``GET /bot{TOKEN}/path?key={APIKEY} HTTP/1.1`` resolves placeholders in
    both path segments and query values. Returns ``(rewritten_line,
    redacted_target)``; ``redacted_target`` is ``None`` if nothing changed.
    """
    parts = line.split(" ", 2)
    if len(parts) < 3:
        return line, None
    method, uri, version = parts

    if not contains_reserved_credential_marker(uri):
        return line, None

    path, sep, query = uri.partition("?")
    query = query if sep else None

    rewritten_path = _rewrite_uri_path(path, resolver)
    resolved_path, redacted_path = rewritten_path if rewritten_path else (path, path)

    if query is not None:
        rewritten_query = _rewrite_uri_query_params(query, resolver)
        resolved_query, redacted_query = rewritten_query if rewritten_query else (query, query)
    else:
        resolved_query = redacted_query = None

    resolved_uri = f"{resolved_path}?{resolved_query}" if resolved_query is not None else resolved_path
    redacted_uri = f"{redacted_path}?{redacted_query}" if redacted_query is not None else redacted_path

    return f"{method} {resolved_uri} {version}", redacted_uri


def _rewrite_uri_path(path: str, resolver: "SecretResolver") -> tuple[str, str] | None:
    """Rewrite placeholders in URL path segments (percent-decode-aware).

    Returns ``(resolved_path, redacted_path)`` if any placeholder was found,
    else ``None``.
    """
    segments = path.split("/")
    resolved_segments: list[str] = []
    redacted_segments: list[str] = []
    any_rewritten = False

    for segment in segments:
        decoded = _percent_decode(segment)
        if not _contains_raw_reserved_marker(decoded):
            resolved_segments.append(segment)
            redacted_segments.append(segment)
            continue
        resolved, redacted = _rewrite_path_segment(decoded, resolver)
        resolved_segments.append(_percent_encode_path_segment(resolved))
        redacted_segments.append(redacted)
        any_rewritten = True

    if not any_rewritten:
        return None
    return "/".join(resolved_segments), "/".join(redacted_segments)


def _rewrite_path_segment(segment: str, resolver: "SecretResolver") -> tuple[str, str]:
    """Rewrite placeholders within a single (percent-decoded) path segment."""
    resolved: list[str] = []
    redacted: list[str] = []
    pos = 0
    n = len(segment)

    while pos < n:
        next_canonical = _find(segment, PLACEHOLDER_PREFIX, pos)
        next_alias = _find(segment, PROVIDER_ALIAS_MARKER, pos)
        if next_alias is not None:
            next_alias = _alias_start_for_marker(segment, next_alias)
        candidates = [c for c in (next_canonical, next_alias) if c is not None]
        if not candidates:
            resolved.append(segment[pos:])
            redacted.append(segment[pos:])
            break

        abs_start = min(candidates)
        resolved.append(segment[pos:abs_start])
        redacted.append(segment[pos:abs_start])

        match = _canonical_token_at(segment, abs_start) or _alias_token_at(segment, abs_start)
        if match is None:
            raise UnresolvedPlaceholderError("path")
        token_end, full_placeholder = match
        secret = resolver.resolve_placeholder(full_placeholder)
        if secret is None:
            raise resolver._unresolved_for("path", full_placeholder)
        if _validate_credential_for_path(secret) is not None:
            raise UnresolvedPlaceholderError("path")
        resolved.append(secret)
        redacted.append("[CREDENTIAL]")
        pos = token_end

    return "".join(resolved), "".join(redacted)


def _rewrite_uri_query_params(query: str, resolver: "SecretResolver") -> tuple[str, str] | None:
    """Rewrite placeholders in query parameter values.

    Returns ``(resolved_query, redacted_query)`` if any placeholder was found.
    """
    if not contains_reserved_credential_marker(query):
        return None

    resolved_params: list[str] = []
    redacted_params: list[str] = []
    any_rewritten = False

    for param in query.split("&"):
        key, sep, value = param.partition("=")
        if not sep:
            resolved_params.append(param)
            redacted_params.append(param)
            continue
        decoded_value = _percent_decode(value)
        if _contains_raw_reserved_marker(decoded_value):
            rewritten, replacements = resolver.rewrite_text_placeholders(decoded_value, "query_param")
            if replacements == 0 or _contains_raw_reserved_marker(rewritten):
                raise UnresolvedPlaceholderError("query_param")
            resolved_params.append(f"{key}={_percent_encode_query(rewritten)}")
            redacted_params.append(f"{key}=[CREDENTIAL]")
            any_rewritten = True
        else:
            resolved_params.append(param)
            redacted_params.append(param)

    if not any_rewritten:
        return None
    return "&".join(resolved_params), "&".join(redacted_params)


# ---------------------------------------------------------------------------
# Public rewrite API
# ---------------------------------------------------------------------------
def rewrite_http_header_block(
    raw: bytes, resolver: "SecretResolver | None"
) -> RewriteResult:
    """Rewrite credential placeholders in an HTTP header block.

    Resolves placeholders in the request line (path + query) and header values
    (including Basic auth), returning the rewritten bytes plus a redacted target
    for logging. Fail-closed: raises if any placeholder is detected but cannot be
    resolved, and with no resolver, any reserved marker in the header region is
    rejected rather than forwarded verbatim.
    """
    header_sep = raw.find(b"\r\n\r\n")

    if resolver is None:
        if header_sep == -1:
            scan_end = len(raw)
        else:
            scan_end = min(len(raw), header_sep + 4 + 256)
        header_region = raw[:scan_end].decode("utf-8", "replace")
        if contains_reserved_credential_marker(header_region):
            raise UnresolvedPlaceholderError("header")
        return RewriteResult(rewritten=raw, redacted_target=None)

    if header_sep == -1:
        return RewriteResult(rewritten=raw, redacted_target=None)
    header_end = header_sep + 4

    header_str = raw[:header_end].decode("utf-8", "replace")
    lines = header_str.split("\r\n")
    if not lines:
        return RewriteResult(rewritten=raw, redacted_target=None)

    request_line = lines[0]
    rewritten_line, redacted_target = _rewrite_request_line(request_line, resolver)

    output = bytearray()
    output += rewritten_line.encode("utf-8")
    output += b"\r\n"

    for line in lines[1:]:
        if line == "":
            break
        output += rewrite_header_line_checked(line, resolver).encode("utf-8")
        output += b"\r\n"

    output += b"\r\n"
    output += raw[header_end:]

    output_header = bytes(output[: min(len(output), header_end + 256)]).decode("utf-8", "replace")
    if contains_reserved_credential_marker(output_header):
        raise UnresolvedPlaceholderError("header")

    return RewriteResult(rewritten=bytes(output), redacted_target=redacted_target)


def rewrite_header_line(line: str, resolver: "SecretResolver") -> str:
    """Best-effort header-line rewrite (returns the line unchanged on failure)."""
    try:
        return rewrite_header_line_checked(line, resolver)
    except UnresolvedPlaceholderError:
        return line


def rewrite_header_line_checked(line: str, resolver: "SecretResolver") -> str:
    name, sep, value = line.partition(":")
    if not sep:
        return line
    rewritten = resolver.rewrite_header_value(value.strip())
    if rewritten is None:
        return line
    return f"{name}: {rewritten}"


def rewrite_target_for_eval(target: str, resolver: "SecretResolver") -> RewriteTargetResult:
    """Resolve placeholders in a request target (path + query) for OPA eval.

    Returns the resolved target (real secrets, for upstream) and a redacted
    version (``[CREDENTIAL]`` for OPA input and logs).
    """
    if not contains_reserved_credential_marker(target):
        return RewriteTargetResult(resolved=target, redacted=target)

    path, sep, query = target.partition("?")
    query = query if sep else None

    rewritten_path = _rewrite_uri_path(path, resolver)
    resolved_path, redacted_path = rewritten_path if rewritten_path else (path, path)

    if query is not None:
        rewritten_query = _rewrite_uri_query_params(query, resolver)
        resolved_query, redacted_query = rewritten_query if rewritten_query else (query, query)
    else:
        resolved_query = redacted_query = None

    resolved = f"{resolved_path}?{resolved_query}" if resolved_query is not None else resolved_path
    redacted = f"{redacted_path}?{redacted_query}" if redacted_query is not None else redacted_path
    return RewriteTargetResult(resolved=resolved, redacted=redacted)


def redact_target_for_policy(target: str) -> str:
    """Log/policy representation of a target without materializing secrets.

    Validates placeholder syntax with the same URI-aware path as upstream
    injection, but resolves every referenced key to ``[CREDENTIAL]`` — so routes
    can be selected and policy evaluated before the real resolver is touched.
    """
    if not contains_reserved_credential_marker(target):
        return target

    decoded = _percent_decode(target)
    provider_env: dict[str, str] = {}
    pos = 0
    n = len(decoded)
    while pos < n:
        next_canonical = _find(decoded, PLACEHOLDER_PREFIX, pos)
        next_alias = _find(decoded, PROVIDER_ALIAS_MARKER, pos)
        if next_alias is not None:
            next_alias = _alias_start_for_marker(decoded, next_alias)
        candidates = [c for c in (next_canonical, next_alias) if c is not None]
        if not candidates:
            break
        start = min(candidates)
        match = _canonical_token_at(decoded, start) or _alias_token_at(decoded, start)
        if match is None:
            raise UnresolvedPlaceholderError("request_target")
        end, token = match
        key = placeholder_env_key(token)
        if key is None:
            raise UnresolvedPlaceholderError("request_target")
        provider_env[key] = "[CREDENTIAL]"
        pos = end

    _, resolver = SecretResolver.from_provider_env(provider_env)
    if resolver is None:
        raise UnresolvedPlaceholderError("request_target")
    return rewrite_target_for_eval(target, resolver).redacted


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _find(text: str, needle: str, start: int) -> int | None:
    idx = text.find(needle, start)
    return None if idx == -1 else idx


def _find_whitespace(s: str) -> int | None:
    for idx, ch in enumerate(s):
        if ch.isspace():
            return idx
    return None
