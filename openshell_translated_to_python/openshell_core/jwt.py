# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Session-JWT identity, minting, and verification.

Translated from ``crates/openshell-core/src/jwt.rs``.

Upstream grew this module from a single unverified ``exp`` reader into the full
short-lived session-token framework used between the gateway, the compute
drivers, and the in-sandbox supervisor. Two token *profiles* exist — ``Gateway``
and ``Sandbox`` — each choosing its own JOSE ``typ`` and JWT ``aud``. Tokens are
Ed25519 (EdDSA) signed, carry a durable sandbox runtime identity
(``sandbox_id`` + ``runtime_generation`` + ``auth_epoch``), and are verified with
strict issuer/audience/subject/lifetime checks.

What this translation covers faithfully (pure logic):
- ``parse_exp_secs`` (unchanged, signature-unverified refresh scheduling),
- the validated value objects :class:`SandboxId`, :class:`CredentialEpoch`,
  :class:`SessionRotation`,
- the :class:`SessionTokenProfile` / :class:`SessionComponent` enums,
- the redacting :class:`SecretJwt`,
- the launch/auth bundle structures and their ``validate`` rules,
- the refreshable :class:`SessionBearerTokenSlot` (monotonic-epoch guarded),
- :meth:`SessionJwtVerifier.validate_claims` (issuer/aud/subject/lifetime logic).

What is stubbed (crypto / external deps), with Rust file:line citations:
- Ed25519 signing (:class:`SessionJwtIssuer`) and signature *decoding*
  (:meth:`SessionJwtVerifier.verify`). Rust uses ``jsonwebtoken`` + ``aws_lc``.
- ``SandboxGenerationId`` / ``SandboxSessionId`` are new sibling proto-backed
  identifiers (see ``sandbox_generation.rs`` / ``sandbox_session.rs``); here they
  are treated as opaque strings.

Rust ``SessionJwtError`` (a ``thiserror`` enum) becomes :class:`SessionJwtError`,
an ``enum.Enum`` of reason codes wrapped by :class:`SessionJwtException`.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from .sandbox_generation import SandboxGenerationId, SandboxGenerationIdException
from .sandbox_session import SandboxSessionId  # noqa: F401  (documents the real type)

# ---------------------------------------------------------------------------
# Signature-unverified exp reader (unchanged from the original translation)
# ---------------------------------------------------------------------------
def parse_exp_secs(token: str) -> int | None:
    """Decode the numeric ``exp`` claim (Unix seconds) without verifying.

    Returns ``None`` (Rust ``Option<i64>``) when the token is not a parseable
    JWT or has no integer ``exp`` claim. A leading ``"Bearer "`` prefix is
    tolerated so callers may pass a raw token or an ``authorization`` header.

    This must NOT be used for any authorization decision — same warning as Rust.
    """
    raw = token[len("Bearer ") :] if token.startswith("Bearer ") else token
    parts = raw.split(".", 2)
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GATEWAY_SESSION_JWT_TYPE = "openshell-gateway-session+jwt"
SANDBOX_SESSION_JWT_TYPE = "openshell-sandbox-session+jwt"
SANDBOX_SESSION_AUDIENCE = "openshell-sandbox"

DEFAULT_SESSION_TOKEN_TTL_SECS = 3600
MIN_SESSION_TOKEN_TTL_SECS = 60
MAX_SESSION_TOKEN_TTL_SECS = 3600
MAX_SESSION_CLOCK_LEEWAY_SECS = 30

_GATEWAY_ISSUER_PREFIX = "openshell-gateway:"
_SANDBOX_SUBJECT_PREFIX = "spiffe://openshell/sandbox/"


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------
class SessionJwtError(Enum):
    """Reason codes mirroring the Rust ``SessionJwtError`` enum."""

    INVALID_SANDBOX_ID = "sandbox ID is invalid"
    INVALID_GATEWAY_ID = "gateway ID is invalid"
    INVALID_CREDENTIAL_EPOCH = "credential epoch must be positive"
    STALE_CREDENTIAL_EPOCH = "credential epoch does not advance the active credential"
    INVALID_SESSION_ROTATION = "session rotation must be positive"
    SESSION_ROTATION_OVERFLOW = "session rotation overflow"
    MISSING_RUNTIME_IDENTITY = "sandbox runtime identity is missing"
    INVALID_RUNTIME_IDENTITY = "sandbox runtime identity is invalid"
    INVALID_KEY_ID = "key ID is invalid"
    DUPLICATE_KEY_ID = "verification key IDs must be unique"
    NO_VERIFICATION_KEYS = "at least one verification key is required"
    INVALID_SIGNING_KEY = "Ed25519 signing key is invalid"
    INVALID_VERIFICATION_KEY = "Ed25519 verification key is invalid"
    INVALID_LIFETIME = "session token lifetime must be between 60 and 3600 seconds"
    PROFILE_MISMATCH = "session token profile does not match its claims"
    SIGNING_FAILED = "session token could not be signed"
    INVALID_TOKEN_ENCODING = "session token encoding is invalid"
    TOKEN_UNAVAILABLE = "session token is unavailable"
    INVALID_TOKEN = "session token is invalid"
    WRONG_ALGORITHM = "session token algorithm must be EdDSA"
    WRONG_TOKEN_TYPE = "session token type is invalid"
    MISSING_KEY_ID = "session token key ID is missing"
    UNKNOWN_KEY_ID = "session token key ID is unknown"
    WRONG_ISSUER = "session token issuer is invalid"
    WRONG_AUDIENCE = "session token audience is invalid"
    SUBJECT_MISMATCH = "session token subject does not match its sandbox ID"
    INVALID_JTI = "session token ID is not a UUID"
    ISSUED_IN_FUTURE = "session token was issued in the future"
    EXPIRED = "session token has expired"


class SessionJwtException(Exception):
    """Raised by the session-JWT helpers, carrying a :class:`SessionJwtError`."""

    def __init__(self, kind: SessionJwtError) -> None:
        self.kind = kind
        super().__init__(kind.value)


def _has_whitespace(value: str) -> bool:
    return value.strip() != value or any(ch.isspace() for ch in value)


# ---------------------------------------------------------------------------
# Validated value objects (newtypes)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SandboxId:
    """Canonical sandbox identity carried by both session-token profiles."""

    _value: str

    @classmethod
    def parse(cls, value: str) -> "SandboxId":
        if value == "" or _has_whitespace(value):
            raise SessionJwtException(SessionJwtError.INVALID_SANDBOX_ID)
        return cls(value)

    def as_str(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value


@dataclass(frozen=True)
class CredentialEpoch:
    """Monotonic order for authenticated Sandbox Protocol connections (> 0)."""

    _value: int

    @classmethod
    def new(cls, value: int) -> "CredentialEpoch":
        if value == 0:
            raise SessionJwtException(SessionJwtError.INVALID_CREDENTIAL_EPOCH)
        return cls(value)

    def get(self) -> int:
        return self._value


@dataclass(frozen=True)
class SessionRotation:
    """Monotonic identity for Sandbox Protocol attachment state (> 0).

    A protocol coordination value, not part of JWT authorization.
    """

    _value: int

    @classmethod
    def new(cls, value: int) -> "SessionRotation":
        if value == 0:
            raise SessionJwtException(SessionJwtError.INVALID_SESSION_ROTATION)
        return cls(value)

    def get(self) -> int:
        return self._value

    def successor(self) -> "SessionRotation":
        # u64 in Rust; there is no overflow in Python, but we keep the guard so
        # the error surface matches (SessionRotationOverflow would fire at 2**64).
        nxt = self._value + 1
        if nxt >= 2**64:
            raise SessionJwtException(SessionJwtError.SESSION_ROTATION_OVERFLOW)
        return SessionRotation.new(nxt)


class SessionComponent(Enum):
    """The only component authorized by either sandbox-session token profile."""

    OPENSHELL_SUPERVISOR = "openshell-supervisor"


class SessionTokenProfile(Enum):
    """Exact token profile — chooses both the JOSE ``typ`` and JWT ``aud``."""

    GATEWAY = "gateway"
    SANDBOX = "sandbox"

    def token_type(self) -> str:
        return (
            GATEWAY_SESSION_JWT_TYPE
            if self is SessionTokenProfile.GATEWAY
            else SANDBOX_SESSION_JWT_TYPE
        )

    def audience(self, issuer: str) -> str:
        return issuer if self is SessionTokenProfile.GATEWAY else SANDBOX_SESSION_AUDIENCE


# ---------------------------------------------------------------------------
# Secret-carrying token (redacted repr)
# ---------------------------------------------------------------------------
class SecretJwt:
    """A JWT whose contents are omitted from ``repr`` (Rust zeroes on drop)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    @classmethod
    def parse(cls, value: str) -> "SecretJwt":
        if value == "" or any(ch.isspace() for ch in value):
            raise SessionJwtException(SessionJwtError.INVALID_TOKEN_ENCODING)
        return cls(value)

    def expose_secret(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretJwt([REDACTED])"


# ---------------------------------------------------------------------------
# Identity / bundle structures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SandboxRuntimeIdentity:
    """Durable identity shared by every short-lived token for one sandbox runtime."""

    sandbox_id: SandboxId
    runtime_generation: str  # SandboxGenerationId (sibling module)
    auth_epoch: CredentialEpoch


@dataclass
class SessionVerificationKey:
    key_id: str
    public_key_pem: bytes


@dataclass
class SupervisorAuthBundle:
    """Trusted launch input delivered only to ``openshell-supervisor``.

    ``session_id`` correlates the two ends of one launch; it is not carried in
    JWTs and is not an authorization identity.
    """

    session_id: str  # SandboxSessionId (sibling module)
    runtime_generation: str  # SandboxGenerationId
    session_rotation: SessionRotation
    auth_epoch: CredentialEpoch
    gateway_token: SecretJwt
    gateway_expires_at: int
    sandbox_token: SecretJwt
    sandbox_expires_at: int

    def validate(self) -> None:
        if self.gateway_expires_at <= 0 or self.sandbox_expires_at <= 0:
            raise SessionJwtException(SessionJwtError.INVALID_LIFETIME)
        try:
            SandboxGenerationId.parse(self.runtime_generation)
        except SandboxGenerationIdException as error:
            raise SessionJwtException(SessionJwtError.INVALID_RUNTIME_IDENTITY) from error
        SessionRotation.new(self.session_rotation.get())

    def sandbox_bearer_slot(self) -> "SessionBearerTokenSlot":
        return SessionBearerTokenSlot.new(
            self.sandbox_token, self.sandbox_expires_at, self.auth_epoch
        )

    def __repr__(self) -> str:  # gateway/sandbox tokens redacted
        return (
            f"SupervisorAuthBundle(session_id={self.session_id!r}, "
            f"runtime_generation={self.runtime_generation!r}, "
            f"session_rotation={self.session_rotation!r}, auth_epoch={self.auth_epoch!r}, "
            f"gateway_token=[REDACTED], gateway_expires_at={self.gateway_expires_at}, "
            f"sandbox_token=[REDACTED], sandbox_expires_at={self.sandbox_expires_at})"
        )


@dataclass
class SandboxLaunchAuthentication:
    """Gateway-created authentication input trusted by a compute driver.

    Drivers split this: the supervisor receives ``supervisor``, while the sandbox
    receives only the gateway identity and public keys.
    """

    supervisor: SupervisorAuthBundle
    gateway_id: str
    verification_keys: list[SessionVerificationKey] = field(default_factory=list)

    def validate(self) -> None:
        self.supervisor.validate()
        _validate_gateway_id(self.gateway_id)
        if not self.verification_keys:
            raise SessionJwtException(SessionJwtError.NO_VERIFICATION_KEYS)
        seen: set[str] = set()
        for key in self.verification_keys:
            _validate_key_id(key.key_id)
            if not key.public_key_pem:
                raise SessionJwtException(SessionJwtError.INVALID_VERIFICATION_KEY)
            if key.key_id in seen:
                raise SessionJwtException(SessionJwtError.DUPLICATE_KEY_ID)
            seen.add(key.key_id)


@dataclass
class MintedSessionToken:
    token: SecretJwt
    expires_at: int
    token_id: str  # Uuid


@dataclass
class MintedSessionTokenPair:
    gateway: MintedSessionToken
    sandbox: MintedSessionToken
    auth_epoch: CredentialEpoch


@dataclass(frozen=True)
class AuthenticatedSandboxSession:
    sandbox_id: SandboxId
    runtime_generation: str
    auth_epoch: CredentialEpoch
    token_id: str
    issued_at: int
    expires_at: int


# ---------------------------------------------------------------------------
# Refreshable bearer-token slot (pure logic; Arc<RwLock<..>> -> threading.RLock)
# ---------------------------------------------------------------------------
@dataclass
class _StoredBearer:
    token: SecretJwt
    expires_at: int
    credential_epoch: CredentialEpoch


class SessionBearerTokenSlot:
    """Refreshable Sandbox Protocol bearer shared by all streams on the current
    HTTP/2 connection. Updates must not regress the credential epoch."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stored: _StoredBearer | None = None

    @classmethod
    def empty(cls) -> "SessionBearerTokenSlot":
        return cls()

    @classmethod
    def new(
        cls, token: SecretJwt, expires_at: int, credential_epoch: CredentialEpoch
    ) -> "SessionBearerTokenSlot":
        slot = cls.empty()
        slot.update(token, expires_at, credential_epoch)
        return slot

    def update(
        self, token: SecretJwt, expires_at: int, credential_epoch: CredentialEpoch
    ) -> None:
        if expires_at <= 0:
            raise SessionJwtException(SessionJwtError.INVALID_LIFETIME)
        with self._lock:
            if (
                self._stored is not None
                and credential_epoch.get() < self._stored.credential_epoch.get()
            ):
                raise SessionJwtException(SessionJwtError.STALE_CREDENTIAL_EPOCH)
            self._stored = _StoredBearer(token, expires_at, credential_epoch)

    def clear(self) -> None:
        with self._lock:
            self._stored = None

    def expires_at(self) -> int | None:
        with self._lock:
            return self._stored.expires_at if self._stored else None

    def credential_epoch(self) -> CredentialEpoch | None:
        with self._lock:
            return self._stored.credential_epoch if self._stored else None

    def authorization_metadata(self) -> str:
        """Return the ``Bearer <token>`` header value, or raise if unavailable/expired."""
        with self._lock:
            stored = self._stored
            if stored is None:
                raise SessionJwtException(SessionJwtError.TOKEN_UNAVAILABLE)
            if stored.expires_at <= SystemJwtClock().now_unix_seconds():
                raise SessionJwtException(SessionJwtError.EXPIRED)
            return f"Bearer {stored.token.expose_secret()}"


# ---------------------------------------------------------------------------
# Clock
# ---------------------------------------------------------------------------
class JwtClock:
    """Rust ``trait JwtClock`` — abstracts wall-clock time for testability."""

    def now_unix_seconds(self) -> int:  # pragma: no cover - interface
        raise NotImplementedError


class SystemJwtClock(JwtClock):
    def now_unix_seconds(self) -> int:
        return int(time.time())


# ---------------------------------------------------------------------------
# Issuer (Ed25519 signing) — crypto stub
# ---------------------------------------------------------------------------
class SessionJwtIssuer:
    """Mints Gateway/Sandbox session-token pairs (Ed25519 / EdDSA).

    The signing itself depends on ``jsonwebtoken`` + ``aws_lc`` in Rust and is
    not translated; the value-object and lifetime rules above are the reusable,
    study-relevant part.
    """

    @classmethod
    def from_ed25519_pem(cls, *args, **kwargs) -> "SessionJwtIssuer":
        # Real implementation:
        #   crates/openshell-core/src/jwt.rs:506 — SessionJwtIssuer::from_ed25519_pem
        raise NotImplementedError(
            "Ed25519 key loading is crypto; see crates/openshell-core/src/jwt.rs:506"
        )

    def mint_pair(self, *args, **kwargs) -> MintedSessionTokenPair:
        # Real implementation:
        #   crates/openshell-core/src/jwt.rs:528 — SessionJwtIssuer::mint_pair
        raise NotImplementedError(
            "EdDSA token minting is crypto; see crates/openshell-core/src/jwt.rs:528"
        )


# ---------------------------------------------------------------------------
# Verifier — claim validation is pure logic; signature decode is stubbed
# ---------------------------------------------------------------------------
@dataclass
class _SessionClaims:
    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    jti: str
    sandbox_id: SandboxId
    runtime_generation: str
    auth_epoch: CredentialEpoch
    component: SessionComponent


class SessionJwtVerifier:
    """Strict verifier used by the gateway or the Sandbox Protocol."""

    def __init__(
        self,
        gateway_id: str,
        profile: SessionTokenProfile,
        keys: list[SessionVerificationKey],
        clock: JwtClock | None = None,
    ) -> None:
        gateway_id = _validate_gateway_id(gateway_id)
        parsed: dict[str, SessionVerificationKey] = {}
        for key in keys:
            key_id = _validate_key_id(key.key_id)
            if key_id in parsed:
                raise SessionJwtException(SessionJwtError.DUPLICATE_KEY_ID)
            parsed[key_id] = key
        if not parsed:
            raise SessionJwtException(SessionJwtError.NO_VERIFICATION_KEYS)
        self._keys = parsed
        self._issuer = f"{_GATEWAY_ISSUER_PREFIX}{gateway_id}"
        self._profile = profile
        self._clock: JwtClock = clock or SystemJwtClock()

    def verify(self, token: str) -> AuthenticatedSandboxSession:
        """Verify an EdDSA session token and return the authenticated identity.

        The header/algorithm/kid checks and Ed25519 signature *decoding* depend
        on ``jsonwebtoken`` and are not translated; :meth:`validate_claims`
        contains the pure issuer/audience/subject/lifetime logic that runs on the
        decoded claims.
        """
        # Real implementation:
        #   crates/openshell-core/src/jwt.rs:680 — SessionJwtVerifier::verify
        raise NotImplementedError(
            "EdDSA signature verification is crypto; see "
            "crates/openshell-core/src/jwt.rs:680 (claim checks: validate_claims)"
        )

    def validate_claims(self, claims: _SessionClaims) -> AuthenticatedSandboxSession:
        """Pure claim validation (Rust ``SessionJwtVerifier::validate_claims``)."""
        if claims.iss != self._issuer:
            raise SessionJwtException(SessionJwtError.WRONG_ISSUER)
        if claims.aud != self._profile.audience(self._issuer):
            raise SessionJwtException(SessionJwtError.WRONG_AUDIENCE)
        if claims.sub != f"{_SANDBOX_SUBJECT_PREFIX}{claims.sandbox_id}":
            raise SessionJwtException(SessionJwtError.SUBJECT_MISMATCH)
        try:
            SandboxGenerationId.parse(claims.runtime_generation)
        except SandboxGenerationIdException as error:
            raise SessionJwtException(SessionJwtError.INVALID_RUNTIME_IDENTITY) from error
        token_id = _parse_uuid(claims.jti)
        if claims.exp <= claims.iat:
            raise SessionJwtException(SessionJwtError.INVALID_LIFETIME)
        lifetime = claims.exp - claims.iat
        if lifetime > MAX_SESSION_TOKEN_TTL_SECS:
            raise SessionJwtException(SessionJwtError.INVALID_LIFETIME)
        now = self._clock.now_unix_seconds()
        leeway = MAX_SESSION_CLOCK_LEEWAY_SECS
        if claims.iat > now + leeway:
            raise SessionJwtException(SessionJwtError.ISSUED_IN_FUTURE)
        if claims.exp < now - leeway:
            raise SessionJwtException(SessionJwtError.EXPIRED)
        return AuthenticatedSandboxSession(
            sandbox_id=claims.sandbox_id,
            runtime_generation=claims.runtime_generation,
            auth_epoch=claims.auth_epoch,
            token_id=token_id,
            issued_at=claims.iat,
            expires_at=claims.exp,
        )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _validate_ttl_secs(ttl: int) -> None:
    if not (MIN_SESSION_TOKEN_TTL_SECS <= ttl <= MAX_SESSION_TOKEN_TTL_SECS):
        raise SessionJwtException(SessionJwtError.INVALID_LIFETIME)


def _validate_gateway_id(gateway_id: str) -> str:
    if gateway_id == "" or _has_whitespace(gateway_id):
        raise SessionJwtException(SessionJwtError.INVALID_GATEWAY_ID)
    return gateway_id


def _validate_key_id(key_id: str) -> str:
    if key_id == "" or _has_whitespace(key_id):
        raise SessionJwtException(SessionJwtError.INVALID_KEY_ID)
    return key_id


def _parse_uuid(value: str) -> str:
    import uuid

    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise SessionJwtException(SessionJwtError.INVALID_JTI) from error
