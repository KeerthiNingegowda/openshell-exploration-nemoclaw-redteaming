# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Runtime provider credential snapshots.

Translated from ``crates/openshell-core/src/provider_credentials.rs``.

Holds the current generation of provider credentials plus a small ring of
previous generations, so that long-running child processes keep working across a
credential refresh (their older placeholders still resolve). Combines the
generation resolvers into one :class:`SecretResolver` for header rewriting.

Rust patterns:
- ``Arc<RwLock<Inner>>`` -> a class holding an inner state guarded by
  :class:`threading.RLock` (Python's GIL + an explicit lock).
- ``Arc<T>`` shared snapshots -> plain object references (Python is refcounted).
- ``VecDeque`` bounded ring -> :class:`collections.deque` with ``maxlen``.
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from dataclasses import dataclass, field

from .secrets import SecretResolver

MAX_RETAINED_CREDENTIAL_GENERATIONS = 8


class StaticCredentialBindingError(Exception):
    """A static credential binding could not be compiled/installed."""


@dataclass
class ProviderCredentialSnapshot:
    revision: int = 0
    child_env: dict[str, str] = field(default_factory=dict)
    # Maps credential name -> proto ProviderProfileCredential (kept opaque here).
    dynamic_credentials: dict = field(default_factory=dict)
    # Opaque identity of the installed supervisor snapshot (upstream added this
    # so a snapshot can be compared/installed atomically without an ordered
    # counter). Regenerated on each install.
    installation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ChildEnvironmentSnapshot:
    """Prepared environment for future workload processes (upstream addition)."""

    installation_id: str
    # Opaque provider content fingerprint — never an ordered counter.
    revision: int
    environment: dict[str, str]


class ProviderCredentialState:
    """Thread-safe holder of the current + recent credential generations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._current = ProviderCredentialSnapshot()
        self._generations: deque[SecretResolver] = deque(
            maxlen=MAX_RETAINED_CREDENTIAL_GENERATIONS
        )
        self._current_resolver: SecretResolver | None = None
        self._combined_resolver: SecretResolver | None = None
        self._suppressed_keys: set[str] = set()

    @classmethod
    def from_environment(
        cls,
        revision: int,
        env: dict[str, str],
        credential_expires_at_ms: dict[str, int] | None = None,
        dynamic_credentials: dict | None = None,
    ) -> "ProviderCredentialState":
        state = cls()
        child_env, resolver = SecretResolver.from_provider_env_for_revision(
            env, credential_expires_at_ms or {}, revision
        )
        state._current = ProviderCredentialSnapshot(
            revision=revision,
            child_env=child_env,
            dynamic_credentials=dynamic_credentials or {},
        )
        if resolver is not None:
            state._generations.append(resolver)
            state._current_resolver = resolver
        state._recompute_combined()
        return state

    @classmethod
    def from_child_env_snapshot(
        cls, revision: int, child_env: dict[str, str]
    ) -> "ProviderCredentialState":
        """Static state from an already-prepared child env (K8s sidecar path).

        The network sidecar owns the resolvers; the process leaf only injects the
        pre-placeholderized map and holds no gateway-side secret material.
        """
        state = cls()
        state._current = ProviderCredentialSnapshot(revision=revision, child_env=dict(child_env))
        return state

    def _recompute_combined(self) -> None:
        resolvers = list(self._generations)
        self._combined_resolver = SecretResolver.merge(resolvers) if resolvers else None

    def snapshot(self) -> ProviderCredentialSnapshot:
        with self._lock:
            return self._current

    def revision(self) -> int:
        with self._lock:
            return self._current.revision

    def resolver(self) -> SecretResolver | None:
        """The combined resolver across retained generations (Rust ``Option``)."""
        with self._lock:
            return self._combined_resolver

    # ---- endpoint-scoped resolution (upstream addition) -------------------
    def resolver_for_endpoint(self, host: str, port: int, path: str) -> SecretResolver | None:
        """Endpoint-scoped resolver for one ``host:port`` + ``path``.

        See :meth:`resolver_for_endpoint_with_revision`.
        """
        return self.resolver_for_endpoint_with_revision(host, port, path)[0]

    def resolver_for_endpoint_with_revision(
        self, host: str, port: int, path: str
    ) -> tuple[SecretResolver | None, int]:
        """Resolve provider placeholders for one endpoint plus the observed revision.

        Callers that materialize credential-bearing requests asynchronously use
        the revision to reject stale material immediately before its first
        upstream write. The full endpoint→bound-key scoping (which narrows the
        combined resolver via :meth:`SecretResolver.scoped_to_env_keys` using
        compiled static-credential bindings) is summarized here: with no compiled
        bindings the combined resolver applies unchanged.

        Real implementation:
          crates/openshell-core/src/provider_credentials.rs —
          resolver_and_body_classifier_for_endpoint (static_credential_bindings
          + secrets::body::BodyCredentialClassifier)
        """
        with self._lock:
            return self._combined_resolver, self._current.revision

    def remove_env_key(self, key: str) -> None:
        with self._lock:
            self._suppressed_keys.add(key)
            self._current.child_env.pop(key, None)

    def child_env_with_gcp_resolved(self) -> dict[str, str]:
        """Return child env, resolving any GCP token placeholder (stub).

        The Rust implementation swaps a GCP access-token placeholder for a freshly
        minted token here. Left as a straight copy; provider-specific token
        minting is out of scope for this educational translation.
        """
        with self._lock:
            return dict(self._current.child_env)

    def install_environment(
        self,
        revision: int,
        env: dict[str, str],
        credential_expires_at_ms: dict[str, int] | None = None,
        dynamic_credentials: dict | None = None,
    ) -> None:
        """Rotate to a new credential generation, retaining recent ones."""
        with self._lock:
            child_env, resolver = SecretResolver.from_provider_env_for_revision(
                env, credential_expires_at_ms or {}, revision
            )
            self._current = ProviderCredentialSnapshot(
                revision=revision,
                child_env=child_env,
                dynamic_credentials=dynamic_credentials or {},
            )
            if resolver is not None:
                self._generations.append(resolver)  # deque drops the oldest at maxlen
                self._current_resolver = resolver
            self._recompute_combined()

    # ---- child-environment snapshots (upstream addition) ------------------
    def child_environment_snapshot(self) -> ChildEnvironmentSnapshot:
        """Capture the prepared workload environment plus its installation identity.

        GCP token placeholders are resolved into the environment as in
        :meth:`child_env_with_gcp_resolved` (a straight copy in this study
        translation).
        """
        with self._lock:
            return ChildEnvironmentSnapshot(
                installation_id=self._current.installation_id,
                revision=self._current.revision,
                environment=dict(self._current.child_env),
            )

    def compare_and_install_child_env_snapshot(
        self, snapshot: ChildEnvironmentSnapshot
    ) -> bool:
        """Install ``snapshot`` only if it still matches the current installation.

        Returns ``True`` when installed, ``False`` when a newer snapshot has
        superseded it (compare-and-swap on ``installation_id``).
        """
        with self._lock:
            if snapshot.installation_id != self._current.installation_id:
                return False
            self._current.child_env = dict(snapshot.environment)
            return True

    @classmethod
    def from_bound_environment(
        cls, revision: int, env: dict[str, str]
    ) -> "ProviderCredentialState":
        """Build state from an already-bound (pre-placeholderized) environment.

        Like :meth:`from_child_env_snapshot`, the caller owns the resolvers; the
        static-credential-binding compilation is not translated.

        Real implementation:
          crates/openshell-core/src/provider_credentials.rs — from_bound_environment
        """
        return cls.from_child_env_snapshot(revision, env)

    def install_bound_environment(self, revision: int, env: dict[str, str]) -> None:
        """Install a pre-bound environment for a new revision (static-credential path).

        Real implementation:
          crates/openshell-core/src/provider_credentials.rs — install_bound_environment
          (compiles static_credential_bindings and identity epochs)
        """
        with self._lock:
            self._current = ProviderCredentialSnapshot(
                revision=revision, child_env=dict(env)
            )

    def revoke_static_provider_environment(self, revision: int) -> None:
        """Revoke static provider material, leaving an empty child env at ``revision``.

        Clears retained generations and resolvers; dynamic credentials are
        preserved (they are re-resolved on demand).
        """
        with self._lock:
            self._current = ProviderCredentialSnapshot(
                revision=revision,
                child_env={},
                dynamic_credentials=dict(self._current.dynamic_credentials),
            )
            self._generations.clear()
            self._current_resolver = None
            self._recompute_combined()

    def gcp_token_response(self) -> tuple[str, int] | None:
        """Return a freshly minted GCP access token + expiry, or ``None`` (stub).

        Provider-specific token minting is out of scope for this translation.

        Real implementation:
          crates/openshell-core/src/provider_credentials.rs — gcp_token_response
        """
        return None