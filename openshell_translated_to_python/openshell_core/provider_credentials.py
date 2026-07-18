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
from collections import deque
from dataclasses import dataclass, field

from .secrets import SecretResolver

MAX_RETAINED_CREDENTIAL_GENERATIONS = 8


@dataclass
class ProviderCredentialSnapshot:
    revision: int = 0
    child_env: dict[str, str] = field(default_factory=dict)
    # Maps credential name -> proto ProviderProfileCredential (kept opaque here).
    dynamic_credentials: dict = field(default_factory=dict)


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
        child_env, resolver = SecretResolver.from_provider_env(
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

    def resolver(self) -> SecretResolver | None:
        """The combined resolver across retained generations (Rust ``Option``)."""
        with self._lock:
            return self._combined_resolver

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
            child_env, resolver = SecretResolver.from_provider_env(
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
