"""gRPC authentication interceptor shared by CLI and TUI.

Translated from ``crates/openshell-core/src/auth.rs``.

Rust implements ``tonic::service::Interceptor``; grpcio's equivalent is a
``grpc.UnaryUnaryClientInterceptor`` (and streaming variants). Here we model the
header-injection logic in a small dataclass and provide a helper that mutates a
metadata list, so it works with or without grpcio installed.

Behavior (identical to Rust):
- OIDC bearer token takes precedence over an edge token.
- Bearer -> ``authorization: Bearer <token>``.
- Edge token -> ``cf-access-jwt-assertion: <token>`` and ``cookie: CF_Authorization=<token>``.
- No token -> no-op.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EdgeAuthInterceptor:
    """Injects auth headers into every outgoing gRPC request.

    ``Option<MetadataValue>`` fields become ``str | None``.
    """

    bearer_value: str | None = None
    header_value: str | None = None
    cookie_value: str | None = None

    @classmethod
    def new(cls, oidc_token: str | None, edge_token: str | None) -> "EdgeAuthInterceptor":
        """Rust ``EdgeAuthInterceptor::new`` — OIDC wins over edge token."""
        if oidc_token is not None:
            return cls(bearer_value=f"Bearer {oidc_token}")
        if edge_token is not None:
            return cls(
                header_value=edge_token,
                cookie_value=f"CF_Authorization={edge_token}",
            )
        return cls()

    @classmethod
    def noop(cls) -> "EdgeAuthInterceptor":
        return cls()

    def metadata(self) -> list[tuple[str, str]]:
        """Return the metadata pairs this interceptor would inject.

        Mirrors ``Interceptor::call`` which inserts headers into the request
        metadata. grpcio interceptors receive metadata as a list of tuples, so
        callers can merge this into ``client_call_details.metadata``.
        """
        pairs: list[tuple[str, str]] = []
        if self.bearer_value is not None:
            pairs.append(("authorization", self.bearer_value))
        if self.header_value is not None:
            pairs.append(("cf-access-jwt-assertion", self.header_value))
        if self.cookie_value is not None:
            pairs.append(("cookie", self.cookie_value))
        return pairs
