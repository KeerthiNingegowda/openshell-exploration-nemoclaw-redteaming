# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Configuration management for OpenShell components.

Translated from ``crates/openshell-core/src/config.rs`` (1400+ lines in Rust).

This module reproduces the public constants, the ``ComputeDriverKind`` enum with
its parsing/normalization helpers, the compute-driver auto-detection logic, and
the ``Config`` / nested config dataclasses. The Rust source additionally contains
a large amount of socket-probing and TOML-loading detail; the socket probes are
translated faithfully (they are ordinary filesystem checks), while deep gateway
TOML parsing is summarized where noted.

Rust patterns:
- ``pub const`` -> module constant.
- ``#[serde(rename_all = "snake_case")]`` enum -> ``enum.Enum`` with snake_case values.
- ``impl FromStr`` -> ``from_str`` classmethod raising ValueError.
- ``Option<T>`` -> ``T | None``.
"""

from __future__ import annotations

import os
import socket
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ── Public default constants (canonical source shared across crates) ────────
DEFAULT_SSH_PORT = 2222
DEFAULT_SERVER_PORT = 17670
DEFAULT_STOP_TIMEOUT_SECS = 10
DEFAULT_DOCKER_NETWORK_NAME = "openshell-docker"
DEFAULT_SERVICE_ROUTING_DOMAIN = "openshell.localhost"
DEFAULT_SUPERVISOR_IMAGE_REPO = "ghcr.io/nvidia/openshell/supervisor"
CDI_GPU_DEVICE_ALL = "nvidia.com/gpu=all"
DEFAULT_SANDBOX_PIDS_LIMIT = 2048


def resolve_supervisor_image_tag(candidates: list[str]) -> str:
    """Return the first non-empty, non-``"0.0.0"`` candidate, else ``"dev"``.

    ``+`` is replaced with ``-`` for OCI tag compatibility.
    """
    for tag in candidates:
        if tag and tag != "0.0.0":
            return tag.replace("+", "-")
    return "dev"


def default_supervisor_image() -> str:
    # Rust reads compile-time env (OPENSHELL_IMAGE_TAG / IMAGE_TAG / CARGO_PKG_VERSION);
    # at runtime in Python we approximate with the runtime env then fall back to "dev".
    tag = resolve_supervisor_image_tag(
        [
            os.environ.get("OPENSHELL_IMAGE_TAG", ""),
            os.environ.get("IMAGE_TAG", ""),
        ]
    )
    return f"{DEFAULT_SUPERVISOR_IMAGE_REPO}:{tag}"


class ComputeDriverKind(Enum):
    """Compute backends the gateway can orchestrate sandboxes through."""

    KUBERNETES = "kubernetes"
    VM = "vm"
    DOCKER = "docker"
    PODMAN = "podman"

    def __str__(self) -> str:  # Rust ``impl Display``
        return self.value

    @classmethod
    def from_str(cls, value: str) -> "ComputeDriverKind":
        """Rust ``impl FromStr`` — raises ValueError on unknown driver."""
        v = value.strip().lower()
        for member in cls:
            if member.value == v:
                return member
        raise ValueError(
            f"unsupported compute driver '{v}'. expected one of: "
            "kubernetes, vm, docker, podman"
        )


def normalize_compute_driver_name(value: str) -> str:
    """Normalize a configured compute driver name (Rust returns ``Result``).

    Lowercase ASCII; letters, digits, ``-`` and ``_`` only. Raises ValueError
    (Rust ``Err(String)``) on empty or invalid input.
    """
    value = value.strip()
    if not value:
        raise ValueError("compute driver name cannot be empty")
    if not all(c.isalnum() and c.isascii() or c in "-_" for c in value):
        raise ValueError(
            f"invalid compute driver name '{value}'. use ASCII letters, digits, '-' or '_'"
        )
    return value.lower()


# ── Compute driver auto-detection ───────────────────────────────────────────


def detect_driver() -> ComputeDriverKind | None:
    """Auto-detect the compute driver: Kubernetes -> Podman -> Docker.

    VM is never auto-detected. Returns ``None`` if nothing is available.
    """
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return ComputeDriverKind.KUBERNETES
    if _is_podman_available():
        return ComputeDriverKind.PODMAN
    if _is_docker_available():
        return ComputeDriverKind.DOCKER
    return None


def _socket_responds(path: Path) -> bool:
    """Return True if ``path`` is a unix socket that accepts a connection.

    Rust probes each candidate with a short connect. We mirror that: check the
    path is a socket, then attempt a connect.
    """
    try:
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            return False
    except OSError:
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            sock.connect(str(path))
        return True
    except OSError:
        return False


def _podman_socket_candidates() -> list[Path]:
    candidates: list[Path] = []
    env_sock = os.environ.get("OPENSHELL_PODMAN_SOCKET", "").strip()
    if env_sock:
        candidates.append(Path(env_sock))
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        candidates.append(Path(runtime_dir) / "podman/podman.sock")
    home = os.environ.get("HOME")
    if home:
        candidates.append(Path(home) / ".local/share/containers/podman/machine/podman.sock")
    return candidates


def _is_podman_available() -> bool:
    return any(_socket_responds(p) for p in _podman_socket_candidates())


def _docker_host_unix_socket_path(host: str) -> Path | None:
    host = host.strip()
    if host.startswith("unix://"):
        path = host[len("unix://") :]
        if path:
            return Path(path)
    return None


def _docker_socket_candidates() -> list[Path]:
    candidates: list[Path] = []
    docker_host = os.environ.get("DOCKER_HOST")
    if docker_host:
        p = _docker_host_unix_socket_path(docker_host)
        if p:
            candidates.append(p)
    candidates.append(Path("/var/run/docker.sock"))
    home = os.environ.get("HOME")
    if home:
        candidates.append(Path(home) / ".docker/run/docker.sock")
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        candidates.append(Path(runtime_dir) / "docker.sock")
    return candidates


def detect_docker_socket() -> Path | None:
    for p in _docker_socket_candidates():
        if _socket_responds(p):
            return p
    return None


def _is_docker_available() -> bool:
    return detect_docker_socket() is not None


# ── Config dataclasses ──────────────────────────────────────────────────────


class GatewayInterceptorBindingPolicy(Enum):
    DYNAMIC = "dynamic"  # default
    ALLOWLIST = "allowlist"
    EXACT = "exact"


class GatewayInterceptorFailurePolicy(Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class GatewayInterceptorPhaseConfig(Enum):
    MODIFY_OPERATION = "modify_operation"
    VALIDATE = "validate"
    POST_COMMIT = "post_commit"


@dataclass
class TlsConfig:
    """TLS configuration. ``client_ca_path=None`` -> HTTPS-only (no client certs)."""

    cert_path: Path
    key_path: Path
    client_ca_path: Path | None = None
    require_client_auth: bool = False


@dataclass
class OidcConfig:
    """OIDC config for Bearer-JWT validation against a JWKS endpoint."""

    issuer: str
    audience: str
    jwks_ttl_secs: int = 3600
    roles_claim: str = "realm_access.roles"  # Keycloak default
    admin_role: str = "openshell-admin"
    user_role: str = "openshell-user"
    scopes_claim: str = ""


@dataclass
class MtlsAuthConfig:
    enabled: bool = False


@dataclass
class GatewayAuthConfig:
    # Unsafe local-development escape hatch: accept unauthenticated user calls.
    allow_unauthenticated_users: bool = False


@dataclass
class GatewayInterceptorConfig:
    name: str = ""
    grpc_endpoint: str = ""
    order: int = 0
    failure_policy: GatewayInterceptorFailurePolicy | None = None
    timeout: str | None = None
    max_response_bytes: int | None = None
    max_patches: int | None = None
    binding_policy: GatewayInterceptorBindingPolicy = GatewayInterceptorBindingPolicy.DYNAMIC
    bindings: list = field(default_factory=list)


@dataclass
class GatewayJwtConfig:
    """Gateway-minted sandbox JWT signing configuration (Ed25519)."""

    signing_key_path: Path
    public_key_path: Path
    kid_path: Path
    gateway_id: str = "openshell"
    ttl_secs: int = 3600  # 0 disables expiration (local single-player only)


@dataclass
class ServiceRoutingConfig:
    base_domains: list[str] = field(default_factory=lambda: [DEFAULT_SERVICE_ROUTING_DOMAIN])
    enable_loopback_service_http: bool = False


@dataclass
class Config:
    """Server configuration, built programmatically (never deserialized directly).

    Mirrors the Rust ``Config`` struct. Only ``bind_address`` is required; all
    other fields carry the Rust defaults.
    """

    bind_address: str  # "host:port"
    health_bind_address: str | None = None
    metrics_bind_address: str | None = None
    log_level: str = "info"
    tls: TlsConfig | None = None
    oidc: OidcConfig | None = None
    auth: GatewayAuthConfig = field(default_factory=GatewayAuthConfig)
    gateway_interceptors: list[GatewayInterceptorConfig] = field(default_factory=list)
    provider_profile_sources: list = field(default_factory=list)
    mtls_auth: MtlsAuthConfig = field(default_factory=MtlsAuthConfig)
    gateway_jwt: GatewayJwtConfig | None = None
    database_url: str = ""
    compute_drivers: list[str] = field(default_factory=list)
    compute_driver_endpoints: dict[str, Path] = field(default_factory=dict)
    ssh_session_ttl_secs: int = 0
    grpc_rate_limit_requests: int | None = None
    grpc_rate_limit_window_secs: int | None = None
    service_routing: ServiceRoutingConfig = field(default_factory=ServiceRoutingConfig)