"""Sandbox policy configuration structures.

Translated from ``crates/openshell-core/src/policy.rs``.

Rust structs become dataclasses; Rust enums become :class:`enum.Enum`. The
``TryFrom<ProtoSandboxPolicy>`` / ``From<Proto...>`` conversions become
classmethods that accept a lightweight "proto-like" mapping (a dict or object
with the relevant attributes), since we do not generate the protobuf types here.

Rust patterns:
- ``Option<SocketAddr>`` -> ``str | None`` (host:port string).
- ``#[default]`` enum variant -> the first / documented default.
- ``impl Default`` -> a classmethod ``default()`` or dataclass field defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .paths import normalize_path


class NetworkMode(Enum):
    """Rust ``NetworkMode`` — default is ``Block``."""

    BLOCK = "block"
    PROXY = "proxy"
    ALLOW = "allow"


class LandlockCompatibility(Enum):
    """Rust ``LandlockCompatibility`` — default is ``BestEffort``."""

    BEST_EFFORT = "best_effort"
    HARD_REQUIREMENT = "hard_requirement"


@dataclass
class FilesystemPolicy:
    read_only: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    # Rust default is ``true`` — automatically include the workdir as read-write.
    include_workdir: bool = True

    @classmethod
    def from_proto(cls, proto) -> "FilesystemPolicy":
        return cls(
            read_only=[normalize_path(p) for p in getattr(proto, "read_only", [])],
            read_write=[normalize_path(p) for p in getattr(proto, "read_write", [])],
            include_workdir=getattr(proto, "include_workdir", True),
        )


@dataclass
class ProxyPolicy:
    # TCP address for a local HTTP proxy (loopback-only). ``Option<SocketAddr>``.
    http_addr: str | None = None


@dataclass
class NetworkPolicy:
    mode: NetworkMode = NetworkMode.BLOCK
    proxy: ProxyPolicy | None = None


@dataclass
class LandlockPolicy:
    compatibility: LandlockCompatibility = LandlockCompatibility.BEST_EFFORT

    @classmethod
    def from_proto(cls, proto) -> "LandlockPolicy":
        compat = (
            LandlockCompatibility.HARD_REQUIREMENT
            if getattr(proto, "compatibility", "") == "hard_requirement"
            else LandlockCompatibility.BEST_EFFORT
        )
        return cls(compatibility=compat)


@dataclass
class ProcessPolicy:
    run_as_user: str | None = None
    run_as_group: str | None = None

    @classmethod
    def from_proto(cls, proto) -> "ProcessPolicy":
        # Rust maps empty strings to None.
        user = getattr(proto, "run_as_user", "") or None
        group = getattr(proto, "run_as_group", "") or None
        return cls(run_as_user=user, run_as_group=group)


@dataclass
class SandboxPolicy:
    version: int
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    landlock: LandlockPolicy = field(default_factory=LandlockPolicy)
    process: ProcessPolicy = field(default_factory=ProcessPolicy)

    @classmethod
    def try_from_proto(cls, proto) -> "SandboxPolicy":
        """Rust ``TryFrom<ProtoSandboxPolicy>``.

        In cluster mode we always run with proxy networking so all egress can be
        evaluated by OPA and ``inference.local`` is always addressable — hence
        the network mode is hardcoded to PROXY here, matching the Rust source.
        """
        network = NetworkPolicy(mode=NetworkMode.PROXY, proxy=ProxyPolicy(http_addr=None))
        fs = getattr(proto, "filesystem", None)
        landlock = getattr(proto, "landlock", None)
        process = getattr(proto, "process", None)
        return cls(
            version=getattr(proto, "version", 0),
            filesystem=FilesystemPolicy.from_proto(fs) if fs else FilesystemPolicy(),
            network=network,
            landlock=LandlockPolicy.from_proto(landlock) if landlock else LandlockPolicy(),
            process=ProcessPolicy.from_proto(process) if process else ProcessPolicy(),
        )
