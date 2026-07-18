"""Shared compute-driver trait and sandbox types.

Corresponds to the ``ComputeDriver`` trait implemented by both the Docker
(``crates/openshell-driver-docker``) and Podman
(``crates/openshell-driver-podman``) crates, plus the ``DriverSandbox`` spec
they consume.

Rust ``#[async_trait] trait ComputeDriver`` -> a Python
:class:`abc.ABC` with ``async`` abstract methods. Each concrete driver subclass
implements the container-lifecycle RPCs the gateway calls.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SandboxSpec:
    """Subset of the proto ``SandboxSpec`` the drivers read."""

    image: str = ""
    command: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    sandbox_token: str = ""
    resources: Any = None  # proto ResourceRequirements (with .gpu/.cpu/.memory)


@dataclass
class DriverSandbox:
    """Driver-facing sandbox record (proto ``DriverSandbox``)."""

    id: str
    name: str
    spec: SandboxSpec | None = None


class ComputeDriver(ABC):
    """Container/VM sandbox lifecycle backend."""

    @abstractmethod
    async def create_sandbox(self, sandbox: DriverSandbox) -> None: ...

    @abstractmethod
    async def delete_sandbox(self, sandbox_id: str, sandbox_name: str) -> None: ...

    @abstractmethod
    async def list_sandboxes(self) -> list[DriverSandbox]: ...
