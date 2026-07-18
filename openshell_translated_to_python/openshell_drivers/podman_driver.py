"""Podman compute driver.

Translated from ``crates/openshell-driver-podman/src/driver.rs`` (1550 lines).

Implements the container sandbox lifecycle over Podman's libpod REST API (spoken
over a unix socket). This port defines the driver class, its config, and the
``create/delete/list`` lifecycle methods. Actual HTTP calls to the Podman socket
are represented as clearly-marked stubs (``_podman_post`` etc.); the control flow,
naming, validation, and GPU selection are translated faithfully.

Rust patterns:
- ``Arc<CdiGpuDefaultSelector>`` -> a shared :class:`CdiGpuDefaultSelector`.
- ``Result<T, ComputeDriverError>`` -> returns ``T`` or raises
  :class:`ComputeDriverError`.
- ``async fn`` (tokio) -> ``async def`` (asyncio).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openshell_core.config import DEFAULT_DOCKER_NETWORK_NAME, DEFAULT_SANDBOX_PIDS_LIMIT
from openshell_core.error import ComputeDriverError
from openshell_core.gpu import CdiGpuDefaultSelector, CdiGpuInventory, effective_driver_gpu_count
from openshell_core.image import default_sandbox_image

from . import podman_container as container
from .base import ComputeDriver, DriverSandbox


@dataclass
class PodmanComputeConfig:
    socket_path: str = ""
    default_image: str = field(default_factory=default_sandbox_image)
    network_name: str = DEFAULT_DOCKER_NETWORK_NAME
    gateway_endpoint: str = ""
    pids_limit: int = DEFAULT_SANDBOX_PIDS_LIMIT
    allow_all_gpus: bool = False


class PodmanComputeDriver(ComputeDriver):
    """Podman-backed :class:`ComputeDriver`."""

    def __init__(self, config: PodmanComputeConfig, network_gateway_ip: str | None = None) -> None:
        self.config = config
        # Sandbox containers reach the gateway via the host's bridge IP.
        self.network_gateway_ip = network_gateway_ip
        self.gpu_selector = CdiGpuDefaultSelector(CdiGpuInventory.new([]), config.allow_all_gpus)

    def __repr__(self) -> str:  # Rust hides secrets; mirror the safe fields.
        return (
            f"PodmanComputeDriver(socket_path={self.config.socket_path!r}, "
            f"default_image={self.config.default_image!r}, "
            f"gpu_inventory={self.gpu_selector.device_ids()!r})"
        )

    # ---- lifecycle -------------------------------------------------------
    async def create_sandbox(self, sandbox: DriverSandbox) -> None:
        """Create a sandbox container (Rust ``create_sandbox``).

        Validates the container name, resolves GPU CDI devices for the requested
        count, creates a per-sandbox JWT secret, builds the container spec, and
        posts it to Podman.
        """
        name = container.container_name(sandbox.name)
        _validate_name(name)

        gpu_devices = None
        gpu = getattr(getattr(sandbox.spec, "resources", None), "gpu", None) if sandbox.spec else None
        count = effective_driver_gpu_count(gpu)
        if count:
            # ``next_device_ids`` advances the round-robin cursor.
            gpu_devices = self.gpu_selector.next_device_ids(count)

        token_secret = await self._create_sandbox_token_secret(sandbox)
        spec = container.build_container_spec(
            sandbox, self.config, token_secret=token_secret, gpu_devices=gpu_devices
        )
        await self._podman_post("/libpod/containers/create", spec)
        await self._podman_post(f"/libpod/containers/{spec['name']}/start", {})

    async def delete_sandbox(self, sandbox_id: str, sandbox_name: str) -> None:
        """Stop and remove the container, volume, and token secret."""
        name = container.container_name(sandbox_name)
        await self._podman_delete(f"/libpod/containers/{name}?force=true")
        await self._podman_delete(f"/libpod/volumes/{container.volume_name(sandbox_id)}?force=true")
        await self._podman_delete(f"/libpod/secrets/{container.token_secret_name(sandbox_id)}")

    async def list_sandboxes(self) -> list[DriverSandbox]:
        """List managed sandbox containers (filtered by the openshell label)."""
        # Real implementation:
        #   crates/openshell-driver-podman/src/driver.rs:713 — fn list_sandboxes
        #   Issues GET /libpod/containers/json?filters={"label":["com.nvidia.openshell.managed=true"]}
        #   over the Podman unix socket, deserializes the libpod ContainerSummary
        #   response, and maps each entry into a DriverSandbox via get_sandbox (line 697).
        raise NotImplementedError(
            "Podman list requires the libpod HTTP client; see "
            "crates/openshell-driver-podman/src/driver.rs:713 — fn list_sandboxes"
        )

    async def _create_sandbox_token_secret(self, sandbox: DriverSandbox) -> str | None:
        spec = sandbox.spec
        token = (getattr(spec, "sandbox_token", "") or "").strip() if spec else ""
        if not token:
            return None
        secret_name = container.token_secret_name(sandbox.id)
        await self._podman_post(f"/libpod/secrets/create?name={secret_name}", token)
        return secret_name

    # ---- transport stubs -------------------------------------------------
    async def _podman_post(self, path: str, body) -> dict:
        # Real implementation:
        #   crates/openshell-driver-podman/src/driver.rs:439 — async fn create_sandbox
        #   uses a reqwest async HTTP client configured for unix-socket transport
        #   (via hyperlocal / unix domain socket connector). All libpod API paths
        #   are prefixed with the socket path from config.socket_path.
        #   The client module is at crates/openshell-driver-podman/src/client.rs.
        raise NotImplementedError(
            f"Podman POST {path} requires an async HTTP-over-unix-socket client; "
            f"see crates/openshell-driver-podman/src/driver.rs:439 (create_sandbox) "
            f"and src/client.rs for the transport"
        )

    async def _podman_delete(self, path: str) -> None:
        # Real implementation:
        #   crates/openshell-driver-podman/src/driver.rs:608 — async fn delete_sandbox
        #   Same unix-socket HTTP client as _podman_post. Sends DELETE requests for
        #   the container, its named volume, and the per-sandbox token secret in sequence.
        raise NotImplementedError(
            f"Podman DELETE {path} requires an async HTTP-over-unix-socket client; "
            f"see crates/openshell-driver-podman/src/driver.rs:608 (delete_sandbox) "
            f"and src/client.rs for the transport"
        )


def _validate_name(name: str) -> None:
    """Podman name validation (Rust ``client::validate_name``)."""
    if not name or any(c.isspace() for c in name):
        raise ComputeDriverError.precondition(f"invalid container name: {name!r}")
