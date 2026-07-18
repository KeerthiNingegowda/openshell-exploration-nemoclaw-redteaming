"""Docker compute driver.

Translated from ``crates/openshell-driver-docker/src/lib.rs`` (3500 lines).

Implements the container sandbox lifecycle over the Docker Engine API. The Rust
driver is notably asynchronous in its *provisioning*: ``create_sandbox`` returns
immediately after reserving a "pending" record and spawns a background task
(``tokio::spawn``) that pulls the image, writes the sandbox JWT, creates and
starts the container, then publishes status snapshots. This port preserves that
two-phase structure using :func:`asyncio.create_task`.

Transport (Docker Engine HTTP over the unix socket) and the progress/snapshot
publishing bus are represented as clearly-marked stubs.

Rust patterns:
- ``self.pending.lock().await`` (``Arc<Mutex<..>>``) -> :class:`asyncio.Lock`.
- ``tokio::spawn`` -> :func:`asyncio.create_task`.
- ``Result<(), Status>`` -> returns ``None`` or raises :class:`ComputeDriverError`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from openshell_core.config import (
    DEFAULT_DOCKER_NETWORK_NAME,
    DEFAULT_SANDBOX_PIDS_LIMIT,
    detect_docker_socket,
)
from openshell_core.error import ComputeDriverError
from openshell_core.gpu import CdiGpuDefaultSelector, CdiGpuInventory, effective_driver_gpu_count
from openshell_core.image import default_sandbox_image

from . import podman_container as container  # naming helpers are shared
from .base import ComputeDriver, DriverSandbox


@dataclass
class DockerComputeConfig:
    socket_path: str = ""
    default_image: str = field(default_factory=default_sandbox_image)
    network_name: str = DEFAULT_DOCKER_NETWORK_NAME
    sandbox_namespace: str = "openshell"
    gateway_endpoint: str = ""
    pids_limit: int = DEFAULT_SANDBOX_PIDS_LIMIT
    allow_all_gpus: bool = False


@dataclass
class _PendingRecord:
    task: asyncio.Task | None = None


class DockerComputeDriver(ComputeDriver):
    """Docker-backed :class:`ComputeDriver` with async provisioning."""

    def __init__(self, config: DockerComputeConfig | None = None) -> None:
        self.config = config or DockerComputeConfig()
        if not self.config.socket_path:
            sock = detect_docker_socket()
            self.config.socket_path = str(sock) if sock else ""
        self.gpu_selector = CdiGpuDefaultSelector(CdiGpuInventory.new([]), self.config.allow_all_gpus)
        self._pending: dict[str, _PendingRecord] = {}
        self._pending_lock = asyncio.Lock()  # Rust Arc<Mutex<HashMap<..>>>

    # ---- lifecycle -------------------------------------------------------
    async def create_sandbox(self, sandbox: DriverSandbox) -> None:
        """Accept a sandbox and provision it in the background.

        Fast path: validate, reject if it already exists, reserve a pending
        record, publish a "Scheduled" progress event, then spawn provisioning.
        """
        if await self._find_container(sandbox.id, sandbox.name) is not None:
            raise ComputeDriverError.already_exists()

        async with self._pending_lock:
            self._pending[sandbox.id] = _PendingRecord()

        image = _sandbox_image(sandbox) or self.config.default_image
        self._publish_progress(sandbox.id, "Scheduled", f'Docker sandbox accepted for image "{image}"')

        task = asyncio.create_task(self._provision(sandbox))
        async with self._pending_lock:
            record = self._pending.get(sandbox.id)
            if record is not None:
                record.task = task
            else:
                task.cancel()  # deleted before provisioning attached

    async def _provision(self, sandbox: DriverSandbox) -> None:
        """Background provisioning (Rust ``provision_sandbox``)."""
        try:
            await self._provision_inner(sandbox)
            await self._clear_pending(sandbox.id)
        except ComputeDriverError as failure:
            await self._fail_pending(sandbox, failure)

    async def _provision_inner(self, sandbox: DriverSandbox) -> None:
        image = _sandbox_image(sandbox) or self.config.default_image

        gpu = getattr(getattr(sandbox.spec, "resources", None), "gpu", None) if sandbox.spec else None
        gpu_devices = None
        count = effective_driver_gpu_count(gpu)
        if count:
            gpu_devices = self.gpu_selector.next_device_ids(count)

        await self._ensure_image_available(sandbox.id, image)
        await self._write_sandbox_token_file(sandbox)
        body = container.build_container_spec(sandbox, self.config, gpu_devices=gpu_devices)
        await self._docker_post("/containers/create", body)
        await self._docker_post(f"/containers/{body['name']}/start", {})

    async def delete_sandbox(self, sandbox_id: str, sandbox_name: str) -> None:
        # Cancel any in-flight provisioning first.
        async with self._pending_lock:
            record = self._pending.pop(sandbox_id, None)
        if record and record.task:
            record.task.cancel()
        name = container.container_name(sandbox_name)
        await self._docker_delete(f"/containers/{name}?force=true")

    async def list_sandboxes(self) -> list[DriverSandbox]:
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs — inside DockerComputeDriver
        #   (struct at line 208). Lists containers via GET /containers/json filtered
        #   by the label com.nvidia.openshell.managed=true, then maps each Docker
        #   ContainerSummary into a DriverSandbox. The resume_sandbox method
        #   (line 930) re-attaches to containers that were already running on
        #   gateway restart.
        raise NotImplementedError(
            "Docker list requires the Engine HTTP client; see "
            "crates/openshell-driver-docker/src/lib.rs (DockerComputeDriver at line 208)"
        )

    async def stop_managed_containers_on_shutdown(self) -> int:
        """Stop all managed containers on gateway shutdown; return the count."""
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs:959 — fn stop_managed_containers_on_shutdown
        #   Queries GET /containers/json with the managed label filter, then issues
        #   POST /containers/{id}/stop for each. Returns the total count stopped.
        raise NotImplementedError(
            "shutdown sweep requires the Engine HTTP client; see "
            "crates/openshell-driver-docker/src/lib.rs:959 — fn stop_managed_containers_on_shutdown"
        )

    # ---- pending bookkeeping --------------------------------------------
    async def _clear_pending(self, sandbox_id: str) -> None:
        async with self._pending_lock:
            self._pending.pop(sandbox_id, None)

    async def _fail_pending(self, sandbox: DriverSandbox, failure: ComputeDriverError) -> None:
        await self._clear_pending(sandbox.id)
        self._publish_progress(sandbox.id, "Failed", str(failure))

    # ---- transport / bus stubs ------------------------------------------
    def _publish_progress(self, sandbox_id: str, phase: str, message: str) -> None:
        # Rust publishes onto a progress bus consumed by the CLI/TUI. No-op here.
        pass

    async def _find_container(self, sandbox_id: str, sandbox_name: str):
        # Returns a container summary or None; requires the Engine client.
        return None

    async def _ensure_image_available(self, sandbox_id: str, image: str) -> None:
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs — inside the provisioning
        #   flow of DockerComputeDriver::new (line 311) and resume_sandbox (line 930).
        #   Calls GET /images/{image}/json; if 404, streams POST /images/create
        #   (Docker pull) and publishes progress events via the progress bus.
        raise NotImplementedError(f"image pull for {image} requires the Engine client; "
                                  f"see crates/openshell-driver-docker/src/lib.rs:311 (DockerComputeDriver::new)")

    async def _write_sandbox_token_file(self, sandbox: DriverSandbox) -> None:
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs:311 — inside DockerComputeDriver::new
        #   provisioning flow. Writes a JSON bundle containing the sandbox JWT and
        #   gateway CA cert to a temp dir on the host, then bind-mounts that dir
        #   into the container at the path defined by OPENSHELL_TOKEN_DIR (sandbox_env.rs).
        raise NotImplementedError("writing the sandbox JWT bundle requires host FS access; "
                                  "see crates/openshell-driver-docker/src/lib.rs:311 (provisioning flow)")

    async def _docker_post(self, path: str, body) -> dict:
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs — DockerComputeDriver (line 208)
        #   uses an internal HTTP client (hyper over the Docker unix socket) to POST
        #   JSON to the Docker Engine API. The socket path comes from config.socket_path.
        raise NotImplementedError(f"Docker POST {path} requires an Engine HTTP client; "
                                  f"see crates/openshell-driver-docker/src/lib.rs:208 (DockerComputeDriver)")

    async def _docker_delete(self, path: str) -> None:
        # Real implementation:
        #   crates/openshell-driver-docker/src/lib.rs — DockerComputeDriver (line 208)
        #   Same HTTP client as _docker_post; issues DELETE to the Docker Engine API.
        raise NotImplementedError(f"Docker DELETE {path} requires an Engine HTTP client; "
                                  f"see crates/openshell-driver-docker/src/lib.rs:208 (DockerComputeDriver)")


def _sandbox_image(sandbox: DriverSandbox) -> str:
    spec = sandbox.spec
    return (getattr(spec, "image", "") or "") if spec else ""
