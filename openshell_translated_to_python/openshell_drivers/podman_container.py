# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Container spec construction for the Podman driver.

Translated from ``crates/openshell-driver-podman/src/container.rs`` (2400 lines).

Builds the JSON body posted to Podman's libpod ``/containers/create`` API for a
sandbox: naming conventions, workspace volume, per-sandbox JWT secret, the
supervisor env vars (from :mod:`openshell_core.sandbox_env`), and GPU CDI device
requests. The exhaustive typed-struct set from Rust is condensed into builder
functions that return a plain ``dict`` (the JSON body).

Rust patterns:
- ``#[derive(Serialize)] struct ContainerSpec`` -> a ``dict`` assembled by
  :func:`build_container_spec`.
- ``Result<Value, ComputeDriverError>`` -> returns a dict or raises.
"""

from __future__ import annotations

from openshell_core import sandbox_env
from openshell_core.image import default_sandbox_image

CONTAINER_PREFIX = "openshell-"
VOLUME_PREFIX = "openshell-"
TOKEN_SECRET_PREFIX = "openshell-token-"


def container_name(sandbox_name: str) -> str:
    return f"{CONTAINER_PREFIX}{sandbox_name}"


def volume_name(sandbox_id: str) -> str:
    return f"{VOLUME_PREFIX}{sandbox_id}-workspace"


def token_secret_name(sandbox_id: str) -> str:
    return f"{TOKEN_SECRET_PREFIX}{sandbox_id}"


def short_id(id_: str) -> str:
    """Standard 12-char short container ID."""
    return id_[:12]


def resolve_image(sandbox, config) -> str:
    """Resolve the container image: sandbox spec image, else driver default."""
    spec = getattr(sandbox, "spec", None)
    image = getattr(spec, "image", "") if spec else ""
    if image:
        return image
    return getattr(config, "default_image", "") or default_sandbox_image()


def build_container_spec(sandbox, config, token_secret: str | None = None, gpu_devices=None) -> dict:
    """Assemble the libpod create-container JSON body for a sandbox.

    Corresponds to ``build_container_spec_with_token_and_gpu_devices``. Sets the
    supervisor protocol env vars so the in-container supervisor can find the
    gateway, its token, and its SSH socket.
    """
    spec = getattr(sandbox, "spec", None)
    name = getattr(sandbox, "name", "")
    sandbox_id = getattr(sandbox, "id", "")

    env: dict[str, str] = {
        sandbox_env.SANDBOX: name,
        sandbox_env.SANDBOX_ID: sandbox_id,
        sandbox_env.ENDPOINT: getattr(config, "gateway_endpoint", "") or "",
        sandbox_env.SSH_SOCKET_PATH: "/run/openshell/ssh.sock",
    }
    command = getattr(spec, "command", None) if spec else None
    if command:
        env[sandbox_env.SANDBOX_COMMAND] = " ".join(command)

    body: dict = {
        "name": container_name(name),
        "image": resolve_image(sandbox, config),
        "env": env,
        # Named workspace volume mounted at the sandbox workdir.
        "volumes": [{"Name": volume_name(sandbox_id), "Dest": "/sandbox"}],
        # PID limit shared with the Docker driver.
        "resource_limits": {"pids": {"limit": getattr(config, "pids_limit", 2048)}},
    }

    if token_secret is not None:
        # Podman secret mounted as a file; supervisor reads it via *_TOKEN_FILE.
        body["secrets"] = [{"source": token_secret, "target": "sandbox_token"}]
        env[sandbox_env.SANDBOX_TOKEN_FILE] = "/run/secrets/sandbox_token"

    if gpu_devices:
        # CDI device requests, e.g. ["nvidia.com/gpu=0", ...].
        body["devices"] = [{"path": dev} for dev in gpu_devices]

    return body