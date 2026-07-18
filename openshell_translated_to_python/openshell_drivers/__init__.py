# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""openshell_drivers — Python translation of the container compute drivers.

- :mod:`openshell_drivers.base` — the ``ComputeDriver`` trait + sandbox types.
- :mod:`openshell_drivers.docker_driver` — ``openshell-driver-docker``.
- :mod:`openshell_drivers.podman_driver` — ``openshell-driver-podman`` (driver.rs).
- :mod:`openshell_drivers.podman_container` — Podman container spec builder
  (container.rs), whose naming helpers the Docker driver also reuses.
"""

from .base import ComputeDriver, DriverSandbox, SandboxSpec
from .docker_driver import DockerComputeConfig, DockerComputeDriver
from .podman_driver import PodmanComputeConfig, PodmanComputeDriver

__all__ = [
    "ComputeDriver",
    "DriverSandbox",
    "SandboxSpec",
    "DockerComputeConfig",
    "DockerComputeDriver",
    "PodmanComputeConfig",
    "PodmanComputeDriver",
]