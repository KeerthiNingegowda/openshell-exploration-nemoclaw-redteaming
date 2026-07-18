# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""openshell_core — Python translation of the ``openshell-core`` Rust crate.

Educational, readable port of the shared OpenShell core: config, auth, JWT
inspection, sandbox-env protocol, secret placeholder resolution, provider
credentials, sandbox policy structures, errors, paths, metadata, image
resolution, and GPU selection.

Each submodule maps 1:1 to a ``crates/openshell-core/src/*.rs`` file and
documents the Rust->Python translation decisions in its module docstring.
"""

from . import (
    auth,
    config,
    error,
    gpu,
    image,
    jwt,
    metadata,
    paths,
    policy,
    provider_credentials,
    sandbox_env,
    secrets,
    time,
)

VERSION = "0.0.0-dev"  # mirrors Rust ``openshell_core::VERSION``

__all__ = [
    "auth",
    "config",
    "error",
    "gpu",
    "image",
    "jwt",
    "metadata",
    "paths",
    "policy",
    "provider_credentials",
    "sandbox_env",
    "secrets",
    "time",
    "VERSION",
]