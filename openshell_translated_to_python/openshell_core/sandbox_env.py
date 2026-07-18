# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Environment-variable names used to configure the sandbox supervisor.

Translated from ``crates/openshell-core/src/sandbox_env.rs``.

These constants are the shared protocol between the compute drivers (which set
the variables when launching a sandbox container/VM) and the sandbox supervisor
process (which reads them on startup). Rust ``pub const &str`` values become
module-level string constants. See the original for the full doc-comment on
each variable's meaning.
"""

from __future__ import annotations

SANDBOX = "OPENSHELL_SANDBOX"
ENDPOINT = "OPENSHELL_ENDPOINT"
SANDBOX_ID = "OPENSHELL_SANDBOX_ID"
SSH_SOCKET_PATH = "OPENSHELL_SSH_SOCKET_PATH"
LOG_LEVEL = "OPENSHELL_LOG_LEVEL"
SANDBOX_COMMAND = "OPENSHELL_SANDBOX_COMMAND"
TELEMETRY_ENABLED = "OPENSHELL_TELEMETRY_ENABLED"
SUPERVISOR_TOPOLOGY = "OPENSHELL_SUPERVISOR_TOPOLOGY"
NETWORK_ENFORCEMENT_MODE = "OPENSHELL_NETWORK_ENFORCEMENT_MODE"
NETWORK_BINARY_IDENTITY = "OPENSHELL_NETWORK_BINARY_IDENTITY"
SIDECAR_CONTROL_SOCKET = "OPENSHELL_SIDECAR_CONTROL_SOCKET"
GATEWAY_TLS_SERVER_NAME = "OPENSHELL_GATEWAY_TLS_SERVER_NAME"
PROXY_TLS_DIR = "OPENSHELL_PROXY_TLS_DIR"
TLS_CA = "OPENSHELL_TLS_CA"
TLS_CERT = "OPENSHELL_TLS_CERT"
TLS_KEY = "OPENSHELL_TLS_KEY"
SANDBOX_TOKEN = "OPENSHELL_SANDBOX_TOKEN"
SANDBOX_TOKEN_FILE = "OPENSHELL_SANDBOX_TOKEN_FILE"
USER_ENVIRONMENT = "OPENSHELL_USER_ENVIRONMENT"
K8S_SA_TOKEN_FILE = "OPENSHELL_K8S_SA_TOKEN_FILE"
PROVIDER_SPIFFE_WORKLOAD_API_SOCKET = "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET"
SANDBOX_UID = "OPENSHELL_SANDBOX_UID"
SANDBOX_GID = "OPENSHELL_SANDBOX_GID"