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
module-level string constants.

Each constant's inline comment is the verbatim doc-comment from the Rust source
(``sandbox_env.rs``), ported here so the meanings are self-contained rather than
requiring a cross-reference to the Rust. Unless noted, the *setter* is the
compute driver (the sole injection point for the child environment); some values
originate from gateway-supplied identity material or from Kubernetes.
"""

from __future__ import annotations

# Name of the sandbox (used for policy sync and identification).
# NOTE: this is the sandbox *name*, not a boolean "am I sandboxed" flag.
SANDBOX = "OPENSHELL_SANDBOX"

# gRPC endpoint of the OpenShell gateway that the sandbox reports to.
ENDPOINT = "OPENSHELL_ENDPOINT"

# Unique identifier of the sandbox being supervised.
SANDBOX_ID = "OPENSHELL_SANDBOX_ID"

# Filesystem path to the UNIX socket used for the in-sandbox SSH server.
SSH_SOCKET_PATH = "OPENSHELL_SSH_SOCKET_PATH"

# Log level for the sandbox supervisor (e.g. "debug", "info", "warn").
LOG_LEVEL = "OPENSHELL_LOG_LEVEL"

# Shell command to run inside the sandbox.
SANDBOX_COMMAND = "OPENSHELL_SANDBOX_COMMAND"

# Deployment-controlled telemetry toggle propagated to the sandbox supervisor.
TELEMETRY_ENABLED = "OPENSHELL_TELEMETRY_ENABLED"

# Kubernetes sidecar mode sets this to "sidecar"; the default combined
# supervisor path omits it.
SUPERVISOR_TOPOLOGY = "OPENSHELL_SUPERVISOR_TOPOLOGY"

# Network enforcement backend selected by the compute driver.
NETWORK_ENFORCEMENT_MODE = "OPENSHELL_NETWORK_ENFORCEMENT_MODE"

# Whether network policy evaluation must bind requests to the peer binary.
# Default when unset is "required". Kubernetes sidecar experiments may set this
# to "relaxed" to enforce endpoint and L7 policy without per-binary /proc
# identity binding.
NETWORK_BINARY_IDENTITY = "OPENSHELL_NETWORK_BINARY_IDENTITY"

# Unix socket used by Kubernetes sidecar topology for local coordination. The
# network sidecar owns gateway credentials and serves policy/provider state over
# this socket instead of exposing gateway credentials to the agent container.
SIDECAR_CONTROL_SOCKET = "OPENSHELL_SIDECAR_CONTROL_SOCKET"

# Optional TLS server name override used when connecting to the gateway.
GATEWAY_TLS_SERVER_NAME = "OPENSHELL_GATEWAY_TLS_SERVER_NAME"

# Directory where the network supervisor writes the proxy CA files consumed by
# workload child processes.
PROXY_TLS_DIR = "OPENSHELL_PROXY_TLS_DIR"

# Path to the CA certificate for mTLS communication with the gateway.
TLS_CA = "OPENSHELL_TLS_CA"

# Path to the client certificate for mTLS communication with the gateway.
TLS_CERT = "OPENSHELL_TLS_CERT"

# Path to the private key for mTLS communication with the gateway.
TLS_KEY = "OPENSHELL_TLS_KEY"

# Raw gateway-minted JWT identifying this sandbox. Mutually exclusive with
# SANDBOX_TOKEN_FILE / K8S_SA_TOKEN_FILE; used only by test harnesses that bypass
# the file-mount path.
SANDBOX_TOKEN = "OPENSHELL_SANDBOX_TOKEN"

# Path to the file holding a gateway-minted sandbox JWT. Set by Docker, Podman,
# and VM drivers, which write the token to a bundle file at sandbox-create time.
# Read once at supervisor startup; the token is held in process memory thereafter.
SANDBOX_TOKEN_FILE = "OPENSHELL_SANDBOX_TOKEN_FILE"

# JSON-serialized map of user-specified environment variables. Set by compute
# drivers from SandboxSpec.environment. Supervisor deserializes this at startup
# and injects the variables into SSH child processes (which use env_clear() for
# security isolation).
USER_ENVIRONMENT = "OPENSHELL_USER_ENVIRONMENT"

# Path to the projected ServiceAccount JWT (Kubernetes driver). Used to bootstrap
# a gateway-minted JWT via IssueSandboxToken. Kubelet writes and rotates this
# file; the supervisor exchanges its contents for a gateway JWT at startup and on
# refresh.
K8S_SA_TOKEN_FILE = "OPENSHELL_K8S_SA_TOKEN_FILE"

# Filesystem path to the SPIFFE Workload API UNIX socket used for provider token
# grants. When set, the supervisor can fetch JWT-SVIDs for upstream provider
# token exchanges without using SPIFFE for gateway authentication.
PROVIDER_SPIFFE_WORKLOAD_API_SOCKET = "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET"

# Resolved sandbox UID used to override run_as_user when the policy specifies a
# numeric value instead of the hardcoded "sandbox" user name. Set by compute
# drivers (Kubernetes, Docker, VM) from resolved config or cluster autodetection.
# Supervisor reads this at startup and uses it directly with setuid()/chown()
# without requiring an /etc/passwd entry in the sandbox image.
SANDBOX_UID = "OPENSHELL_SANDBOX_UID"

# Resolved sandbox GID paired with SANDBOX_UID. Used alongside UID for PVC init
# container chown operations and when the supervisor drops privileges to a group
# other than the UID's primary group.
SANDBOX_GID = "OPENSHELL_SANDBOX_GID"

# Raw OCI Config.User declaration from the immutable image selected by a local
# container driver. Docker and Podman overwrite this value with the image
# declaration, including an empty string when the image has no USER, and clear
# SANDBOX_UID and SANDBOX_GID. Drivers with an authoritative numeric identity
# overwrite this value with an empty string while supplying both numeric fields.
# Supervisor resolves omitted policy identity fields from OCI only for the former
# contract.
OCI_IMAGE_USER = "OPENSHELL_OCI_IMAGE_USER"