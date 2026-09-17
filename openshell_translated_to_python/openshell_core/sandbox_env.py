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

import base64
import json
from dataclasses import dataclass, field

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

# Versioned specification for the exact canonical main process. Replaces the
# former OPENSHELL_SANDBOX_COMMAND string. Most drivers use JSON directly;
# transports that cannot preserve spaces in environment values may use the
# "base64url:"-prefixed representation. See MainProcessConfig below.
MAIN_PROCESS_SPEC = "OPENSHELL_MAIN_PROCESS_SPEC"

_MAIN_PROCESS_SPEC_BASE64URL_PREFIX = "base64url:"


@dataclass
class MainProcessConfig:
    """Lossless driver-to-supervisor representation of the canonical process.

    An empty ``command`` means "no command supplied": the supervisor asks the
    sandbox boundary to resolve the default login shell against the agent image.
    A non-empty command is the exact program+args and is run verbatim.
    """

    version: int
    command: list[str]
    tty: bool
    await_main_process_attachment: bool = False

    # The single supported wire version.
    VERSION = 1

    @classmethod
    def scratch(cls) -> "MainProcessConfig":
        """Default config for a sandbox created without a command.

        The command is left empty on purpose: the sandbox boundary picks a login
        shell that exists in the agent image (bash when present, else ``/bin/sh``).
        A TTY is requested because the default is an interactive login shell.
        """
        return cls(version=cls.VERSION, command=[], tty=True, await_main_process_attachment=False)

    @classmethod
    def from_driver_spec(cls, spec) -> "MainProcessConfig":
        """Build from a ``DriverSandboxSpec`` proto (or ``None``).

        A spec with a non-empty command is copied verbatim; otherwise (missing
        spec or empty command) falls back to :meth:`scratch`.
        """
        if spec is not None and getattr(spec, "command", None):
            return cls(
                version=cls.VERSION,
                command=list(spec.command),
                tty=bool(spec.tty),
                await_main_process_attachment=bool(
                    getattr(spec, "await_main_process_attachment", False)
                ),
            )
        return cls.scratch()

    @classmethod
    def decode(cls, encoded: str) -> "MainProcessConfig":
        """Decode the versioned transport without shell interpretation.

        Accepts either raw JSON or the ``base64url:``-prefixed form. Raises
        ``ValueError`` on malformed input, unsupported version, or a
        present-but-blank program (an empty command list, however, is valid).
        """
        if encoded.startswith(_MAIN_PROCESS_SPEC_BASE64URL_PREFIX):
            payload = encoded[len(_MAIN_PROCESS_SPEC_BASE64URL_PREFIX) :]
            try:
                json_str = base64.urlsafe_b64decode(_pad_b64(payload)).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError(f"invalid {MAIN_PROCESS_SPEC} base64url/UTF-8: {error}") from error
        else:
            json_str = encoded
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid {MAIN_PROCESS_SPEC}: {error}") from error
        config = cls(
            version=int(data["version"]),
            command=list(data.get("command", [])),
            tty=bool(data.get("tty", False)),
            await_main_process_attachment=bool(data.get("await_main_process_attachment", False)),
        )
        if config.version != cls.VERSION:
            raise ValueError(f"unsupported {MAIN_PROCESS_SPEC} version {config.version}")
        # Empty command is valid ("no command supplied"); only a present-but-blank
        # program is rejected.
        if config.command and config.command[0] == "":
            raise ValueError(f"{MAIN_PROCESS_SPEC} command program must not be empty")
        return config

    @classmethod
    def encode_driver_spec(cls, spec) -> str:
        """Encode the versioned driver-to-supervisor transport as JSON."""
        return json.dumps(cls.from_driver_spec(spec).to_dict(), separators=(",", ":"))

    @classmethod
    def encode_driver_spec_base64url(cls, spec) -> str:
        """Encode the versioned transport without whitespace (constrained env vars)."""
        payload = base64.urlsafe_b64encode(cls.encode_driver_spec(spec).encode("utf-8"))
        stripped = payload.rstrip(b"=").decode("ascii")  # URL_SAFE_NO_PAD
        return f"{_MAIN_PROCESS_SPEC_BASE64URL_PREFIX}{stripped}"

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "command": self.command,
            "tty": self.tty,
            "await_main_process_attachment": self.await_main_process_attachment,
        }


def _pad_b64(payload: str) -> bytes:
    """Restore ``=`` padding stripped by URL_SAFE_NO_PAD before decoding."""
    return (payload + "=" * (-len(payload) % 4)).encode("ascii")


# Deployment-controlled telemetry toggle propagated to the sandbox supervisor.
TELEMETRY_ENABLED = "OPENSHELL_TELEMETRY_ENABLED"

# Kubernetes sidecar mode sets this to "sidecar"; the default combined
# supervisor path omits it.
SUPERVISOR_TOPOLOGY = "OPENSHELL_SUPERVISOR_TOPOLOGY"

# The isolation backend admitted by the deployment configuration (RFC 0012).
# Delivered on a channel separate from the topology descriptor so descriptor
# verification against the admitted backend is not self-referential. Required
# whenever a topology descriptor is supplied.
ADMITTED_ISOLATION_BACKEND = "OPENSHELL_ADMITTED_ISOLATION_BACKEND"

# Network enforcement backend selected by the compute driver.
NETWORK_ENFORCEMENT_MODE = "OPENSHELL_NETWORK_ENFORCEMENT_MODE"

# Comma-separated runtime networking capabilities supplied by the compute driver.
# Capabilities describe substrate the shared supervisor may activate; they never
# move policy evaluation into the driver.
NETWORK_RUNTIME_CAPABILITIES = "OPENSHELL_NETWORK_RUNTIME_CAPABILITIES"

# Driver capability for policy-gated DNS and transparent TCP interception.
POLICY_DNS_TRANSPARENT_TCP_CAPABILITY = "policy-dns-transparent-tcp"

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

# Optional path to a durable PEM-encoded interception CA certificate. Must be
# configured together with PROXY_CA_KEY.
PROXY_CA_CERT = "OPENSHELL_PROXY_CA_CERT"

# Optional path to the private key for PROXY_CA_CERT. Must be configured together
# with the certificate path.
PROXY_CA_KEY = "OPENSHELL_PROXY_CA_KEY"

# Whether the control-owned SSH Unix socket is shared across trusted UIDs.
SSH_SOCKET_SHARED = "OPENSHELL_SSH_SOCKET_SHARED"

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