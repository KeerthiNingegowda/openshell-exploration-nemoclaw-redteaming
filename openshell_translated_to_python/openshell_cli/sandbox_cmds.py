"""Sandbox subcommands: create / connect / list / delete.

Translated from the sandbox-related handlers in
``crates/openshell-cli/src/run.rs`` (10k lines in Rust) and the
``SandboxCommands`` enum in ``crates/openshell-cli/src/main.rs``.

Each handler in the Rust source (``sandbox_create``, ``sandbox_list``,
``sandbox_delete``, ...) opens an authenticated gRPC channel to the gateway and
issues one RPC (``CreateSandbox``, ``ListSandboxes``, ``DeleteSandbox`` ...). The
gRPC request/response wiring depends on generated stubs which are not vendored
here, so the RPC calls are represented as clearly-marked stubs while the
argument model, validation, and control flow are translated faithfully.

Rust patterns:
- ``async fn ... -> Result<()>`` -> ``async def`` returning ``None`` or raising.
- clap ``#[derive(Subcommand)] enum SandboxCommands`` -> a dataclass per command
  plus a dispatcher.
- ``Option<T>`` flags -> ``T | None`` dataclass fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openshell_core import forward_check  # local helper below
from openshell_core.image import resolve_community_image


# ---- Command argument models (mirror the clap SandboxCommands variants) ----


@dataclass
class SandboxCreateArgs:
    """``openshell sandbox create`` arguments."""

    name: str | None = None
    from_: str | None = None  # --from image or Dockerfile
    uploads: list[str] = field(default_factory=list)
    keep: bool = False  # delete sandbox after initial command exits when False
    gpu: str | None = None
    cpu: str | None = None
    memory: str | None = None
    editor: str | None = None
    providers: list[str] = field(default_factory=list)
    policy: str | None = None
    forward: str | None = None
    command: list[str] = field(default_factory=list)  # trailing "-- <cmd>"
    labels: dict[str, str] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxListArgs:
    output: str = "table"  # table | json
    all: bool = False


@dataclass
class SandboxDeleteArgs:
    name: str | None = None
    all: bool = False


@dataclass
class SandboxConnectArgs:
    name: str
    editor: str | None = None


# ---- Handlers -------------------------------------------------------------


async def sandbox_create(server: str, gateway_name: str, args: SandboxCreateArgs, tls) -> None:
    """Create a sandbox (Rust ``run::sandbox_create``).

    Validates flag combinations and port availability *before* creating the
    sandbox (so a failed forward doesn't orphan a sandbox), resolves ``--from``
    into an image reference, then issues ``CreateSandbox`` over gRPC.
    """
    if args.editor is not None and args.command:
        raise ValueError(
            "--editor cannot be used with a trailing command; use "
            "`openshell sandbox connect <name> --editor ...` after the sandbox is ready"
        )

    # Check port availability up front to avoid leaving an orphaned sandbox.
    if args.forward is not None:
        forward_check.check_port_available(args.forward)

    # Resolve --from into a fully-qualified image reference (Dockerfile build
    # detection is elided; see run::resolve_from).
    image: str | None = None
    if args.from_ is not None:
        image = resolve_community_image(args.from_)

    _ = image  # would be placed on the CreateSandbox request
    # Real implementation:
    #   crates/openshell-cli/src/run.rs:1960 — async fn sandbox_create
    #   Builds a CreateSandboxRequest proto, opens an authenticated tonic channel
    #   to the gateway (connect_channel_pub), calls SandboxService::create_sandbox,
    #   then optionally connects over SSH or launches an editor session.
    raise NotImplementedError(
        "CreateSandbox RPC requires the OpenShell gRPC stubs; see "
        "crates/openshell-cli/src/run.rs:1960 — async fn sandbox_create"
    )


async def sandbox_list(server: str, args: SandboxListArgs, tls) -> None:
    """List sandboxes (Rust ``run::sandbox_list``) — issues ``ListSandboxes``."""
    # Real implementation:
    #   crates/openshell-cli/src/run.rs:3488 — async fn sandbox_list
    #   Calls SandboxService::list_sandboxes, then formats the result as a table
    #   or JSON depending on --output. Also fetches live sandbox status snapshots.
    raise NotImplementedError(
        "ListSandboxes RPC requires the OpenShell gRPC stubs; see "
        "crates/openshell-cli/src/run.rs:3488 — async fn sandbox_list"
    )


async def sandbox_delete(server: str, args: SandboxDeleteArgs, tls) -> None:
    """Delete a sandbox by name, or all sandboxes (Rust ``run::sandbox_delete``)."""
    if not args.all and not args.name:
        raise ValueError("provide a sandbox name or --all")
    # Real implementation:
    #   crates/openshell-cli/src/run.rs:3780 — async fn sandbox_delete
    #   If --all, calls list_sandboxes first and iterates. For each sandbox calls
    #   SandboxService::delete_sandbox, waits for confirmation, and cleans up any
    #   active SSH port-forwards (stop_forwards_for_sandbox in forward.rs:437).
    raise NotImplementedError(
        "DeleteSandbox RPC requires the OpenShell gRPC stubs; see "
        "crates/openshell-cli/src/run.rs:3780 — async fn sandbox_delete"
    )


async def sandbox_connect(server: str, args: SandboxConnectArgs, tls) -> None:
    """Connect to a sandbox over SSH (delegates to :mod:`openshell_cli.ssh`)."""
    from . import ssh

    if args.editor is not None:
        # Editor path installs an SSH config block and launches the editor.
        ssh.install_ssh_config(gateway="default", name=args.name)
        return
    await ssh.sandbox_connect(server, args.name, tls)
