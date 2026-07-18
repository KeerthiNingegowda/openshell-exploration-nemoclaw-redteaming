"""SSH connection and proxy utilities for the CLI.

Translated from ``crates/openshell-cli/src/ssh.rs`` (2300 lines in Rust).

The CLI connects to sandboxes over SSH tunneled through the gateway. It does not
talk raw TCP to the sandbox; instead ``ssh`` is invoked with a ``ProxyCommand``
that runs ``openshell ssh-proxy`` — that subcommand opens a gRPC stream to the
gateway and relays the SSH bytes. This module reproduces:
- building the base ``ssh`` command with hardened options,
- rendering + installing the managed ``~/.config/openshell/ssh_config`` block,
- the host-alias convention and editor launch.

The heavy stream-relay and sync (rsync-like up/down) paths are represented as
clearly-marked stubs, since they are large and depend on the gRPC transport.

Rust patterns:
- ``tokio::process::Command`` -> :mod:`subprocess` / :mod:`asyncio.subprocess`.
- ``Result<()>`` -> returns ``None`` or raises.
- ``async fn`` -> ``async def`` (asyncio).
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from openshell_core import paths


def host_alias(name: str) -> str:
    """SSH host alias for a sandbox: ``openshell-<name>``."""
    return f"openshell-{name}"


def ssh_base_command(proxy_command: str) -> list[str]:
    """Return the hardened ``ssh`` argv with the given ProxyCommand.

    Mirrors ``ssh_base_command``: disables host-key checking (the tunnel is
    already authenticated end-to-end via the gateway) and enables keepalives so
    a silently-dropped relay is detected within ~45s.
    """
    ssh_log_level = os.environ.get("OPENSHELL_SSH_LOG_LEVEL", "ERROR")
    return [
        "ssh",
        "-o", f"ProxyCommand={proxy_command}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"LogLevel={ssh_log_level}",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]


def render_ssh_config(gateway: str, name: str) -> str:
    """Render an SSH ``Host`` block for a sandbox.

    The ``ProxyCommand`` invokes this CLI's ``ssh-proxy`` subcommand with
    ``--gateway-name`` so it resolves the gateway endpoint + mTLS certs from the
    gateway metadata directory.
    """
    exe = shlex.quote(sys.argv[0] or "openshell")
    proxy_cmd = f"{exe} ssh-proxy --gateway-name {shlex.quote(gateway)} --name {shlex.quote(name)}"
    alias = host_alias(name)
    return (
        f"Host {alias}\n"
        "    User sandbox\n"
        "    StrictHostKeyChecking no\n"
        "    UserKnownHostsFile /dev/null\n"
        "    GlobalKnownHostsFile /dev/null\n"
        "    LogLevel ERROR\n"
        "    ServerAliveInterval 15\n"
        "    ServerAliveCountMax 3\n"
        f"    ProxyCommand {proxy_cmd}\n"
    )


def openshell_ssh_config_path() -> Path:
    return paths.xdg_config_dir() / "openshell" / "ssh_config"


def user_ssh_config_path() -> Path:
    home = os.environ.get("HOME")
    if not home:
        raise RuntimeError("HOME is not set")
    return Path(home) / ".ssh" / "config"


def _upsert_host_block(contents: str, alias: str, block: str) -> str:
    """Replace an existing ``Host <alias>`` block or append a new one.

    Simplified port of the Rust ``upsert_host_block``: splits on ``Host``
    directives, drops any block whose first line targets ``alias``, and appends
    the fresh block.
    """
    lines = contents.splitlines(keepends=True)
    out: list[str] = []
    skipping = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Host "):
            skipping = stripped == f"Host {alias}"
        if not skipping:
            out.append(line)
    result = "".join(out)
    if result and not result.endswith("\n"):
        result += "\n"
    return result + block


def install_ssh_config(gateway: str, name: str) -> Path:
    """Write/refresh the managed OpenShell SSH config for a sandbox.

    Ensures ``~/.ssh/config`` includes the managed file, then upserts the host
    block. Returns the managed config path.
    """
    managed = openshell_ssh_config_path()
    paths.create_dir_restricted(managed.parent)
    # NOTE: ensuring the ``Include`` line in ~/.ssh/config is elided here for
    # brevity (Rust ``ensure_openshell_include``); the block-upsert is the core.
    alias = host_alias(name)
    block = render_ssh_config(gateway, name)
    contents = managed.read_text() if managed.exists() else ""
    managed.write_text(_upsert_host_block(contents, alias, block))
    return managed


def print_ssh_config(gateway: str, name: str) -> None:
    print(render_ssh_config(gateway, name), end="")


async def sandbox_connect(server: str, name: str, tls) -> None:
    """Open an interactive SSH session to a sandbox.

    Runs ``ssh`` with a ProxyCommand pointing at this CLI's ssh-proxy. The full
    Rust path first verifies the sandbox exists over gRPC and negotiates a
    per-session token; that gRPC handshake is stubbed here.
    """
    proxy_command = f"{shlex.quote(sys.argv[0] or 'openshell')} ssh-proxy --name {shlex.quote(name)}"
    argv = ssh_base_command(proxy_command) + ["sandbox"]
    # Interactive: inherit stdio so the user gets a real terminal.
    subprocess.run(argv, check=False)


async def sandbox_ssh_proxy_by_name(server: str, name: str, tls) -> None:
    """Relay SSH bytes over a gRPC stream to the sandbox (Rust ``sandbox_ssh_proxy``).

    Platform/transport-specific: opens a bidirectional gRPC stream to the gateway
    and pumps stdin<->stream<->stdout. Requires the generated gRPC stubs.
    """
    # Real implementation (two functions work together):
    #   crates/openshell-cli/src/ssh.rs:1420 — async fn sandbox_ssh_proxy_by_name
    #     Resolves the sandbox name to a gateway endpoint + TLS certs, then calls:
    #   crates/openshell-cli/src/ssh.rs:1322 — async fn sandbox_ssh_proxy
    #     Connects a tonic channel, calls SandboxService::ssh_session to obtain a
    #     per-session token, then opens a bidirectional streaming RPC
    #     (SandboxService::sandbox_ssh_proxy_stream) and splices stdin/stdout onto
    #     it using tokio::io::copy_bidirectional.
    raise NotImplementedError(
        "ssh-proxy relay requires the OpenShell gRPC stubs; see "
        "crates/openshell-cli/src/ssh.rs:1420 — async fn sandbox_ssh_proxy_by_name "
        "and ssh.rs:1322 — async fn sandbox_ssh_proxy"
    )
