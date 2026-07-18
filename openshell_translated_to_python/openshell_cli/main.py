# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""OpenShell CLI entry point and command dispatch.

Translated from ``crates/openshell-cli/src/main.rs`` (4800 lines in Rust).

Rust uses ``clap`` derive macros to define the ``openshell`` command tree
(``sandbox``, ``forward``, ``service``, ``policy``, ``provider``, ``gateway``,
``logs``, ``ssh-proxy`` ...). This Python port uses :mod:`argparse` to build the
equivalent top-level parser and dispatches the ``sandbox`` subcommands to
:mod:`openshell_cli.sandbox_cmds`. The many other subcommand groups are
represented structurally; their handlers live in ``run.rs`` in Rust and would
map to additional modules here.

Rust patterns:
- ``#[derive(Parser)] struct Cli`` / ``#[derive(Subcommand)] enum Commands`` ->
  argparse subparsers.
- ``#[tokio::main] async fn main()`` -> :func:`asyncio.run` around :func:`main`.
- ``ValueEnum`` -> ``choices=[...]``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from openshell_core import VERSION
from openshell_core.config import DEFAULT_SERVER_PORT

from . import sandbox_cmds

# TLS options are resolved from gateway metadata in the real CLI; a placeholder
# object stands in so handler signatures match the Rust ``&TlsOptions``.
_TLS_PLACEHOLDER = object()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openshell", description="OpenShell CLI")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--server",
        default=f"127.0.0.1:{DEFAULT_SERVER_PORT}",
        help="gateway endpoint (host:port)",
    )
    parser.add_argument("--gateway-name", default="default")

    sub = parser.add_subparsers(dest="command", required=True)

    # ---- sandbox (alias: sb) --------------------------------------------
    sandbox = sub.add_parser("sandbox", aliases=["sb"], help="manage sandboxes")
    sbsub = sandbox.add_subparsers(dest="sandbox_command", required=True)

    create = sbsub.add_parser("create", help="create a sandbox")
    create.add_argument("name", nargs="?")
    create.add_argument("--from", dest="from_", help="image or Dockerfile")
    create.add_argument("--keep", action="store_true")
    create.add_argument("--gpu")
    create.add_argument("--cpu")
    create.add_argument("--memory")
    create.add_argument("--editor")
    create.add_argument("--policy")
    create.add_argument("--forward")
    create.add_argument("--provider", action="append", default=[], dest="providers")
    # Trailing "-- <command>" is captured by argparse.REMAINDER.
    create.add_argument("command", nargs=argparse.REMAINDER)

    lst = sbsub.add_parser("list", help="list sandboxes")
    lst.add_argument("--output", choices=["table", "json"], default="table")
    lst.add_argument("--all", action="store_true")

    delete = sbsub.add_parser("delete", help="delete a sandbox")
    delete.add_argument("name", nargs="?")
    delete.add_argument("--all", action="store_true")

    connect = sbsub.add_parser("connect", help="connect to a sandbox")
    connect.add_argument("name")
    connect.add_argument("--editor")

    # ---- other top-level command groups (structure only) ----------------
    # In Rust these dispatch into run.rs handlers. Registered so `--help` shows
    # the same command surface; handlers are out of scope for this port.
    for name, alias, help_text in [
        ("forward", "fwd", "forward a local port to a sandbox"),
        ("service", "svc", "manage browser-facing sandbox services"),
        ("policy", "pol", "manage sandbox policies"),
        ("provider", None, "manage credential providers"),
        ("gateway", "gw", "manage gateway endpoints"),
        ("logs", "lg", "stream gateway/sandbox logs"),
    ]:
        aliases = [alias] if alias else []
        sub.add_parser(name, aliases=aliases, help=help_text)

    # ssh-proxy is a hidden helper invoked by SSH ProxyCommand.
    proxy = sub.add_parser("ssh-proxy", help=argparse.SUPPRESS)
    proxy.add_argument("--gateway-name", default="default")
    proxy.add_argument("--name", required=True)

    return parser


async def _dispatch(args: argparse.Namespace) -> int:
    """Route parsed args to the right handler (Rust ``match cli.command``)."""
    server = args.server

    if args.command in ("sandbox", "sb"):
        cmd = args.sandbox_command
        if cmd == "create":
            create_args = sandbox_cmds.SandboxCreateArgs(
                name=args.name,
                from_=args.from_,
                keep=args.keep,
                gpu=args.gpu,
                cpu=args.cpu,
                memory=args.memory,
                editor=args.editor,
                policy=args.policy,
                forward=args.forward,
                providers=args.providers,
                # Strip a leading "--" that argparse.REMAINDER keeps.
                command=[c for c in args.command if c != "--"],
            )
            await sandbox_cmds.sandbox_create(
                server, args.gateway_name, create_args, _TLS_PLACEHOLDER
            )
        elif cmd == "list":
            await sandbox_cmds.sandbox_list(
                server, sandbox_cmds.SandboxListArgs(output=args.output, all=args.all), _TLS_PLACEHOLDER
            )
        elif cmd == "delete":
            await sandbox_cmds.sandbox_delete(
                server, sandbox_cmds.SandboxDeleteArgs(name=args.name, all=args.all), _TLS_PLACEHOLDER
            )
        elif cmd == "connect":
            await sandbox_cmds.sandbox_connect(
                server, sandbox_cmds.SandboxConnectArgs(name=args.name, editor=args.editor), _TLS_PLACEHOLDER
            )
        return 0

    if args.command == "ssh-proxy":
        from . import ssh

        await ssh.sandbox_ssh_proxy_by_name(server, args.name, _TLS_PLACEHOLDER)
        return 0

    print(f"command '{args.command}' is registered but its handler is not ported", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_dispatch(args))
    except NotImplementedError as exc:
        print(f"not implemented: {exc}", file=sys.stderr)
        return 3
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())