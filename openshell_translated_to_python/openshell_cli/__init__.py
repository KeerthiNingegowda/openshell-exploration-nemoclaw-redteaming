# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""openshell_cli — Python translation of the ``openshell-cli`` Rust crate.

- :mod:`openshell_cli.main` — command tree + dispatch (``src/main.rs``).
- :mod:`openshell_cli.sandbox_cmds` — sandbox create/connect/list/delete (``src/run.rs``).
- :mod:`openshell_cli.ssh` — SSH tunneling / proxy / config (``src/ssh.rs``).
"""

from . import main, sandbox_cmds, ssh

__all__ = ["main", "sandbox_cmds", "ssh"]